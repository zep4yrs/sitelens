// CP-05 性能分片/续扫：把「页面 / 模板批次」切成可恢复分片，支持 checkpoint
// 跳过、并发度硬上限（≤4）与单分片失败重试（默认 1 次）。
//
// 本文件是纯逻辑（无网络、无引擎状态、无全局变量），只提供执行器与数据形态；
// 接线由调用方（engine 各阶段）完成，不改 engine.go。典型接线：
//
//	// 1) 切分：页面批次（URL 列表）或模板批次（模板路径列表）
//	plan := engine.SplitShards(pageURLs, 3)
//	// 2) 续扫：从上次落盘的 checkpoint 恢复（只认 ID+Items 完全一致的分片）
//	if saved, err := engine.LoadShardCheckpoint(data); err == nil {
//	    plan = engine.MergeShardCheckpoint(plan, saved)
//	}
//	// 3) 执行：Done 分片自动跳过；并发 ≤4；失败重试 1 次
//	stats, err := engine.RunShards(ctx, plan, engine.ShardOptions{}, func(ctx context.Context, sh engine.Shard) error {
//	    return analyzePages(sh.Items) // 单页指纹/被动检查，或模板批次执行
//	})
//	// 4) 落盘：成功分片 Done=true，可直接序列化作为 checkpoint
//	data, _ = engine.MarshalShardCheckpoint(plan)
//
// 纪律：并发只在分片层（CPU/模板批次）；若 fn 内部发网络请求，仍须受引擎
// 既有 httpx 并发/限速约束，本执行器不额外增加网络并发；fn 内不要并发调用
// 进度/事件回调（本执行器会并发调用 fn），由调用方自行串行化。
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
)

const (
	// MaxShardConcurrency 分片执行器的并发硬上限（产品口径 ≤4）。
	MaxShardConcurrency = 4

	// DefaultShardRetries 单分片失败后的默认重试次数（1 次 ⇒ 最多 2 次尝试）。
	DefaultShardRetries = 1
)

// Shard 一个可恢复分片：ID 在计划内稳定（SplitShards 从 0 递增），Items 为
// 该片工作项（页面 URL / 模板路径等），Done=true 表示已完成（续扫时跳过）。
type Shard struct {
	ID    int      `json:"id"`
	Items []string `json:"items"`
	Done  bool     `json:"done"`
}

// ShardStats 一次分片执行的统计（诊断/进度展示用）。
type ShardStats struct {
	Total     int // 计划内分片总数
	Skipped   int // checkpoint 命中（Done=true）而跳过的分片数
	Completed int // 本次成功完成的分片数
	Failed    int // 重试耗尽仍失败的分片数
	Items     int // 本次实际执行（已派发）分片的工作项总数，不含跳过分片
	Retries   int // 实际发生的重试次数
}

// ShardOptions 分片执行参数（零值 = 默认：并发 4、重试 1 次）。
type ShardOptions struct {
	// Concurrency 并发度：≤0 用 MaxShardConcurrency；大于 MaxShardConcurrency
	// 会被夹到硬上限（调用方传入再大也不会突破 ≤4）。
	Concurrency int
	// Retries 单分片失败后的重试次数：0 用 DefaultShardRetries；负数表示
	// 不重试（只执行一次）。总尝试次数 = Retries+1（负数按 0 处理）。
	Retries int
}

// ShardFunc 单分片执行函数：返回错误则该分片失败（按 ShardOptions.Retries
// 重试）；返回 nil 则分片完成并置 Done。参数中的 Items 只读，不要修改。
type ShardFunc func(ctx context.Context, shard Shard) error

// SplitShards 把 items 按原顺序均分成 shards 个分片：
//   - shards≤0 → 1 片；shards>len(items) → 每项一片；
//   - 空输入返回 nil（没有可执行分片）；
//   - 各分片大小差 ≤1（余数依次分给前面的分片），分片 ID 从 0 连续编号；
//   - 不裁剪、不去重、不改变 items 顺序（调用方决定目标清单语义）。
func SplitShards(items []string, shards int) []Shard {
	if len(items) == 0 {
		return nil
	}
	if shards <= 0 {
		shards = 1
	}
	if shards > len(items) {
		shards = len(items)
	}
	base := len(items) / shards
	rem := len(items) % shards
	out := make([]Shard, 0, shards)
	pos := 0
	for i := 0; i < shards; i++ {
		size := base
		if i < rem {
			size++
		}
		part := make([]string, size)
		copy(part, items[pos:pos+size])
		out = append(out, Shard{ID: i, Items: part})
		pos += size
	}
	return out
}

// MarshalShardCheckpoint 把分片计划（含 Done 标记）序列化为 checkpoint JSON。
func MarshalShardCheckpoint(shards []Shard) ([]byte, error) {
	if shards == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(shards)
}

// LoadShardCheckpoint 解析 checkpoint；空内容返回 (nil, nil)，损坏/非法
// （负 ID、ID 重复）返回错误——宁可重建计划，不带着坏 checkpoint 跳过任务。
func LoadShardCheckpoint(data []byte) ([]Shard, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var out []Shard
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("分片 checkpoint 解析失败：%w", err)
	}
	seen := make(map[int]bool, len(out))
	for i := range out {
		if out[i].ID < 0 {
			return nil, fmt.Errorf("分片 checkpoint 含非法 ID %d", out[i].ID)
		}
		if seen[out[i].ID] {
			return nil, fmt.Errorf("分片 checkpoint ID 重复：%d", out[i].ID)
		}
		seen[out[i].ID] = true
	}
	return out, nil
}

// MergeShardCheckpoint 用旧 checkpoint 的 Done 标记恢复新计划，返回新副本
// （不修改入参）。只在「分片 ID 相同且 Items 完全一致」时才认可完成标记：
// 目标清单变更（页面增删、模板更新）后不会错误跳过，只会重跑该分片。
// checkpoint 里多出来的分片忽略。
func MergeShardCheckpoint(plan, checkpoint []Shard) []Shard {
	saved := make(map[int][]string, len(checkpoint))
	for _, c := range checkpoint {
		saved[c.ID] = c.Items
	}
	out := make([]Shard, len(plan))
	for i := range plan {
		out[i] = Shard{
			ID:    plan[i].ID,
			Items: append([]string(nil), plan[i].Items...),
			Done:  plan[i].Done,
		}
		if out[i].Done {
			continue
		}
		if items, ok := saved[out[i].ID]; ok && slices.Equal(items, plan[i].Items) {
			out[i].Done = true
		}
	}
	return out
}

// PendingShards 返回未完成分片（续扫入口；顺序与计划一致，副本）。
func PendingShards(shards []Shard) []Shard {
	out := make([]Shard, 0, len(shards))
	for _, s := range shards {
		if s.Done {
			continue
		}
		out = append(out, Shard{
			ID:    s.ID,
			Items: append([]string(nil), s.Items...),
		})
	}
	return out
}

// RemainingItems 汇总未完成分片的工作项（按分片顺序、片内顺序；保留重复项）。
func RemainingItems(shards []Shard) []string {
	var out []string
	for _, s := range shards {
		if s.Done {
			continue
		}
		out = append(out, s.Items...)
	}
	return out
}

// AllShardsDone 计划是否全部完成（空计划视为已完成）。
func AllShardsDone(shards []Shard) bool {
	for _, s := range shards {
		if !s.Done {
			return false
		}
	}
	return true
}

// RunShards 并发执行未完成分片：
//   - Done=true 的分片直接跳过（checkpoint/续扫语义），计入 Skipped；
//   - 并发度夹到 [1, MaxShardConcurrency]（最多 min(并发, 未完成分片数) 个 worker）；
//   - 每个分片失败后最多重试 opts.Retries 次（默认 1 次，负数=不重试）；
//   - 某分片重试耗尽后其余分片继续执行（不中断整批），错误按分片 ID 汇总
//     （errors.Join），最终 error 非 nil 时成功分片的 Done 仍然保留；
//   - ctx 取消后不再派发新分片，已派发分片尽快返回；返回 ctx.Err()（与分片
//     错误合并）。取消时未派发的分片保持 Done=false，可续扫。
//
// 成功分片会把 Done 置 true（写入入参切片，便于直接落 checkpoint）。运行
// 期间调用方不得并发读写该切片；ShardFunc 内也不要修改传入的 Items。
func RunShards(ctx context.Context, shards []Shard, opts ShardOptions, fn ShardFunc) (ShardStats, error) {
	stats := ShardStats{Total: len(shards)}
	if fn == nil {
		return stats, errors.New("分片执行函数为空")
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}

	pending := make([]int, 0, len(shards))
	for i := range shards {
		if shards[i].Done {
			stats.Skipped++
			continue
		}
		pending = append(pending, i)
	}
	if len(pending) == 0 {
		return stats, nil
	}

	workers := opts.Concurrency
	if workers <= 0 {
		workers = MaxShardConcurrency
	}
	if workers > MaxShardConcurrency {
		workers = MaxShardConcurrency
	}
	if workers > len(pending) {
		workers = len(pending)
	}
	retries := opts.Retries
	if retries == 0 {
		retries = DefaultShardRetries
	}
	if retries < 0 {
		retries = 0
	}

	var (
		mu      sync.Mutex
		failErr []error
		wg      sync.WaitGroup
	)
	idxCh := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxCh {
				shard := shards[idx] // 值拷贝：Items 只读约定见文档
				var lastErr error
				for attempt := 0; attempt <= retries; attempt++ {
					if attempt > 0 {
						if ctx.Err() != nil {
							break
						}
						mu.Lock()
						stats.Retries++
						mu.Unlock()
					}
					lastErr = fn(ctx, shard)
					if lastErr == nil {
						break
					}
				}
				mu.Lock()
				stats.Items += len(shard.Items)
				if lastErr == nil {
					shards[idx].Done = true
					stats.Completed++
				} else {
					stats.Failed++
					failErr = append(failErr, fmt.Errorf("分片 %d 失败：%w", shard.ID, lastErr))
				}
				mu.Unlock()
			}
		}()
	}

dispatch:
	for _, idx := range pending {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break dispatch
		case idxCh <- idx:
		}
	}
	close(idxCh)
	wg.Wait()

	var err error
	if len(failErr) > 0 {
		err = errors.Join(failErr...)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		if err != nil {
			return stats, errors.Join(err, ctxErr)
		}
		return stats, ctxErr
	}
	return stats, err
}
