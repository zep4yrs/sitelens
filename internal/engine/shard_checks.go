// CP-05 模板批次分片接线（additive）。
//
// 默认（ShardWorkers<=0）走既有 checks.RunListWithLog 单次并发执行，行为与
// 旧版逐项一致；ShardWorkers>0 时把模板批次 SplitShards+RunShards 执行：
//   - 分片数 = ShardWorkers（RunShards 内部再夹到 ≤4 硬上限）；
//   - 每片内部串行（不嵌套并发），保证总并发 ≤4，不额外放大请求并发；
//   - 结果按分片 ID（=模板清单顺序区间）合并，onHit 在合并后串行回调
//     （避免并发回调；与 ShardFunc 的「回调串行化」约定一致）；
//   - 支持 checkpoint：传入上次 MarshalShardCheckpoint 的 JSON 时只跑未完成
//     分片（ID+Items 完全一致才认可 Done），执行后回传新 checkpoint。
//
// 注意：分片会打断 checks.runList 的「同路径聚类」跨模板共享（同一路径的
// 模板若落在不同分片会各发一次请求）→ 只有在调用方显式开启时才启用，
// 默认路径不变；开启后请求量上界为各分片组数之和，仍受 httpx 限速约束。
package engine

import (
	"context"
	"fmt"
	"sync"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// shardExecInfo 模板批次分片执行摘要（挂 res.Extras["shards"]["templates"]）。
type shardExecInfo struct {
	Enabled    bool
	Shards     int
	Stats      ShardStats
	Pending    int
	Checkpoint []byte // 传入 checkpoint 时回传更新后的分片计划 JSON
}

// runCheckList 执行模板批次：默认路径与既有实现逐项一致；ShardWorkers>0
// 时走分片执行。返回命中/执行证据/分片摘要（未启用分片时摘要为 nil）。
func runCheckList(client *httpx.Client, baseURL string, list []checks.Check,
	workers int, cancelled func() bool, onProgress func(done, total int, msg string),
	onHit func(checks.Hit), shardWorkers int, checkpoint []byte) ([]checks.Hit, []checks.CheckRun, *shardExecInfo) {
	if shardWorkers <= 0 || len(list) == 0 {
		hits, runs := checks.RunListWithLog(client, baseURL, list, workers, cancelled, onProgress, onHit)
		return hits, runs, nil
	}

	items := make([]string, len(list))
	byItem := make(map[string]checks.Check, len(list))
	for i, chk := range list {
		key := fmt.Sprintf("%d|%s", i, chk.ID)
		items[i] = key
		byItem[key] = chk
	}
	plan := SplitShards(items, shardWorkers)
	if len(plan) < 2 {
		// 太少（1 片）时分片无收益，回退旧路径保持行为一致。
		hits, runs := checks.RunListWithLog(client, baseURL, list, workers, cancelled, onProgress, onHit)
		return hits, runs, nil
	}
	if len(checkpoint) > 0 {
		if saved, err := LoadShardCheckpoint(checkpoint); err == nil && saved != nil {
			plan = MergeShardCheckpoint(plan, saved)
		} else {
			// checkpoint 损坏/为空：不带着坏续扫数据跳过任务，直接全量重跑。
			plan = MergeShardCheckpoint(plan, nil)
		}
	}

	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	total := len(list)
	var (
		progMu   sync.Mutex
		progDone int
	)
	// innerProgress 把各分片内部进度汇总成全局进度；回调在锁内串行调用
	// （检查器内部并发 worker 会并发回调，防止竞态/乱序）。
	innerProgress := func(_ int, _ int, msg string) {
		progMu.Lock()
		progDone++
		if progDone > total {
			progDone = total
		}
		done := progDone
		progMu.Unlock()
		onProgress(done, total, msg)
	}

	shardHits := make([][]checks.Hit, len(plan))
	shardRuns := make([][]checks.CheckRun, len(plan))
	stats, runErr := RunShards(context.Background(), plan, ShardOptions{Concurrency: shardWorkers},
		func(_ context.Context, sh Shard) error {
			if cancelled != nil && cancelled() {
				return nil // 取消：不再执行该片（RunShards 标记完成，取消语义由上层收尾）
			}
			subset := make([]checks.Check, 0, len(sh.Items))
			for _, key := range sh.Items {
				if chk, ok := byItem[key]; ok {
					subset = append(subset, chk)
				}
			}
			if len(subset) == 0 {
				return nil
			}
			// 片内串行（workers=1）：总并发由 RunShards 的上限（≤4）控制，
			// 避免嵌套 worker 放大请求并发。
			hits, runs := checks.RunListWithLog(client, baseURL, subset, 1, cancelled,
				innerProgress, nil)
			shardHits[sh.ID] = hits
			shardRuns[sh.ID] = runs
			return nil
		})
	_ = runErr // 模板检测是尽力而为：分片失败不影响扫描主流程，摘要里计数

	info := &shardExecInfo{
		Enabled: true, Shards: len(plan), Stats: stats,
		Pending: len(PendingShards(plan)),
	}
	if len(checkpoint) > 0 {
		if data, err := MarshalShardCheckpoint(plan); err == nil {
			info.Checkpoint = data
		}
	}

	// 按分片顺序合并（=模板清单顺序区间），命中回调串行触发。
	var hits []checks.Hit
	var runs []checks.CheckRun
	for i := range shardHits {
		if len(shardHits[i]) > 0 {
			hits = append(hits, shardHits[i]...)
			if onHit != nil {
				for _, h := range shardHits[i] {
					onHit(h)
				}
			}
		}
		runs = append(runs, shardRuns[i]...)
	}
	return hits, runs, info
}

// putShardStats 把分片摘要挂到 res.Extras（additive；未启用分片时不出现）。
func putShardStats(extras map[string]any, key string, info *shardExecInfo) {
	if extras == nil || info == nil || !info.Enabled {
		return
	}
	m, _ := extras["shards"].(map[string]any)
	if m == nil {
		m = map[string]any{}
		extras["shards"] = m
	}
	entry := map[string]any{
		"shards": info.Shards, "pending": info.Pending,
		"total": info.Stats.Total, "skipped": info.Stats.Skipped,
		"completed": info.Stats.Completed, "failed": info.Stats.Failed,
		"items": info.Stats.Items, "retries": info.Stats.Retries,
	}
	if len(info.Checkpoint) > 0 {
		entry["checkpoint_bytes"] = len(info.Checkpoint)
	}
	m[key] = entry
}

// putPageBatchStats 页面批次分片摘要（与模板批次共用 res.Extras["shards"]）。
func putPageBatchStats(extras map[string]any, stats *ShardStats) {
	if extras == nil || stats == nil {
		return
	}
	putShardStats(extras, "page_batch", &shardExecInfo{
		Enabled: true, Shards: stats.Total, Stats: *stats,
	})
}
