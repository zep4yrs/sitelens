package engine

// CP-05 分片/续扫测试：切分、checkpoint 序列化/恢复、checkpoint 跳过、
// 单分片重试 1 次、并发上限 ≤4、空输入、ctx 取消。全部纯本地逻辑。

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSplitShards(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e", "f", "g"}
	shards := SplitShards(items, 3)
	if len(shards) != 3 {
		t.Fatalf("应切成 3 片，实得 %d", len(shards))
	}
	wantSizes := []int{3, 2, 2} // 余数分给前面的分片，大小差 ≤1
	var flat []string
	for i, sh := range shards {
		if sh.ID != i {
			t.Fatalf("分片 ID 应连续从 0 开始，第 %d 片 ID=%d", i, sh.ID)
		}
		if len(sh.Items) != wantSizes[i] {
			t.Fatalf("第 %d 片大小应为 %d，实得 %d", i, wantSizes[i], len(sh.Items))
		}
		if sh.Done {
			t.Fatalf("新计划分片不应是完成态：%+v", sh)
		}
		flat = append(flat, sh.Items...)
	}
	if !slices.Equal(flat, items) {
		t.Fatalf("分片拼接应还原原顺序：got %v want %v", flat, items)
	}
	// 切分是拷贝：之后修改入参不影响已切分片（checkpoint 不串改）。
	items[0] = "changed"
	if shards[0].Items[0] != "a" {
		t.Fatalf("切分应复制工作项，实得 %q", shards[0].Items[0])
	}
}

func TestSplitShardsEdges(t *testing.T) {
	if got := SplitShards(nil, 3); got != nil {
		t.Fatalf("空输入应返回 nil，实得 %+v", got)
	}
	if got := SplitShards([]string{}, 2); got != nil {
		t.Fatalf("空切片应返回 nil，实得 %+v", got)
	}
	// shards≤0 → 1 片且包含全部项。
	for _, n := range []int{0, -3} {
		got := SplitShards([]string{"a", "b", "c"}, n)
		if len(got) != 1 || !slices.Equal(got[0].Items, []string{"a", "b", "c"}) {
			t.Fatalf("shards=%d 应退化为单片：%+v", n, got)
		}
	}
	// shards > 项数 → 每项一片。
	got := SplitShards([]string{"a", "b"}, 5)
	if len(got) != 2 || len(got[0].Items) != 1 || len(got[1].Items) != 1 {
		t.Fatalf("分片数超过项数时应每项一片：%+v", got)
	}
}

func TestSplitShardsBalance(t *testing.T) {
	items := make([]string, 20)
	for i := range items {
		items[i] = "p" + string(rune('a'+i%26))
	}
	for n := 1; n <= 7; n++ {
		shards := SplitShards(items, n)
		if len(shards) != n {
			t.Fatalf("n=%d 应切 %d 片，实得 %d", n, n, len(shards))
		}
		minSize, maxSize, total := 1<<30, 0, 0
		var flat []string
		for i, sh := range shards {
			if sh.ID != i {
				t.Fatalf("n=%d 第 %d 片 ID 错：%d", n, i, sh.ID)
			}
			size := len(sh.Items)
			total += size
			if size < minSize {
				minSize = size
			}
			if size > maxSize {
				maxSize = size
			}
			flat = append(flat, sh.Items...)
		}
		if total != len(items) || !slices.Equal(flat, items) {
			t.Fatalf("n=%d 分片未覆盖/乱序：total=%d", n, total)
		}
		if maxSize-minSize > 1 {
			t.Fatalf("n=%d 分片大小差应 ≤1，实得 min=%d max=%d", n, minSize, maxSize)
		}
	}
}

func TestShardCheckpointRoundTrip(t *testing.T) {
	plan := SplitShards([]string{"a", "b", "c", "d", "e"}, 3)
	plan[0].Done = true
	plan[2].Done = true
	data, err := MarshalShardCheckpoint(plan)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	back, err := LoadShardCheckpoint(data)
	if err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if !reflect.DeepEqual(back, plan) {
		t.Fatalf("checkpoint 往返不一致：\n got=%+v\nwant=%+v", back, plan)
	}

	// 空内容 → nil；损坏 / 非法 ID → 明确报错（宁可重建计划，不误跳）。
	if got, err := LoadShardCheckpoint(nil); err != nil || got != nil {
		t.Fatalf("空 checkpoint 应返回 (nil,nil)，实得 %+v err=%v", got, err)
	}
	if _, err := LoadShardCheckpoint([]byte("{not json")); err == nil {
		t.Fatal("损坏 checkpoint 应报错")
	}
	if _, err := LoadShardCheckpoint([]byte(`[{"id":-1,"items":["a"]}]`)); err == nil {
		t.Fatal("负 ID 应报错")
	}
	if _, err := LoadShardCheckpoint([]byte(`[{"id":1,"items":["a"]},{"id":1,"items":["b"]}]`)); err == nil {
		t.Fatal("重复 ID 应报错")
	}
	if data, err := MarshalShardCheckpoint(nil); err != nil || string(data) != "[]" {
		t.Fatalf("nil 计划应序列化为 []，实得 %q err=%v", data, err)
	}
}

func TestMergeShardCheckpoint(t *testing.T) {
	plan := SplitShards([]string{"a", "b", "c", "d", "e", "f"}, 3) // 每片 2 项
	checkpoint := []Shard{
		{ID: 0, Items: []string{"a", "b"}, Done: true},         // 完全一致 → 认可
		{ID: 1, Items: []string{"c", "DIFFERENT"}, Done: true}, // Items 变化 → 不认可
		{ID: 2, Items: []string{"e", "f"}, Done: true},         // 完全一致 → 认可
		{ID: 99, Items: []string{"x"}, Done: true},             // 多余分片 → 忽略
	}
	merged := MergeShardCheckpoint(plan, checkpoint)
	if !merged[0].Done || merged[1].Done || !merged[2].Done {
		t.Fatalf("checkpoint 合并错误：%+v", merged)
	}
	// 不修改入参计划。
	for i := range plan {
		if plan[i].Done {
			t.Fatalf("MergeShardCheckpoint 不应修改入参计划：%+v", plan)
		}
	}

	pending := PendingShards(merged)
	if len(pending) != 1 || pending[0].ID != 1 {
		t.Fatalf("未完分片应只有 ID=1，实得 %+v", pending)
	}
	// 副本独立：改返回值不影响原计划。
	pending[0].Items[0] = "mutated"
	if merged[1].Items[0] != "c" {
		t.Fatalf("PendingShards 应返回副本，实得 %q", merged[1].Items[0])
	}
	if items := RemainingItems(merged); !slices.Equal(items, []string{"c", "d"}) {
		t.Fatalf("剩余工作项应为待跑分片的项，实得 %v", items)
	}
	if AllShardsDone(merged) {
		t.Fatal("仍有待跑分片，AllShardsDone 应为 false")
	}
	if !AllShardsDone(nil) {
		t.Fatal("空计划应视为全部完成")
	}

	// 计划自身已完成的分片保持完成（无 checkpoint 也保留 Done）。
	plan2 := []Shard{
		{ID: 0, Items: []string{"a"}, Done: true},
		{ID: 1, Items: []string{"b"}},
	}
	merged2 := MergeShardCheckpoint(plan2, nil)
	if !merged2[0].Done || merged2[1].Done {
		t.Fatalf("计划内 Done 标记应保留：%+v", merged2)
	}
}

func TestRunShardsSkipsDone(t *testing.T) {
	plan := []Shard{
		{ID: 0, Items: []string{"a"}},
		{ID: 1, Items: []string{"b"}, Done: true},
		{ID: 2, Items: []string{"c", "d"}},
	}
	var mu sync.Mutex
	var ran []int
	stats, err := RunShards(context.Background(), plan, ShardOptions{}, func(_ context.Context, sh Shard) error {
		mu.Lock()
		ran = append(ran, sh.ID)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if stats.Total != 3 || stats.Skipped != 1 || stats.Completed != 2 || stats.Failed != 0 || stats.Items != 3 || stats.Retries != 0 {
		t.Fatalf("统计不符: %+v", stats)
	}
	slices.Sort(ran)
	if !slices.Equal(ran, []int{0, 2}) {
		t.Fatalf("checkpoint 分片应被跳过，实际执行 %v", ran)
	}
	if !plan[0].Done || !plan[1].Done || !plan[2].Done {
		t.Fatalf("成功分片应置 Done：%+v", plan)
	}
}

func TestRunShardsRetrySucceeds(t *testing.T) {
	plan := SplitShards([]string{"a", "b", "c"}, 3)
	var mu sync.Mutex
	attempts := map[int]int{}
	stats, err := RunShards(context.Background(), plan, ShardOptions{}, func(_ context.Context, sh Shard) error {
		mu.Lock()
		attempts[sh.ID]++
		n := attempts[sh.ID]
		mu.Unlock()
		if sh.ID == 1 && n == 1 {
			return errors.New("首次失败")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if stats.Failed != 0 || stats.Completed != 3 || stats.Retries != 1 {
		t.Fatalf("统计不符: %+v attempts=%v", stats, attempts)
	}
	if attempts[1] != 2 {
		t.Fatalf("失败分片应重试 1 次（共 2 次尝试），实得 %d", attempts[1])
	}
}

func TestRunShardsRetryExhausted(t *testing.T) {
	plan := []Shard{
		{ID: 0, Items: []string{"a"}},
		{ID: 1, Items: []string{"b"}},
		{ID: 2, Items: []string{"c"}},
	}
	var mu sync.Mutex
	attempts := map[int]int{}
	stats, err := RunShards(context.Background(), plan, ShardOptions{}, func(_ context.Context, sh Shard) error {
		mu.Lock()
		attempts[sh.ID]++
		mu.Unlock()
		if sh.ID == 1 {
			return errors.New("总是失败")
		}
		return nil
	})
	if err == nil {
		t.Fatal("重试耗尽应返回错误")
	}
	if !strings.Contains(err.Error(), "分片 1") {
		t.Fatalf("错误应带失败分片 ID: %v", err)
	}
	if stats.Failed != 1 || stats.Completed != 2 || stats.Retries != 1 {
		t.Fatalf("统计不符: %+v", stats)
	}
	if attempts[1] != 2 {
		t.Fatalf("默认应重试 1 次（2 次尝试），实得 %d", attempts[1])
	}
	if plan[1].Done {
		t.Fatal("失败分片不应置 Done（保留续扫）")
	}
	if !plan[0].Done || !plan[2].Done {
		t.Fatalf("其余分片应正常完成：%+v", plan)
	}
}

func TestRunShardsNoRetryOption(t *testing.T) {
	plan := []Shard{{ID: 0, Items: []string{"a"}}}
	var attempts atomic.Int32
	stats, err := RunShards(context.Background(), plan, ShardOptions{Retries: -1}, func(context.Context, Shard) error {
		attempts.Add(1)
		return errors.New("失败")
	})
	if err == nil || stats.Failed != 1 || stats.Completed != 0 {
		t.Fatalf("负 Retries 应不重试：err=%v stats=%+v", err, stats)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("Retries<0 时只应尝试 1 次，实得 %d", got)
	}
}

func TestRunShardsErrorJoinMultiple(t *testing.T) {
	plan := []Shard{{ID: 0, Items: []string{"a"}}, {ID: 1, Items: []string{"b"}}}
	_, err := RunShards(context.Background(), plan, ShardOptions{}, func(context.Context, Shard) error {
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("应返回错误")
	}
	msg := err.Error()
	if !strings.Contains(msg, "分片 0") || !strings.Contains(msg, "分片 1") {
		t.Fatalf("聚合错误应包含两个分片 ID: %v", err)
	}
}

func TestRunShardsConcurrencyCap(t *testing.T) {
	plan := SplitShards([]string{"a", "b", "c", "d", "e", "f", "g", "h"}, 8)
	run := func(requested int) int32 {
		var inflight, maxInflight atomic.Int32
		stats, err := RunShards(context.Background(), cloneShards(plan), ShardOptions{Concurrency: requested},
			func(context.Context, Shard) error {
				cur := inflight.Add(1)
				for { // CAS 更新最大并发
					old := maxInflight.Load()
					if cur <= old || maxInflight.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(15 * time.Millisecond)
				inflight.Add(-1)
				return nil
			})
		if err != nil || stats.Completed != 8 {
			t.Fatalf("执行失败: %+v err=%v", stats, err)
		}
		return maxInflight.Load()
	}

	if got := run(100); got > MaxShardConcurrency {
		t.Fatalf("并发度应被夹到硬上限 %d，实测峰值 %d", MaxShardConcurrency, got)
	} else if got < 2 {
		t.Fatalf("8 个分片应发生真实并发（峰值≥2），实测 %d", got)
	}
	if got := run(2); got > 2 {
		t.Fatalf("请求并发 2 时峰值不应超过 2，实测 %d", got)
	}
}

func TestRunShardsEmptyAndAllDone(t *testing.T) {
	stats, err := RunShards(context.Background(), nil, ShardOptions{}, func(context.Context, Shard) error {
		t.Fatal("空计划不应调用执行函数")
		return nil
	})
	if err != nil || stats.Total != 0 || stats.Completed != 0 {
		t.Fatalf("空计划应零统计：%+v err=%v", stats, err)
	}
	done := []Shard{{ID: 0, Items: []string{"a"}, Done: true}, {ID: 1, Items: []string{"b"}, Done: true}}
	stats, err = RunShards(context.Background(), done, ShardOptions{}, func(context.Context, Shard) error {
		t.Fatal("全部完成时不应调用执行函数")
		return nil
	})
	if err != nil || stats.Skipped != 2 || stats.Completed != 0 {
		t.Fatalf("全完成计划应全部跳过：%+v err=%v", stats, err)
	}
}

func TestRunShardsContextCanceled(t *testing.T) {
	plan := SplitShards([]string{"a", "b", "c"}, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 运行前已取消
	var calls atomic.Int32
	stats, err := RunShards(ctx, plan, ShardOptions{}, func(context.Context, Shard) error {
		calls.Add(1)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 context.Canceled，实得 %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("取消后不应派发分片，实际调用 %d 次", calls.Load())
	}
	if stats.Completed != 0 || stats.Failed != 0 {
		t.Fatalf("取消时不应计入完成/失败：%+v", stats)
	}
	for _, sh := range plan {
		if sh.Done {
			t.Fatalf("取消后不应置 Done（可续扫）：%+v", plan)
		}
	}
}

func TestRunShardsNilFunc(t *testing.T) {
	if _, err := RunShards(context.Background(), []Shard{{ID: 0, Items: []string{"a"}}}, ShardOptions{}, nil); err == nil {
		t.Fatal("nil 执行函数应报错")
	}
}

// cloneShards 深拷贝分片计划（并发用例复用同一计划模板）。
func cloneShards(plan []Shard) []Shard {
	out := make([]Shard, len(plan))
	for i, sh := range plan {
		out[i] = Shard{ID: sh.ID, Items: append([]string(nil), sh.Items...), Done: sh.Done}
	}
	return out
}
