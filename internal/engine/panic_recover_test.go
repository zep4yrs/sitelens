package engine

// V-09 回归：引擎侧 panic 兜底。
//
// server 侧已给 runScanJob/loginbrute/osv/scheduler 加了 recover，但引擎
// 自身（engine.Scan 顶层 + 自建 goroutine）此前没有——panic 会穿透到
// 未包 recover 的调用方（CLI/MCP/未来调度路径）直接杀进程。本文件锁住：
//  1. Scan 走 runScanGuarded，panic → 非 nil Result + Error 非空；
//  2. 引擎自建 goroutine 走 safeGo，panic 只记日志、不崩进程；
//  3. 分片执行 callShardSafe 把单分片 panic 转成该分片失败，其余分片继续。

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestRunScanGuardedRecoversPanic Scan 顶层兜底：主体 panic 时调用方仍拿到
// 非 nil 结果，且 Error 明确包含失败信息（不穿透 panic）。
func TestRunScanGuardedRecoversPanic(t *testing.T) {
	res := runScanGuarded("http://panic.example/", func() *Result {
		panic("boom: injected scan panic")
	})
	if res == nil {
		t.Fatal("panic 后必须返回非 nil Result（调用方按结果判失败）")
	}
	if strings.TrimSpace(res.Error) == "" {
		t.Fatal("panic 后 Result.Error 不得为空")
	}
	if !strings.Contains(res.Error, "boom") {
		t.Errorf("Result.Error 应包含 panic 摘要，实得 %q", res.Error)
	}
	if res.Extras == nil || res.Extras["panic"] == nil {
		t.Errorf("Extras 应带 panic 标记便于诊断: %+v", res.Extras)
	}
	if res.URL != "http://panic.example/" {
		t.Errorf("Result.URL 应回填扫描目标，实得 %q", res.URL)
	}
}

// TestRunScanGuardedNormalPath Scan 正常路径语义不变：返回值原样透传。
func TestRunScanGuardedNormalPath(t *testing.T) {
	want := &Result{URL: "http://ok.example/", Error: ""}
	got := runScanGuarded("http://ok.example/", func() *Result { return want })
	if got != want {
		t.Fatalf("正常路径不得改写返回结果: got %p want %p", got, want)
	}
}

// TestSafeGoRecoversPanic goroutine 兜底：worker panic 不应打崩进程，
// 且其 defer（wg.Done）仍会执行。
func TestSafeGoRecoversPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	safeGo("test-worker", func() {
		defer wg.Done() // panic 展开时仍应执行
		panic("boom: injected goroutine panic")
	})
	wg.Wait() // 若 panic 未被 recover，进程已崩（测试不可能走到这里）

	// 再次确认 safeGo 后进程仍可正常工作。
	done := make(chan struct{})
	wg.Add(1)
	safeGo("test-worker-2", func() {
		defer wg.Done()
		close(done)
	})
	<-done
	wg.Wait()
}

// TestCallShardSafeConvertsPanic shard panic → 该分片失败，其余分片继续。
func TestCallShardSafeConvertsPanic(t *testing.T) {
	shards := []Shard{{ID: 0, Items: []string{"a"}}, {ID: 1, Items: []string{"b"}}}
	stats, err := RunShards(context.Background(), shards, ShardOptions{Concurrency: 2, Retries: -1},
		func(ctx context.Context, sh Shard) error {
			if sh.ID == 0 {
				panic("boom: injected shard panic")
			}
			return nil
		})
	if err == nil {
		t.Fatal("panic 分片应体现为错误（不能静默成功）")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("错误应说明 panic：%v", err)
	}
	if stats.Failed != 1 || stats.Completed != 1 {
		t.Errorf("统计表示 1 失败 1 成功，实得 %+v", stats)
	}
}
