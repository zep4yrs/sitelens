package server

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

func testServerWithDataDir(t *testing.T) *Server {
	t.Helper()
	return testServer(&config.Config{Store: config.StoreConfig{DataDir: t.TempDir()}})
}

func TestBatchStateRoundTrip(t *testing.T) {
	s := testServerWithDataDir(t)
	st := newBatchState("job1", []batchItem{
		{URL: "https://a.example.com", Level: "quick"},
		{URL: "https://b.example.com"},
	})
	st.Items[0].Status = "done"
	st.Items[0].Findings = 2
	st.Items[0].Attempts = 1
	if err := s.saveBatchState(st); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got := s.loadBatchState("job1")
	if got == nil || len(got.Items) != 2 || got.Items[0].Status != "done" || got.Items[0].Findings != 2 {
		t.Fatalf("状态回读错误: %+v", got)
	}
	if got.Items[1].Status != "queued" || got.Items[1].Level != "" {
		t.Fatalf("第二项初始状态错误: %+v", got.Items[1])
	}
}

func TestBatchStateListAndCleanup(t *testing.T) {
	s := testServerWithDataDir(t)
	unfinished := newBatchState("unfinished", []batchItem{{URL: "https://a.com"}})
	if err := s.saveBatchState(unfinished); err != nil {
		t.Fatal(err)
	}
	finished := newBatchState("finished", []batchItem{{URL: "https://b.com"}})
	finished.Finished = true
	if err := s.saveBatchState(finished); err != nil {
		t.Fatal(err)
	}
	jobs := s.listBatchStates()
	if len(jobs) != 1 || jobs[0].JobID != "unfinished" {
		t.Fatalf("应只列出未完成任务，实得 %+v", jobs)
	}
	// 完成态文件应被清理
	if s.loadBatchState("finished") != nil {
		t.Fatal("已完成状态文件应被清理")
	}
	// 陈旧未完成（>7 天）也应清理：直接写文件（saveBatchState 会刷新 UpdatedAt）
	stale := newBatchState("stale", []batchItem{{URL: "https://c.com"}})
	stale.UpdatedAt = time.Now().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.batchStatePath("stale"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if jobs := s.listBatchStates(); len(jobs) != 1 {
		t.Fatalf("陈旧状态应被清理，实得 %+v", jobs)
	}
}

func TestPendingBatchItems(t *testing.T) {
	st := &batchState{Items: []batchStateItem{
		{URL: "https://done.com", Status: "done"},
		{URL: "https://fail.com", Status: "failed", Level: "deep"},
		{URL: "https://queued.com", Status: "queued", Level: "quick"},
		{URL: "https://skip.com", Status: "skipped"},
		{URL: "  ", Status: "queued"},
	}}
	got := pendingBatchItems(st, true)
	if len(got) != 3 {
		t.Fatalf("应续跑 3 条（failed/queued/skipped），实得 %d: %+v", len(got), got)
	}
	if got[0].URL != "https://fail.com" || got[0].Level != "deep" {
		t.Fatalf("续跑首项错误: %+v", got[0])
	}
	if noRetry := pendingBatchItems(st, false); len(noRetry) != 2 {
		t.Fatalf("不重试失败时应续跑 2 条，实得 %d", len(noRetry))
	}
	if got := pendingBatchItems(nil, true); got != nil {
		t.Fatalf("nil 状态应返回 nil，实得 %+v", got)
	}
}
