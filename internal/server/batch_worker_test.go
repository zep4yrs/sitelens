// 企业化 6.x：批量扫描 worker 池接线回归（默认旧路径零变化 + 开启后同样完成）。
package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// newBatchTarget 起一个最小目标站（批量扫描对象）。
func newBatchTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><head><title>batch target</title></head>
<body><a href="/a">a</a></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// resultRows 取批量任务结果里的 rows。
func resultRows(t *testing.T, s *Server, jobID string) []map[string]any {
	t.Helper()
	j := s.jobs.Get(jobID)
	if j == nil {
		t.Fatalf("作业 %s 不存在", jobID)
	}
	if j.Status != "done" {
		t.Fatalf("作业状态应为 done，实际 %q（%s）", j.Status, j.Message)
	}
	rows, _ := j.Result["rows"].([]map[string]any)
	return rows
}

// TestBatchLegacyPathDefault 默认（UseWorkerPool=false）走旧路径：行为零变化。
func TestBatchLegacyPathDefault(t *testing.T) {
	s, _ := newServer(t)
	if s.cfgSnap().Batch.UseWorkerPool {
		t.Fatal("默认 Batch.UseWorkerPool 必须为 false（旧路径）")
	}
	url := newBatchTarget(t)
	setTestConfig(s, func(c *config.Config) { c.Batch.Workers = 2 })
	s.jobs.Create("job-legacy", "batch", map[string]any{"urls": []string{url}}, 1)
	s.runBatch("job-legacy", []batchItem{{URL: url}}, nil)

	rows := resultRows(t, s, "job-legacy")
	if len(rows) != 1 || rows[0]["status"] != "done" || rows[0]["url"] != url {
		t.Fatalf("旧路径批量结果异常: %v", rows)
	}
	if j := s.jobs.Get("job-legacy"); j.Progress != 100 {
		t.Fatalf("旧路径进度应为 100，实际 %d", j.Progress)
	}
}

// TestBatchWorkerPoolPath 开启 UseWorkerPool → worker 池分派同样完成并回写结果。
func TestBatchWorkerPoolPath(t *testing.T) {
	s, _ := newServer(t)
	url := newBatchTarget(t)
	setTestConfig(s, func(c *config.Config) {
		c.Batch.UseWorkerPool = true
		c.Batch.Workers = 2
	})
	s.jobs.Create("job-pool", "batch", map[string]any{"urls": []string{url}}, 1)
	s.runBatch("job-pool", []batchItem{{URL: url}}, nil)

	rows := resultRows(t, s, "job-pool")
	if len(rows) != 1 || rows[0]["status"] != "done" || rows[0]["url"] != url {
		t.Fatalf("worker 池批量结果异常: %v", rows)
	}
	if j := s.jobs.Get("job-pool"); j.Progress != 100 {
		t.Fatalf("worker 池进度应为 100，实际 %d", j.Progress)
	}
}

// TestBatchWorkerPoolMultiItems worker 池并发多条：全部完成、进度 100。
func TestBatchWorkerPoolMultiItems(t *testing.T) {
	s, _ := newServer(t)
	url := newBatchTarget(t)
	setTestConfig(s, func(c *config.Config) {
		c.Batch.UseWorkerPool = true
		c.Batch.Workers = 2
	})
	items := []batchItem{{URL: url}, {URL: url + "/b"}, {URL: url + "/c"}}
	s.jobs.Create("job-pool-multi", "batch", nil, len(items))
	s.runBatch("job-pool-multi", items, nil)

	rows := resultRows(t, s, "job-pool-multi")
	if len(rows) != len(items) {
		t.Fatalf("应回写 %d 行，实际 %d", len(items), len(rows))
	}
	for _, r := range rows {
		if r["status"] != "done" {
			t.Fatalf("批量项未完成: %v", r)
		}
	}
	// 历史已落库（每条成功扫描都进历史）
	if sums := s.st.List(10, ""); len(sums) == 0 {
		t.Fatal("批量成功扫描应落历史")
	}
	_ = time.Now()
}
