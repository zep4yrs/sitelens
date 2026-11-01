package server

// XC-01 任务中心后端测试：空列表、批量状态+扫描历史聚合、排序/limit、
// 批量状态推导、活跃 Job 转换、可选 List() 接口探测。
//
// 路由由 Lead/server-store 接线，本测试直接调用 handler（hTasks）验证契约。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// newTasksTestServer 构造任务中心/资产查询测试用的服务（数据目录全部指向
// 临时目录，缺失情报资产按「加载失败降级」处理，无网络依赖）。
func newTasksTestServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	dir := t.TempDir()
	techPath := filepath.Join(dir, "technologies.json")
	writeTestTechFile(t, techPath)

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Store.DataDir = t.TempDir()
	cfg.Intel.TechnologiesPath = techPath
	cfg.Intel.DumpPath = filepath.Join(dir, "missing_dump.json.gz")
	cfg.Intel.RangesPath = filepath.Join(dir, "missing_ranges.json")
	cfg.Checks.PluginDir = filepath.Join(dir, "missing_plugins")
	if mutate != nil {
		mutate(cfg)
	}
	s, err := New(cfg, filepath.Join(t.TempDir(), "cfg.yml"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// callHandler 直接调用 handler 并把 JSON 响应解码为 map（不依赖路由接线）。
func callHandler(t *testing.T, h http.HandlerFunc, target string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, target, nil))
	var m map[string]any
	if rec.Body.Len() > 0 {
		if err := json.NewDecoder(rec.Body).Decode(&m); err != nil {
			t.Fatalf("响应不是 JSON（%d）：%v", rec.Code, err)
		}
	}
	return rec.Code, m
}

// getTasks 调用 hTasks 并返回解码后的任务条目。
func getTasks(t *testing.T, s *Server, query string) []map[string]any {
	t.Helper()
	code, m := callHandler(t, s.hTasks, "/api/tasks"+query)
	if code != 200 {
		t.Fatalf("GET /api/tasks%s = %d: %v", query, code, m)
	}
	return decodeTasks(t, m)
}

// decodeTasks 校验任务中心响应契约（tasks 数组 + total + 六字段）。
func decodeTasks(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	raw, ok := m["tasks"].([]any)
	if !ok {
		t.Fatalf("tasks 字段类型异常（应为数组）: %#v", m["tasks"])
	}
	out := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		item, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("task 条目类型异常: %#v", v)
		}
		for _, key := range []string{"id", "kind", "status", "progress", "message", "created"} {
			if _, ok := item[key]; !ok {
				t.Fatalf("task 条目缺字段 %q: %v", key, item)
			}
		}
		if id, _ := item["id"].(string); strings.TrimSpace(id) == "" {
			t.Fatalf("task id 为空: %v", item)
		}
		prog, _ := item["progress"].(float64)
		if prog < 0 || prog > 100 {
			t.Fatalf("progress 越界: %v", item)
		}
		out = append(out, item)
	}
	if total, _ := m["total"].(float64); int(total) != len(out) {
		t.Fatalf("total 与条目数不一致: total=%v len=%d", m["total"], len(out))
	}
	return out
}

// TestTasksAPIEmpty 无任何任务来源时返回空数组（不是 null）与 total=0。
func TestTasksAPIEmpty(t *testing.T) {
	s := newTasksTestServer(t, nil)
	code, m := callHandler(t, s.hTasks, "/api/tasks")
	if code != 200 {
		t.Fatalf("hTasks = %d", code)
	}
	raw, ok := m["tasks"].([]any)
	if !ok || len(raw) != 0 {
		t.Fatalf("空任务中心应返回 []，实际: %#v", m["tasks"])
	}
	if total, _ := m["total"].(float64); total != 0 {
		t.Fatalf("total 应为 0: %v", m["total"])
	}
}

// TestTasksAPIAggregatesAndSorts 批量状态 + 扫描历史聚合、按 created 倒序、limit 生效。
func TestTasksAPIAggregatesAndSorts(t *testing.T) {
	s := newTasksTestServer(t, nil)

	// 扫描历史（store.Import 走真实落库路径）。
	if _, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 1, URL: "https://old.example", Host: "old.example",
			ScannedAt: "2026-01-01 09:00:00", VulnCount: 0},
	}); err != nil {
		t.Fatalf("Import old: %v", err)
	}
	if _, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 2, URL: "https://new.example", Host: "new.example",
			ScannedAt: "2026-01-03 09:00:00", VulnCount: 3},
	}); err != nil {
		t.Fatalf("Import new: %v", err)
	}

	// 批量状态：一个未完成（running，1/3 完成、1 失败），一个刚完成（2/2）。
	if err := s.saveBatchState(&batchState{
		JobID: "batch-run", CreatedAt: "2026-01-01T10:00:00Z",
		Items: []batchStateItem{
			{URL: "https://a", Status: "done"},
			{URL: "https://b", Status: "running"},
			{URL: "https://c", Status: "failed"},
		},
	}); err != nil {
		t.Fatalf("save running batch: %v", err)
	}
	if err := s.saveBatchState(&batchState{
		JobID: "batch-done", CreatedAt: "2026-01-02T10:00:00Z", Finished: true,
		Items: []batchStateItem{
			{URL: "https://d", Status: "done"},
			{URL: "https://e", Status: "done"},
		},
	}); err != nil {
		t.Fatalf("save finished batch: %v", err)
	}

	tasks := getTasks(t, s, "")
	if len(tasks) != 4 {
		t.Fatalf("应聚合 4 条任务，实际 %d: %v", len(tasks), tasks)
	}

	// 时间倒序：scan(01-03) > batch-done(01-02) > batch-run(01-01T10) > scan(01-01T09)。
	var prev time.Time
	for i, task := range tasks {
		created, _ := task["created"].(string)
		ts, err := time.Parse(time.RFC3339, created)
		if err != nil {
			t.Fatalf("created 应为 RFC3339: %q", created)
		}
		if i > 0 && ts.After(prev) {
			t.Fatalf("任务未按时间倒序: %v", tasks)
		}
		prev = ts
	}
	if kind, _ := tasks[0]["kind"].(string); kind != "scan" {
		t.Fatalf("最新任务应为扫描，实际: %v", tasks[0])
	}
	if msg, _ := tasks[0]["message"].(string); !strings.Contains(msg, "new.example") ||
		!strings.Contains(msg, "3") {
		t.Fatalf("扫描任务消息应含目标与情报数: %q", msg)
	}

	byID := map[string]map[string]any{}
	for _, task := range tasks {
		id, _ := task["id"].(string)
		byID[id] = task
	}
	run := byID["batch-run"]
	if run == nil {
		t.Fatalf("缺 batch-run: %v", tasks)
	}
	if status, _ := run["status"].(string); status != "running" {
		t.Fatalf("batch-run 状态应为 running: %v", run)
	}
	if prog, _ := run["progress"].(float64); int(prog) != 33 {
		t.Fatalf("batch-run 进度应为 33: %v", run)
	}
	if msg, _ := run["message"].(string); !strings.Contains(msg, "1/3") || !strings.Contains(msg, "失败 1") {
		t.Fatalf("batch-run 消息异常: %q", msg)
	}
	done := byID["batch-done"]
	if done == nil {
		t.Fatalf("缺 batch-done: %v", tasks)
	}
	if status, _ := done["status"].(string); status != "done" {
		t.Fatalf("batch-done 状态应为 done: %v", done)
	}
	if prog, _ := done["progress"].(float64); int(prog) != 100 {
		t.Fatalf("batch-done 进度应为 100: %v", done)
	}

	// limit 生效。
	if got := getTasks(t, s, "?limit=2"); len(got) != 2 {
		t.Fatalf("limit=2 应返回 2 条，实际 %d", len(got))
	}
}

// TestBatchTaskItemStatuses 批量状态推导（cancelled / running / pending / 空条目）。
func TestBatchTaskItemStatuses(t *testing.T) {
	cases := []struct {
		st       *batchState
		wantStat string
		wantProg int
	}{
		{&batchState{JobID: "x", Cancelled: true, Items: []batchStateItem{{Status: "done"}}}, "cancelled", 100},
		{&batchState{JobID: "y", Items: []batchStateItem{{Status: "running"}}}, "running", 0},
		{&batchState{JobID: "z", Items: []batchStateItem{{Status: "queued"}}}, "pending", 0},
		{&batchState{JobID: "e"}, "pending", 100}, // 无条目：视为已完成空任务
	}
	for _, tc := range cases {
		item := batchTaskItem(tc.st)
		if item.Kind != "batch" || item.ID != tc.st.JobID {
			t.Fatalf("条目基本信息异常: %+v", item)
		}
		if item.Status != tc.wantStat || item.Progress != tc.wantProg {
			t.Fatalf("状态/进度不符: got %s/%d want %s/%d", item.Status, item.Progress, tc.wantStat, tc.wantProg)
		}
	}
}

// TestSortTaskItemsStable 排序：时间倒序、不可解析排最后、同时间按 ID 倒序。
func TestSortTaskItemsStable(t *testing.T) {
	items := []taskItem{
		{ID: "a", Created: ""},
		{ID: "b", Created: "2026-01-01T00:00:00Z"},
		{ID: "c", Created: "bad-time"},
		{ID: "d", Created: "2026-02-01T00:00:00Z"},
		{ID: "e", Created: "2026-01-01T00:00:00Z"},
	}
	sortTaskItems(items)
	got := make([]string, 0, len(items))
	for _, it := range items {
		got = append(got, it.ID)
	}
	// b/e 同时间按 ID 倒序；空串与非法时间都排最后，同为不可解析按 ID 倒序。
	if strings.Join(got, ",") != "d,e,b,c,a" {
		t.Fatalf("排序不符: %v", got)
	}
}

// TestLiveJobAdapter Optional List() 接口与 Job→任务条目转换。
func TestLiveJobAdapter(t *testing.T) {
	s := newTasksTestServer(t, nil)
	// 当前 store.JobManager 无 List()：liveJobTaskItems 必须安全返回 nil。
	if got := s.liveJobTaskItems(); got != nil {
		t.Fatalf("无 List() 时应返回 nil，实际: %v", got)
	}

	s.jobs.Create("job-1", "scan", map[string]any{"url": "https://x"}, 100)
	s.jobs.Update("job-1", func(j *store.Job) { j.Status = "running"; j.Progress = 42; j.Message = "爬取中" })
	s.jobs.AppendEvent("job-1", "stage", "爬取中")
	j := s.jobs.Get("job-1")
	if j == nil {
		t.Fatal("JobManager.Get 失败")
	}
	item := jobToTaskItem(j)
	if item.ID != "job-1" || item.Kind != "scan" || item.Status != "running" ||
		item.Progress != 42 || item.Message != "爬取中" {
		t.Fatalf("Job 转换异常: %+v", item)
	}
	if _, err := time.Parse(time.RFC3339, item.Created); err != nil {
		t.Fatalf("Job created 应为 RFC3339: %q", item.Created)
	}
}

// TestCollectTasksNilServer nil 服务安全返回空数组（防御装配顺序问题）。
func TestCollectTasksNilServer(t *testing.T) {
	var s *Server
	if got := s.collectTasks(10); len(got) != 0 {
		t.Fatalf("nil Server 应返回空任务，实际: %v", got)
	}
}
