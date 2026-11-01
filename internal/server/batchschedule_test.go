package server

// BT-03 定时批量任务测试：Schedule 归一化/CRUD/原子写/到期判断/调度触发/
// tag 传递/启动空列表。全部本地文件 + fake 启动钩子，不真的拉起扫描。

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleNormalize(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sc := normalizeSchedule(Schedule{
		EveryMinutes: 0,
		Tag:          "  grp  ",
		Enabled:      true,
		Entries: []batchItem{
			{URL: "  https://a.example.com  ", Level: " DEEP "},
			{URL: "   "},
			{URL: "https://b.example.com", Level: "bogus", Tag: " own "},
		},
	}, now)
	if sc.ID == "" {
		t.Fatal("空 ID 应生成新 ID")
	}
	if sc.CreatedAt != now.Format(time.RFC3339) {
		t.Fatalf("CreatedAt 应为 now，实得 %q", sc.CreatedAt)
	}
	if sc.EveryMinutes != 1 {
		t.Fatalf("周期应夹到 ≥1 分钟，实得 %d", sc.EveryMinutes)
	}
	if sc.Tag != "grp" {
		t.Fatalf("Tag 应 trim，实得 %q", sc.Tag)
	}
	if len(sc.Entries) != 2 {
		t.Fatalf("空 URL 条目应丢弃，实得 %+v", sc.Entries)
	}
	if sc.Entries[0].URL != "https://a.example.com" || sc.Entries[0].Level != "deep" {
		t.Fatalf("首条未归一化：%+v", sc.Entries[0])
	}
	if sc.Entries[0].Tag != "grp" {
		t.Fatalf("条目未继承 schedule.Tag：%+v", sc.Entries[0])
	}
	if sc.Entries[1].Level != "" || sc.Entries[1].Tag != "own" {
		t.Fatalf("非法档位应清空、显式 Tag 应保留：%+v", sc.Entries[1])
	}
	if want := now.Add(time.Minute).Format(time.RFC3339); sc.NextRunAt != want {
		t.Fatalf("启用且未排期时 NextRunAt 应为 now+周期 %q，实得 %q", want, sc.NextRunAt)
	}

	// 禁用：不排期。
	off := normalizeSchedule(Schedule{EveryMinutes: 5, Enabled: false,
		NextRunAt: "2030-01-01T00:00:00Z",
		Entries:   []batchItem{{URL: "https://c.example.com"}}}, now)
	if off.NextRunAt != "" {
		t.Fatalf("禁用任务 NextRunAt 应清空，实得 %q", off.NextRunAt)
	}

	// 已有合法未来排期应原样保留（编辑标签不打断节奏）。
	const keep = "2030-01-01T00:00:00Z"
	got := normalizeSchedule(Schedule{EveryMinutes: 5, Enabled: true, NextRunAt: keep,
		Entries: []batchItem{{URL: "https://d.example.com"}}}, now)
	if got.NextRunAt != keep {
		t.Fatalf("合法 NextRunAt 应保留 %q，实得 %q", keep, got.NextRunAt)
	}
}

func TestScheduleCRUD(t *testing.T) {
	s := testServerWithDataDir(t)
	sc, err := s.UpsertSchedule(Schedule{
		EveryMinutes: 30, Enabled: true, Tag: "prod",
		Entries: []batchItem{{URL: "https://a.example.com", Level: "quick"}},
	})
	if err != nil {
		t.Fatalf("新建失败: %v", err)
	}
	if sc.ID == "" || sc.NextRunAt == "" {
		t.Fatalf("新建后应补齐 ID/NextRunAt：%+v", sc)
	}
	if _, err := os.Stat(s.schedulesPath()); err != nil {
		t.Fatalf("schedules.json 未落盘: %v", err)
	}
	list, err := s.LoadSchedules()
	if err != nil || len(list) != 1 || list[0].ID != sc.ID || list[0].Tag != "prod" {
		t.Fatalf("回读错误: %+v err=%v", list, err)
	}

	// 按同一 ID 更新：不新增记录，周期/Tag 生效。
	sc.EveryMinutes = 60
	sc.Tag = "prod2"
	if _, err := s.UpsertSchedule(sc); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	list, err = s.LoadSchedules()
	if err != nil || len(list) != 1 {
		t.Fatalf("更新后应仍为 1 条: %+v err=%v", list, err)
	}
	if list[0].EveryMinutes != 60 || list[0].Tag != "prod2" {
		t.Fatalf("更新未生效: %+v", list[0])
	}

	// 空目标应拒绝。
	if _, err := s.UpsertSchedule(Schedule{EveryMinutes: 5, Entries: []batchItem{{URL: "  "}}}); err == nil {
		t.Fatal("空目标列表应拒绝")
	}

	// 删除：幂等。
	ok, err := s.DeleteSchedule(sc.ID)
	if err != nil || !ok {
		t.Fatalf("删除失败: ok=%v err=%v", ok, err)
	}
	if list, _ := s.LoadSchedules(); len(list) != 0 {
		t.Fatalf("删除后应为空: %+v", list)
	}
	if ok, err := s.DeleteSchedule(sc.ID); err != nil || ok {
		t.Fatalf("重复删除应 (false,nil)，实得 ok=%v err=%v", ok, err)
	}
}

func TestSchedulesAtomicWriteNoTempLeftover(t *testing.T) {
	s := testServerWithDataDir(t)
	list := []Schedule{{
		ID: "x1", EveryMinutes: 5, Enabled: true,
		Entries: []batchItem{{URL: "https://a.example.com"}},
	}}
	if err := s.SaveSchedules(list); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	entries, err := os.ReadDir(s.batchStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != schedulesFileName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("目录里应只有 %s（无临时文件残留），实得 %v", schedulesFileName, names)
	}
	data, err := os.ReadFile(s.schedulesPath())
	if err != nil {
		t.Fatal(err)
	}
	var got []Schedule
	if err := json.Unmarshal(data, &got); err != nil || len(got) != 1 || got[0].ID != "x1" {
		t.Fatalf("落盘内容不可回读: %+v err=%v", got, err)
	}
}

// TestSchedulesBakRecovery 模拟「临时文件已改名到 .bak、正式文件尚未就位」
// 的崩溃残留：Load 应从 .bak 恢复并把备份转正，不静默丢配置。
func TestSchedulesBakRecovery(t *testing.T) {
	s := testServerWithDataDir(t)
	if err := os.MkdirAll(s.batchStateDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	list := []Schedule{{
		ID: "recovered", EveryMinutes: 5, Enabled: true,
		Entries: []batchItem{{URL: "https://a.example.com"}},
	}}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.schedulesPath()+".bak", data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSchedules()
	if err != nil || len(got) != 1 || got[0].ID != "recovered" {
		t.Fatalf("应从 .bak 恢复配置: %+v err=%v", got, err)
	}
	if _, err := os.Stat(s.schedulesPath()); err != nil {
		t.Fatalf("备份应转正为正式文件: %v", err)
	}
	if _, err := os.Stat(s.schedulesPath() + ".bak"); err == nil {
		t.Fatal("恢复后不应残留 .bak")
	}
}

func TestSchedulesNoDataDirAndCorrupt(t *testing.T) {
	// 未配置数据目录：所有入口返回明确错误，不 panic。
	bare := &Server{}
	if _, err := bare.LoadSchedules(); err == nil {
		t.Fatal("未配置数据目录时 LoadSchedules 应报错")
	}
	if err := bare.SaveSchedules(nil); err == nil {
		t.Fatal("未配置数据目录时 SaveSchedules 应报错")
	}
	if _, err := bare.UpsertSchedule(Schedule{Entries: []batchItem{{URL: "https://a.com"}}}); err == nil {
		t.Fatal("未配置数据目录时 UpsertSchedule 应报错")
	}
	if _, err := bare.DeleteSchedule("x"); err == nil {
		t.Fatal("未配置数据目录时 DeleteSchedule 应报错")
	}
	if got := bare.DueSchedules(time.Now()); got != nil {
		t.Fatalf("未配置数据目录时 DueSchedules 应返回空，实得 %+v", got)
	}

	// 文件损坏：Load 报错、DueSchedules 静默返回空（不让调度循环崩）。
	s := testServerWithDataDir(t)
	if err := os.MkdirAll(s.batchStateDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.schedulesPath(), []byte("{not a json array"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSchedules(); err == nil {
		t.Fatal("损坏文件应返回错误")
	}
	if got := s.DueSchedules(time.Now()); got != nil {
		t.Fatalf("损坏文件时 DueSchedules 应返回空，实得 %+v", got)
	}
}

func TestScheduleDueRules(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	past := now.Add(-time.Minute).Format(time.RFC3339)
	future := now.Add(time.Minute).Format(time.RFC3339)
	cases := []struct {
		name string
		sc   Schedule
		want bool
	}{
		{"启用+已过期", Schedule{Enabled: true, NextRunAt: past}, true},
		{"启用+未来", Schedule{Enabled: true, NextRunAt: future}, false},
		{"启用+未排期(首跑)", Schedule{Enabled: true}, true},
		{"启用+时间损坏", Schedule{Enabled: true, NextRunAt: "not-a-time"}, true},
		{"禁用+已过期", Schedule{Enabled: false, NextRunAt: past}, false},
	}
	for _, tc := range cases {
		if got := scheduleDue(tc.sc, now); got != tc.want {
			t.Fatalf("%s: scheduleDue=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestDueSchedulesFilters(t *testing.T) {
	s := testServerWithDataDir(t)
	now := time.Now()
	due := now.Add(-time.Minute).Format(time.RFC3339)
	future := now.Add(time.Minute).Format(time.RFC3339)
	list := []Schedule{
		{ID: "a-due", EveryMinutes: 5, Enabled: true, NextRunAt: due, Entries: []batchItem{{URL: "https://a.com"}}},
		{ID: "b-first", EveryMinutes: 5, Enabled: true, Entries: []batchItem{{URL: "https://b.com"}}},
		{ID: "c-future", EveryMinutes: 5, Enabled: true, NextRunAt: future, Entries: []batchItem{{URL: "https://c.com"}}},
		{ID: "d-off", EveryMinutes: 5, Enabled: false, NextRunAt: due, Entries: []batchItem{{URL: "https://d.com"}}},
	}
	if err := s.SaveSchedules(list); err != nil {
		t.Fatal(err)
	}
	got := s.DueSchedules(now)
	if len(got) != 2 {
		t.Fatalf("应只有 2 条到期（含首跑），实得 %+v", got)
	}
	ids := map[string]bool{}
	for _, sc := range got {
		ids[sc.ID] = true
	}
	if !ids["a-due"] || !ids["b-first"] {
		t.Fatalf("到期集合错误: %v", ids)
	}
}

func TestRunDueSchedules(t *testing.T) {
	oldStarter := batchJobStarter.Load()
	var mu sync.Mutex
	var calls [][]batchItem
	batchJobStarter.Store(func(_ *Server, entries []batchItem) (string, int) {
		mu.Lock()
		calls = append(calls, entries)
		mu.Unlock()
		return "job-triggered", len(entries)
	})
	t.Cleanup(func() { batchJobStarter.Store(oldStarter) })

	s := testServerWithDataDir(t)
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	past := now.Add(-time.Minute).Format(time.RFC3339)
	if err := s.SaveSchedules([]Schedule{
		{
			ID: "due", EveryMinutes: 5, Enabled: true, Tag: "grp", NextRunAt: past,
			Entries: []batchItem{{URL: "https://a.example.com"}, {URL: "https://b.example.com", Tag: "own"}},
		},
		{
			ID: "future", EveryMinutes: 5, Enabled: true, NextRunAt: now.Add(time.Hour).Format(time.RFC3339),
			Entries: []batchItem{{URL: "https://c.example.com"}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if n := s.runDueSchedules(now); n != 1 {
		t.Fatalf("应触发 1 个到期任务，实得 %d", n)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("启动钩子调用错误: %+v", got)
	}
	if got[0][0].Tag != "grp" || got[0][1].Tag != "own" {
		t.Fatalf("schedule.Tag 应下发到未单独设标签的条目: %+v", got[0])
	}

	list, err := s.LoadSchedules()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Schedule{}
	for _, sc := range list {
		byID[sc.ID] = sc
	}
	if byID["due"].LastRunAt != now.Format(time.RFC3339) {
		t.Fatalf("LastRunAt 未回写: %+v", byID["due"])
	}
	if want := now.Add(5 * time.Minute).Format(time.RFC3339); byID["due"].NextRunAt != want {
		t.Fatalf("NextRunAt 应推进到 %q，实得 %q", want, byID["due"].NextRunAt)
	}
	if byID["future"].LastRunAt != "" {
		t.Fatalf("未到期任务不应回写 LastRunAt: %+v", byID["future"])
	}

	// 同一时刻重复检查：已推进排期，不再重复触发。
	if n := s.runDueSchedules(now); n != 0 {
		t.Fatalf("同刻重复运行应不触发，实得 %d", n)
	}
	// 下一周期到点：再次触发。
	if n := s.runDueSchedules(now.Add(5 * time.Minute)); n != 1 {
		t.Fatalf("下一周期应触发，实得 %d", n)
	}
}

func TestRunSchedulerLoop(t *testing.T) {
	oldInterval := batchSchedulerInterval.Load()
	oldStarter := batchJobStarter.Load()
	batchSchedulerInterval.Store(int64(10 * time.Millisecond))
	var n atomic.Int32
	batchJobStarter.Store(func(*Server, []batchItem) (string, int) {
		n.Add(1)
		return "job-loop", 1
	})
	t.Cleanup(func() {
		batchSchedulerInterval.Store(oldInterval)
		batchJobStarter.Store(oldStarter)
	})

	s := testServerWithDataDir(t)
	now := time.Now()
	if err := s.SaveSchedules([]Schedule{{
		ID: "loop", EveryMinutes: 60, Enabled: true,
		NextRunAt: now.Add(-time.Minute).Format(time.RFC3339),
		Entries:   []batchItem{{URL: "https://a.example.com"}},
	}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.RunScheduler(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunScheduler 未随 ctx 取消退出")
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("到期任务应只触发一次（下一次 60 分钟后），实得 %d", got)
	}
}

func TestStartBatchJobEmpty(t *testing.T) {
	s := testServerWithDataDir(t)
	if id, n := s.startBatchJob(nil); id != "" || n != 0 {
		t.Fatalf("空列表应返回 (\"\",0)，实得 (%q,%d)", id, n)
	}
	if id, n := s.startBatchJob([]batchItem{{URL: "  "}, {}}); id != "" || n != 0 {
		t.Fatalf("全空白目标应返回 (\"\",0)，实得 (%q,%d)", id, n)
	}
}

func TestBatchTagOf(t *testing.T) {
	cases := []struct {
		items []batchItem
		want  string
	}{
		{nil, ""},
		{[]batchItem{{URL: "https://a.com"}}, ""},
		{[]batchItem{{URL: "https://a.com"}, {URL: "https://b.com", Tag: "t1"}, {Tag: "t2"}}, "t1"},
	}
	for i, tc := range cases {
		if got := batchTagOf(tc.items); got != tc.want {
			t.Fatalf("case %d: batchTagOf=%q want %q", i, got, tc.want)
		}
	}
}
