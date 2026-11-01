// FE-12 零丢失回归：取消时部分结果落库可读、状态迁移、续扫计划。
package server

import (
	"encoding/json"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// newPartialTestStore 新建临时历史存储。
func newPartialTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.TempDir(), 20)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// partialSampleResult 构造取消时引擎返回的部分结果（页面/技术/发现/证据齐全）。
func partialSampleResult() *engine.Result {
	return &engine.Result{
		URL: "https://t.example", Host: "t.example",
		ScannedAt:       "2026-01-01 00:00:00",
		Technologies:    []engine.Tech{{Name: "nginx"}, {Name: "php"}},
		Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-0001", Title: "样本发现"}},
		Verified:        []map[string]any{{"check": "weak-cookie"}},
		Pages: []engine.PageInfo{
			{URL: "https://t.example/", Status: 200},
			{URL: "https://t.example/a", Status: 200},
			{URL: "https://t.example/b", Status: 0}, // 未采集成功：续扫页面目标
		},
		Diagnostics: &engine.ScanDiagnostics{Phases: []engine.PhaseDiagnostics{
			{Phase: "home"}, {Phase: "crawl"},
		}},
	}
}

// TestSavePartialPersistsAndReadable 取消时部分结果落库：报告可读、页面/
// 技术/发现/证据不丢，Options 标记 status=partial，历史能按 partial 读回。
func TestSavePartialPersistsAndReadable(t *testing.T) {
	st := newPartialTestStore(t)
	opts := PartialOptions(engine.Options{Checks: "all", DAST: true, Passive: true})
	scanID, rec := SavePartial(st, partialSampleResult(), opts)
	if scanID <= 0 || rec == nil {
		t.Fatalf("SavePartial 应返回有效记录：id=%d rec=%v", scanID, rec)
	}
	if rec.Status != engine.StatePartial || !rec.Partial {
		t.Errorf("记录状态 = %s partial=%v", rec.Status, rec.Partial)
	}
	if rec.PageCount != 3 || rec.TechCount != 2 || rec.FindingCount != 1 || rec.EvidenceCount != 1 {
		t.Errorf("统计 = %d 页/%d 技术/%d 发现/%d 证据",
			rec.PageCount, rec.TechCount, rec.FindingCount, rec.EvidenceCount)
	}
	if rec.URL != "https://t.example" || rec.ScannedAt == "" {
		t.Errorf("记录 URL/时间异常：%q %q", rec.URL, rec.ScannedAt)
	}
	// 已完成阶段来自诊断账本；未完成阶段按选项判定（dast/passive/nuclei 启用）
	if !containsStr(rec.CompletedPhases, "home") || !containsStr(rec.CompletedPhases, "crawl") {
		t.Errorf("CompletedPhases 异常：%v", rec.CompletedPhases)
	}
	for _, want := range []string{"dast", "passive", "nuclei"} {
		if !containsStr(rec.RemainingPhases, want) {
			t.Errorf("RemainingPhases 缺 %q：%v", want, rec.RemainingPhases)
		}
	}
	if containsStr(rec.RemainingPhases, "home") {
		t.Errorf("已完成阶段不应在剩余列表：%v", rec.RemainingPhases)
	}
	if !containsStr(rec.ResumeTargets, "phase:dast") {
		t.Errorf("ResumeTargets 应含 phase:dast：%v", rec.ResumeTargets)
	}
	if !containsStr(rec.ResumeTargets, "page:https://t.example/b") {
		t.Errorf("ResumeTargets 应含未采集成功页面：%v", rec.ResumeTargets)
	}

	// 历史可读：store.Get 原样保留部分结果
	record := st.Get(scanID)
	if record == nil || record.Result == nil {
		t.Fatal("历史记录不存在")
	}
	if !record.Result.Partial {
		t.Error("历史结果应标记 partial")
	}
	if len(record.Result.Pages) != 3 || len(record.Result.Technologies) != 2 ||
		len(record.Result.Vulnerabilities) != 1 || len(record.Result.Verified) != 1 {
		t.Errorf("落库部分结果内容丢失：pages=%d techs=%d vulns=%d verified=%d",
			len(record.Result.Pages), len(record.Result.Technologies),
			len(record.Result.Vulnerabilities), len(record.Result.Verified))
	}
	if got := record.Options["status"]; got != "partial" {
		t.Errorf("Options.status = %v，期望 partial", got)
	}

	// LoadPartialRecord 读回：可续扫记录
	loaded, ok := LoadPartialRecord(st, scanID)
	if !ok || loaded == nil {
		t.Fatal("LoadPartialRecord 应读回部分结果")
	}
	if loaded.ScanID != scanID || loaded.Status != engine.StatePartial {
		t.Errorf("读回记录异常：%+v", loaded)
	}
	if len(loaded.ResumeTargets) == 0 {
		t.Error("读回记录应带续扫目标")
	}
	data, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"partial":true`, `"status":"partial"`, `"resume_targets"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("可读记录 JSON 应含 %s：%s", key, data)
		}
	}
	if strings.Contains(string(data), "CVE-2024-0001") {
		t.Error("可读记录不应内嵌完整 Result（体积过大）")
	}
}

// TestSavePartialNilSafe 空参数不 panic、不落库。
func TestSavePartialNilSafe(t *testing.T) {
	st := newPartialTestStore(t)
	if id, rec := SavePartial(nil, partialSampleResult(), nil); id != 0 || rec != nil {
		t.Errorf("nil store 应返回 0/nil：%d %v", id, rec)
	}
	if id, rec := SavePartial(st, nil, nil); id != 0 || rec != nil {
		t.Errorf("nil result 应返回 0/nil：%d %v", id, rec)
	}
	if _, ok := LoadPartialRecord(st, 9999); ok {
		t.Error("不存在的记录应返回 false")
	}
	if _, ok := LoadPartialRecord(nil, 1); ok {
		t.Error("nil store 应返回 false")
	}
	if got := ListPartials(nil, 10); got != nil {
		t.Errorf("nil store 列表应为空：%v", got)
	}
	if got := ListPartials(st, 0); got != nil {
		t.Errorf("limit=0 列表应为空：%v", got)
	}
}

// TestSavePartialJobTransitions 接线入口：运行中任务取消 → job 状态 partial
// 且带 scan_id/续扫目标；已结束任务 → 拒绝状态迁移但数据仍落库（零丢失）。
func TestSavePartialJobTransitions(t *testing.T) {
	st := newPartialTestStore(t)
	s := &Server{jobs: store.NewJobManagerWithCap(10), st: store.WrapTiered(st, 0)}
	s.jobs.Create("job-run", "scan", map[string]any{"url": "https://t.example"}, 100)
	s.jobs.Update("job-run", func(j *store.Job) { j.Status = "running" })

	scanID, rec := s.SavePartialJob("job-run", partialSampleResult(),
		PartialOptions(engine.Options{DAST: true}), "crawl")
	if scanID <= 0 || rec == nil {
		t.Fatalf("SavePartialJob 应落库：id=%d rec=%v", scanID, rec)
	}
	if rec.JobID != "job-run" {
		t.Errorf("记录 JobID = %q", rec.JobID)
	}
	if rec.InterruptedPhase != "crawl" {
		t.Errorf("中断阶段 = %q", rec.InterruptedPhase)
	}
	job := s.jobs.Get("job-run")
	if job == nil {
		t.Fatal("job 不存在")
	}
	if job.Status != "partial" {
		t.Errorf("job 状态 = %q，期望 partial", job.Status)
	}
	if job.Result == nil || job.Result["scan_id"] == nil {
		t.Fatalf("job.Result 应带 scan_id：%+v", job.Result)
	}
	if id, _ := job.Result["scan_id"].(int64); id != scanID {
		t.Errorf("job scan_id = %v，期望 %d", job.Result["scan_id"], scanID)
	}
	if !strings.Contains(job.Message, "部分结果") {
		t.Errorf("job 文案异常：%q", job.Message)
	}
	if len(job.Events) == 0 || !strings.Contains(job.Events[len(job.Events)-1].Text, "可续扫目标") {
		t.Errorf("应追加部分结果事件：%+v", job.Events)
	}
	// 中断阶段在续扫计划首位（该阶段可能只跑了一半）
	if len(rec.ResumeTargets) == 0 || rec.ResumeTargets[0] != "phase:crawl" {
		t.Errorf("续扫目标首位应为中断阶段：%v", rec.ResumeTargets)
	}

	// 非法迁移：已 done 的任务拒绝改状态，但数据仍落库
	s.jobs.Create("job-done", "scan", nil, 100)
	s.jobs.Update("job-done", func(j *store.Job) { j.Status = "done" })
	scanID2, rec2 := s.SavePartialJob("job-done", partialSampleResult(), nil, "")
	if scanID2 <= 0 || rec2 == nil {
		t.Fatal("非法迁移下数据仍应落库（零丢失优先）")
	}
	if job2 := s.jobs.Get("job-done"); job2.Status != "done" {
		t.Errorf("done 任务状态不应被改写，实际 %q", job2.Status)
	}
	events := s.jobs.Get("job-done").Events
	foundReject := false
	for _, ev := range events {
		if strings.Contains(ev.Text, "拒绝") && strings.Contains(ev.Text, "迁移") {
			foundReject = true
		}
	}
	if !foundReject {
		t.Errorf("非法迁移应记录事件：%+v", events)
	}
	if _, ok := LoadPartialRecord(st, scanID2); !ok {
		t.Error("非法迁移下仍应能读回部分结果")
	}
}

// TestResumePlan 续扫计划：中断阶段优先、已完成跳过、未启用阶段不出现、
// 页面只给失败页、去重且顺序稳定。
func TestResumePlan(t *testing.T) {
	rec := &PartialRecord{
		CompletedPhases:  []string{"home", "crawl", "fingerprint", "security"},
		InterruptedPhase: "crawl",
		Options: map[string]any{
			"dast": true, "passive": true, "checks": "all", "netsec": true,
		},
		Result: &engine.Result{Pages: []engine.PageInfo{
			{URL: "https://x.example/ok", Status: 200},
			{URL: "https://x.example/bad", Status: 0},
			{URL: "https://x.example/err", Status: 502},
			{URL: "https://x.example/bad", Status: 0}, // 重复 URL
		}},
	}
	plan := ResumePlan(rec)
	if len(plan) == 0 {
		t.Fatal("续扫计划不应为空")
	}
	if plan[0] != "phase:crawl" {
		t.Errorf("首位应为中断阶段 phase:crawl，实际 %v", plan)
	}
	if countStr(plan, "phase:crawl") != 1 {
		t.Errorf("phase:crawl 不应重复：%v", plan)
	}
	for _, want := range []string{"phase:dast", "phase:passive", "phase:nuclei",
		"phase:netsec", "phase:intel"} {
		if !containsStr(plan, want) {
			t.Errorf("计划缺 %q：%v", want, plan)
		}
	}
	for _, absent := range []string{"phase:home", "phase:fingerprint", "phase:security",
		"phase:modules", "page:https://x.example/ok"} {
		if containsStr(plan, absent) {
			t.Errorf("计划不应含 %q：%v", absent, plan)
		}
	}
	if !containsStr(plan, "page:https://x.example/bad") ||
		!containsStr(plan, "page:https://x.example/err") {
		t.Errorf("计划应含失败页面：%v", plan)
	}
	if countStr(plan, "page:https://x.example/bad") != 1 {
		t.Errorf("页面目标不应重复：%v", plan)
	}
	// 阶段顺序稳定：phase 目标都在 page 目标之前
	seenPage := false
	for _, tgt := range plan {
		if strings.HasPrefix(tgt, "page:") {
			seenPage = true
		} else if seenPage {
			t.Errorf("阶段目标应在页面目标之前：%v", plan)
		}
	}

	// nil 安全
	if ResumePlan(nil) != nil {
		t.Error("nil 记录应返回空计划")
	}
	// 未启用可选阶段：默认选项只剩核心阶段
	plain := ResumePlan(&PartialRecord{Options: map[string]any{}})
	for _, absent := range []string{"phase:dast", "phase:passive", "phase:nuclei", "phase:netsec"} {
		if containsStr(plain, absent) {
			t.Errorf("未启用阶段不应出现 %q：%v", absent, plain)
		}
	}
	for _, want := range []string{"phase:home", "phase:crawl", "phase:checks", "phase:intel"} {
		if !containsStr(plain, want) {
			t.Errorf("核心阶段应出现 %q：%v", want, plain)
		}
	}
}

// TestPartialOptions 引擎选项展开为落库/规划用扁平 map。
func TestPartialOptions(t *testing.T) {
	opts := PartialOptions(engine.Options{
		Deep: true, Checks: "all", DAST: true, Passive: true, Netsec: true,
		DirScan: true, Subdomain: true, Graph: true, NucleiCap: 500,
	})
	for _, key := range []string{"deep", "checks", "dast", "passive", "netsec",
		"dir_scan", "subdomain", "graph", "nuclei_cap"} {
		if _, ok := opts[key]; !ok {
			t.Errorf("PartialOptions 缺键 %q", key)
		}
	}
	if opts["checks"] != "all" || opts["nuclei_cap"] != 500 {
		t.Errorf("取值异常：checks=%v nuclei_cap=%v", opts["checks"], opts["nuclei_cap"])
	}
}

// TestListPartials 历史列表只列部分结果（新→旧），正常记录不混入。
func TestListPartials(t *testing.T) {
	st := newPartialTestStore(t)
	// 一条正常完成记录（无 partial 标记）
	normalID := st.Save(&engine.Result{
		URL: "https://normal.example", Host: "normal.example",
		Technologies: []engine.Tech{}, Vulnerabilities: []intel.Finding{},
		Verified: []map[string]any{}, Pages: []engine.PageInfo{}, Extras: map[string]any{},
	}, map[string]any{"status": "done"})
	id1, _ := SavePartial(st, partialSampleResult(), nil)
	id2, _ := SavePartialAt(st, partialSampleResult(), nil, "dast")

	list := ListPartials(st, 10)
	if len(list) != 2 {
		t.Fatalf("应列出 2 条部分结果，实际 %d：%+v", len(list), list)
	}
	if list[0].ScanID != id2 || list[1].ScanID != id1 {
		t.Errorf("列表应新→旧：%v（期望 %d,%d）", []int64{list[0].ScanID, list[1].ScanID}, id2, id1)
	}
	for _, item := range list {
		if item.ScanID == normalID {
			t.Error("正常完成记录不应出现在部分结果列表")
		}
		if item.Status != "partial" || item.PageCount != 3 {
			t.Errorf("摘要异常：%+v", item)
		}
	}
	if !containsStr(list[0].RemainingPhases, "dast") {
		t.Errorf("摘要应带剩余阶段：%+v", list[0])
	}
}

// ---- 测试小工具（避免与既有 server 测试辅助函数重名） ----

// containsStr 复用 verified.go 的同名工具（逐项精确匹配）。
// countStr 统计目标出现次数（去重断言用）。
func countStr(list []string, want string) int {
	n := 0
	for _, s := range list {
		if s == want {
			n++
		}
	}
	return n
}
