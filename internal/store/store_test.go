package store

import (
	"fmt"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/security"
)

func sampleResult(host, title string, techs int) *engine.Result {
	res := &engine.Result{
		URL: "https://" + host, Host: host, Title: title, Status: 200,
		ScannedAt: "2026-09-07 02:30:00", Duration: 1.23,
		Security:     &security.Report{Score: 40, Grade: "D"},
		Technologies: []engine.Tech{}, Verified: []map[string]any{},
		Vulnerabilities: []intel.Finding{}, Pages: []engine.PageInfo{},
		Extras: map[string]any{},
	}
	for i := 0; i < techs; i++ {
		res.Technologies = append(res.Technologies,
			engine.Tech{Name: fmt.Sprintf("Tech%d", i), Categories: []string{"cms"}})
	}
	res.Verified = append(res.Verified, map[string]any{
		"check": "xss-reflect", "title": "反射 XSS", "severity": "high",
	})
	return res
}

func TestSaveListGetDelete(t *testing.T) {
	s, err := New(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	id1 := s.Save(sampleResult("a.com", "A", 3), map[string]any{"deep": true})
	id2 := s.Save(sampleResult("b.com", "B", 1), nil)
	if id1 == 0 || id2 <= id1 {
		t.Fatalf("id 应递增: %d %d", id1, id2)
	}

	list := s.List(10, "")
	if len(list) != 2 || list[0].ID != id2 {
		t.Fatalf("列表应新→旧: %+v", list)
	}
	if list[0].TechCount != 1 || list[0].SecurityGrade != "D" {
		t.Fatalf("摘要字段缺失: %+v", list[0])
	}

	rec := s.Get(id1)
	if rec == nil || rec.Result.Title != "A" || !rec.Options["deep"].(bool) {
		t.Fatalf("详情读取失败: %+v", rec)
	}

	if !s.Delete(id1) || s.Get(id1) != nil {
		t.Fatal("删除失败")
	}
}

func TestTechFilter(t *testing.T) {
	s, _ := New(t.TempDir(), 100)
	s.Save(sampleResult("a.com", "A", 2), nil) // Tech0/Tech1
	list := s.List(10, "tech0")
	if len(list) != 1 {
		t.Fatalf("技术过滤失败: %+v", list)
	}
	if len(s.List(10, "不存在")) != 0 {
		t.Fatal("无匹配应为空")
	}
}

func TestMaxRecordsPrune(t *testing.T) {
	s, _ := New(t.TempDir(), 3)
	for i := 0; i < 5; i++ {
		s.Save(sampleResult(fmt.Sprintf("h%d.com", i), "x", 1), nil)
	}
	list := s.List(10, "")
	if len(list) != 3 || list[0].Host != "h4.com" {
		t.Fatalf("应裁掉最旧只留 3 条: %+v", list)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir, 100)
	id := s.Save(sampleResult("a.com", "A", 1), nil)

	s2, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Get(id) == nil {
		t.Fatal("重开后应能读到历史")
	}
	// 顺序不应错乱
	next := s2.Save(sampleResult("b.com", "B", 1), nil)
	if next <= id {
		t.Fatalf("重开后 id 应延续: %d vs %d", next, id)
	}
}

func TestVerifiedAggregation(t *testing.T) {
	s, _ := New(t.TempDir(), 100)
	s.Save(sampleResult("a.com", "A", 1), nil)
	s.Save(sampleResult("b.com", "B", 1), nil)
	items := s.Verified(10)
	if len(items) != 2 {
		t.Fatalf("汇总应含 2 条: %d", len(items))
	}
	for _, it := range items {
		if it["host"] == "" || it["scan_id"] == 0 || it["check"] == "" {
			t.Fatalf("汇总条目缺字段: %+v", it)
		}
	}
}

func TestTopTechsAndStats(t *testing.T) {
	s, _ := New(t.TempDir(), 100)
	s.Save(sampleResult("a.com", "A", 3), nil)
	s.Save(sampleResult("b.com", "B", 3), nil)
	top := s.TopTechs(2)
	if len(top) != 2 || top[0]["name"] != "Tech0" || top[0]["n"] != 2 {
		t.Fatalf("TOP 技术统计失败: %+v", top)
	}
	st := s.HistoryStats()
	if st["scans"] != 2 || st["hosts"] != 2 {
		t.Fatalf("历史统计失败: %+v", st)
	}
}

func TestJobs(t *testing.T) {
	m := NewJobManager()
	m.Create("j1", "scan", map[string]any{"url": "https://a.com"}, 100)
	j := m.Get("j1")
	if j == nil || j.Status != "pending" || j.Total != 100 {
		t.Fatalf("作业创建失败: %+v", j)
	}
	m.Update("j1", func(x *Job) {
		x.Status = "running"
		x.Progress = 50
		x.Message = "一半"
	})
	j = m.Get("j1")
	if j.Status != "running" || j.Progress != 50 || j.Message != "一半" {
		t.Fatalf("作业更新失败: %+v", j)
	}
	if m.CancelRequested("j1") {
		t.Fatal("未取消不应返回 true")
	}
	m.Update("j1", func(x *Job) { x.Status = "cancelling" })
	if !m.CancelRequested("j1") {
		t.Fatal("取消标志未生效")
	}
	if m.Get("nope") != nil {
		t.Fatal("不存在作业应返回 nil")
	}
}

func TestJobManagerEviction(t *testing.T) {
	m := NewJobManagerWithCap(3)
	for i := 0; i < 5; i++ {
		m.Create(fmt.Sprintf("j%d", i), "scan", nil, 1)
	}
	for _, gone := range []string{"j0", "j1"} {
		if m.Get(gone) != nil {
			t.Fatalf("最旧作业 %s 应被淘汰", gone)
		}
	}
	for _, keep := range []string{"j2", "j3", "j4"} {
		if m.Get(keep) == nil {
			t.Fatalf("作业 %s 应保留", keep)
		}
	}
}
