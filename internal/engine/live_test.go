package engine

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// TestLiveTrackerPhasesAndCounters 实时统计器：阶段切换强制推送、页面计数、
// 请求/拦截取自注入的 Stats、done 收尾快照；emit=nil 时不创建（零开销）。
func TestLiveTrackerPhasesAndCounters(t *testing.T) {
	var got []LiveStats
	stats := httpx.Stats{}
	lt := newLiveTracker(func() httpx.Stats { return stats }, func(s LiveStats) { got = append(got, s) })
	if lt == nil {
		t.Fatal("emit 非 nil 时应创建 tracker")
	}
	lt.setPhase("home", "首页采集")
	stats = httpx.Stats{Requests: 3, Blocked: 1}
	lt.notePage()
	lt.touch()
	lt.setPhase("dast", "参数级 DAST")
	stats = httpx.Stats{Requests: 10, Blocked: 2}
	lt.touch()
	lt.done()

	if len(got) < 3 {
		t.Fatalf("应至少推送 3 次（home/dast/done），实得 %d: %+v", len(got), got)
	}
	if got[0].Phase != "home" || got[0].PhaseName != "首页采集" {
		t.Fatalf("首个快照阶段错误: %+v", got[0])
	}
	var sawDast bool
	for _, s := range got {
		if s.Phase == "dast" {
			sawDast = true
		}
	}
	if !sawDast {
		t.Fatalf("缺 dast 阶段快照: %+v", got)
	}
	last := got[len(got)-1]
	if last.Phase != "done" || last.PhaseName != "完成" {
		t.Fatalf("收尾阶段应为 done/完成: %+v", last)
	}
	if last.Requests != 10 || last.Blocked != 2 || last.Pages != 1 {
		t.Fatalf("收尾计数错误（应 req=10 blocked=2 pages=1）: %+v", last)
	}
	if last.ElapsedMS < 0 || last.Rate < 0 {
		t.Fatalf("时长/速率不应为负: %+v", last)
	}

	if newLiveTracker(nil, nil) != nil {
		t.Fatal("emit 为 nil 时应返回 nil tracker（零开销）")
	}
}
