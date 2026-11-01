// CP-11/CP-05 接线回归：置信信号收集（串行/分片等价）、置信度回写。
package engine

import (
	"reflect"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// testCrawlPages 构造带最终 URL 的页批次（仅用 resp.FinalURL）。
func testCrawlPages(urls ...string) []crawlPage {
	out := make([]crawlPage, len(urls))
	for i, u := range urls {
		out[i] = crawlPage{resp: &httpx.Response{FinalURL: u, Status: 200}}
	}
	return out
}

// samplePageHits 6 页命中样本（含跨页同技术、同页多技术）。
func samplePageHits() [][]sitelens.MatchHit {
	h := func(name, ev, ver string, conf int) sitelens.MatchHit {
		return sitelens.MatchHit{Name: name, Evidence: ev, Version: ver, Conf: conf}
	}
	return [][]sitelens.MatchHit{
		{h("Nginx", "Server=nginx", "", 90)},
		{h("Nginx", "Server=nginx", "1.24", 90), h("WordPress", "meta generator=WordPress", "6.4", 80)},
		{h("WordPress", "meta generator=WordPress", "6.4", 80)},
		{h("jQuery", "src /jquery-3.5.1.min.js", "3.5.1", 70)},
		{h("jQuery", "src /jquery-3.5.1.min.js", "3.5.1", 70), h("PHP", "cookie PHPSESSID", "", 85)},
		{h("Nginx", "Server=nginx", "1.24", 90)},
	}
}

// TestCollectFingerprintSignalsSerialVsSharded CP-05 页面批次：分片收集与
// 串行收集逐项一致（页序、页面 URL、信号内容），并发夹到 ≤4。
func TestCollectFingerprintSignalsSerialVsSharded(t *testing.T) {
	pages := testCrawlPages(
		"https://x/", "https://x/a", "https://x/b",
		"https://x/c", "https://x/d", "https://x/e")
	hits := samplePageHits()

	serial, stats := collectFingerprintSignals(pages, hits, 0)
	if serial == nil || stats != nil {
		t.Fatalf("串行路径应返回信号且无分片统计：%v %v", len(serial), stats)
	}
	if len(serial) == 0 {
		t.Fatal("信号不应为空")
	}
	// 页序与页面 URL 关联
	if serial[0].Page != "https://x/" || serial[0].Name != "Nginx" {
		t.Errorf("首个信号异常：%+v", serial[0])
	}

	for _, workers := range []int{2, 3, 9} { // 9 会被 RunShards 夹到 ≤4
		sharded, st := collectFingerprintSignals(pages, hits, workers)
		if st == nil || st.Total == 0 || st.Completed != st.Total {
			t.Fatalf("workers=%d 分片统计异常：%+v", workers, st)
		}
		if !reflect.DeepEqual(serial, sharded) {
			t.Fatalf("workers=%d 分片与串行信号不一致：\n串行=%+v\n分片=%+v",
				workers, serial, sharded)
		}
	}

	// 空输入：两种路径都返回 nil
	if got, st := collectFingerprintSignals(nil, nil, 0); got != nil || st != nil {
		t.Errorf("空输入串行 = %v/%v", got, st)
	}
	if got, st := collectFingerprintSignals(nil, nil, 3); got != nil || st != nil {
		t.Errorf("空输入分片 = %v/%v", got, st)
	}
}

// TestCalibrateTechnologies CP-11：按技术聚合信号 → 校准 → 回写
// Confidence(0-100) 并把 reasons 追加到 Evidence；无信号技术保持原值。
func TestCalibrateTechnologies(t *testing.T) {
	hits := samplePageHits()
	pages := testCrawlPages(
		"https://x/", "https://x/a", "https://x/b",
		"https://x/c", "https://x/d", "https://x/e")
	signals, _ := collectFingerprintSignals(pages, hits, 0)

	techs := []Tech{
		{Name: "Nginx", Confidence: 90, Evidence: []string{"Server=nginx"}},
		{Name: "WordPress", Confidence: 80, Evidence: []string{"meta generator=WordPress"}},
		{Name: "Ghost", Confidence: 50, Evidence: []string{"关键词 ghost"}},
	}
	out := calibrateTechnologies(techs, signals)
	if len(out) != 3 {
		t.Fatalf("技术数 = %d", len(out))
	}
	if out[0].Name != "Nginx" || out[1].Name != "WordPress" || out[2].Name != "Ghost" {
		t.Fatalf("技术顺序被改变：%+v", out)
	}

	// 期望值：用同一套输入独立跑 sitelens.CalibrateTechs 对照
	byName := map[string][]sitelens.ConfidenceSignal{}
	for _, s := range signals {
		byName[s.Name] = append(byName[s.Name], s)
	}
	inputs := []sitelens.TechConfidenceInput{
		{Name: "Nginx", Signals: byName["Nginx"], BaseConf: byName["Nginx"][0].BaseConf},
		{Name: "WordPress", Signals: byName["WordPress"], BaseConf: byName["WordPress"][0].BaseConf},
		{Name: "Ghost", Signals: nil},
	}
	want := sitelens.CalibrateTechs(inputs)
	for i := 0; i < 2; i++ {
		if got, exp := out[i].Confidence, sitelens.ConfidenceToConf(want[i].Confidence); got != exp {
			t.Errorf("%s.Confidence = %d，期望 %d", out[i].Name, got, exp)
		}
		if !strings.HasPrefix(strings.Join(out[i].Evidence, "\n"), strings.Join(techs[i].Evidence, "\n")) {
			t.Errorf("%s 原 Evidence 未被保留：%v", out[i].Name, out[i].Evidence)
		}
		joined := strings.Join(out[i].Evidence, ";")
		if !strings.Contains(joined, "证据") || !strings.Contains(joined, "通道") {
			t.Errorf("%s Evidence 应追加 reasons：%v", out[i].Name, out[i].Evidence)
		}
	}
	// 无信号技术保持原值（不被误降为 0）
	if out[2].Confidence != 50 || len(out[2].Evidence) != 1 {
		t.Errorf("无信号技术不应被改写：%+v", out[2])
	}

	// 空输入安全
	if got := calibrateTechnologies(nil, signals); got != nil {
		t.Errorf("空技术列表应返回 nil：%v", got)
	}
}
