// FE-12 部分结果标记回归：MarkPartial / CompletedPhases / 统计 / 兼容性。
package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// partialResult 构造一份「取消时」的部分结果样本。
func partialResult() *Result {
	return &Result{
		URL: "https://t.example", Host: "t.example",
		Technologies:    []Tech{{Name: "nginx"}},
		Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-0001", Title: "样本"}},
		Verified:        []map[string]any{{"check": "weak-cookie"}},
		Pages: []PageInfo{
			{URL: "https://t.example/", Status: 200},
			{URL: "https://t.example/a", Status: 200},
		},
		Diagnostics: &ScanDiagnostics{Phases: []PhaseDiagnostics{
			{Phase: "home"}, {Phase: "crawl"}, {Phase: "home"},
		}},
	}
}

// TestMarkPartialSetsFields 标记 additive 字段：Partial/中断阶段/去重已完成阶段。
func TestMarkPartialSetsFields(t *testing.T) {
	res := partialResult()
	if got := MarkPartial(res, "crawl"); got != res {
		t.Fatal("MarkPartial 应返回同一指针")
	}
	if !res.Partial {
		t.Error("Partial 应为 true")
	}
	if res.InterruptedPhase != "crawl" {
		t.Errorf("InterruptedPhase = %q", res.InterruptedPhase)
	}
	want := []string{"home", "crawl"}
	if len(res.CompletedPhases) != len(want) {
		t.Fatalf("CompletedPhases = %v，期望 %v", res.CompletedPhases, want)
	}
	for i := range want {
		if res.CompletedPhases[i] != want[i] {
			t.Errorf("CompletedPhases[%d] = %q，期望 %q",
				i, res.CompletedPhases[i], want[i])
		}
	}
	// JSON additive 输出（omitempty：正常结果不含这些键）
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"partial":true`, `"interrupted_phase":"crawl"`, `"completed_phases"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("部分结果 JSON 应含 %s：%s", key, data)
		}
	}
}

// TestNormalResultJSONUnchanged 正常（未标记）结果不输出 FE-12 字段，
// 保证既有 JSON 逐字节兼容。
func TestNormalResultJSONUnchanged(t *testing.T) {
	res := &Result{URL: "https://t.example", Technologies: []Tech{},
		Vulnerabilities: []intel.Finding{}, Verified: []map[string]any{},
		Pages: []PageInfo{}, Extras: map[string]any{}}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"partial", "interrupted_phase", "completed_phases"} {
		if strings.Contains(string(data), `"`+key+`"`) {
			t.Errorf("正常结果不应输出 %q：%s", key, data)
		}
	}
}

// TestMarkPartialNil nil 安全。
func TestMarkPartialNil(t *testing.T) {
	if MarkPartial(nil, "") != nil {
		t.Error("nil 结果应返回 nil")
	}
	if CompletedPhases(nil) != nil {
		t.Error("nil 结果无已完成阶段")
	}
	if p, te, f, e := PartialCounts(nil); p != 0 || te != 0 || f != 0 || e != 0 {
		t.Errorf("nil 统计应为 0，实际 %d/%d/%d/%d", p, te, f, e)
	}
	if txt := PartialSummaryText(nil); !strings.Contains(txt, "0 页/0 技术/0 发现/0 证据") {
		t.Errorf("nil 文案异常：%q", txt)
	}
	// 无诊断信息时 CompletedPhases 为空
	if got := CompletedPhases(&Result{}); got != nil {
		t.Errorf("无诊断应返回 nil，实际 %v", got)
	}
}

// TestPartialCounts 统计口径：页面/技术/发现/证据。
func TestPartialCounts(t *testing.T) {
	res := partialResult()
	pages, techs, findings, evidence := PartialCounts(res)
	if pages != 2 || techs != 1 || findings != 1 || evidence != 1 {
		t.Fatalf("统计 = %d 页/%d 技术/%d 发现/%d 证据", pages, techs, findings, evidence)
	}
	text := PartialSummaryText(res)
	if !strings.Contains(text, "2 页/1 技术/1 发现/1 证据") {
		t.Errorf("文案异常：%q", text)
	}
}

// TestPartialCountsWithGraph 证据数包含结构化事实图中的 evidence 实体。
func TestPartialCountsWithGraph(t *testing.T) {
	res := partialResult()
	g := model.NewGraph("scan-partial")
	g.Add(model.NewEvidence("snippet", model.OriginBlackbox, "audit", "scan-partial",
		"https://t.example/", "", 0, "证据正文"))
	g.Add(model.NewEvidence("response", model.OriginBlackbox, "audit", "scan-partial",
		"https://t.example/a", "", 0, "响应正文"))
	res.Graph = g
	res.Verified = append(res.Verified, map[string]any{"check": "second"})
	_, _, _, evidence := PartialCounts(res)
	if evidence != 4 { // 2 verified + 2 graph evidences
		t.Fatalf("证据数 = %d，期望 4", evidence)
	}
}

// TestCompletedPhasesOrderAndDedup 已完成阶段保序去重。
func TestCompletedPhasesOrderAndDedup(t *testing.T) {
	res := &Result{Diagnostics: &ScanDiagnostics{Phases: []PhaseDiagnostics{
		{Phase: "home"}, {Phase: ""}, {Phase: "crawl"}, {Phase: "crawl"},
		{Phase: "fingerprint"},
	}}}
	got := CompletedPhases(res)
	want := []string{"home", "crawl", "fingerprint"}
	if len(got) != len(want) {
		t.Fatalf("CompletedPhases = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q，期望 %q", i, got[i], want[i])
		}
	}
}
