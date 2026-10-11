package server

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestMergeVerifiedDedup 回归：verified 按 (check, host, path) 归并——
// 同一站点同一 check 在多页重复上报（cookie-attrs 类）必须合成一项，
// 原始条数保留在计数里以便复核。
func TestMergeVerifiedDedup(t *testing.T) {
	list := []map[string]any{
		{"check": "cookie-attrs", "severity": "low", "title": "Cookie 缺安全属性",
			"url": "http://a.example/p1", "evidence": "PHPSESSID", "src": "passive"},
		{"check": "cookie-attrs", "severity": "low", "title": "Cookie 缺安全属性",
			"url": "http://a.example/p2", "evidence": "PHPSESSID", "src": "passive"},
		{"check": "cookie-attrs", "severity": "low", "title": "Cookie 缺安全属性",
			"url": "http://a.example/p3", "evidence": "PHPSESSID", "src": "passive"},
		{"check": "sqli-error", "severity": "high", "title": "SQL 注入",
			"url": "http://a.example/v?id=1", "src": "dast"},
	}
	got := mergeVerified(list)
	if len(got) != 2 {
		t.Fatalf("应归并为 2 项, got %d: %+v", len(got), got)
	}
	// 排序：high 在 low 前
	if got[0].Check != "sqli-error" || got[1].Check != "cookie-attrs" {
		t.Fatalf("severity 排序失败: %+v", got)
	}
	if len(got[1].URLs) != 3 {
		t.Fatalf("cookie-attrs 应保留 3 个 URL, got %v", got[1].URLs)
	}
	// 不同 host 不归并
	other := mergeVerified([]map[string]any{
		{"check": "cookie-attrs", "url": "http://a.example/p1", "src": "passive"},
		{"check": "cookie-attrs", "url": "http://b.example/p1", "src": "passive"},
	})
	if len(other) != 2 {
		t.Fatalf("跨 host 不应归并, got %d", len(other))
	}
}

// TestSplitBySrc 回归：按来源分列，且分列计数之和 == 归并组数（不漏不重）。
func TestSplitBySrc(t *testing.T) {
	groups := mergeVerified([]map[string]any{
		{"check": "a", "severity": "high", "url": "http://x/1", "src": "nuclei"},
		{"check": "b", "severity": "high", "url": "http://x/2", "src": "dast"},
		{"check": "c", "severity": "low", "url": "http://x/3", "src": "check"},
		{"check": "d", "severity": "low", "url": "http://x/4"}, // 缺 src → 自研检测
	})
	order, bySrc := splitBySrc(groups)
	sum := 0
	for _, s := range order {
		sum += len(bySrc[s])
	}
	if sum != len(groups) {
		t.Fatalf("分列计数 %d != 组数 %d", sum, len(groups))
	}
	if len(bySrc["nuclei"]) != 1 || len(bySrc["check"]) != 2 {
		t.Fatalf("来源分列错误: %+v", bySrc)
	}
	if srcLabel("nuclei") != "模板通道" || srcLabel("") != "自研检测" {
		t.Fatalf("来源标签错误")
	}
}

// TestReportRendersMergedAndSplit 回归：HTML/MD 双通道都必须渲染
// 「项 / 原始」计数与来源分组标题，且 Result==nil 不得 panic。
func TestReportRendersMergedAndSplit(t *testing.T) {
	rec := &store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 1, URL: "http://a.example", Host: "a.example"},
		Result: &engine.Result{
			Verified: []map[string]any{
				{"check": "cookie-attrs", "severity": "low", "title": "Cookie", "url": "http://a.example/p1", "src": "passive"},
				{"check": "cookie-attrs", "severity": "low", "title": "Cookie", "url": "http://a.example/p2", "src": "passive"},
				{"check": "sqli-error", "severity": "high", "title": "SQLi", "url": "http://a.example/v?a=1", "src": "dast"},
			},
		},
	}
	h := htmlReport(rec)
	if !strings.Contains(h, "2 项 / 原始 3 条") {
		t.Fatalf("HTML 未呈现归并计数:\n%s", h)
	}
	if !strings.Contains(h, "被动检查") || !strings.Contains(h, "主动探测") {
		t.Fatalf("HTML 未按来源分列")
	}
	m := markdownReport(rec)
	if !strings.Contains(m, "2 项 / 原始 3 条") {
		t.Fatalf("MD 未呈现归并计数:\n%s", m)
	}
	if !strings.Contains(m, "### 被动检查") || !strings.Contains(m, "### 主动探测") {
		t.Fatalf("MD 未按来源分列")
	}

	// Result == nil：两通道都必须安全返回提示（此前是 panic 疑虑点）
	nilRec := &store.ScanRecord{ScanSummary: store.ScanSummary{URL: "http://x"}}
	if s := htmlReport(nilRec); !strings.Contains(s, "无详细结果数据") {
		t.Fatalf("HTML nil Result 未安全返回")
	}
	if s := markdownReport(nilRec); !strings.Contains(s, "无详细结果数据") {
		t.Fatalf("MD nil Result 未安全返回")
	}
}
