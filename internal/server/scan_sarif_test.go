package server

import (
	"encoding/json"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

func TestScanSARIF(t *testing.T) {
	rec := &store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 7, URL: "https://example.com/app", Host: "example.com"},
		Result: &engine.Result{
			URL:  "https://example.com/app",
			Host: "example.com",
			Vulnerabilities: []intel.Finding{
				{CVE: "CVE-2021-44228", Title: "Log4j RCE", Severity: "critical", Desc: "远程代码执行"},
				{Title: "弱口令", Severity: "medium", Tech: "WordPress"},
			},
			Verified: []map[string]any{
				{"title": "SQL 注入（报错型）", "severity": "high", "src": "dast", "evidence": "MySQL syntax error"},
				{"title": "缺失 HSTS", "severity": "low", "src": "check"},
			},
		},
	}
	data, err := scanSARIF(rec)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("SARIF 非法 JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("version 错误: %v", log["version"])
	}
	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("应有 4 条结果，实得 %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["ruleId"] != "CVE-2021-44228" || first["level"] != "error" {
		t.Fatalf("首条映射错误: %+v", first)
	}
	// 指纹稳定
	data2, _ := scanSARIF(rec)
	if string(data) != string(data2) {
		t.Fatal("两次导出应逐字节一致（指纹稳定）")
	}
	// 无结果时 results 必须是 [] 而非 null
	empty, err := scanSARIF(&store.ScanRecord{Result: &engine.Result{URL: "https://a.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), `"results": []`) {
		t.Fatalf("空结果应为 []: %s", string(empty))
	}
	if _, err := scanSARIF(&store.ScanRecord{}); err == nil {
		t.Fatal("无 Result 应报错")
	}
}
