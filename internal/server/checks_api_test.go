package server

import (
	"encoding/json"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestChecksAPIMetadata GET /api/checks：全量 1,010 条 + 元数据字段。
func TestChecksAPIMetadata(t *testing.T) {
	_, api := newServer(t)
	code, body := getJSON(t, api.URL+"/api/checks")
	if code != 200 {
		t.Fatalf("GET /api/checks = %d: %v", code, body)
	}
	if n, _ := body["count"].(float64); n < 1000 {
		t.Fatalf("check 数量不足：%v", body["count"])
	}
	list, _ := body["checks"].([]any)
	if len(list) == 0 {
		t.Fatal("checks 为空")
	}
	var gitLeak map[string]any
	for _, it := range list {
		m, _ := it.(map[string]any)
		if m["id"] == "git-leak" {
			gitLeak = m
			break
		}
	}
	if gitLeak == nil {
		t.Fatal("缺少 git-leak")
	}
	if gitLeak["safety"] != "read_only" {
		t.Fatalf("git-leak safety 错误: %v", gitLeak["safety"])
	}
	attack, _ := gitLeak["attack"].([]any)
	found := false
	for _, a := range attack {
		if a == "T1552.001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("git-leak attack 缺少 T1552.001: %v", attack)
	}
}

// TestScanSARIFCheckMetadata 验证型发现带 check ID 时，SARIF 结果带
// properties.attack/noise/safety 与 rule tags。
func TestScanSARIFCheckMetadata(t *testing.T) {
	rec := &store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 9, URL: "https://example.com", Host: "example.com"},
		Result: &engine.Result{
			URL:  "https://example.com",
			Host: "example.com",
			Verified: []map[string]any{
				{"check": "git-leak", "title": "Git 仓库泄露", "severity": "high", "src": "check"},
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
	run := log["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("应有 1 条结果，实得 %d", len(results))
	}
	target := results[0].(map[string]any)
	props, _ := target["properties"].(map[string]any)
	if props == nil || props["safety"] != "read_only" {
		t.Fatalf("properties 缺少元数据: %v", target["properties"])
	}
	if attack, _ := props["attack"].(string); attack == "" {
		t.Fatalf("properties.attack 为空: %v", props)
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	hasTags := false
	for _, r := range rules {
		rm := r.(map[string]any)
		if rm["id"] == "sitelens-verified-check" {
			if tags, _ := rm["tags"].([]any); len(tags) > 0 {
				hasTags = true
			}
		}
	}
	if !hasTags {
		t.Fatal("rule tags 未写入 ATT&CK 技术 ID")
	}
}
