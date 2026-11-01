package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// /api/scan 是 MCP/CLI/前端共用的入口：URL 自动修正必须在这里回显
// （input_url / normalized_url / url_corrections），否则调用方不知道实际扫了哪个地址。
func TestScanAPIReportsURLCorrections(t *testing.T) {
	_, api := newServer(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head><title>norm-test</title></head><body>ok</body></html>"))
	}))
	defer site.Close()

	dirty := "hxxp://" + strings.TrimPrefix(site.URL, "http://") + "。"
	payload, err := json.Marshal(map[string]any{"url": dirty, "passive": true})
	if err != nil {
		t.Fatal(err)
	}
	code, body := postJSON(t, api.URL+"/api/scan", string(payload))
	if code != 200 {
		t.Fatalf("scan %d: %v", code, body)
	}
	if body["input_url"] != dirty {
		t.Fatalf("input_url = %v, want %q", body["input_url"], dirty)
	}
	if body["normalized_url"] != site.URL {
		t.Fatalf("normalized_url = %v, want %q", body["normalized_url"], site.URL)
	}
	corr, ok := body["url_corrections"].([]any)
	if !ok || len(corr) != 2 {
		t.Fatalf("url_corrections = %v, want 2 条（hxxp + 末尾标点）", body["url_corrections"])
	}

	// 等任务收尾，避免测试结束后后台仍写临时数据目录。
	jobID, _ := body["job_id"].(string)
	if jobID == "" {
		t.Fatalf("缺 job_id: %v", body)
	}
	deadline := time.Now().Add(scanFlowTimeout())
	for {
		_, job := getJSON(t, api.URL+"/api/job/"+jobID)
		status, _ := job["status"].(string)
		if status == "done" || status == "error" || status == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("扫描超时: %v", job)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// /api/preflight 与 /api/scan 共用同一套 URL 自动修正字段，建议卡依赖它展示修正原因。
func TestPreflightAPIReportsURLCorrections(t *testing.T) {
	_, api := newServer(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head><title>pf-norm</title></head></html>"))
	}))
	defer site.Close()

	dirty := "hxxp://" + strings.TrimPrefix(site.URL, "http://") + "。"
	payload, err := json.Marshal(map[string]any{"url": dirty})
	if err != nil {
		t.Fatal(err)
	}
	code, body := postJSON(t, api.URL+"/api/preflight", string(payload))
	if code != 200 {
		t.Fatalf("preflight %d: %v", code, body)
	}
	if body["input_url"] != dirty {
		t.Fatalf("input_url = %v, want %q", body["input_url"], dirty)
	}
	if body["normalized_url"] != site.URL {
		t.Fatalf("normalized_url = %v, want %q", body["normalized_url"], site.URL)
	}
	if corr, ok := body["url_corrections"].([]any); !ok || len(corr) == 0 {
		t.Fatalf("url_corrections 缺失: %v", body["url_corrections"])
	}
}
