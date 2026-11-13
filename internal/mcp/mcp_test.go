package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI 模拟 SiteLens 本地 API 的最小面。
type fakeAPI struct {
	srv *httptest.Server

	mu       sync.Mutex
	scanBody map[string]any
	triage   map[string]any
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": "5.2.0-fake"})
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"scans": 3, "findings": 12})
	})
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.scanBody = body
		f.mu.Unlock()
		writeJSON(w, map[string]any{
			"job_id":          "job-1",
			"input_url":       "hxxp://example[.]com。",
			"normalized_url":  "https://example.com/",
			"url_corrections": []string{"还原失陷指标写法（[.] 等）", "还原 hxxp 为 http(s)", "去除末尾标点"},
		})
	})
	mux.HandleFunc("/api/job/job-1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"job_id": "job-1", "status": "done", "progress": 100,
			"scan_id": 7, "done": 10, "total": 10,
		})
	})
	mux.HandleFunc("/api/job/running", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"job_id": "running", "status": "running", "progress": 40,
			"message": "dast", "done": 4, "total": 10,
		})
	})
	mux.HandleFunc("/api/history/7", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"id": 7, "url": "https://example.com/", "host": "example.com",
			"title": "Example", "security_grade": "B", "security_score": 72,
			"tech_count": 2, "vuln_count": 2, "scanned_at": "2026-11-01T09:00:00Z",
			"duration": 12.5,
			"result": map[string]any{
				"technologies": []any{
					map[string]any{"name": "nginx", "version": "1.25.0"},
					map[string]any{"name": "php", "version": "8.2"},
				},
				"verified": []any{
					map[string]any{
						"check": "sqli-error", "title": "报错注入", "severity": "high",
						"url": "https://example.com/?id=1", "confirmed": true,
						"signals": []any{"sql syntax"}, "replay": "curl -sk 'https://example.com/?id=1'",
						"request": "GET /?id=1 HTTP/1.1", "response": map[string]any{"status": 500},
					},
				},
				"vulnerabilities": []any{
					map[string]any{"cve": "CVE-2024-0001", "severity": "medium", "title": "组件漏洞"},
				},
				"security": map[string]any{"grade": "B", "score": 72},
			},
		})
	})
	mux.HandleFunc("/api/export/7", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sarif+json")
		_, _ = fmt.Fprint(w, strings.Repeat("S", 20000))
	})
	mux.HandleFunc("/api/triage/7", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.triage = body
		f.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/graph/7/chain", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"nodes": []any{}, "edges": []any{}})
	})
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"scans": []any{map[string]any{"id": 7}}})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newTestServer(t *testing.T, apiURL string, active bool, maxBytes int) *Server {
	t.Helper()
	c, err := NewClient(apiURL, "test-token", 3*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return NewServer(c, Options{Version: "test", Active: active, MaxBytes: maxBytes, AllowHosts: []string{"example.com"}})
}

// runRPC 把若干请求行喂给 server，返回解析后的响应行。
func runRPC(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var in, out bytes.Buffer
	for _, l := range lines {
		in.WriteString(l)
		in.WriteByte('\n')
	}
	if err := s.Serve(context.Background(), &in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("响应不是 JSON: %q", line)
		}
		resps = append(resps, m)
	}
	return resps
}

func rpcReq(id int, method string, params any) string {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func rpcNotify(method string) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	return string(b)
}

func toolCallReq(id int, name string, args any) string {
	return rpcReq(id, "tools/call", map[string]any{"name": name, "arguments": args})
}

func toolResult(t *testing.T, resp map[string]any) (text string, isError bool) {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 result: %+v", resp)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("缺少 content: %+v", res)
	}
	item, _ := content[0].(map[string]any)
	text, _ = item["text"].(string)
	isError, _ = res["isError"].(bool)
	return text, isError
}

func toolNames(t *testing.T, resp map[string]any) map[string]bool {
	t.Helper()
	res, _ := resp["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	out := make(map[string]bool, len(tools))
	for _, v := range tools {
		tm, _ := v.(map[string]any)
		name, _ := tm["name"].(string)
		out[name] = true
	}
	return out
}

func TestInitializeAndToolsListReadOnly(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	resps := runRPC(t, s,
		rpcReq(1, "initialize", map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "chenji"},
		}),
		rpcReq(2, "tools/list", map[string]any{}),
	)
	if len(resps) != 2 {
		t.Fatalf("应有两行响应，得到 %d", len(resps))
	}
	init := resps[0]["result"].(map[string]any)
	if got := init["protocolVersion"]; got != protocolVersion {
		t.Fatalf("protocolVersion = %v, want %s", got, protocolVersion)
	}
	names := toolNames(t, resps[1])
	for _, want := range []string{"capabilities", "scan_status", "scan_result", "scan_cancel", "history", "graph", "export", "triage", "apispec"} {
		if !names[want] {
			t.Fatalf("只读工具缺少 %q: %v", want, names)
		}
	}
	for _, active := range []string{"scan", "graphql_introspect", "assets"} {
		if names[active] {
			t.Fatalf("未允许主动工具时不应出现 %q", active)
		}
	}
}

func TestToolsListActive(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, true, 0)
	names := toolNames(t, runRPC(t, s, rpcReq(1, "tools/list", map[string]any{}))[0])
	for _, want := range []string{"scan", "graphql_introspect", "assets"} {
		if !names[want] {
			t.Fatalf("--allow-active 时缺少 %q: %v", want, names)
		}
	}
}

func TestCapabilities(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "capabilities", map[string]any{}))[0])
	if isErr {
		t.Fatalf("capabilities 不应报错: %s", text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("capabilities 不是 JSON: %v", err)
	}
	if got["api_reachable"] != true {
		t.Fatalf("api_reachable = %v", got["api_reachable"])
	}
	if got["api_version"] != "5.2.0-fake" {
		t.Fatalf("api_version = %v", got["api_version"])
	}
}

func TestScanGatedWhenInactive(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan", map[string]any{"url": "https://example.com"}))[0])
	if !isErr {
		t.Fatalf("未启用主动工具时 scan 应 isError: %s", text)
	}
	if !strings.Contains(text, "allow-active") {
		t.Fatalf("错误信息应提示 --allow-active: %s", text)
	}
}

func TestScanCallsAPI(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, true, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan", withConfirm(t, s, "scan", map[string]any{
		"url":   "https://example.com/",
		"level": "quick",
		"options": map[string]any{
			"dast": true,
		},
	})))[0])
	if isErr {
		t.Fatalf("scan 失败: %s", text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("scan 结果不是 JSON: %v", err)
	}
	if got["job_id"] != "job-1" {
		t.Fatalf("job_id = %v", got["job_id"])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scanBody["url"] != "https://example.com/" {
		t.Fatalf("透传 url 错误: %v", f.scanBody)
	}
	if f.scanBody["level"] != "quick" || f.scanBody["dast"] != true {
		t.Fatalf("level/options 未透传: %v", f.scanBody)
	}
}

// TestScanReturnsURLCorrections 验证 scan 工具把后端 URL 自动修正字段回传给智能体
// （input_url / normalized_url / url_corrections），避免 Agent 误以为扫的是原始输入。
func TestScanReturnsURLCorrections(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, true, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan", withConfirm(t, s, "scan", map[string]any{
		"url": "hxxp://example[.]com。",
	})))[0])
	if isErr {
		t.Fatalf("scan 失败: %s", text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("scan 结果不是 JSON: %v", err)
	}
	if got["input_url"] != "hxxp://example[.]com。" {
		t.Fatalf("input_url = %v", got["input_url"])
	}
	if got["normalized_url"] != "https://example.com/" {
		t.Fatalf("normalized_url = %v", got["normalized_url"])
	}
	corr, ok := got["url_corrections"].([]any)
	if !ok || len(corr) == 0 {
		t.Fatalf("url_corrections 缺失或为空: %v", got["url_corrections"])
	}
	if len(corr) != 3 {
		t.Fatalf("url_corrections 条数 = %d, want 3: %v", len(corr), corr)
	}
}

func TestScanResultRunning(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan_result", map[string]any{"job_id": "running"}))[0])
	if isErr {
		t.Fatalf("未完成扫描不应报错: %s", text)
	}
	var got map[string]any
	_ = json.Unmarshal([]byte(text), &got)
	if got["finished"] != false {
		t.Fatalf("finished 应为 false: %v", got)
	}
}

func TestScanResultNormalized(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan_result", map[string]any{
		"job_id": "job-1", "max_findings": 10,
	}))[0])
	if isErr {
		t.Fatalf("scan_result 失败: %s", text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("scan_result 不是 JSON: %v", err)
	}
	if intOf(got["scan_id"]) != 7 {
		t.Fatalf("scan_id = %v", got["scan_id"])
	}
	findings, _ := got["findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	first, _ := findings[0].(map[string]any)
	if first["source"] != "verified" || first["check"] != "sqli-error" {
		t.Fatalf("verified 发现未保留: %v", first)
	}
	if _, ok := first["request"]; !ok {
		t.Fatalf("include_evidence 默认应保留 request")
	}
	second, _ := findings[1].(map[string]any)
	if second["source"] != "intel" {
		t.Fatalf("intel 发现来源标注错误: %v", second)
	}
	techs, _ := got["technologies"].([]any)
	if len(techs) != 2 {
		t.Fatalf("technologies = %d, want 2", len(techs))
	}
}

func TestNotificationIgnored(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	resps := runRPC(t, s,
		rpcNotify("notifications/initialized"),
		rpcReq(1, "ping", map[string]any{}),
	)
	if len(resps) != 1 {
		t.Fatalf("通知不应产生响应，得到 %d 行", len(resps))
	}
	if resps[0]["result"] == nil {
		t.Fatalf("ping 应返回空 result: %+v", resps[0])
	}
}

func TestUnknownMethodAndTool(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	resps := runRPC(t, s,
		rpcReq(1, "no/such/method", map[string]any{}),
		toolCallReq(2, "no-such-tool", map[string]any{}),
	)
	for i, wantCode := range []float64{codeMethodNotFound, codeInvalidParams} {
		errObj, _ := resps[i]["error"].(map[string]any)
		if errObj == nil {
			t.Fatalf("响应 %d 缺少 error: %+v", i, resps[i])
		}
		if code, _ := errObj["code"].(float64); code != wantCode {
			t.Fatalf("响应 %d code = %v, want %v", i, code, wantCode)
		}
	}
}

func TestParseError(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	resps := runRPC(t, s, "{not-json")
	if len(resps) != 1 {
		t.Fatalf("解析错误应有一行响应")
	}
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != codeParseError {
		t.Fatalf("应返回 -32700: %+v", resps[0])
	}
}

func TestExportTruncation(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 4096)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "export", map[string]any{
		"scan_id": 7, "format": "sarif",
	}))[0])
	if isErr {
		t.Fatalf("export 失败: %s", text)
	}
	if !strings.Contains(text, `"truncated":true`) && !strings.Contains(text, `"truncated": true`) {
		t.Fatalf("超限导出应标记 truncated: %.200s", text)
	}
}

func TestTriageWrites(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "triage", map[string]any{
		"scan_id": 7, "fingerprint": "abc123", "verdict": "confirmed", "note": "人工复核",
	}))[0])
	if isErr {
		t.Fatalf("triage 失败: %s", text)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.triage["fingerprint"] != "abc123" || f.triage["verdict"] != "confirmed" {
		t.Fatalf("triage 请求体错误: %v", f.triage)
	}
}

func TestGraphAndHistory(t *testing.T) {
	f := newFakeAPI(t)
	s := newTestServer(t, f.srv.URL, false, 0)
	resps := runRPC(t, s,
		toolCallReq(1, "graph", map[string]any{"scan_id": 7}),
		toolCallReq(2, "history", map[string]any{"limit": 5}),
	)
	for i, resp := range resps {
		if _, isErr := toolResult(t, resp); isErr {
			t.Fatalf("工具 %d 报错", i)
		}
	}
}

func TestValidateLocalAPI(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:5000", "http://localhost:5000", "http://[::1]:5000"} {
		if err := ValidateLocalAPI(ok); err != nil {
			t.Fatalf("%s 应通过: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://10.0.0.1:5000", "https://example.com"} {
		if err := ValidateLocalAPI(bad); err == nil {
			t.Fatalf("%s 应被拒绝", bad)
		}
	}
}
