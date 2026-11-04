package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestBuildScanHARFromEvidence：HAR 导出的核心契约——
//  1. checks/nuclei 的真实请求报文能还原 method/url/headers/body；
//  2. 只有 replay curl 的发现也能还原（best-effort）；
//  3. 无请求证据的条目被跳过（不能凭空造请求）；
//  4. 响应只能给 status/size/snippet（记录里没有完整响应头，必须如实标注）；
//  5. 敏感头默认脱敏。
func TestBuildScanHARFromEvidence(t *testing.T) {
	rec := &store.ScanRecord{
		Result: &engine.Result{
			URL: "https://t.example/", Host: "t.example",
			ScannedAt: "2026-01-02T03:04:05Z",
			Verified: []map[string]any{
				{
					"check": "sqli", "src": "checks", "severity": "high",
					"url":     "https://t.example/search?x=1",
					"request": "POST /search HTTP/1.1\r\nHost: t.example\r\nContent-Type: application/json\r\nAuthorization: Bearer SECRET\r\nCookie: sid=abc\r\n\r\n{\"q\":\"1'\"}",
					"response": map[string]any{
						"status": 200, "size": 1234, "snippet": "error near '1''",
					},
				},
				{
					"check": "open-redirect", "src": "dast",
					"url":    "https://t.example/r?u=1",
					"replay": "curl -sk --path-as-is -d 'next=https%3A%2F%2Fevil' 'https://t.example/r?u=1'",
				},
				{"check": "no-request-evidence", "url": "https://t.example/x"},
			},
		},
	}
	data, err := buildScanHAR(rec, false)
	if err != nil {
		t.Fatalf("buildScanHAR: %v", err)
	}
	var doc harDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("HAR 不是合法 JSON: %v", err)
	}
	if doc.Log.Version != "1.2" {
		t.Fatalf("HAR version = %q", doc.Log.Version)
	}
	if doc.Log.Creator.Name != "SiteLens" || doc.Log.Creator.Version != Version {
		t.Fatalf("creator = %+v", doc.Log.Creator)
	}
	if len(doc.Log.Entries) != 2 {
		t.Fatalf("应导出 2 条（无请求证据的条目必须跳过），实际 %d", len(doc.Log.Entries))
	}

	e0 := doc.Log.Entries[0]
	if e0.Request.Method != "POST" {
		t.Fatalf("method = %q", e0.Request.Method)
	}
	if e0.Request.URL != "https://t.example/search?x=1" {
		t.Fatalf("url = %q", e0.Request.URL)
	}
	if e0.Request.PostData == nil || !strings.Contains(e0.Request.PostData.Text, `"q"`) {
		t.Fatalf("postData 未还原: %+v", e0.Request.PostData)
	}
	// 敏感头默认脱敏
	assertHeader(t, e0.Request.Headers, "Authorization", "***")
	assertHeader(t, e0.Request.Headers, "Cookie", "***")
	if len(e0.Request.Cookies) != 1 || e0.Request.Cookies[0].Name != "sid" || e0.Request.Cookies[0].Value != "***" {
		t.Fatalf("Cokies 应脱敏: %+v", e0.Request.Cookies)
	}
	// query 拆解
	if len(e0.Request.QueryString) != 1 || e0.Request.QueryString[0].Name != "x" || e0.Request.QueryString[0].Value != "1" {
		t.Fatalf("queryString = %+v", e0.Request.QueryString)
	}
	// 响应：只有 status/size/snippet，且必须标注"响应头未保存"
	if e0.Response.Status != 200 || e0.Response.Content.Size != 1234 {
		t.Fatalf("response = %+v", e0.Response)
	}
	if len(e0.Response.Headers) != 0 {
		t.Fatalf("记录里没有响应头，HAR 不能凭空填充: %+v", e0.Response.Headers)
	}
	if !strings.Contains(e0.Comment, "响应头未保存") {
		t.Fatalf("必须如实标注响应头缺失: %q", e0.Comment)
	}

	e1 := doc.Log.Entries[1]
	if e1.Request.Method != "POST" {
		t.Fatalf("curl(-d) 应还原为 POST，实际 %q", e1.Request.Method)
	}
	if e1.Request.URL != "https://t.example/r?u=1" {
		t.Fatalf("curl URL = %q", e1.Request.URL)
	}
	if e1.Request.PostData == nil || !strings.Contains(e1.Request.PostData.Text, "evil") {
		t.Fatalf("curl -d 未还原为 postData: %+v", e1.Request.PostData)
	}
	if e1.Response.Status != 0 || !strings.Contains(e1.Comment, "未记录响应状态") {
		t.Fatalf("无响应的条目应 status=0 且显式标注: status=%d comment=%q", e1.Response.Status, e1.Comment)
	}
}

// TestBuildScanHARRawKeepsSecrets：?raw=1 保留原值（审计/复现场景）。
func TestBuildScanHARRawKeepsSecrets(t *testing.T) {
	rec := &store.ScanRecord{Result: &engine.Result{
		URL: "https://t.example/", Host: "t.example", ScannedAt: "2026-01-02T03:04:05Z",
		Verified: []map[string]any{{
			"check": "x", "url": "https://t.example/a",
			"request": "GET /a HTTP/1.1\r\nHost: t.example\r\nAuthorization: Bearer SECRET\r\n\r\n",
		}},
	}}
	data, err := buildScanHAR(rec, true)
	if err != nil {
		t.Fatal(err)
	}
	var doc harDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	assertHeader(t, doc.Log.Entries[0].Request.Headers, "Authorization", "Bearer SECRET")
}

// TestBuildScanHARMasksUserinfo：URL 里的 user:pass@ 必须脱敏。
func TestBuildScanHARMasksUserinfo(t *testing.T) {
	rec := &store.ScanRecord{Result: &engine.Result{
		URL: "https://u:p@t.example/", Host: "t.example", ScannedAt: "2026-01-02T03:04:05Z",
		Verified: []map[string]any{{
			"check": "x", "url": "https://u:p@t.example/a",
			"request": "GET /a HTTP/1.1\r\nHost: t.example\r\n\r\n",
		}},
	}}
	data, err := buildScanHAR(rec, false)
	if err != nil {
		t.Fatal(err)
	}
	var doc harDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc.Log.Entries[0].Request.URL, "u:p@") {
		t.Fatalf("URL 基本认证凭据未脱敏: %q", doc.Log.Entries[0].Request.URL)
	}
}

// TestBuildScanHAREmptyResult：无结果/无证据时返回明确错误，不产出空 HAR。
func TestBuildScanHAREmptyResult(t *testing.T) {
	if _, err := buildScanHAR(&store.ScanRecord{}, false); err == nil {
		t.Fatal("result 为 nil 时必须报错")
	}
	if _, err := buildScanHAR(&store.ScanRecord{Result: &engine.Result{URL: "https://t.example/"}}, false); err == nil {
		t.Fatal("没有任何请求证据时必须报错")
	}
}

func assertHeader(t *testing.T, hs []harNameValue, name, want string) {
	t.Helper()
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			if h.Value != want {
				t.Fatalf("%s = %q, want %q", name, h.Value, want)
			}
			return
		}
	}
	t.Fatalf("缺少头 %s（现有 %+v）", name, hs)
}

// TestExportHAREndToEnd：HTTP 层契约——
//   - ?fmt=har 返回 200 + application/json + .har 附件名，且 body 可被解析为 HAR；
//   - result 为 null 的历史记录返回 404 + JSON 错误（不能 panic 炸连接）。
func TestExportHAREndToEnd(t *testing.T) {
	s, api := newServer(t)
	id, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{
			ID: 9001, URL: "https://har.example/", Host: "har.example",
			ScannedAt: "2026-01-02T03:04:05Z",
		},
		Options: map[string]any{},
		Result: &engine.Result{
			URL: "https://har.example/", Host: "har.example", ScannedAt: "2026-01-02T03:04:05Z",
			Verified: []map[string]any{{
				"check": "x", "url": "https://har.example/a",
				"request":  "GET /a HTTP/1.1\r\nHost: har.example\r\nCookie: sid=1\r\n\r\n",
				"response": map[string]any{"status": 200, "size": 10, "snippet": "hello"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	resp, err := http.Get(api.URL + "/api/export/" + strconv.FormatInt(id, 10) + "?fmt=har")
	if err != nil {
		t.Fatalf("GET fmt=har: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("fmt=har 应 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, ".har") {
		t.Fatalf("Content-Disposition 应以 .har 结尾: %q", cd)
	}
	var doc harDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("响应不是合法 HAR: %v", err)
	}
	if doc.Log.Version != "1.2" || len(doc.Log.Entries) != 1 {
		t.Fatalf("HAR 结构异常: version=%q entries=%d", doc.Log.Version, len(doc.Log.Entries))
	}

	// result 为 null：404 + JSON 错误体（与 csv/wide 同口径）
	nilID, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 9002, URL: "http://nil.example", Host: "nil.example"},
		Options:     map[string]any{},
		Result:      nil,
	})
	if err != nil {
		t.Fatalf("Import nil: %v", err)
	}
	resp2, err := http.Get(api.URL + "/api/export/" + strconv.FormatInt(nilID, 10) + "?fmt=har")
	if err != nil {
		t.Fatalf("fmt=har(nil) 请求被重置: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Fatalf("nil result 应 404, got %d", resp2.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&m); err != nil || m["error"] == nil {
		t.Fatalf("错误响应应为带 error 的 JSON: %v %v", m, err)
	}
}
