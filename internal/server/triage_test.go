// triage_test.go CP-08 复核/白名单 HTTP 适配层单测（不启动真实监听）。
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// newTriageTestAPI 建「只有历史存储」的 Server + 接好 triage 路由的 mux，
// 并预置一条可复核的扫描记录（scan_id=1）。
func newTriageTestAPI(t *testing.T) (*Server, *store.Store, *http.ServeMux) {
	t.Helper()
	st, err := store.New(t.TempDir(), 100)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	s := &Server{st: store.WrapTiered(st, 0)}
	if _, err := st.Import(store.ScanRecord{ScanSummary: store.ScanSummary{
		ID: 1, URL: "https://a.example.com", Host: "a.example.com",
		Title: "A", ScannedAt: "2026-11-01 07:00:00",
	}}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	mux := http.NewServeMux()
	s.registerTriageRoutes(mux)
	return s, st, mux
}

// triageDo 发一次请求并解 JSON 响应。
func triageDo(t *testing.T, mux *http.ServeMux, method, path, body string) (int, map[string]any) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s 响应非 JSON: %q (%v)", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func summaryOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	s, ok := resp["summary"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺少 summary: %+v", resp)
	}
	return s
}

func num(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("字段 %s 不是数字: %+v", key, m)
	}
	return int(v)
}

// TestTriageHTTPMarkAndList 标记/覆盖 → 列表/汇总；异常路径 400/404。
func TestTriageHTTPMarkAndList(t *testing.T) {
	_, _, mux := newTriageTestAPI(t)

	code, resp := triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"fp-1","verdict":"false_positive","note":"WAF 误报"}`)
	if code != 200 || resp["ok"] != true {
		t.Fatalf("标记失败: code=%d resp=%+v", code, resp)
	}
	if s := summaryOf(t, resp); num(t, s, "false_positive") != 1 || num(t, s, "total") != 1 {
		t.Fatalf("首次标记 summary 不符: %+v", s)
	}

	// 同指纹改判：覆盖而不是新增。
	code, resp = triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"fp-1","verdict":"confirmed","note":""}`)
	if code != 200 {
		t.Fatalf("覆盖标记失败: code=%d resp=%+v", code, resp)
	}
	if s := summaryOf(t, resp); num(t, s, "confirmed") != 1 || num(t, s, "false_positive") != 0 {
		t.Fatalf("覆盖后 summary 不符: %+v", s)
	}

	// 再加一条 ignored。
	code, resp = triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"fp-2","verdict":"ignored"}`)
	if code != 200 {
		t.Fatalf("第二次标记失败: code=%d resp=%+v", code, resp)
	}
	if s := summaryOf(t, resp); num(t, s, "total") != 2 || num(t, s, "ignored") != 1 {
		t.Fatalf("两次标记后 summary 不符: %+v", s)
	}

	// 列表：host 回填 + 条目按指纹升序 + 汇总一致。
	code, resp = triageDo(t, mux, http.MethodGet, "/api/triage/1", "")
	if code != 200 {
		t.Fatalf("列表失败: code=%d", code)
	}
	if resp["host"] != "a.example.com" {
		t.Fatalf("列表 host 不符: %+v", resp)
	}
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("列表条目不符: %+v", resp["entries"])
	}
	first, _ := entries[0].(map[string]any)
	if first["fingerprint"] != "fp-1" || first["verdict"] != "confirmed" {
		t.Fatalf("条目顺序/内容不符: %+v", first)
	}
	if s := summaryOf(t, resp); num(t, s, "total") != 2 ||
		num(t, s, "confirmed") != 1 || num(t, s, "ignored") != 1 {
		t.Fatalf("列表 summary 不符: %+v", s)
	}

	// 404 / 400 路径。
	if code, _ := triageDo(t, mux, http.MethodGet, "/api/triage/999", ""); code != 404 {
		t.Fatalf("不存在的 scan 应 404，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/999",
		`{"fingerprint":"fp","verdict":"confirmed"}`); code != 404 {
		t.Fatalf("对不存在 scan 标记应 404，实得 %d", code)
	}
	if code, resp := triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"fp-3","verdict":"maybe"}`); code != 400 ||
		!strings.Contains(resp["error"].(string), "verdict") {
		t.Fatalf("非法 verdict 应 400 且提示 verdict: code=%d resp=%+v", code, resp)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/1", `{bad json`); code != 400 {
		t.Fatalf("非法 JSON 应 400，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/abc",
		`{"fingerprint":"fp","verdict":"confirmed"}`); code != 400 {
		t.Fatalf("非数字 scanID 应 400，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/0",
		`{"fingerprint":"fp","verdict":"confirmed"}`); code != 400 {
		t.Fatalf("scanID=0 应 400，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"","verdict":"confirmed"}`); code != 400 {
		t.Fatalf("空 fingerprint 应 400，实得 %d", code)
	}
}

// TestWhitelistHTTP 增删查 + 命中检查 + 参数校验。
func TestWhitelistHTTP(t *testing.T) {
	_, _, mux := newTriageTestAPI(t)

	code, resp := triageDo(t, mux, http.MethodPost, "/api/whitelist",
		`{"host":"*.example.com","rule_id":"*","reason":"整站忽略"}`)
	if code != 200 || resp["ok"] != true {
		t.Fatalf("新增通配白名单失败: code=%d resp=%+v", code, resp)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/whitelist",
		`{"host":"exact.example.net","rule_id":"xss-reflect"}`); code != 200 {
		t.Fatalf("新增精确白名单失败: code=%d", code)
	}

	code, resp = triageDo(t, mux, http.MethodGet, "/api/whitelist", "")
	if code != 200 {
		t.Fatalf("白名单列表失败: code=%d", code)
	}
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("白名单条目不符: %+v", resp["entries"])
	}

	check := func(query string, want bool) {
		t.Helper()
		code, resp := triageDo(t, mux, http.MethodGet, "/api/whitelist/check?"+query, "")
		if code != 200 {
			t.Fatalf("check 失败: code=%d resp=%+v", code, resp)
		}
		got, _ := resp["whitelisted"].(bool)
		if got != want {
			t.Fatalf("check %s = %v want %v", query, got, want)
		}
	}
	check("host=exact.example.net&rule=xss-reflect", true) // 精确 host + 规则
	check("host=EXACT.example.net&rule=XSS-REFLECT", true) // 大小写不敏感
	check("host=exact.example.net&rule=other", false)      // 精确条目不覆盖别的规则
	check("host=deep.sub.example.com&rule=anything", true) // 子域通配
	check("host=a.example.com&rule=other", true)           // 通配条目 rule=* 覆盖任意规则
	check("host=example.com&rule=anything", false)         // 通配不含 apex

	if code, _ := triageDo(t, mux, http.MethodGet, "/api/whitelist/check", ""); code != 400 {
		t.Fatalf("缺 host 的 check 应 400，实得 %d", code)
	}

	// 删除：幂等语义。
	code, resp = triageDo(t, mux, http.MethodDelete, "/api/whitelist",
		`{"host":"exact.example.net","rule_id":"xss-reflect"}`)
	if code != 200 || resp["removed"] != true {
		t.Fatalf("删除已有条目失败: code=%d resp=%+v", code, resp)
	}
	code, resp = triageDo(t, mux, http.MethodDelete, "/api/whitelist",
		`{"host":"exact.example.net","rule_id":"xss-reflect"}`)
	if code != 200 || resp["removed"] != false {
		t.Fatalf("重复删除应 removed=false: code=%d resp=%+v", code, resp)
	}
	if code, _ := triageDo(t, mux, http.MethodDelete, "/api/whitelist",
		`{"host":"","rule_id":"x"}`); code != 400 {
		t.Fatalf("删除空 host 应 400，实得 %d", code)
	}

	// 非法 host 拒绝。
	if code, resp := triageDo(t, mux, http.MethodPost, "/api/whitelist",
		`{"host":"*","rule_id":"r"}`); code != 400 {
		t.Fatalf("纯 * host 应 400，实得 %d resp=%+v", code, resp)
	}
}

// TestTriageHTTPNoStore 存储未初始化（无 data_dir）：503，不 panic。
func TestTriageHTTPNoStore(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.registerTriageRoutes(mux)
	if code, _ := triageDo(t, mux, http.MethodGet, "/api/triage/1", ""); code != 503 {
		t.Fatalf("无存储 GET triage 应 503，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/triage/1",
		`{"fingerprint":"fp","verdict":"confirmed"}`); code != 503 {
		t.Fatalf("无存储 POST triage 应 503，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodPost, "/api/whitelist",
		`{"host":"a.com","rule_id":"r"}`); code != 503 {
		t.Fatalf("无存储 POST whitelist 应 503，实得 %d", code)
	}
	if code, _ := triageDo(t, mux, http.MethodGet, "/api/whitelist", ""); code != 503 {
		t.Fatalf("无存储 GET whitelist 应 503，实得 %d", code)
	}
}

// TestTriageHTTPEmptyList 空状态返回 JSON 空数组（而不是 null），前端免判空。
func TestTriageHTTPEmptyList(t *testing.T) {
	_, _, mux := newTriageTestAPI(t)
	code, resp := triageDo(t, mux, http.MethodGet, "/api/whitelist", "")
	if code != 200 {
		t.Fatalf("空白名单列表失败: %d", code)
	}
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 0 {
		t.Fatalf("空白名单应为 []: %#v", resp["entries"])
	}
}

// TestTriageRouteRegistryNil 注册函数对 nil 安全（Lead 误接时不 panic）。
func TestTriageRouteRegistryNil(t *testing.T) {
	s := &Server{}
	s.registerTriageRoutes(nil) // 不应 panic
	var nilServer *Server
	nilServer.registerTriageRoutes(http.NewServeMux()) // 也不应 panic
}
