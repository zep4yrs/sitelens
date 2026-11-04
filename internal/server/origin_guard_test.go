package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// newGuardServer 只构造中间件所需的最小 Server（不加载指纹/知识库/存储）。
func newGuardServer(t *testing.T, listen string) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Web.Listen = listen
	return testServer(cfg)
}

// guardReq 发一次经过 originGuard 的请求，返回状态码与是否到达下游。
func guardReq(s *Server, req *http.Request) (int, bool) {
	reached := false
	h := s.originGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, reached
}

func newReq(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

// TestOriginGuardHostWhitelist Host 白名单（DNS rebinding 主闸）：
// 回环监听时只认回环 Host；非回环监听时不做主机名限制。
func TestOriginGuardHostWhitelist(t *testing.T) {
	s := newGuardServer(t, "127.0.0.1:5000")
	for _, host := range []string{"127.0.0.1:5000", "localhost:5000", "[::1]:5000", "127.0.0.1"} {
		req := newReq(http.MethodGet, "http://"+host+"/api/version")
		req.Host = host
		if code, reached := guardReq(s, req); code != 200 || !reached {
			t.Fatalf("回环 Host %q 应放行，实际 code=%d reached=%v", host, code, reached)
		}
	}
	// DNS rebinding 形态：攻击者域名解析到 127.0.0.1，Host 仍是攻击者域名。
	req := newReq(http.MethodGet, "http://evil.example/api/history")
	req.Host = "evil.example"
	if code, reached := guardReq(s, req); code != http.StatusForbidden || reached {
		t.Fatalf("非回环 Host 应 403，实际 code=%d reached=%v", code, reached)
	}

	// 显式对外监听（0.0.0.0）：主机名无法枚举 → 放行任意 Host，仍由 Origin 规则兜底。
	sPub := newGuardServer(t, "0.0.0.0:5000")
	req = newReq(http.MethodGet, "http://evil.example/api/history")
	req.Host = "evil.example"
	if code, reached := guardReq(sPub, req); code != 200 || !reached {
		t.Fatalf("非回环监听应放行任意 Host，实际 code=%d reached=%v", code, reached)
	}
}

// TestOriginGuardOriginAndFetchSite Origin/Referer 同源 + Sec-Fetch-Site 跨站拒绝。
func TestOriginGuardOriginAndFetchSite(t *testing.T) {
	s := newGuardServer(t, "127.0.0.1:5000")

	// 跨站（现代浏览器显式声明）
	req := newReq(http.MethodGet, "http://127.0.0.1:5000/api/history")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if code, reached := guardReq(s, req); code != http.StatusForbidden || reached {
		t.Fatalf("cross-site 应 403，实际 code=%d reached=%v", code, reached)
	}

	// 同源 Origin 放行；跨源 Origin 拒绝；"null" 拒绝
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("Origin", "http://127.0.0.1:5000")
	req.Header.Set("Content-Type", "application/json")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("同源 Origin 应放行，实际 code=%d reached=%v", code, reached)
	}
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	if code, reached := guardReq(s, req); code != http.StatusForbidden || reached {
		t.Fatalf("跨源 Origin 应 403，实际 code=%d reached=%v", code, reached)
	}
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("Origin", "null")
	req.Header.Set("Content-Type", "application/json")
	if code, _ := guardReq(s, req); code != http.StatusForbidden {
		t.Fatalf("Origin: null 应 403，实际 %d", code)
	}

	// Referer 跨源同样拒绝
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("Referer", "https://evil.example/page")
	req.Header.Set("Content-Type", "application/json")
	if code, _ := guardReq(s, req); code != http.StatusForbidden {
		t.Fatalf("跨源 Referer 应 403，实际 %d", code)
	}
}

// TestOriginGuardPostContentType CSRF 主闸：POST 必须是 JSON（或有白名单/自定义头）。
func TestOriginGuardPostContentType(t *testing.T) {
	s := newGuardServer(t, "127.0.0.1:5000")

	// 简单请求形态（表单/text-plain）→ 拒绝：跨站 form 正是 CSRF 载体
	req := newReq(http.MethodPost, "http://127.0.0.1:5000/api/history/clear")
	req.Header.Set("Content-Type", "text/plain")
	if code, reached := guardReq(s, req); code != http.StatusUnsupportedMediaType || reached {
		t.Fatalf("text/plain POST 应 415，实际 code=%d reached=%v", code, reached)
	}
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/history/clear")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code, reached := guardReq(s, req); code != http.StatusUnsupportedMediaType || reached {
		t.Fatalf("表单 POST 应 415，实际 code=%d reached=%v", code, reached)
	}

	// JSON 放行（SPA 的 api.post 形态）
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/history/clear")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("JSON POST 应放行，实际 code=%d reached=%v", code, reached)
	}
	// 显式自定义头放行（F6 后续会统一加）
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/history/clear")
	req.Header.Set(csrfHeader, csrfHeaderValue)
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("带 CSRF 头应放行，实际 code=%d reached=%v", code, reached)
	}
	// 携带显式凭据头（CLI/测试）豁免内容类型
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("X-Token", "whatever")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("带 X-Token 应豁免类型检查，实际 code=%d reached=%v", code, reached)
	}
	// multipart 白名单：/api/audit 上传
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/audit")
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("/api/audit multipart 应放行，实际 code=%d reached=%v", code, reached)
	}
	// 其他路径的 multipart 不放行
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/batch")
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	if code, _ := guardReq(s, req); code != http.StatusUnsupportedMediaType {
		t.Fatalf("非白名单 multipart 应 415，实际 %d", code)
	}

	// PUT/DELETE 不受内容类型约束（跨站必须预检，本身不可 CSRF；无 body 的
	// DELETE 也不该被误伤）。
	req = newReq(http.MethodDelete, "http://127.0.0.1:5000/api/history/1")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("DELETE 应放行，实际 code=%d reached=%v", code, reached)
	}
}

// TestOriginGuardDangerousStrict 危险端点在严格模式下必须带自定义头。
func TestOriginGuardDangerousStrict(t *testing.T) {
	old := requireCSRFHeaderStrict
	requireCSRFHeaderStrict = true
	defer func() { requireCSRFHeaderStrict = old }()

	s := newGuardServer(t, "127.0.0.1:5000")
	// 仅 JSON（无自定义头）→ 严格模式拒绝
	req := newReq(http.MethodPost, "http://127.0.0.1:5000/api/history/clear")
	req.Header.Set("Content-Type", "application/json")
	if code, reached := guardReq(s, req); code != http.StatusUnsupportedMediaType || reached {
		t.Fatalf("严格模式危险端点无自定义头应 415，实际 code=%d reached=%v", code, reached)
	}
	// 带头放行
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/admin/reload")
	req.Header.Set(csrfHeader, csrfHeaderValue)
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("严格模式带自定义头应放行，实际 code=%d reached=%v", code, reached)
	}
	// 非危险端点不受严格模式影响（JSON 即可）
	req = newReq(http.MethodPost, "http://127.0.0.1:5000/api/scan")
	req.Header.Set("Content-Type", "application/json")
	if code, reached := guardReq(s, req); code != 200 || !reached {
		t.Fatalf("严格模式下普通端点 JSON 应放行，实际 code=%d reached=%v", code, reached)
	}
}

// TestHeadersSecurityHeaders V-15 安全响应头。
func TestHeadersSecurityHeaders(t *testing.T) {
	s := newGuardServer(t, "127.0.0.1:5000")
	rec := httptest.NewRecorder()
	s.headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newReq(http.MethodGet, "http://127.0.0.1:5000/app"))
	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP 应含 frame-ancestors 'none'，实际 %q", csp)
	}
	if pp := rec.Header().Get("Permissions-Policy"); pp == "" {
		t.Error("缺少 Permissions-Policy")
	}
}

// TestOriginGuardEndToEnd 用真实 Handler 链路验证：跨站 POST 被挡、同源 JSON 通过。
// 复用 newServer（完整装配）以免中间件接线遗漏。
func TestOriginGuardEndToEnd(t *testing.T) {
	_, api := newServer(t)

	// 跨站表单形态（text/plain JSON 是经典绕过）→ 415，历史绝不能被清空
	req, err := http.NewRequest(http.MethodPost, api.URL+"/api/history/clear",
		strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// 跨源 Origin 优先判 403；关键是不放行（403/415 均可）。
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("跨站 POST 应被拒，实际 %d", resp.StatusCode)
	}

	// 同源 JSON → 通过中间件（到达 handler；空库返回 200）
	req, _ = http.NewRequest(http.MethodPost, api.URL+"/api/history/clear", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", api.URL)
	resp, err = api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("同源 JSON POST 应放行，实际 %d", resp.StatusCode)
	}

	// Host 伪装（DNS rebinding 形态）→ 403
	req, _ = http.NewRequest(http.MethodGet, api.URL+"/api/history", nil)
	req.Host = "evil.example"
	resp, err = api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("伪装 Host 应 403，实际 %d", resp.StatusCode)
	}
}
