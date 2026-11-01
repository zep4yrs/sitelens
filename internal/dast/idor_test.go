package dast

// G09 越权矩阵测试：同资源不同角色（水平）、403/200 差异、长度相同但内容
// 不同、RoleIDs 精确越权可读、垂直越权（管理路径）、请求预算、只读 GET、
// 非法输入与证据脱敏。

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/authn"
)

// idorTestFetcher 真实 HTTP Fetcher：记录方法/请求数，可注入会话头。
// Post* 一旦被调用即记录（IDOR 检测必须只读 GET）。
type idorTestFetcher struct {
	mu      sync.Mutex
	srv     *httptest.Server
	client  *http.Client
	reqs    int
	methods []string
}

func newIDORTestFetcher(t *testing.T, mux *http.ServeMux) *idorTestFetcher {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &idorTestFetcher{srv: srv, client: srv.Client()}
}

func (f *idorTestFetcher) do(method, rawURL string, headers map[string]string) *Resp {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	f.mu.Lock()
	f.reqs++
	f.methods = append(f.methods, method)
	f.mu.Unlock()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	h := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		h[k] = resp.Header.Get(k)
	}
	return &Resp{Status: resp.StatusCode, Headers: h, Body: string(body)}
}

func (f *idorTestFetcher) GetSmall(rawURL string) *Resp {
	return f.do(http.MethodGet, rawURL, nil)
}
func (f *idorTestFetcher) GetWithHeaders(rawURL string, headers map[string]string) *Resp {
	return f.do(http.MethodGet, rawURL, headers)
}
func (f *idorTestFetcher) PostFormSmall(rawURL string, data map[string]string) *Resp {
	return f.do(http.MethodPost, rawURL, nil)
}
func (f *idorTestFetcher) PostRawSmall(rawURL, contentType, body string) *Resp {
	return f.do(http.MethodPost, rawURL, nil)
}
func (f *idorTestFetcher) PostMultipartSmall(rawURL, fileField, fileName, content string, extra map[string]string) *Resp {
	return f.do(http.MethodPost, rawURL, nil)
}

func (f *idorTestFetcher) methodStats() (get, other int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.methods {
		if m == http.MethodGet {
			get++
		} else {
			other++
		}
	}
	return get, other
}

// idorSession 构造仅 Cookie 会话（凭据值只用于发请求，不得出现在证据里）。
func idorSession(role string) authn.Session {
	return authn.Session{Role: role, Cookies: "session=" + role}
}

// roleOf 从 Cookie 取角色（测试站用）。
func roleOf(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

func writeJSONBody(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

// TestDetectIDORHorizontal 同资源不同角色均能读取（一致关键字段）→ 水平越权。
func TestDetectIDORHorizontal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/profile/", func(w http.ResponseWriter, r *http.Request) {
		if roleOf(r) == "" {
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/profile/")
		owner := map[string]string{"1": "alice", "2": "bob"}[id]
		if owner == "" {
			writeJSONBody(w, 404, `{"error":"not found"}`)
			return
		}
		// 故意忽略会话主体：任何已登录角色都能按 ID 读取同一资源。
		writeJSONBody(w, 200, fmt.Sprintf(`{"id":%s,"owner":%q,"email":%q}`, id, owner, owner+"@example.com"))
	})
	f := newIDORTestFetcher(t, mux)
	matrix := IDORMatrix{
		BaseURL:   f.srv.URL,
		Templates: []string{"/profile/{id}"},
		IDs:       []string{"1", "2"},
		Sessions:  []authn.Session{idorSession("alice"), idorSession("bob")},
	}
	res, err := DetectIDOR(matrix, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("应产出 2 条水平越权（id=1、id=2），实际 %d: %+v", len(res.Findings), res.Findings)
	}
	for _, fnd := range res.Findings {
		if fnd.Type != "idor-horizontal" || fnd.Severity != "high" {
			t.Fatalf("发现类型/级别异常: %+v", fnd)
		}
		if fnd.Role != "bob" || fnd.VictimRole != "alice" {
			t.Fatalf("攻击者/归属角色异常: %+v", fnd)
		}
		if !strings.Contains(fnd.Evidence, "关键字段指纹一致") {
			t.Fatalf("证据应说明指纹一致: %q", fnd.Evidence)
		}
		if !strings.Contains(fnd.Replay, "curl -sk") || !strings.Contains(fnd.Replay, "redacted") {
			t.Fatalf("replay 应为脱敏 curl: %q", fnd.Replay)
		}
		if strings.Contains(fnd.Replay, "session=") {
			t.Fatalf("replay 泄露会话凭据: %q", fnd.Replay)
		}
	}
	if res.Requests != 4 || res.Truncated {
		t.Fatalf("请求数应为 2 ID × 2 角色 = 4，实际 %+v", res)
	}
	if get, other := f.methodStats(); get != 4 || other != 0 {
		t.Fatalf("IDOR 检测必须只读 GET: get=%d other=%d", get, other)
	}
}

// TestDetectIDOR403NoFinding 403/200 差异：拒绝访问不构成越权（宁少报）。
func TestDetectIDOR403NoFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secure/", func(w http.ResponseWriter, r *http.Request) {
		switch roleOf(r) {
		case "alice":
			writeJSONBody(w, 200, `{"id":1,"owner":"alice","email":"alice@example.com"}`)
		case "bob":
			writeJSONBody(w, 403, `{"error":"forbidden"}`)
		default:
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
		}
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/secure/{id}"}, IDs: []string{"1"},
		Sessions: []authn.Session{idorSession("alice"), idorSession("bob")},
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("存在访问控制时不应报越权: %+v", res.Findings)
	}
	if res.Requests != 2 {
		t.Fatalf("请求数应为 2，实际 %d", res.Requests)
	}
}

// TestDetectIDORSameLengthDifferentContent 长度相同但关键内容不同：不得误报。
func TestDetectIDORSameLengthDifferentContent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/doc/", func(w http.ResponseWriter, r *http.Request) {
		role := roleOf(r)
		switch role {
		case "alice":
			writeJSONBody(w, 200, `{"user":"alice","level":"1"}`)
		case "bob":
			writeJSONBody(w, 200, `{"user":"bobby","level":"2"}`)
		default:
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
		}
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/doc/1"}, IDs: []string{"1"},
		Sessions: []authn.Session{idorSession("alice"), idorSession("bob")},
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("同长度不同内容不应判定越权: %+v", res.Findings)
	}
}

// TestDetectIDORRoleIDsRead RoleIDs 精确判定「B 角色读到 A 角色的资源」。
func TestDetectIDORRoleIDsRead(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user/", func(w http.ResponseWriter, r *http.Request) {
		if roleOf(r) == "" {
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/user/")
		owner := map[string]string{"1": "alice", "2": "bob"}[id]
		writeJSONBody(w, 200, fmt.Sprintf(`{"id":%s,"owner":%q,"email":%q}`, id, owner, owner+"@example.com"))
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/user/{id}"},
		Sessions: []authn.Session{idorSession("alice"), idorSession("bob")},
		RoleIDs:  map[string][]string{"alice": {"1"}, "bob": {"2"}},
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("应产出 2 条 idor-read（互相读取对方资源），实际 %d: %+v", len(res.Findings), res.Findings)
	}
	pairs := map[string]bool{}
	for _, fnd := range res.Findings {
		if fnd.Type != "idor-read" || fnd.Severity != "high" {
			t.Fatalf("类型/级别异常: %+v", fnd)
		}
		pairs[fnd.Role+"<-"+fnd.VictimRole] = true
	}
	if !pairs["bob<-alice"] || !pairs["alice<-bob"] {
		t.Fatalf("越权角色对不符: %v", pairs)
	}
}

// TestDetectIDORVertical 垂直越权：低权角色能访问管理路径且内容与管理角色一致。
func TestDetectIDORVertical(t *testing.T) {
	mkMux := func(vulnerable bool) *http.ServeMux {
		mux := http.NewServeMux()
		mux.HandleFunc("/admin/users/", func(w http.ResponseWriter, r *http.Request) {
			switch roleOf(r) {
			case "admin":
				writeJSONBody(w, 200, `{"id":1,"admin":true,"owner":"root","email":"root@example.com"}`)
			case "user":
				if vulnerable {
					writeJSONBody(w, 200, `{"id":1,"admin":true,"owner":"root","email":"root@example.com"}`)
				} else {
					writeJSONBody(w, 403, `{"error":"forbidden"}`)
				}
			default:
				writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			}
		})
		return mux
	}
	base := IDORMatrix{
		BaseURL: "", Templates: nil, IDs: []string{"1"},
		Sessions:   []authn.Session{idorSession("admin"), idorSession("user")},
		AdminRoles: []string{"admin"},
		AdminPaths: []string{"/admin/users/{id}"},
	}

	// 不脆弱：user 403 → 不报。
	f1 := newIDORTestFetcher(t, mkMux(false))
	m1 := base
	m1.BaseURL = f1.srv.URL
	res1, err := DetectIDOR(m1, f1)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res1.Findings) != 0 {
		t.Fatalf("访问控制生效时不应报垂直越权: %+v", res1.Findings)
	}

	// 脆弱：user 也读到相同管理内容 → 垂直越权。
	f2 := newIDORTestFetcher(t, mkMux(true))
	m2 := base
	m2.BaseURL = f2.srv.URL
	res2, err := DetectIDOR(m2, f2)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res2.Findings) != 1 {
		t.Fatalf("应产出 1 条垂直越权，实际 %d: %+v", len(res2.Findings), res2.Findings)
	}
	fnd := res2.Findings[0]
	if fnd.Type != "idor-vertical" || fnd.Severity != "high" || fnd.Role != "user" || fnd.VictimRole != "admin" {
		t.Fatalf("垂直越权字段异常: %+v", fnd)
	}
	if !strings.Contains(fnd.URL, "/admin/users/1") {
		t.Fatalf("URL 异常: %q", fnd.URL)
	}
	if res2.Requests != 2 {
		t.Fatalf("垂直探测请求数应为 2，实际 %d", res2.Requests)
	}
}

// TestDetectIDORBudget 请求上限：超过 MaxRequests 即停止并标记 Truncated。
func TestDetectIDORBudget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/item/", func(w http.ResponseWriter, r *http.Request) {
		if roleOf(r) == "" {
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/item/")
		writeJSONBody(w, 200, fmt.Sprintf(`{"id":%s,"owner":"x","email":"x@example.com"}`, id))
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/item/{id}"},
		IDs:         []string{"1", "2", "3", "4", "5"},
		Sessions:    []authn.Session{idorSession("a"), idorSession("b")},
		MaxRequests: 3,
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if res.Requests > 3 {
		t.Fatalf("请求数超过硬上限: %d", res.Requests)
	}
	if !res.Truncated {
		t.Fatalf("预算耗尽应标记 Truncated: %+v", res)
	}
	if get, other := f.methodStats(); get != res.Requests || other != 0 {
		t.Fatalf("实际请求数与统计不一致（且必须只读 GET）: get=%d other=%d requests=%d", get, other, res.Requests)
	}
}

// TestDetectIDORInvalidInput 输入校验：空/坏 BaseURL、无会话、非 HeaderFetcher、
// 重复角色、未知管理角色均返回错误。
func TestDetectIDORInvalidInput(t *testing.T) {
	f := newIDORTestFetcher(t, http.NewServeMux())
	okSessions := []authn.Session{idorSession("a"), idorSession("b")}
	cases := []struct {
		name string
		m    IDORMatrix
		f    Fetcher
	}{
		{"nil-fetcher", IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"}, Sessions: okSessions}, nil},
		{"bad-base", IDORMatrix{BaseURL: "ftp://x", Templates: []string{"/x/{id}"}, Sessions: okSessions}, f},
		{"empty-base", IDORMatrix{Templates: []string{"/x/{id}"}, Sessions: okSessions}, f},
		{"no-sessions", IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"}}, f},
		{"no-templates", IDORMatrix{BaseURL: f.srv.URL, Sessions: okSessions}, f},
		{"dup-role", IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"},
			Sessions: []authn.Session{idorSession("a"), idorSession("a")}}, f},
		{"unknown-admin", IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"},
			Sessions: okSessions, AdminRoles: []string{"ghost"}}, f},
		{"invalid-session", IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"},
			Sessions: []authn.Session{{Role: "a"}}}, f},
	}
	for _, tc := range cases {
		if _, err := DetectIDOR(tc.m, tc.f); err == nil {
			t.Fatalf("%s 应返回错误", tc.name)
		}
	}

	// 不实现 HeaderFetcher 的 Fetcher：明确报错（不能静默跳过）。
	if _, err := DetectIDOR(IDORMatrix{BaseURL: f.srv.URL, Templates: []string{"/x/{id}"},
		Sessions: okSessions}, getOnlyFetcher{}); err == nil {
		t.Fatal("非 HeaderFetcher 应返回错误")
	}
}

// getOnlyFetcher 只实现必选 Fetcher（不支持会话头注入）。
type getOnlyFetcher struct{}

func (getOnlyFetcher) GetSmall(string) *Resp { return nil }
func (getOnlyFetcher) PostFormSmall(string, map[string]string) *Resp {
	return nil
}
func (getOnlyFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (getOnlyFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// TestIDORStrongFingerprint 关键字段指纹：纯 ID 回显不可比对，身份字段参与比对。
func TestIDORStrongFingerprint(t *testing.T) {
	cases := []struct {
		name string
		body string
		id   string
		want string // "" 表示期望空指纹
	}{
		{"only-id", `{"id":1}`, "1", ""},
		{"id-echo-value", `{"id":1,"user":"1"}`, "1", ""},
		{"identity-fields", `{"id":1,"owner":"alice","email":"alice@example.com"}`, "1", "owner=alice"},
		{"nested-identity", `{"data":{"owner_id":"42","tenant":"acme"}}`, "1", "owner_id=42"},
		{"non-json", `<div data-owner="alice">x</div>`, "1", "owner=alice"},
	}
	for _, tc := range cases {
		got := idorStrongFingerprint(tc.body, tc.id)
		if tc.want == "" {
			if got != "" {
				t.Fatalf("%s 应为空指纹，实际 %q", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Fatalf("%s 指纹缺 %q: %q", tc.name, tc.want, got)
		}
	}
	// 同内容不同仅 id 回显 → 指纹一致（因为它们都不含身份字段）。
	if idorStrongFingerprint(`{"id":1}`, "1") != idorStrongFingerprint(`{"id":2}`, "2") {
		t.Fatal("纯 ID 回显的指纹应一致（都为空）")
	}
}

// TestIDORReplayRedacted replay 不含真实凭据，只含脱敏占位。
func TestIDORReplayRedacted(t *testing.T) {
	replay := idorReplayCurl("https://target.example/u/1", "bob")
	if !strings.HasPrefix(replay, "curl -sk --path-as-is") {
		t.Fatalf("replay 命令格式异常: %q", replay)
	}
	if !strings.Contains(replay, "redacted") {
		t.Fatalf("replay 应含脱敏占位: %q", replay)
	}
	for _, secret := range []string{"session=bob", "Authorization: Bearer", "Cookie: session"} {
		if strings.Contains(replay, secret) {
			t.Fatalf("replay 泄露凭据片段 %q: %s", secret, replay)
		}
	}
}

// TestDetectIDORDefaultIDs IDs 为空时按 1..MaxID 探测。
func TestDetectIDORDefaultIDs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/n/", func(w http.ResponseWriter, r *http.Request) {
		if roleOf(r) == "" {
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/n/")
		writeJSONBody(w, 200, fmt.Sprintf(`{"id":%s,"owner":"x","email":"x@example.com"}`, id))
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/n/{id}"}, MaxID: 2,
		Sessions: []authn.Session{idorSession("a"), idorSession("b")},
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if res.Requests != 4 { // 2 ID × 2 角色
		t.Fatalf("默认 ID 1..MaxID 应产生 4 请求，实际 %d", res.Requests)
	}
}
