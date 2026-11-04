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

// TestDetectIDORHorizontal 同资源不同角色均能读取，且**两角色正文一致**。
//
// B-10 定稿语义：两侧归一化正文一致 = B 读到了 A 可见的同一份对象内容
// → confirmed（high）。用例覆盖点：同资源多角色可读、角色对、replay 脱敏、
// 只读 GET、请求计数。possible 档由
// TestDetectIDORSameLengthDifferentContentPossible 覆盖。
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
		t.Fatalf("应产出 2 条水平发现（id=1、id=2），实际 %d: %+v", len(res.Findings), res.Findings)
	}
	for _, fnd := range res.Findings {
		if fnd.Type != "idor-horizontal" || fnd.Severity != "high" || fnd.Verdict != "confirmed" {
			t.Fatalf("发现类型/级别/verdict 异常: %+v", fnd)
		}
		if fnd.Role != "bob" || fnd.VictimRole != "alice" {
			t.Fatalf("攻击者/归属角色异常: %+v", fnd)
		}
		if !strings.Contains(fnd.Evidence, "两角色返回同一对象内容") {
			t.Fatalf("confirmed 证据应说明返回同一对象内容: %q", fnd.Evidence)
		}
		if !strings.Contains(fnd.Evidence, "复核建议") {
			t.Fatalf("confirmed 证据应带资源归属复核建议: %q", fnd.Evidence)
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

// TestDetectIDORSameLengthDifferentContentPossible 长度相同但内容不同 → possible。
//
// B-10 定稿语义：B 可读但归一化正文与 A 不同 → 可能是按角色渲染（各看各的）
// /公共资源/不同对象，无法仅凭响应断言越权，故为 possible（medium）。
// 夹具（同长度、不同内容）原样保留，覆盖点不变（长度相等时不得靠长度
// 判定，必须比内容）；confirmed 档由 TestDetectIDORHorizontal 覆盖。
func TestDetectIDORSameLengthDifferentContentPossible(t *testing.T) {
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
	if len(res.Findings) != 1 {
		t.Fatalf("内容不同应产出 1 条 possible，实际 %d: %+v", len(res.Findings), res.Findings)
	}
	fnd := res.Findings[0]
	if fnd.Type != "idor-horizontal" || fnd.Verdict != "possible" || fnd.Severity != "medium" {
		t.Fatalf("类型/verdict/级别异常: %+v", fnd)
	}
	if !strings.Contains(fnd.Evidence, "两角色内容不同") {
		t.Fatalf("证据应说明两角色内容不同: %q", fnd.Evidence)
	}
	if !strings.Contains(fnd.Evidence, "需人工确认归属") {
		t.Fatalf("possible 证据应要求人工确认归属: %q", fnd.Evidence)
	}
}

// TestDetectIDORRoleIDsRead RoleIDs 精确判定「B 角色读到 A 角色的资源」。
// B-10：本用例两侧正文一致 → confirmed（high）；角色对/数量覆盖不变。
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
		if fnd.Type != "idor-read" || fnd.Severity != "high" || fnd.Verdict != "confirmed" {
			t.Fatalf("类型/级别/verdict 异常: %+v", fnd)
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

	// 脆弱：user 也读到与管理角色**一致**的管理内容 → confirmed（high）。
	// 403 分支（none）仍要求 0 条，见上方不脆弱用例。
	f2 := newIDORTestFetcher(t, mkMux(true))
	m2 := base
	m2.BaseURL = f2.srv.URL
	res2, err := DetectIDOR(m2, f2)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res2.Findings) != 1 {
		t.Fatalf("应产出 1 条垂直发现，实际 %d: %+v", len(res2.Findings), res2.Findings)
	}
	fnd := res2.Findings[0]
	if fnd.Type != "idor-vertical" || fnd.Severity != "high" || fnd.Verdict != "confirmed" ||
		fnd.Role != "user" || fnd.VictimRole != "admin" {
		t.Fatalf("垂直发现字段异常: %+v", fnd)
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

// ---- B-10 三值判定回归测试 -------------------------------------------------

// TestIDORVerdictOfTriState 三值判定纯函数：none / possible / confirmed。
func TestIDORVerdictOfTriState(t *testing.T) {
	ref := idorCell{status: 200, size: 52, bodyHash: "aaaa1111", readable: true}
	same := idorCell{status: 200, size: 52, bodyHash: "aaaa1111", readable: true}
	diff := idorCell{status: 200, size: 28, bodyHash: "bbbb2222", readable: true}
	denied403 := idorCell{status: 403, size: 9}
	denied404 := idorCell{status: 404, size: 9}
	empty := idorCell{status: 200, size: 0}

	cases := []struct {
		name  string
		other idorCell
		want  idorVerdict
	}{
		{"内容一致", same, idorVerdictConfirmed},
		{"内容不同", diff, idorVerdictPossible},
		{"403 拒绝", denied403, idorVerdictNone},
		{"404 拒绝", denied404, idorVerdictNone},
		{"空正文", empty, idorVerdictNone},
	}
	for _, tc := range cases {
		if got := idorVerdictOf(ref, tc.other); got != tc.want {
			t.Fatalf("%s: verdict=%v, 期望 %v", tc.name, got, tc.want)
		}
	}
	// 参照方不可读时一律 none（无法比较）。
	if got := idorVerdictOf(denied403, same); got != idorVerdictNone {
		t.Fatalf("参照方不可读应为 none, 实际 %v", got)
	}
	// 字符串与级别映射。
	if idorVerdictConfirmed.String() != "confirmed" || idorVerdictConfirmed.Severity() != "high" {
		t.Fatal("confirmed 应映射 confirmed/high")
	}
	if idorVerdictPossible.String() != "possible" || idorVerdictPossible.Severity() != "medium" {
		t.Fatal("possible 应映射 possible/medium")
	}
	if idorVerdictNone.String() != "none" {
		t.Fatal("none 应映射 none")
	}
}

// TestIDORStableBodyVolatileOnly 稳定化：差异仅来自 UUID / ISO 时间戳 /
// 命名时间字段 / 毫秒时间戳时，归一化哈希必须一致；真实内容差异仍要能区分。
func TestIDORStableBodyVolatileOnly(t *testing.T) {
	a := `{"id":1,"owner":"alice","request_id":"550e8400-e29b-41d4-a716-446655440000",` +
		`"server_time":"2026-11-03T16:09:09Z","nonce":1730000000123}`
	b := `{"id":1,"owner":"alice","request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8",` +
		`"server_time":"2026-11-03T17:22:41.123Z","nonce":1730000009999}`
	if idorBodyHash(a) != idorBodyHash(b) {
		t.Fatalf("仅易变字段不同应归一化为同一哈希:\n a=%s\n b=%s\n ha=%s hb=%s",
			idorStableBody(a), idorStableBody(b), idorBodyHash(a), idorBodyHash(b))
	}
	// 反例：真实内容差异必须保留（否则 confirmed 永远判不出来）。
	c := strings.Replace(a, `"owner":"alice"`, `"owner":"bob"`, 1)
	if idorBodyHash(a) == idorBodyHash(c) {
		t.Fatal("真实内容差异不得被归一化吃掉")
	}
}

// TestDetectIDORVolatileOnlyConfirmed 端到端对照：两角色响应**只**差在
// 时间戳/UUID/随机数上 → 归一化后一致 → 必须判 confirmed，不能被噪声
// 误判成 possible（同一对象不该因为每次响应带不同 nonce 就降级）。
func TestDetectIDORVolatileOnlyConfirmed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/event/", func(w http.ResponseWriter, r *http.Request) {
		role := roleOf(r)
		if role == "" {
			writeJSONBody(w, 401, `{"error":"unauthorized"}`)
			return
		}
		uuid := "550e8400-e29b-41d4-a716-446655440000"
		ts := "2026-11-03T16:09:09Z"
		nonce := int64(1730000000123)
		if role == "bob" { // 同一资源，只有易变字段不同（长度也不同）
			uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
			ts = "2026-11-03T17:22:41.123Z"
			nonce = 1730000009999
		}
		writeJSONBody(w, 200, fmt.Sprintf(
			`{"id":1,"owner":"alice","email":"alice@example.com","request_id":%q,"server_time":%q,"nonce":%d}`,
			uuid, ts, nonce))
	})
	f := newIDORTestFetcher(t, mux)
	res, err := DetectIDOR(IDORMatrix{
		BaseURL: f.srv.URL, Templates: []string{"/event/{id}"}, IDs: []string{"1"},
		Sessions: []authn.Session{idorSession("alice"), idorSession("bob")},
	}, f)
	if err != nil {
		t.Fatalf("DetectIDOR: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("应产出 1 条 confirmed，实际 %d: %+v", len(res.Findings), res.Findings)
	}
	fnd := res.Findings[0]
	if fnd.Verdict != "confirmed" || fnd.Severity != "high" {
		t.Fatalf("仅易变字段不同（归一化后一致）应判 confirmed/high，实际 verdict=%q severity=%q\n证据: %s",
			fnd.Verdict, fnd.Severity, fnd.Evidence)
	}
	if !strings.Contains(fnd.Evidence, "两角色返回同一对象内容") {
		t.Fatalf("证据应说明归一化后返回同一对象内容: %q", fnd.Evidence)
	}
}
