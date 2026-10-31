package loginbrute

// LB-01 安全护栏回归：锁号/限流停止、连续失败阈值与退避、每账号上限、
// 一次性 CSRF token 重取、成功证据（差异摘要/Set-Cookie/跳转/curl）。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const (
	lbLoginPage = `<html><form action="/login" method="post">
<input name="user"><input type="password" name="pass"></form></html>`
	lbFailPage = `<html><form action="/login"><input type="password" name="pass"></form>
用户名或密码错误</html>`
)

// scriptedPoster 按调用次数编排 POST 响应，并记录每次提交。
type scriptedPoster struct {
	getBody      string
	postFn       func(fields map[string]string, n int) (int, string)
	gets         int
	posts        int
	attemptUsers []string
}

func (s *scriptedPoster) GetSmall(string) (int, string, error) { s.gets++; return 200, s.getBody, nil }

func (s *scriptedPoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (s *scriptedPoster) PostForm(_ string, fields map[string]string) (int, string, error) {
	s.posts++
	n := s.posts
	if n > 1 {
		s.attemptUsers = append(s.attemptUsers, fields["user"])
	}
	if s.postFn != nil {
		st, body := s.postFn(fields, n)
		return st, body, nil
	}
	return 200, lbFailPage, nil
}

// TestLockoutKeywordStopsBrute LB-01 验收：失败响应含锁号关键字 → 立即停止。
// 基线（n=1）正常失败；第 1 次真实尝试返回「账号已被锁定」→ 必须停止且
// 只发出 基线+1 个请求。
func TestLockoutKeywordStopsBrute(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage}
	p.postFn = func(fields map[string]string, n int) (int, string) {
		if n == 1 {
			return 200, lbFailPage
		}
		return 200, `<html>您的账号已被锁定，请 30 分钟后再试</html>`
	}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"a", "b"}, MaxTries: 10}, nil)
	if err == nil || !strings.Contains(err.Error(), "锁号") {
		t.Fatalf("锁定响应应停止并返回明确原因: %v", err)
	}
	if !strings.Contains(err.Error(), "锁定") {
		t.Fatalf("停止原因应包含具体特征: %v", err)
	}
	if p.posts != 2 {
		t.Fatalf("锁号后不得继续尝试：posts=%d，期望 2（基线+1 次尝试）", p.posts)
	}
}

// TestLockout429StopsBrute LB-01 验收：429 限流 → 立即停止。
func TestLockout429StopsBrute(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage}
	p.postFn = func(fields map[string]string, n int) (int, string) {
		if n == 1 {
			return 200, lbFailPage
		}
		return 429, "Too Many Requests"
	}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"a", "b"}, MaxTries: 10}, nil)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("429 应停止并返回限流原因: %v", err)
	}
	if p.posts != 2 {
		t.Fatalf("429 后不得继续尝试：posts=%d，期望 2", p.posts)
	}
}

// TestLockout403StopsBrute LB-01 验收：403（疑似封禁）→ 立即停止。
func TestLockout403StopsBrute(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage}
	p.postFn = func(fields map[string]string, n int) (int, string) {
		if n == 1 {
			return 200, lbFailPage
		}
		return 403, "Forbidden"
	}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"a", "b"}, MaxTries: 10}, nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403 应停止并返回原因: %v", err)
	}
	if p.posts != 2 {
		t.Fatalf("403 后不得继续尝试：posts=%d，期望 2", p.posts)
	}
}

// TestLockoutOnBaselineStops 基线提交即命中锁号特征 → 一次尝试都不发。
func TestLockoutOnBaselineStops(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage, postFn: func(map[string]string, int) (int, string) {
		return 200, `<html>account is locked</html>`
	}}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"a"}, MaxTries: 10}, nil)
	if err == nil || !strings.Contains(err.Error(), "基线") {
		t.Fatalf("基线即锁号应停止并说明: %v", err)
	}
	if p.posts != 1 {
		t.Fatalf("基线锁号后不应有尝试：posts=%d，期望 1", p.posts)
	}
}

// TestPerUserAttemptCap LB-01 验收：同一用户名最多默认 3 次尝试。
// 关闭连续失败阈值以隔离验证（MaxConsecutiveFails<0）。
func TestPerUserAttemptCap(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage} // 全部失败
	users := []string{"alice", "bob"}
	pwds := []string{"p1", "p2", "p3", "p4", "p5"}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: users, Passwords: pwds, MaxTries: 100, MaxConsecutiveFails: -1}, nil)
	if err != nil {
		t.Fatalf("关闭连续失败阈值后不应报错: %v", err)
	}
	if len(p.attemptUsers) != 6 {
		t.Fatalf("2 用户 × 每账号默认 3 次 = 6 次尝试，实际 %d（%v）", len(p.attemptUsers), p.attemptUsers)
	}
	perUser := map[string]int{}
	for _, u := range p.attemptUsers {
		perUser[u]++
	}
	if perUser["alice"] != 3 || perUser["bob"] != 3 {
		t.Fatalf("每账号尝试数应为 3：%v", perUser)
	}
	if p.posts != 7 { // 基线 + 6 尝试
		t.Fatalf("总提交数应为 7，实际 %d", p.posts)
	}
}

// TestConsecutiveFailStop LB-01 验收：连续失败达默认阈值 5 → 停止并说明原因。
func TestConsecutiveFailStop(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage} // 全部失败
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"alice", "bob"}, Passwords: []string{"p1", "p2", "p3"}, MaxTries: 100}, nil)
	if err == nil || !strings.Contains(err.Error(), "连续失败") {
		t.Fatalf("连续失败达阈值应停止: %v", err)
	}
	if p.posts != 6 { // 基线 + 5 次失败尝试
		t.Fatalf("应在第 5 次连续失败后停止：posts=%d，期望 6", p.posts)
	}
}

// TestConsecutiveFailBackoffContinues 配置 FailBackoffMS 后改为指数退避继续，
// 命中仍能拿到（默认停止 vs 可配退避两种行为都可用）。
func TestConsecutiveFailBackoffContinues(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage}
	p.postFn = func(fields map[string]string, n int) (int, string) {
		if fields["user"] == "bob" && fields["pass"] == "p3" {
			return 302, ""
		}
		return 200, lbFailPage
	}
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"alice", "bob"}, Passwords: []string{"p1", "p2", "p3"},
		MaxTries: 100, MaxConsecutiveFails: 2, FailBackoffMS: 1}, nil)
	if err != nil {
		t.Fatalf("退避模式不应因连续失败停止: %v", err)
	}
	if len(hits) != 1 || hits[0].User != "bob" || hits[0].Password != "p3" {
		t.Fatalf("退避后应继续并命中: %+v", hits)
	}
}

// TestMaxTriesRespectedWithTokenRefresh LB-01 约束：CSRF 刷新不绕开
// MaxTries——含隐藏字段的表单每次尝试多一个 GET，但 POST 尝试数仍受硬上限。
func TestMaxTriesRespectedWithTokenRefresh(t *testing.T) {
	p := &scriptedPoster{getBody: `<html><form action="/login" method="post">
<input name="user"><input type="password" name="pass">
<input type="hidden" name="csrf" value="t"></form></html>`}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"a", "b", "c"}, Passwords: []string{"1", "2", "3"},
		MaxTries: 4, MaxConsecutiveFails: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.posts > 4 {
		t.Fatalf("MaxTries=4 应最多 4 次 POST（基线+3），实际 %d", p.posts)
	}
	if p.gets < p.posts {
		t.Fatalf("含隐藏字段的表单应每次尝试前刷新 token：GET=%d POST=%d", p.gets, p.posts)
	}
}

// csrfPoster 一次性 CSRF token：每次 GET 换新 token，POST 只认最新 token。
type csrfPoster struct {
	gets  int
	token string
	posts int
}

func (c *csrfPoster) GetSmall(string) (int, string, error) {
	c.gets++
	c.token = fmt.Sprintf("tok-%d", c.gets)
	return 200, fmt.Sprintf(`<html><form action="/login" method="post">
<input name="user"><input type="password" name="pass">
<input type="hidden" name="csrf" value="%s"></form></html>`, c.token), nil
}

func (c *csrfPoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (c *csrfPoster) PostForm(_ string, fields map[string]string) (int, string, error) {
	c.posts++
	valid := fields["csrf"] == c.token
	if valid {
		c.token = fmt.Sprintf("used-%d", c.posts) // 一次性 token：用过即失效
	}
	if !valid {
		return 200, `<html><form action="/login"><input type="password" name="pass"></form>
CSRF token invalid</html>`, nil
	}
	if fields["user"] == "admin" && fields["pass"] == "letmein" {
		return 302, "", nil
	}
	return 200, lbFailPage, nil
}

// TestCSRFOneTimeTokenHit LB-01 验收：每次 POST 前重取 hidden/CSRF token，
// 一次性 token 靶站不得因「用旧 token」而误判失败。
func TestCSRFOneTimeTokenHit(t *testing.T) {
	p := &csrfPoster{}
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"root", "admin"}, Passwords: []string{"123456", "letmein"},
		MaxTries: 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" || hits[0].Password != "letmein" {
		t.Fatalf("一次性 CSRF token 场景应命中: %+v", hits)
	}
	if p.gets < p.posts {
		t.Fatalf("每次 POST 前都应重取 token：GET=%d POST=%d", p.gets, p.posts)
	}
	if !strings.Contains(hits[0].Curl, "csrf=") || !strings.Contains(hits[0].Curl, "user=admin") {
		t.Fatalf("命中 curl 应含 CSRF 与用户字段: %q", hits[0].Curl)
	}
}

// TestCSRFRefreshDisabledMisses 对照：关闭 token 刷新后旧 token 一律失效，
// 证明上一次命中确实来自「重取 token」而非偶然。
func TestCSRFRefreshDisabledMisses(t *testing.T) {
	p := &csrfPoster{}
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"root", "admin"}, Passwords: []string{"123456", "letmein"},
		MaxTries: 20, DisableTokenRefresh: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("关闭刷新后一次性 token 必然失效，不应命中: %+v", hits)
	}
}

// evidencePoster 实现可选 ResponsePoster：返回 Set-Cookie 与 Location。
type evidencePoster struct{ posts int }

func (e *evidencePoster) GetSmall(string) (int, string, error) { return 200, lbLoginPage, nil }

func (e *evidencePoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (e *evidencePoster) PostForm(u string, f map[string]string) (int, string, error) {
	st, body, h, err := e.PostFormResponse(u, f)
	_ = h
	return st, body, err
}

func (e *evidencePoster) PostFormResponse(_ string, fields map[string]string) (int, string, http.Header, error) {
	e.posts++
	if fields["user"] == "admin" && fields["pass"] == "letmein" {
		h := http.Header{}
		h.Set("Location", "/dashboard")
		h.Add("Set-Cookie", "session=abc123; Path=/; HttpOnly")
		h.Add("Set-Cookie", "csrf=xyz; Path=/")
		return 302, "", h, nil
	}
	return 200, lbFailPage, nil, nil
}

// TestHitEvidenceFields LB-01 验收：命中证据含响应差异摘要 + Set-Cookie +
// 跳转 URL + 可复制 curl（命中判定逻辑不变）。
func TestHitEvidenceFields(t *testing.T) {
	p := &evidencePoster{}
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"letmein"}, MaxTries: 10}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("应命中 1 组: %+v", hits)
	}
	h := hits[0]
	if h.Redirect != "/dashboard" {
		t.Fatalf("跳转证据 = %q，期望 /dashboard", h.Redirect)
	}
	if len(h.SetCookie) != 2 || !strings.Contains(h.SetCookie[0], "session=abc123") {
		t.Fatalf("Set-Cookie 证据缺失: %+v", h.SetCookie)
	}
	if h.Evidence == "" || !strings.Contains(h.Evidence, "302") ||
		!strings.Contains(h.Evidence, "失败基线") {
		t.Fatalf("响应差异摘要异常: %q", h.Evidence)
	}
	if !strings.Contains(h.Curl, "curl -i -sS -X POST") ||
		!strings.Contains(h.Curl, "user=admin") || !strings.Contains(h.Curl, "pass=letmein") {
		t.Fatalf("curl 证据异常: %q", h.Curl)
	}
}

// jsonGuardPoster JSON 假件：基线 401，按需返回 429/成功响应头。
type jsonGuardPoster struct {
	tpl      string
	hit      bool
	lock     bool
	calls    int
	respBody string
}

func (j *jsonGuardPoster) GetSmall(string) (int, string, error) { return 200, "<html>json</html>", nil }

func (j *jsonGuardPoster) PostForm(string, map[string]string) (int, string, error) {
	return 200, "", nil
}

func (j *jsonGuardPoster) PostJSON(_, body string) (int, string, error) {
	st, rb, _, err := j.PostJSONResponse("", body)
	return st, rb, err
}

func (j *jsonGuardPoster) PostJSONResponse(_, body string) (int, string, http.Header, error) {
	j.calls++
	j.respBody = body
	if j.lock && j.calls > 1 {
		return 429, `{"msg":"too many attempts"}`, nil, nil
	}
	if j.hit && strings.Contains(body, "admin") {
		h := http.Header{}
		h.Add("Set-Cookie", "token=ok; Path=/")
		return 200, `{"msg":"login ok","token":"abc"}`, h, nil
	}
	return 401, `{"msg":"bad credentials"}`, nil, nil
}

// TestJSONBruteLockoutStops LB-01 护栏同样覆盖 JSON 模式：429 → 停止。
func TestJSONBruteLockoutStops(t *testing.T) {
	p := &jsonGuardPoster{lock: true}
	_, err := JSONBrute(p, Options{
		PageURL:      "https://x.com/api/login",
		JSONTemplate: `{"u":"{user}","p":"{pass}"}`,
		Users:        []string{"a", "b"}, Passwords: []string{"1", "2"}, MaxTries: 10,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("JSON 429 应停止并说明原因: %v", err)
	}
	if p.calls != 2 { // 基线 + 1 次尝试
		t.Fatalf("JSON 429 后不得继续：calls=%d，期望 2", p.calls)
	}
}

// TestJSONBruteEvidence JSON 命中证据：curl 带 JSON content-type + Set-Cookie。
func TestJSONBruteEvidence(t *testing.T) {
	p := &jsonGuardPoster{hit: true}
	hits, err := JSONBrute(p, Options{
		PageURL:      "https://x.com/api/login",
		JSONEndpoint: "https://x.com/api/login",
		JSONTemplate: `{"username":"{user}","password":"{pass}"}`,
		Users:        []string{"admin"}, Passwords: []string{"letmein"}, MaxTries: 10,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("JSON 应命中: %+v", hits)
	}
	h := hits[0]
	if len(h.SetCookie) != 1 || !strings.Contains(h.SetCookie[0], "token=ok") {
		t.Fatalf("JSON Set-Cookie 证据缺失: %+v", h.SetCookie)
	}
	if !strings.Contains(h.Curl, "Content-Type: application/json") ||
		!strings.Contains(h.Curl, `"username":"admin"`) {
		t.Fatalf("JSON curl 证据异常: %q", h.Curl)
	}
}
