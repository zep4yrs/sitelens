// CP-02 回归：认证矩阵注入（Header/Bearer/Basic/Cookie）、多会话切换、
// 空凭据/非法配置错误、SLENS_AUTH_* 环境变量、凭据不落日志。
package authn

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClient 实现 Client，并把注入结果真正应用到发往 httptest 的请求
// （模拟接线后 httpx 的「持久头 + Cookie」行为）。
type testClient struct {
	mu      sync.Mutex
	headers map[string]string
	cookie  string
	timeout time.Duration
	hc      *http.Client
}

func newTestClient() *testClient {
	return &testClient{headers: map[string]string{}, hc: &http.Client{Timeout: 5 * time.Second}}
}

func (t *testClient) SetHeader(name, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.headers[name] = value
}

func (t *testClient) SetCookie(cookie string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cookie = cookie
}

func (t *testClient) SetTimeout(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeout = d
}

// Get 发起真实请求，把已注入的请求头/Cookie 带上。
func (t *testClient) Get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if t.cookie != "" {
		req.Header.Set("Cookie", t.cookie)
	}
	t.mu.Unlock()
	return t.hc.Do(req)
}

// state 注入状态快照（零副作用断言用）。
func (t *testClient) state() (map[string]string, string, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := make(map[string]string, len(t.headers))
	for k, v := range t.headers {
		h[k] = v
	}
	return h, t.cookie, t.timeout
}

// newEchoServer 返回记录「最近一次请求头」的 httptest 服务。
func newEchoServer(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	last := http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return last.Clone()
	}
}

// TestApplyInjectsHeaders 四种认证方式真正注入到 httptest 请求头。
func TestApplyInjectsHeaders(t *testing.T) {
	srv, lastHeader := newEchoServer(t)
	basicWant := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	cases := []struct {
		name string
		cfg  Config
		want map[string]string
	}{
		{"header 自定义头", Config{Mode: ModeHeader, Header: "X-API-Key", Value: "key-123"},
			map[string]string{"X-API-Key": "key-123"}},
		{"bearer", Config{Mode: ModeBearer, Token: "tok-abc"},
			map[string]string{"Authorization": "Bearer tok-abc"}},
		{"bearer 容忍前缀", Config{Mode: ModeBearer, Token: "Bearer tok-abc"},
			map[string]string{"Authorization": "Bearer tok-abc"}},
		{"basic", Config{Mode: ModeBasic, Username: "alice", Password: "s3cret"},
			map[string]string{"Authorization": basicWant}},
		{"cookie", Config{Mode: ModeCookie, Cookie: "sid=abc; theme=dark"},
			map[string]string{"Cookie": "sid=abc; theme=dark"}},
		{"none 不注入", Config{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl := newTestClient()
			if err := c.cfg.Apply(cl); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			resp, err := cl.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			hdr := lastHeader()
			for k, want := range c.want {
				if got := hdr.Get(k); got != want {
					t.Errorf("请求头 %s = %q，期望 %q", k, got, want)
				}
			}
			if len(c.want) == 0 {
				if hdr.Get("Authorization") != "" || hdr.Get("Cookie") != "" || hdr.Get("X-API-Key") != "" {
					t.Errorf("mode=none 不应注入任何认证头: %v", hdr)
				}
			}
		})
	}
}

// TestApplyTimeout 注入同时调整客户端超时。
func TestApplyTimeout(t *testing.T) {
	cl := newTestClient()
	cfg := Config{Mode: ModeBearer, Token: "t", Timeout: 3 * time.Second}
	if err := cfg.Apply(cl); err != nil {
		t.Fatal(err)
	}
	if _, _, timeout := cl.state(); timeout != 3*time.Second {
		t.Fatalf("超时应注入 3s，实际 %v", timeout)
	}
}

// TestApplyInvalidNoSideEffects 校验失败时 client 零副作用（先校验后注入）。
func TestApplyInvalidNoSideEffects(t *testing.T) {
	cl := newTestClient()
	cfg := Config{Mode: ModeBearer, Token: "   ", Timeout: 3 * time.Second}
	if err := cfg.Apply(cl); err == nil || !strings.Contains(err.Error(), "令牌") {
		t.Fatalf("空令牌应明确报错: %v", err)
	}
	h, cookie, timeout := cl.state()
	if len(h) != 0 || cookie != "" || timeout != 0 {
		t.Fatalf("校验失败不得修改 client: headers=%v cookie=%q timeout=%v", h, cookie, timeout)
	}
}

// TestConfigValidate 合法/非法配置矩阵；错误只说明缺什么，不回显凭据。
func TestConfigValidate(t *testing.T) {
	ok := []Config{
		{},
		{Mode: ModeNone},
		{Mode: ModeNone, Timeout: time.Second},
		{Mode: ModeHeader, Header: "Authorization", Value: "Bearer x"},
		{Mode: ModeBearer, Token: "t"},
		{Mode: ModeBasic, Username: "u", Password: "p"},
		{Mode: ModeCookie, Cookie: "a=b; c=d"},
	}
	for i, cfg := range ok {
		if err := cfg.Validate(); err != nil {
			t.Errorf("#%d 合法配置被拒: %v", i, err)
		}
	}
	bad := []struct {
		name    string
		cfg     Config
		wantSub string
	}{
		{"header 缺头名", Config{Mode: ModeHeader, Value: "v"}, "头名"},
		{"header 空值", Config{Mode: ModeHeader, Header: "X-Key"}, "头值"},
		{"header 值含 CRLF", Config{Mode: ModeHeader, Header: "X-Key", Value: "a\r\nX-Evil: 1"}, "CR/LF"},
		{"header 非法头名", Config{Mode: ModeHeader, Header: "X Key", Value: "v"}, "非法字符"},
		{"bearer 空令牌", Config{Mode: ModeBearer}, "令牌"},
		{"bearer 令牌含 CRLF", Config{Mode: ModeBearer, Token: "a\nb"}, "CR/LF"},
		{"basic 缺口令", Config{Mode: ModeBasic, Username: "u"}, "口令"},
		{"basic 缺用户名", Config{Mode: ModeBasic, Password: "p"}, "用户名"},
		{"cookie 空", Config{Mode: ModeCookie}, "Cookie"},
		{"cookie 形态非法", Config{Mode: ModeCookie, Cookie: "novalue"}, "k=v"},
		{"cookie 含 CRLF", Config{Mode: ModeCookie, Cookie: "a=b\r\nX: 1"}, "CR/LF"},
		{"未知认证方式", Config{Mode: Mode("oauth2")}, "未知认证方式"},
		{"负超时", Config{Mode: ModeNone, Timeout: -time.Second}, "timeout"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatalf("非法配置应报错: %+v", c.cfg)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("错误信息应含 %q，实际: %v", c.wantSub, err)
			}
		})
	}
}

// TestErrorsDoNotLeakCredentials 校验错误不得回显凭据值。
func TestErrorsDoNotLeakCredentials(t *testing.T) {
	const secret = "SUPER-SECRET-VALUE-42"
	cfgs := []Config{
		{Mode: ModeBearer, Token: "  ", Cookie: secret},
		{Mode: ModeBasic, Username: secret, Password: ""},
		{Mode: ModeCookie, Cookie: "novalue-" + secret},
		{Mode: ModeHeader, Header: "X-Key", Value: "a\r\n" + secret},
	}
	for _, cfg := range cfgs {
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("非法配置应报错: %+v", cfg)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("错误信息泄露凭据: %v", err)
		}
		cl := newTestClient()
		if err2 := cfg.Apply(cl); err2 == nil || strings.Contains(err2.Error(), secret) {
			t.Fatalf("Apply 错误异常或泄露凭据: %v", err2)
		}
	}
}

// TestHeaders 按请求注入的头部视图。
func TestHeaders(t *testing.T) {
	if h, err := (Config{}).Headers(); err != nil || h != nil {
		t.Fatalf("none 应返回 nil: %v %v", h, err)
	}
	h, err := Config{Mode: ModeBearer, Token: "tok"}.Headers()
	if err != nil || h["Authorization"] != "Bearer tok" {
		t.Fatalf("bearer 头视图异常: %v %v", h, err)
	}
	h, err = Config{Mode: ModeCookie, Cookie: "sid=x"}.Headers()
	if err != nil || h["Cookie"] != "sid=x" {
		t.Fatalf("cookie 头视图异常: %v %v", h, err)
	}
	if _, err := (Config{Mode: ModeHeader, Header: "X-Key"}).Headers(); err == nil {
		t.Fatal("非法配置的 Headers 应报错")
	}
}

// TestNilClient 注入目标为空时明确报错。
func TestNilClient(t *testing.T) {
	if err := (Config{Mode: ModeBearer, Token: "t"}).Apply(nil); err == nil ||
		!strings.Contains(err.Error(), "客户端为空") {
		t.Fatalf("nil client 应明确报错: %v", err)
	}
	if _, err := ApplyAll(nil, []Session{{Role: "a", Headers: map[string]string{"X": "y"}}}); err == nil {
		t.Fatal("ApplyAll(nil) 应明确报错")
	}
}

// TestConfigFromEnv SLENS_AUTH_* 环境变量读取、显式配置优先、非法/不完整报错。
func TestConfigFromEnv(t *testing.T) {
	keys := []string{"MODE", "HEADER", "VALUE", "TOKEN", "USERNAME", "PASSWORD", "COOKIE", "TIMEOUT"}
	clearEnv := func() {
		for _, k := range keys {
			t.Setenv(EnvPrefix+k, "")
		}
	}
	clearEnv()
	// 未设置 → 零值（不注入），不是错误
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("未设置环境变量不应报错: %v", err)
	}
	if cfg.Mode != "" || cfg.Token != "" {
		t.Fatalf("未设置环境变量应为零值: %+v", cfg)
	}

	// bearer + timeout
	t.Setenv(EnvPrefix+"MODE", "bearer")
	t.Setenv(EnvPrefix+"TOKEN", "env-token-1")
	t.Setenv(EnvPrefix+"TIMEOUT", "1500ms")
	cfg, err = ConfigFromEnv()
	if err != nil {
		t.Fatalf("环境变量配置应合法: %v", err)
	}
	if cfg.Mode != ModeBearer || cfg.Token != "env-token-1" || cfg.Timeout != 1500*time.Millisecond {
		t.Fatalf("环境变量未正确读取: %+v", cfg)
	}
	// 注入后 httptest 请求头可见
	srv, lastHeader := newEchoServer(t)
	cl := newTestClient()
	if err := cfg.Apply(cl); err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := lastHeader().Get("Authorization"); got != "Bearer env-token-1" {
		t.Fatalf("环境变量令牌未注入请求头: %q", got)
	}

	// 显式配置优先：非空字段不被环境变量覆盖
	t.Setenv(EnvPrefix+"TOKEN", "env-token-2")
	explicit := Config{Mode: ModeBearer, Token: "explicit-token"}
	if err := explicit.FillFromEnv(); err != nil {
		t.Fatal(err)
	}
	if explicit.Token != "explicit-token" {
		t.Fatalf("显式配置应优先于环境变量，实际 %q", explicit.Token)
	}

	// 非法 mode
	clearEnv()
	t.Setenv(EnvPrefix+"MODE", "oauth2")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "未知认证方式") {
		t.Fatalf("未知 mode 应明确报错: %v", err)
	}
	// 非法 timeout
	t.Setenv(EnvPrefix+"MODE", "bearer")
	t.Setenv(EnvPrefix+"TOKEN", "t")
	t.Setenv(EnvPrefix+"TIMEOUT", "abc")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "TIMEOUT") {
		t.Fatalf("非法 timeout 应明确报错: %v", err)
	}
	// 不完整（bearer 无令牌）→ 明确错误，不静默降级为无认证
	clearEnv()
	t.Setenv(EnvPrefix+"MODE", "bearer")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "令牌") {
		t.Fatalf("不完整配置应明确报错: %v", err)
	}
}

// TestSessionApplyAndHeaderMap 单会话注入（头 + Cookie）与按请求头视图。
func TestSessionApplyAndHeaderMap(t *testing.T) {
	srv, lastHeader := newEchoServer(t)
	s := Session{
		Role:    "admin",
		Headers: map[string]string{"Authorization": "Bearer admin-token", "X-API-Key": "admin-key"},
		Cookies: "sid=admin-session",
	}
	cl := newTestClient()
	if err := s.Apply(cl); err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	hdr := lastHeader()
	if hdr.Get("Authorization") != "Bearer admin-token" ||
		hdr.Get("X-API-Key") != "admin-key" ||
		hdr.Get("Cookie") != "sid=admin-session" {
		t.Fatalf("会话注入异常: %v", hdr)
	}
	hm, err := s.HeaderMap()
	if err != nil {
		t.Fatal(err)
	}
	if hm["Cookie"] != "sid=admin-session" || hm["Authorization"] != "Bearer admin-token" {
		t.Fatalf("HeaderMap 异常: %v", hm)
	}
}

// TestSessionValidate 会话校验：空 Role / 空凭据 / 头非法 / Cookie 歧义。
func TestSessionValidate(t *testing.T) {
	bad := []struct {
		name string
		s    Session
		sub  string
	}{
		{"缺 Role", Session{Headers: map[string]string{"X": "y"}}, "Role"},
		{"空凭据", Session{Role: "a"}, "空凭据"},
		{"头值为空", Session{Role: "a", Headers: map[string]string{"X": " "}}, "值为空"},
		{"头名非法", Session{Role: "a", Headers: map[string]string{"X Y": "v"}}, "非法字符"},
		{"头值含 CRLF", Session{Role: "a", Headers: map[string]string{"X": "v\r\nY: 1"}}, "CR/LF"},
		{"Cookie 歧义", Session{Role: "a", Headers: map[string]string{"Cookie": "a=b"}, Cookies: "c=d"}, "不明确"},
		{"Cookie 形态非法", Session{Role: "a", Cookies: "bad"}, "k=v"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			err := c.s.Validate()
			if err == nil || !strings.Contains(err.Error(), c.sub) {
				t.Fatalf("会话校验应报 %q: %v", c.sub, err)
			}
		})
	}
}

// TestApplyAllMultiSession 多会话：首个生效、Use 切换、Roles/Session 副本、
// 未知角色/重复角色/空会话/非法会话错误且零副作用。
func TestApplyAllMultiSession(t *testing.T) {
	srv, lastHeader := newEchoServer(t)
	admin := Session{Role: "admin", Headers: map[string]string{"Authorization": "Bearer admin-token"}}
	user := Session{Role: "user", Headers: map[string]string{"Authorization": "Bearer user-token"}}
	cl := newTestClient()
	set, err := ApplyAll(cl, []Session{admin, user})
	if err != nil {
		t.Fatal(err)
	}
	getAuth := func() string {
		resp, gerr := cl.Get(srv.URL)
		if gerr != nil {
			t.Fatal(gerr)
		}
		resp.Body.Close()
		return lastHeader().Get("Authorization")
	}
	if got := getAuth(); got != "Bearer admin-token" {
		t.Fatalf("首个会话应立即生效，实际 %q", got)
	}
	if set.Len() != 2 || set.Current() != "admin" {
		t.Fatalf("会话集状态异常: len=%d current=%q", set.Len(), set.Current())
	}
	if got := set.Roles(); !reflect.DeepEqual(got, []string{"admin", "user"}) {
		t.Fatalf("Roles 异常: %v", got)
	}
	if err := set.Use("user"); err != nil {
		t.Fatal(err)
	}
	if got := getAuth(); got != "Bearer user-token" {
		t.Fatalf("切换角色后应使用 user 会话，实际 %q", got)
	}
	if set.Current() != "user" {
		t.Fatalf("Current 应为 user: %q", set.Current())
	}
	// Session(role) 返回深拷贝：改动副本不影响集合
	sess, ok := set.Session("admin")
	if !ok || sess.Role != "admin" {
		t.Fatalf("Session(admin) 异常: %+v %v", sess, ok)
	}
	sess.Headers["Authorization"] = "mutated"
	again, _ := set.Session("admin")
	if again.Headers["Authorization"] != "Bearer admin-token" {
		t.Fatalf("Session 应返回副本，实际 %q", again.Headers["Authorization"])
	}
	// 未知角色
	if err := set.Use("nobody"); err == nil || !strings.Contains(err.Error(), "未知角色") {
		t.Fatalf("未知角色应报错: %v", err)
	}
	// 错误路径
	if _, err := ApplyAll(cl, nil); err == nil || !strings.Contains(err.Error(), "至少需要一个会话") {
		t.Fatalf("空会话列表应报错: %v", err)
	}
	if _, err := ApplyAll(cl, []Session{admin, {Role: "admin", Headers: map[string]string{"X": "y"}}}); err == nil ||
		!strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复角色应报错: %v", err)
	}
	// 非法会话：校验失败零副作用（不得先注入第一个再报错）
	cl2 := newTestClient()
	if _, err := ApplyAll(cl2, []Session{
		{Role: "ok", Headers: map[string]string{"X": "y"}},
		{Role: "", Headers: map[string]string{"Z": "w"}},
	}); err == nil {
		t.Fatal("含非法会话应报错")
	}
	if h, cookie, timeout := cl2.state(); len(h) != 0 || cookie != "" || timeout != 0 {
		t.Fatalf("校验失败不得修改 client: headers=%v cookie=%q timeout=%v", h, cookie, timeout)
	}
}

// TestNoCredentialsInLogs 凭据不落日志/不落格式化输出（String 脱敏）。
func TestNoCredentialsInLogs(t *testing.T) {
	const (
		token  = "TOKEN-SECRET-9000"
		pass   = "PASS-SECRET-9000"
		cookie = "sid=COOKIE-SECRET-9000"
	)
	var logBuf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(old)

	cfg := Config{Mode: ModeBasic, Username: "alice", Password: pass, Timeout: time.Second}
	cl := newTestClient()
	if err := cfg.Apply(cl); err != nil {
		t.Fatal(err)
	}
	sessions := []Session{
		{Role: "admin", Headers: map[string]string{"Authorization": "Bearer " + token}},
		{Role: "user", Cookies: cookie},
	}
	set, err := ApplyAll(cl, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Use("user"); err != nil {
		t.Fatal(err)
	}

	outputs := []string{
		fmt.Sprintf("%v", cfg), fmt.Sprintf("%s", cfg), fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%v", sessions[0]), fmt.Sprintf("%+v", sessions[0]),
		fmt.Sprintf("%v", set), fmt.Sprintf("%+v", set),
		logBuf.String(),
	}
	for _, out := range outputs {
		for _, secret := range []string{token, pass, "COOKIE-SECRET-9000"} {
			if strings.Contains(out, secret) {
				t.Fatalf("凭据出现在输出/日志中（%q）: %q", secret, out)
			}
		}
	}
	// 脱敏表示仍保留可诊断信息（mode/角色）
	if !strings.Contains(fmt.Sprintf("%v", cfg), "basic") {
		t.Fatalf("脱敏表示应保留认证方式: %v", cfg)
	}
	if !strings.Contains(fmt.Sprintf("%v", set), "admin") {
		t.Fatalf("脱敏表示应保留角色列表: %v", set)
	}
	// 错误信息同样不含凭据
	badCfg := Config{Mode: ModeBearer, Token: "   ", Cookie: cookie}
	if err := badCfg.Validate(); err == nil || strings.Contains(err.Error(), "COOKIE-SECRET-9000") {
		t.Fatalf("错误信息泄露凭据或未报错: %v", err)
	}
	// 未注入路径也不得产生日志（凭据不落日志的红线）
	if logBuf.Len() != 0 {
		t.Fatalf("认证注入不应写日志，实际: %q", logBuf.String())
	}
}
