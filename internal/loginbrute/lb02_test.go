// LB-02 回归：失败原因分类、多步登录、授权白名单、批量目标。
package loginbrute

import (
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

// ---- 失败原因分类 ----

// TestClassifyFailure 分类枚举：状态码兜底 + 关键词优先级。
func TestClassifyFailure(t *testing.T) {
	// 枚举值是与前端/文档约定的字符串，改名视为破坏性变更
	enum := map[string]string{
		FailureLocked:          "locked",
		FailureRateLimited:     "rate_limited",
		FailureCaptchaRequired: "captcha_required",
		FailureInvalidUser:     "invalid_user",
		FailureInvalidPassword: "invalid_password",
		FailureMFARequired:     "mfa_required",
		FailureUnknown:         "unknown",
	}
	for got, want := range enum {
		if got != want {
			t.Fatalf("枚举值漂移: %q != %q", got, want)
		}
	}

	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"429 限流", 429, "", FailureRateLimited},
		{"限流关键词", 200, "Too Many Requests, slow down", FailureRateLimited},
		{"锁定关键词", 200, "您的账号已被锁定，请 30 分钟后再试", FailureLocked},
		{"403 视为锁号", 403, "Forbidden", FailureLocked},
		{"锁定优先于限流", 429, "account is locked", FailureLocked},
		{"图形验证码", 200, "请输入图形验证码", FailureCaptchaRequired},
		{"英文 captcha", 200, "Please complete the captcha", FailureCaptchaRequired},
		{"短信验证码归 MFA", 200, "短信验证码已发送", FailureMFARequired},
		{"2FA", 200, "Enter your 2FA code", FailureMFARequired},
		{"用户名不存在", 200, "用户名不存在", FailureInvalidUser},
		{"user not found", 200, "user not found", FailureInvalidUser},
		{"密码错误", 200, "密码错误", FailureInvalidPassword},
		{"401 兜底口令错误", 401, "", FailureInvalidPassword},
		{"未知", 200, "something odd", FailureUnknown},
		{"网络错误", 0, "", FailureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyFailure(c.status, c.body); got != c.want {
				t.Fatalf("ClassifyFailure(%d, %q) = %q，期望 %q", c.status, c.body, got, c.want)
			}
		})
	}
}

// TestBruteFailureClassificationObservable 分类在进度文案与 OnFailure 回调里
// 可观测；既有 "user / ***" 进度前缀与命中判定不变。
func TestBruteFailureClassificationObservable(t *testing.T) {
	p := &scriptedPoster{getBody: lbLoginPage, postFn: func(map[string]string, int) (int, string) {
		return 200, `<html><form action="/login"><input type="password" name="pass"></form>密码错误</html>`
	}}
	var events []FailureEvent
	var msgs []string
	_, err := Brute(p, Options{
		PageURL: "https://x.com/login", Users: []string{"alice"},
		Passwords: []string{"p1", "p2"}, MaxTries: 10, MaxConsecutiveFails: -1,
		OnFailure: func(ev FailureEvent) { events = append(events, ev) },
	}, func(_ int, _ int, msg string) { msgs = append(msgs, msg) })
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("两次失败尝试应各回调一次，实际 %d: %+v", len(events), events)
	}
	for _, ev := range events {
		if ev.Category != FailureInvalidPassword || ev.Status != 200 || ev.User != "alice" {
			t.Fatalf("失败事件异常（不含口令）: %+v", ev)
		}
	}
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "alice / **") && strings.Contains(m, "[失败: invalid_password]") {
			found = true
		}
	}
	if !found {
		t.Fatalf("进度文案应带失败分类且保留原前缀: %v", msgs)
	}
}

// ---- 授权白名单 ----

// countingPoster 统计请求次数的假件（白名单零请求断言用）。
type countingPoster struct {
	gets, posts, jsonPosts int
	page                   string
}

func (c *countingPoster) GetSmall(string) (int, string, error) {
	c.gets++
	return 200, c.page, nil
}

func (c *countingPoster) PostJSON(string, string) (int, string, error) {
	c.jsonPosts++
	return 200, "", nil
}

func (c *countingPoster) PostForm(string, map[string]string) (int, string, error) {
	c.posts++
	return 200, lbFailPage, nil
}

const lb02LoginPage = `<html><form action="/login" method="post">
<input name="user"><input type="password" name="pass"></form></html>`

// TestAllowHostsRejectsZeroRequests 白名单外目标：三种入口都直接报错且零请求。
func TestAllowHostsRejectsZeroRequests(t *testing.T) {
	opts := Options{
		PageURL: "https://evil.example/login", Users: []string{"a"}, Passwords: []string{"b"},
		MaxTries: 10, AllowHosts: []string{"allowed.example"},
	}
	// 表单模式
	p1 := &countingPoster{page: lb02LoginPage}
	if _, err := Brute(p1, opts, nil); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("表单模式应白名单拒绝: %v", err)
	}
	if p1.gets != 0 || p1.posts != 0 {
		t.Fatalf("白名单拒绝必须零请求: gets=%d posts=%d", p1.gets, p1.posts)
	}
	// JSON 模式
	p2 := &countingPoster{}
	jo := opts
	jo.JSONTemplate = `{"u":"{user}","p":"{pass}"}`
	if _, err := JSONBrute(p2, jo, nil); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("JSON 模式应白名单拒绝: %v", err)
	}
	if p2.gets != 0 || p2.posts != 0 || p2.jsonPosts != 0 {
		t.Fatalf("JSON 白名单拒绝必须零请求: %+v", p2)
	}
	// 多步模式
	p3 := &countingPoster{page: lb02LoginPage}
	if _, err := BruteMultiStep(p3, opts, nil, nil); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("多步模式应白名单拒绝: %v", err)
	}
	if p3.gets != 0 || p3.posts != 0 {
		t.Fatalf("多步白名单拒绝必须零请求: gets=%d posts=%d", p3.gets, p3.posts)
	}
}

// TestAllowHostsMatching 白名单匹配：忽略端口/大小写，支持 "*.域名" 子域匹配。
func TestAllowHostsMatching(t *testing.T) {
	cases := []struct {
		allow []string
		host  string
		want  bool
	}{
		{[]string{"example.com"}, "example.com", true},
		{[]string{"Example.COM:8443"}, "example.com", true},
		{[]string{"*.example.com"}, "a.example.com", true},
		{[]string{"*.example.com"}, "a.b.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"other.com"}, "example.com", false},
		{[]string{"example.com"}, "a.example.com", false},
	}
	for _, c := range cases {
		if got := hostAllowed(allowHostList(c.allow), c.host); got != c.want {
			t.Fatalf("hostAllowed(%v, %q) = %v，期望 %v", c.allow, c.host, got, c.want)
		}
	}
	// 正向对照：命中白名单的目标正常执行（不能把功能修死）
	f := &fakePoster{hitUser: "admin", hitPass: "letmein"}
	hits, err := Brute(f, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"letmein"}, MaxTries: 10,
		AllowHosts: []string{"x.com"}}, nil)
	if err != nil {
		t.Fatalf("白名单内目标应正常执行: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("白名单内目标应命中: %+v", hits)
	}
}

// ---- 多步登录 ----

// multiStepPoster 两步登录假件：第一步只收用户名（admin 才出现密码框），
// 第二步校验一次性 csrf（tok2）。第一步带口令会被记为失败页（防回归）。
type multiStepPoster struct {
	gets, posts   int
	step2CSRFSeen string
	step2UserSeen string
	step2PassSeen string
}

func (m *multiStepPoster) GetSmall(string) (int, string, error) {
	m.gets++
	return 200, `<html><form action="/login" method="post"><input name="user"></form></html>`, nil
}

func (m *multiStepPoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (m *multiStepPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	m.posts++
	switch rawURL {
	case "https://x.com/login":
		if fields["pass"] != "" {
			return 200, lbFailPage, nil // 第一步不应携带口令
		}
		if fields["user"] == "admin" {
			return 200, `<html><form action="/login/step2" method="post">
<input name="user"><input type="password" name="pass">
<input type="hidden" name="csrf" value="tok2"></form></html>`, nil
		}
		return 200, `<html><div>用户名不存在</div></html>`, nil
	case "https://x.com/login/step2":
		m.step2CSRFSeen = fields["csrf"]
		m.step2UserSeen = fields["user"]
		m.step2PassSeen = fields["pass"]
		if fields["user"] == "admin" && fields["pass"] == "letmein" && fields["csrf"] == "tok2" {
			return 302, "", nil
		}
		return 200, `<html><form action="/login/step2"><input type="password" name="pass"></form>密码错误</html>`, nil
	}
	return 200, lbFailPage, nil
}

// TestBruteMultiStepHitDynamic Options.MultiStep 自动推导：第一步响应出现
// 密码框 → 第二步；第二步 hidden/CSRF 取自第一步响应。
func TestBruteMultiStepHitDynamic(t *testing.T) {
	p := &multiStepPoster{}
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"letmein"}, MaxTries: 10,
		MultiStep: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" || hits[0].Password != "letmein" {
		t.Fatalf("两步登录应命中: %+v", hits)
	}
	if p.step2CSRFSeen != "tok2" || p.step2UserSeen != "admin" || p.step2PassSeen != "letmein" {
		t.Fatalf("第二步字段异常: csrf=%q user=%q pass=%q",
			p.step2CSRFSeen, p.step2UserSeen, p.step2PassSeen)
	}
	// 基线（probe 用户名在第一步即失败，无第二步）+ 命中尝试（两步）= 3 次 POST
	if p.posts != 3 {
		t.Fatalf("两步流程 POST 次数应为 3，实际 %d", p.posts)
	}
	if hits[0].Type != "login-form" {
		t.Fatalf("多步命中类型应为 login-form: %+v", hits[0])
	}
	if strings.Count(hits[0].Curl, "curl -i -sS -X POST") != 2 {
		t.Fatalf("命中证据应含两步 curl: %q", hits[0].Curl)
	}
	if !strings.Contains(hits[0].Curl, "csrf=tok2") || !strings.Contains(hits[0].Curl, "pass=letmein") {
		t.Fatalf("第二步 curl 缺字段: %q", hits[0].Curl)
	}
}

// TestBruteMultiStepExplicitSteps 显式两步（每步字段由调用方给出）。
func TestBruteMultiStepExplicitSteps(t *testing.T) {
	p := &multiStepPoster{}
	steps := []Step{
		{Action: "/login", UserField: "user"},
		{Action: "/login/step2", UserField: "user", PassField: "pass"},
	}
	hits, err := BruteMultiStep(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"letmein"}, MaxTries: 10}, steps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" {
		t.Fatalf("显式两步应命中: %+v", hits)
	}
	// 显式第二步未写 csrf：必须从第一步响应补齐（一次性 token 可靠性）
	if p.step2CSRFSeen != "tok2" {
		t.Fatalf("第二步应从第一步响应补齐 hidden 字段，实际 csrf=%q", p.step2CSRFSeen)
	}
	// 基线两步 + 命中两步 = 4 次 POST
	if p.posts != 4 {
		t.Fatalf("显式两步 POST 次数应为 4，实际 %d", p.posts)
	}
}

// TestBruteMultiStepInvalidUserShortCircuit 用户名不存在时第一步即短路：
// 不发第二步请求、不误判成功（宁少报不误报），并归类 invalid_user。
func TestBruteMultiStepInvalidUserShortCircuit(t *testing.T) {
	p := &multiStepPoster{}
	var events []FailureEvent
	hits, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"nobody"}, Passwords: []string{"x"}, MaxTries: 10,
		MultiStep: true, MaxConsecutiveFails: -1,
		OnFailure: func(ev FailureEvent) { events = append(events, ev) }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("「用户名不存在」不得判成功（宁少报）: %+v", hits)
	}
	if p.posts != 2 { // 基线 1 + 尝试 1（无第二步）
		t.Fatalf("短路时 POST 次数应为 2，实际 %d", p.posts)
	}
	if len(events) != 1 || events[0].Category != FailureInvalidUser {
		t.Fatalf("应归类 invalid_user: %+v", events)
	}
}

// TestBruteMultiStepTooManySteps 步骤数上限：最多两步。
func TestBruteMultiStepTooManySteps(t *testing.T) {
	_, err := BruteMultiStep(&multiStepPoster{}, Options{PageURL: "https://x.com/login",
		Users: []string{"a"}, Passwords: []string{"b"}}, []Step{{}, {}, {}}, nil)
	if err == nil || !strings.Contains(err.Error(), "最多支持两步") {
		t.Fatalf("超过两步应明确报错: %v", err)
	}
}

// captchaStepPoster 第一步后返回带验证码的密码框页面。
type captchaStepPoster struct{ gets, posts int }

func (c *captchaStepPoster) GetSmall(string) (int, string, error) {
	c.gets++
	return 200, `<html><form action="/login" method="post"><input name="user"></form></html>`, nil
}

func (c *captchaStepPoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (c *captchaStepPoster) PostForm(_ string, fields map[string]string) (int, string, error) {
	c.posts++
	if fields["user"] == "admin" {
		return 200, `<html><form action="/login/step2" method="post">
<input name="user"><input type="password" name="pass">
<img src="/captcha.img" class="captcha-img"><input name="captcha"></form></html>`, nil
	}
	return 200, `<html><div>用户名不存在</div></html>`, nil
}

// TestBruteMultiStepCaptchaRequiresOCR 第二步需要验证码但未配置 OCR：明确报错
// （与单步模式同口径），不得静默当失败继续跑。
func TestBruteMultiStepCaptchaRequiresOCR(t *testing.T) {
	p := &captchaStepPoster{}
	_, err := Brute(p, Options{PageURL: "https://x.com/login",
		Users: []string{"admin"}, Passwords: []string{"x"}, MaxTries: 10,
		MultiStep: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "验证码") {
		t.Fatalf("需要验证码但无 OCR 应明确报错: %v", err)
	}
	if p.posts != 2 { // 基线 1 + 尝试第一步 1，第二步不发
		t.Fatalf("缺 OCR 时不应发第二步请求，posts=%d", p.posts)
	}
}

// TestDeriveStepPlan 自动推导：登录页已有密码框 → 同一表单 URL 两步；
// 显式步骤的 Action 归一为绝对地址且第一步强制不带口令。
func TestDeriveStepPlan(t *testing.T) {
	doc := htmlx.Parse(lb02LoginPage)
	plan, err := deriveStepPlan(doc, "https://x.com/login")
	if err != nil {
		t.Fatalf("登录页含密码框应可推导: %v", err)
	}
	if plan.dynamic {
		t.Fatal("登录页已有密码框时应推导为「同一表单 URL 两步」，而非动态发现")
	}
	if plan.first.Action != "https://x.com/login" || plan.second.Action != "https://x.com/login" {
		t.Fatalf("同表单两步 action 异常: %+v", plan)
	}
	if plan.first.PassField != "" {
		t.Fatalf("第一步不得携带口令字段: %q", plan.first.PassField)
	}
	if plan.second.PassField != "pass" {
		t.Fatalf("第二步口令字段应为 pass: %q", plan.second.PassField)
	}

	// 显式步骤：相对 action 归一为绝对地址；第一步的 PassField 被清空
	explicit, err := buildStepPlan(doc, "https://x.com/login", []Step{
		{Action: "/login", PassField: "pass"},
		{Action: "/step2", PassField: "pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.first.Action != "https://x.com/login" || explicit.second.Action != "https://x.com/step2" {
		t.Fatalf("显式步骤 action 归一失败: %+v", explicit)
	}
	if explicit.first.PassField != "" {
		t.Fatal("第一步不应携带口令字段")
	}
}

// ---- 批量目标 ----

// batchPoster 按 host 响应：a.example.com 命中 admin/letmein，其余失败。
type batchPoster struct {
	mu        sync.Mutex
	gets      map[string]int
	posts     map[string]int
	jsonPosts map[string]int
}

func newBatchPoster() *batchPoster {
	return &batchPoster{gets: map[string]int{}, posts: map[string]int{}, jsonPosts: map[string]int{}}
}

func (b *batchPoster) GetSmall(rawURL string) (int, string, error) {
	h := urlHost(rawURL)
	b.mu.Lock()
	b.gets[h]++
	b.mu.Unlock()
	return 200, lb02LoginPage, nil
}

func (b *batchPoster) PostJSON(rawURL, body string) (int, string, error) {
	h := urlHost(rawURL)
	b.mu.Lock()
	b.jsonPosts[h]++
	b.mu.Unlock()
	if h == "a.example.com" && strings.Contains(body, `"admin"`) && strings.Contains(body, `"letmein"`) {
		return 200, `{"ok":true}`, nil
	}
	return 401, `{"msg":"bad credentials"}`, nil
}

func (b *batchPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	h := urlHost(rawURL)
	b.mu.Lock()
	b.posts[h]++
	b.mu.Unlock()
	if h == "a.example.com" && fields["user"] == "admin" && fields["pass"] == "letmein" {
		return 302, "", nil
	}
	return 200, lbFailPage, nil
}

// TestTargetPageURL LoginPath 解析：相对路径拼接、绝对 URL 直用、空=URL 本身。
func TestTargetPageURL(t *testing.T) {
	cases := []struct {
		t    Target
		want string
	}{
		{Target{URL: "https://x.com", LoginPath: "/login"}, "https://x.com/login"},
		{Target{URL: "https://x.com/base", LoginPath: "login.php"}, "https://x.com/login.php"},
		{Target{URL: "https://x.com/base/login"}, "https://x.com/base/login"},
		{Target{URL: "https://x.com", LoginPath: "https://other.com/login"}, "https://other.com/login"},
	}
	for _, c := range cases {
		if got := targetPageURL(c.t); got != c.want {
			t.Fatalf("targetPageURL(%+v) = %q，期望 %q", c.t, got, c.want)
		}
	}
}

// TestBruteTargetsAggregates 串行批量：命中汇总、白名单目标零请求拒绝、
// 每目标独立护栏、LoginPath 生效。
func TestBruteTargetsAggregates(t *testing.T) {
	p := newBatchPoster()
	opts := Options{
		Users: []string{"admin"}, Passwords: []string{"letmein"},
		MaxTries: 10, MaxConsecutiveFails: -1,
		AllowHosts: []string{"a.example.com", "b.example.com"},
	}
	res := BruteTargets(p, opts, []Target{
		{URL: "https://a.example.com", LoginPath: "/login"},
		{URL: "https://b.example.com"},
		{URL: "https://evil.example"},
	}, nil)

	if res.Total != 3 || len(res.Targets) != 3 {
		t.Fatalf("汇总目标数异常: %+v", res)
	}
	// a：LoginPath 生效且命中
	if res.Targets[0].PageURL != "https://a.example.com/login" {
		t.Fatalf("LoginPath 未生效: %q", res.Targets[0].PageURL)
	}
	if len(res.Hits) != 1 || res.Hits[0].User != "admin" || res.Hits[0].Password != "letmein" {
		t.Fatalf("批量命中汇总异常: %+v", res.Hits)
	}
	if res.Targets[0].Error != "" || res.Targets[0].Tries != 1 {
		t.Fatalf("目标 a 应 1 次尝试命中: %+v", res.Targets[0])
	}
	// b：正常执行但未命中
	if res.Targets[1].Error != "" || len(res.Targets[1].Hits) != 0 || res.Targets[1].Tries != 1 {
		t.Fatalf("目标 b 应执行 1 次未命中: %+v", res.Targets[1])
	}
	// evil：白名单拒绝，零请求
	if !strings.Contains(res.Targets[2].Error, "白名单") {
		t.Fatalf("白名单外目标应拒绝: %+v", res.Targets[2])
	}
	if p.gets["evil.example"] != 0 || p.posts["evil.example"] != 0 {
		t.Fatalf("白名单外目标必须零请求: gets=%d posts=%d",
			p.gets["evil.example"], p.posts["evil.example"])
	}
	if res.Failed != 1 || res.Tries != 2 {
		t.Fatalf("汇总计数异常: failed=%d tries=%d", res.Failed, res.Tries)
	}
}

// TestBruteTargetsJSONMode JSON 模式批量：端点随目标解析，命中汇总。
func TestBruteTargetsJSONMode(t *testing.T) {
	p := newBatchPoster()
	opts := Options{
		LoginMode:    "json",
		JSONTemplate: `{"username":"{user}","password":"{pass}"}`,
		JSONEndpoint: "/api/login",
		Users:        []string{"admin"}, Passwords: []string{"letmein"},
		MaxTries: 10, AllowHosts: []string{"a.example.com"},
	}
	res := BruteTargets(p, opts, []Target{{URL: "https://a.example.com"}}, nil)
	if len(res.Hits) != 1 || res.Hits[0].Type != "json-api" {
		t.Fatalf("JSON 批量应命中: %+v", res)
	}
	if !strings.Contains(res.Hits[0].Curl, "https://a.example.com/api/login") {
		t.Fatalf("JSON 端点应随目标解析: %q", res.Hits[0].Curl)
	}
	if p.jsonPosts["a.example.com"] < 2 { // 基线 + 尝试
		t.Fatalf("JSON 请求次数异常: %d", p.jsonPosts["a.example.com"])
	}
}

// TestBruteTargetsTotalCap 批量总量上限：累计尝试到顶后剩余目标标记未执行，
// 且不再发出任何请求。
func TestBruteTargetsTotalCap(t *testing.T) {
	p := newBatchPoster()
	opts := Options{
		Users: []string{"u1", "u2"}, Passwords: []string{"p1"},
		MaxTries: 100, MaxConsecutiveFails: -1, MaxTotalTries: 1,
		AllowHosts: []string{"a.example.com", "b.example.com"},
	}
	res := BruteTargets(p, opts, []Target{
		{URL: "https://a.example.com"},
		{URL: "https://b.example.com"},
	}, nil)
	if res.Tries > 1 {
		t.Fatalf("累计尝试不得超过 MaxTotalTries=1，实际 %d", res.Tries)
	}
	if res.Skipped != 1 || !strings.Contains(res.StopReason, "总量上限") {
		t.Fatalf("超限后应标记未执行并给出原因: skipped=%d reason=%q", res.Skipped, res.StopReason)
	}
	if p.gets["b.example.com"] != 0 || p.posts["b.example.com"] != 0 {
		t.Fatalf("未执行目标必须零请求: gets=%d posts=%d",
			p.gets["b.example.com"], p.posts["b.example.com"])
	}
}
