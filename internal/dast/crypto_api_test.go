package dast

import (
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 验证码：字段识别 + 受理判定
// ---------------------------------------------------------------------------

func TestCaptchaFieldIn(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"username", "password", "g-recaptcha-response"}, "g-recaptcha-response"},
		{[]string{"user", "captcha"}, "captcha"},
		{[]string{"user", "verify_code"}, "verify_code"},
		{[]string{"user", "password"}, ""},
	}
	for _, c := range cases {
		if got := captchaFieldIn(c.in); got != c.want {
			t.Errorf("captchaFieldIn(%v) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestCaptchaVerdict(t *testing.T) {
	// DVWA：成功块里有 "success"，失败块里是 "incorrect"
	if ok, _ := captchaVerdict(200, `<div class="success">Captcha was correct</div>`); !ok {
		t.Fatal("成功标记应判为受理")
	}
	if ok, _ := captchaVerdict(200, `<div class="error">Incorrect captcha</div>`); ok {
		t.Fatal("拒绝标记应判为不受理")
	}
	if ok, _ := captchaVerdict(302, ""); !ok {
		t.Fatal("302 无拒绝标记应判为受理")
	}
	if ok, _ := captchaVerdict(500, ""); ok {
		t.Fatal("5xx 应判为不受理")
	}
	if ok, _ := captchaVerdict(200, `<html>nothing here</html>`); ok {
		t.Fatal("无标记应判为不受理（宁缺勿滥）")
	}
}

// captchaAcceptFetch 恒真验证码校验（任意值都被受理）。
type captchaAcceptFetch struct{ n int }

func (f *captchaAcceptFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<form><input name=captcha></form>"}
}
func (f *captchaAcceptFetch) PostFormSmall(string, map[string]string) *Resp {
	f.n++
	return &Resp{Status: 200, Body: `<div class="success">Captcha was correct</div>`}
}
func (f *captchaAcceptFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *captchaAcceptFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestCaptchaMissingHits(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.StoredXSS = false
	opts.CaptchaReplay = true
	hits := New(&captchaAcceptFetch{}, opts).RunForms([]FormTarget{{
		Action: "https://a.com/captcha", Fields: []string{"user", "captcha"},
	}})
	if !hasCheck(hits, "captcha-missing") {
		t.Fatalf("任意验证码被受理应命中 captcha-missing: %+v", hits)
	}
}

// captchaRejectFetch 正常校验（错误验证码被拒）——不得误报。
type captchaRejectFetch struct{}

func (f *captchaRejectFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<form><input name=captcha></form>"}
}
func (f *captchaRejectFetch) PostFormSmall(string, map[string]string) *Resp {
	return &Resp{Status: 200, Body: `<div class="error">Incorrect captcha</div>`}
}
func (f *captchaRejectFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *captchaRejectFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestCaptchaMissingNoFalsePositive(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.StoredXSS = false
	hits := New(&captchaRejectFetch{}, opts).RunForms([]FormTarget{{
		Action: "https://a.com/captcha", Fields: []string{"user", "captcha"},
	}})
	if hasCheck(hits, "captcha-missing") {
		t.Fatalf("正常校验不得报 captcha-missing: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 越权：标识可控 + 无访问控制
// ---------------------------------------------------------------------------

// authzIDORFetch /?user_id=N：1 与 2 返回不同内容，高权标识照样放行。
type authzIDORFetch struct{ deny bool }

func (f *authzIDORFetch) GetSmall(u string) *Resp {
	if f.deny {
		return &Resp{Status: 403, Body: "Forbidden"}
	}
	id := ""
	if p, err := url.Parse(u); err == nil {
		id = p.Query().Get("user_id")
	}
	switch id {
	case "1":
		return &Resp{Status: 200, Body: "<html>alice profile " + strings.Repeat("a", 200) + "</html>"}
	case "999999":
		return &Resp{Status: 200, Body: "<html>not found " + strings.Repeat("b", 60) + "</html>"}
	case "admin", "2":
		return &Resp{Status: 200, Body: "<html>admin profile " + strings.Repeat("c", 300) + "</html>"}
	}
	return &Resp{Status: 404, Body: "nope"}
}
func (f *authzIDORFetch) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }
func (f *authzIDORFetch) PostRawSmall(string, string, string) *Resp         { return nil }
func (f *authzIDORFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAuthzBypassHits(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.AuthzBypass = true
	hits := New(&authzIDORFetch{}, opts).RunAuthz([]string{"https://a.com/profile?user_id=1"})
	if !hasCheck(hits, "authz-bypass") {
		t.Fatalf("标识可控且高权值放行应命中 authz-bypass: %+v", hits)
	}
}

// 访问控制生效（403）→ 不报。
func TestAuthzBypassDeniedNoHit(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.AuthzBypass = true
	hits := New(&authzIDORFetch{deny: true}, opts).RunAuthz([]string{"https://a.com/profile?user_id=1"})
	if hasCheck(hits, "authz-bypass") {
		t.Fatalf("403 不得报 authz-bypass: %+v", hits)
	}
}

// 标识无效（不同取值响应相同）→ 不报，避免把静态页当越权。
type authzStaticFetch struct{}

func (f *authzStaticFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<html>same page</html>"}
}
func (f *authzStaticFetch) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }
func (f *authzStaticFetch) PostRawSmall(string, string, string) *Resp         { return nil }
func (f *authzStaticFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAuthzBypassStaticPageNoHit(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.AuthzBypass = true
	hits := New(&authzStaticFetch{}, opts).RunAuthz([]string{"https://a.com/profile?user_id=1"})
	if hasCheck(hits, "authz-bypass") {
		t.Fatalf("静态页不得报 authz-bypass: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 加密：确定性加密
// ---------------------------------------------------------------------------

// cryptoDetFetch 同一明文 → 同一密文（ECB/固定 IV），换明文换密文。
type cryptoDetFetch struct{ seen map[string]string }

func (f *cryptoDetFetch) cipher(plain string) string {
	switch plain {
	case "sitelens-crypto-plain":
		return "0123456789abcdef0123456789abcdef"
	case "sitelens-crypto-plain-2":
		return "fedcba9876543210fedcba9876543210"
	}
	return "00000000000000000000000000000000"
}

func (f *cryptoDetFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<form><input name=text></form>"}
}
func (f *cryptoDetFetch) PostFormSmall(_ string, data map[string]string) *Resp {
	return &Resp{Status: 200, Body: "<html>cipher: " + f.cipher(data["text"]) + "</html>"}
}
func (f *cryptoDetFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *cryptoDetFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestCryptoDeterministicHits(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.StoredXSS = false
	opts.CaptchaReplay = false
	opts.CryptoProbe = true
	hits := New(&cryptoDetFetch{}, opts).RunForms([]FormTarget{{
		Action: "https://a.com/crypto", Fields: []string{"text"},
	}})
	if !hasCheck(hits, "crypto-deterministic") {
		t.Fatalf("确定性加密应命中 crypto-deterministic: %+v", hits)
	}
}

// 随机 IV（同明文不同密文）→ 不报，避免把正常的 AEAD 误判。
type cryptoRandFetch struct{ n int }

func (f *cryptoRandFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<form><input name=text></form>"}
}
func (f *cryptoRandFetch) PostFormSmall(string, map[string]string) *Resp {
	f.n++
	return &Resp{Status: 200, Body: "<html>cipher: " + strings.Repeat(string(rune('a'+f.n%26)), 32) + "</html>"}
}
func (f *cryptoRandFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *cryptoRandFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestCryptoRandomIVNoHit(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.StoredXSS = false
	opts.CaptchaReplay = false
	hits := New(&cryptoRandFetch{}, opts).RunForms([]FormTarget{{
		Action: "https://a.com/crypto", Fields: []string{"text"},
	}})
	if hasCheck(hits, "crypto-deterministic") {
		t.Fatalf("随机 IV 不得报 crypto-deterministic: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 开放 API：未授权读取 + IDOR
// ---------------------------------------------------------------------------

// apiFetch /api/v2/user/N 返回含 password_hash 的 JSON，且任何 N 都可读。
type apiFetch struct{}

func (f *apiFetch) GetSmall(u string) *Resp {
	if !strings.Contains(u, "/api/") {
		return &Resp{Status: 200, Body: "<html>hi</html>"}
	}
	id := "1"
	if m := apiIdRE.FindStringSubmatch(u); m != nil {
		id = m[1]
	}
	// id=2 的主体多一段订单历史：内容确实不同（服务端按标识取数）
	extra := ""
	if id == "2" {
		extra = `,"orders":[` + strings.Repeat(`{"n":1},`, 20) + `{}]`
	}
	return &Resp{Status: 200, Body: `{"id":` + id + `,"username":"u` + id +
		`","password_hash":"5f4dcc3b5aa765d61d8327deb882cf99","email":"u` + id + `@x.com"` +
		extra + `}`}
}
func (f *apiFetch) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }
func (f *apiFetch) PostRawSmall(string, string, string) *Resp         { return nil }
func (f *apiFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAPIUnauthHits(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.APIAudit = true
	hits := New(&apiFetch{}, opts).RunAPI([]string{"https://a.com/api/v2/user/1"})
	if !hasCheck(hits, "api-unauth") {
		t.Fatalf("API 无凭证返回敏感字段应命中 api-unauth: %+v", hits)
	}
}

func TestAPIIDORHits(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.APIAudit = true
	hits := New(&apiFetch{}, opts).RunAPI([]string{"https://a.com/api/v2/user/1"})
	if !hasCheck(hits, "api-idor") {
		t.Fatalf("标识可替换且跨主体可见应命中 api-idor: %+v", hits)
	}
}

// 非结构化响应（普通 HTML 出现 password 单词）→ 不报。
type apiHTMLFetch struct{}

func (f *apiHTMLFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<html>please enter your password to continue</html>"}
}
func (f *apiHTMLFetch) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }
func (f *apiHTMLFetch) PostRawSmall(string, string, string) *Resp         { return nil }
func (f *apiHTMLFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAPIHTMLNoFalsePositive(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.APIAudit = true
	hits := New(&apiHTMLFetch{}, opts).RunAPI(nil)
	if hasCheck(hits, "api-unauth") {
		t.Fatalf("非结构化响应不得报 api-unauth: %+v", hits)
	}
	if field := apiSensitiveIn("<html>password here</html>"); field != "" {
		t.Fatalf("非 JSON 正文不应命中敏感字段，实得 %q", field)
	}
}

// 受保护 API（401）→ 不报。
type apiProtectedFetch struct{}

func (f *apiProtectedFetch) GetSmall(string) *Resp {
	return &Resp{Status: 401, Body: `{"error":"unauthorized"}`}
}
func (f *apiProtectedFetch) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }
func (f *apiProtectedFetch) PostRawSmall(string, string, string) *Resp         { return nil }
func (f *apiProtectedFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAPIProtectedNoHit(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.APIAudit = true
	hits := New(&apiProtectedFetch{}, opts).RunAPI([]string{"https://a.com/api/v2/user/1"})
	if hasCheck(hits, "api-unauth") || hasCheck(hits, "api-idor") {
		t.Fatalf("401 不得报 API 越权: %+v", hits)
	}
}

// 总闸关闭 → 一条都不报。
func TestCryptoAPIGatesOff(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.APIAudit = false
	opts.CryptoProbe = false
	r := New(&apiFetch{}, opts)
	if len(r.RunAPI([]string{"https://a.com/api/v2/user/1"})) != 0 {
		t.Fatal("APIAudit 关闭时不应产出发现")
	}
	hits := New(&cryptoDetFetch{}, opts).RunForms([]FormTarget{{
		Action: "https://a.com/crypto", Fields: []string{"text"},
	}})
	if hasCheck(hits, "crypto-deterministic") {
		t.Fatal("CryptoProbe 关闭时不应产出发现")
	}
}
