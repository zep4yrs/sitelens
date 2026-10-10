package dast

import (
	"strings"
	"testing"
)

// authFetch 模拟经典易注入登录表单：
// 用户名含 SQL 注释截断（'-- / '# / '/*）→ 302 跳受保护区（成功）；
// 其余 → 200 重渲染登录页（含 password 输入框，失败）。
type authFetch struct{ request int }

func (f *authFetch) GetSmall(string) *Resp { return &Resp{Status: 200, Body: "<html></html>"} }

func (f *authFetch) PostFormSmall(_ string, data map[string]string) *Resp {
	f.request++
	u := data["username"]
	if strings.Contains(u, "'--") || strings.Contains(u, "'#") || strings.Contains(u, "'/*") {
		return &Resp{Status: 302, Headers: map[string]string{"Location": "/bank/main.jsp"}}
	}
	return &Resp{Status: 200, Body: "<form><input type=\"password\" name=\"password\"></form>invalid credentials"}
}
func (f *authFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *authFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAuthBypassDetected(t *testing.T) {
	r := newRunner(&authFetch{})
	hits := r.RunForms([]FormTarget{{
		Action:      "http://t/login",
		Fields:      []string{"username", "password", "submit", "Login"},
		LoginFields: []string{"username", "password"},
	}})
	var got *Finding
	for i := range hits {
		if hits[i].Check == "sqli-auth-bypass" {
			got = &hits[i]
		}
	}
	if got == nil {
		t.Fatalf("应报出 sqli-auth-bypass，实得 %d 条：%+v", len(hits), hits)
	}
	if got.Severity != "critical" {
		t.Errorf("严重度应为 critical，实得 %s", got.Severity)
	}
	if got.Param != "username" {
		t.Errorf("Param 应为 username，实得 %s", got.Param)
	}
}

// authSafeFetch 不可注入：任何输入都回登录页 → 不得报。
type authSafeFetch struct{ request int }

func (f *authSafeFetch) GetSmall(string) *Resp { return &Resp{Status: 200, Body: "<html></html>"} }
func (f *authSafeFetch) PostFormSmall(string, map[string]string) *Resp {
	f.request++
	return &Resp{Status: 200, Body: "<input type=\"password\" name=\"password\">invalid login"}
}
func (f *authSafeFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *authSafeFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAuthBypassNoFalsePositive(t *testing.T) {
	r := newRunner(&authSafeFetch{})
	hits := r.RunForms([]FormTarget{{
		Action:      "http://t/login",
		Fields:      []string{"username", "password"},
		LoginFields: []string{"username", "password"},
	}})
	for _, h := range hits {
		if h.Check == "sqli-auth-bypass" {
			t.Fatalf("安全登录表单不应报认证绕过：%+v", h)
		}
	}
}

// 302 跳回登录页 → 判失败（不报）。
type authRedirectBackFetch struct{ request int }

func (f *authRedirectBackFetch) GetSmall(string) *Resp {
	return &Resp{Status: 200, Body: "<html></html>"}
}
func (f *authRedirectBackFetch) PostFormSmall(string, map[string]string) *Resp {
	f.request++
	return &Resp{Status: 302, Headers: map[string]string{"Location": "/login.php?error=1"}}
}
func (f *authRedirectBackFetch) PostRawSmall(string, string, string) *Resp { return nil }
func (f *authRedirectBackFetch) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

func TestAuthBypassRedirectBackNotHit(t *testing.T) {
	r := newRunner(&authRedirectBackFetch{})
	hits := r.RunForms([]FormTarget{{
		Action:      "http://t/login.php",
		Fields:      []string{"username", "password"},
		LoginFields: []string{"username", "password"},
	}})
	for _, h := range hits {
		if h.Check == "sqli-auth-bypass" {
			t.Fatalf("跳回登录页不应判成功：%+v", h)
		}
	}
}
