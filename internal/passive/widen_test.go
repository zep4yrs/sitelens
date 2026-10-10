package passive

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

// DVWA CSRF 模块的形态：改密表单两个字段，未带 token。
// 旧实现只认 HasPassword，这个表单必漏；拓宽后应命中。
func TestCSRFStateChangeFormWithoutPassword(t *testing.T) {
	page := `<form action="#" method="GET">
<input name="password_new" type="password"><input name="password_conf" type="password">
<input name="Change" type="submit" value="Change"></form>`
	hits := onlyCheck(Run(respWithCookie(""), htmlx.Parse(page), "http://t/vulnerabilities/csrf/"), "csrf-form")
	if len(hits) != 1 {
		t.Fatalf("DVWA 改密表单应报 csrf-form，实际 %+v", hits)
	}
	if hits[0].Severity != "high" {
		t.Fatalf("含状态字段的变更表单应为 high，实际 %s", hits[0].Severity)
	}
}

// 带 token 的表单不得误报。
func TestCSRFWithTokenNotReported(t *testing.T) {
	page := `<form action="/update" method="post">
<input name="email">
<input type="hidden" name="csrf_token" value="a1b2c3d4e5f6a7b8"></form>`
	if hits := onlyCheck(Run(respWithCookie(""), htmlx.Parse(page), "http://t/"), "csrf-form"); len(hits) != 0 {
		t.Fatalf("带 token 的表单不得报 CSRF：%+v", hits)
	}
}

// 纯搜索 GET 表单（无状态语义）不得误报为 CSRF。
func TestCSRFPureSearchFormNotReported(t *testing.T) {
	page := `<form action="/search" method="get"><input name="q"></form>`
	if hits := onlyCheck(Run(respWithCookie(""), htmlx.Parse(page), "http://t/"), "csrf-form"); len(hits) != 0 {
		t.Fatalf("纯搜索表单不得报 CSRF：%+v", hits)
	}
}

// 弱会话 ID：DVWA 弱会话模块的递增整数形态。
func TestWeakSessionIDInteger(t *testing.T) {
	hits := onlyCheck(Run(respWithCookie("dvwaSession=1; path=/"), htmlx.Parse(""), "http://t/"), "weak-session-id")
	if len(hits) != 1 {
		t.Fatalf("dvwaSession=1 应报 weak-session-id：%+v", hits)
	}
}

// 强随机会话 ID 不得误报。
func TestStrongSessionIDNotReported(t *testing.T) {
	strong := strings.Repeat("f", 32) // 32 位十六进制随机串
	hits := onlyCheck(Run(respWithCookie("PHPSESSID="+strong+"; path=/"), htmlx.Parse(""), "http://t/"), "weak-session-id")
	if len(hits) != 0 {
		t.Fatalf("强随机会话 ID 不得误报：%+v", hits)
	}
}

// 时间戳形态会话 ID 应报。
func TestWeakSessionIDTimestamp(t *testing.T) {
	hits := onlyCheck(Run(respWithCookie("JSESSIONID=1695000000; path=/"), htmlx.Parse(""), "http://t/"), "weak-session-id")
	if len(hits) != 1 {
		t.Fatalf("时间戳形态会话 ID 应报：%+v", hits)
	}
}
