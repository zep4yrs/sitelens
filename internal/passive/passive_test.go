package passive

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// onlyCheck 过滤出指定 check 的命中（同一响应可能命中多类检查）。
func onlyCheck(hits []Hit, check string) []Hit {
	var out []Hit
	for _, h := range hits {
		if h.Check == check {
			out = append(out, h)
		}
	}
	return out
}

func respWithCookie(cookie string) *httpx.Response {
	return &httpx.Response{Status: 200, SetCookies: []string{cookie}}
}

// 同一 cookie 在 24 个页面上重复出现：去重后只能出 1 条。
func TestDedupCookieAttrsAcrossPages(t *testing.T) {
	d := NewDeduper()
	var got []Hit
	for i := 0; i < 24; i++ {
		r := respWithCookie("PHPSESSID=abc; path=/")
		got = append(got, RunDedup(r, htmlx.Parse(""), "http://t/p"+string(rune('a'+i)), d)...)
	}
	if len(got) != 1 {
		t.Fatalf("跨页去重失败：24 页应只报 1 条，实际 %d", len(got))
	}
	if got[0].Check != "cookie-attrs" {
		t.Fatalf("检查项不符: %+v", got[0])
	}
}

// 同一表单在多个页面回显：去重后只能出 1 条。
func TestDedupCSRFAcrossPages(t *testing.T) {
	page := `<form action="/login" method="post">
<input name="user"><input type="password" name="pass"></form>`
	d := NewDeduper()
	var got []Hit
	for i := 0; i < 5; i++ {
		// 同 action → 同一坑；URL 不同但 action 相同
		got = append(got, RunDedup(respWithCookie(""), htmlx.Parse(page), "http://t/page"+string(rune('a'+i)), d)...)
	}
	n := 0
	for _, h := range got {
		if h.Check == "csrf-form" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("同 action 表单应只报 1 条，实际 %d", n)
	}
}

// 不同 cookie / 不同缺失属性：各自成条，不被误去重。
func TestDedupKeepsDistinctFindings(t *testing.T) {
	d := NewDeduper()
	// 只比对 cookie-attrs：SID=1 还会命中 weak-session-id（那是另一类检查）
	a := onlyCheck(RunDedup(respWithCookie("SID=1"), htmlx.Parse(""), "http://t/a", d), "cookie-attrs")
	b := onlyCheck(RunDedup(respWithCookie("OTHER=x"), htmlx.Parse(""), "http://t/b", d), "cookie-attrs")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("不同 cookie 应各自成条: a=%d b=%d", len(a), len(b))
	}
	if a[0].Evidence == b[0].Evidence {
		t.Fatalf("两条证据串不应相同: %q", a[0].Evidence)
	}
}

// Hygiene 表必须覆盖两个配置卫生项。
func TestHygieneTable(t *testing.T) {
	h := Hygiene()
	// cookie-attrs 是纯配置卫生（缺属性）；csrf-form / weak-session-id
	// 是 CWE-352 / CWE-330 这类真漏洞，必须落在 verified 里参与覆盖率口径
	if !h["cookie-attrs"] {
		t.Fatal("cookie-attrs 应归入配置卫生")
	}
	for _, k := range []string{"csrf-form", "weak-session-id"} {
		if h[k] {
			t.Fatalf("%s 是真漏洞项，不得归入配置卫生", k)
		}
	}
}

// RunDedup 传 nil 去重器时退化为无去重（兼容旧调用）。
func TestRunDedupNilDeduper(t *testing.T) {
	r := respWithCookie("PHPSESSID=x")
	if got := RunDedup(r, htmlx.Parse(""), "http://t/", nil); len(got) != 1 {
		t.Fatalf("nil 去重器应退化为无去重: %+v", got)
	}
	// 且无去重时重复调用每次都出
	if got := RunDedup(r, htmlx.Parse(""), "http://t/", nil); len(got) != 1 {
		t.Fatalf("nil 去重器不应记忆: %+v", got)
	}
}

// cookie 缺 Secure 的判定文案保持稳定（ML 特征与前端展示依赖）。
func TestCookieEvidenceStable(t *testing.T) {
	hits := checkCookieAttrs(respWithCookie("PHPSESSID=1; path=/"), "http://t/")
	if len(hits) != 1 {
		t.Fatalf("应报 1 条: %+v", hits)
	}
	e := hits[0].Evidence
	if !strings.Contains(e, "PHPSESSID") || !strings.Contains(e, "HttpOnly") {
		t.Fatalf("证据文案不符: %q", e)
	}
}

// 标准靶场回归：GET 搜索/查询表单（name/id + submit 按钮）不得误报 CSRF；
// GET 改密表单（password_new/password_conf）必须命中；POST 表单仍命中。
func TestCSRFFormGetSearchNotFlagged(t *testing.T) {
	search := `<form action="/dvwa/vulnerabilities/xss_r/" method="GET">
<input name="name" type="text"><input name="Submit" type="submit" value="Submit"></form>`
	got := onlyCheck(Run(respWithCookie(""), htmlx.Parse(search), "http://t/x"), "csrf-form")
	if len(got) != 0 {
		t.Fatalf("GET 搜索表单不应报 csrf-form: %+v", got)
	}

	changePwd := `<form action="#" method="GET">
<input name="password_new" type="text"><input name="password_conf" type="text">
<input name="Change" type="submit" value="Change"></form>`
	got = onlyCheck(Run(respWithCookie(""), htmlx.Parse(changePwd), "http://t/csrf"), "csrf-form")
	if len(got) != 1 {
		t.Fatalf("GET 改密表单应报 csrf-form: %+v", got)
	}

	postForm := `<form action="/login" method="post"><input name="user"><input type="password" name="pass"></form>`
	got = onlyCheck(Run(respWithCookie(""), htmlx.Parse(postForm), "http://t/login"), "csrf-form")
	if len(got) != 1 {
		t.Fatalf("POST 表单应报 csrf-form: %+v", got)
	}
}

// 跨源表单（文章内嵌 jsfiddle/codepen 示例）不属于本站 CSRF 面；同源绝对地址仍要报。
func TestCSRFFormCrossOriginNotFlagged(t *testing.T) {
	cross := `<form action="https://jsfiddle.net/api/post/library/pure/" method="post">
<input name="html" type="text"></form>`
	got := onlyCheck(Run(respWithCookie(""), htmlx.Parse(cross), "https://blog.example/posts/x.html"), "csrf-form")
	if len(got) != 0 {
		t.Fatalf("跨源表单不应报 csrf-form: %+v", got)
	}

	same := `<form action="https://blog.example/update" method="post"><input name="pass"></form>`
	got = onlyCheck(Run(respWithCookie(""), htmlx.Parse(same), "https://blog.example/posts/x.html"), "csrf-form")
	if len(got) != 1 {
		t.Fatalf("同源绝对地址表单应报 csrf-form: %+v", got)
	}
}
