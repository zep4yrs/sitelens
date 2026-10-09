package passive

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

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
	a := RunDedup(respWithCookie("SID=1"), htmlx.Parse(""), "http://t/a", d)
	b := RunDedup(respWithCookie("OTHER=2; HttpOnly"), htmlx.Parse(""), "http://t/b", d)
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
	for _, k := range []string{"cookie-attrs", "csrf-form"} {
		if !h[k] {
			t.Fatalf("%s 应归入配置卫生", k)
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
