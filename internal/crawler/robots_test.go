package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

func TestRobotsParseAllowDisallowLongestMatch(t *testing.T) {
	f := parseRobots(`
User-agent: *
Disallow: /admin/
Allow: /admin/public/
Disallow: /private/
`)
	g := f.selectGroup("*")
	if g == nil {
		t.Fatal("应命中 * 组")
	}
	cases := map[string]bool{
		"/":               true,
		"/index.html":     true,
		"/admin/":         false,
		"/admin/secret":   false,
		"/admin/public/x": true, // Allow 更长，覆盖 Disallow
		"/private/":       false,
		"/private2":       true, // 前缀不同（有尾斜杠）
	}
	for p, want := range cases {
		if got := g.allowedBy(p); got != want {
			t.Errorf("allowedBy(%q)=%v want %v", p, got, want)
		}
	}
}

func TestRobotsEmptyDisallowAllowsAll(t *testing.T) {
	f := parseRobots("User-agent: *\nDisallow:\n")
	g := f.selectGroup("*")
	if g == nil {
		t.Fatal("应有 * 组")
	}
	if !g.allowedBy("/anything") {
		t.Fatal("空 Disallow 应允许全部")
	}
}

func TestRobotsBlanketBlock(t *testing.T) {
	// 复刻 pentest-ground.com:4280 的真实 robots.txt
	f := parseRobots("User-agent: *\nDisallow: /\n")
	g := f.selectGroup("*")
	if g == nil {
		t.Fatal("应有 * 组")
	}
	if g.allowedBy("/") || g.allowedBy("/login.php") {
		t.Fatal("Disallow: / 应封禁全部路径")
	}
}

func TestRobotsWildcardAndEndAnchor(t *testing.T) {
	f := parseRobots(`
User-agent: *
Disallow: /*.php$
Disallow: /tmp/*
Allow: /tmp/ok
`)
	g := f.selectGroup("*")
	cases := map[string]bool{
		"/a.php":     false, // 命中 *.php$
		"/a.php?x=1": true,  // $ 锚点不匹配 query
		"/a.php/":    true,
		"/tmp/any":   false,
		"/tmp/ok":    true, // Allow 更长
		"/":          true,
	}
	for p, want := range cases {
		if got := g.allowedBy(p); got != want {
			t.Errorf("allowedBy(%q)=%v want %v", p, got, want)
		}
	}
}

func TestRobotsUserAgentSelection(t *testing.T) {
	f := parseRobots(`
User-agent: Googlebot
Disallow: /google-only

User-agent: *
Disallow: /everyone
`)
	if g := f.selectGroup("googlebot"); g == nil || g.allowedBy("/google-only") {
		t.Fatalf("googlebot 应命中专用组: %+v", g)
	}
	// 非 googlebot 落到 * 组
	if g := f.selectGroup("sitelens"); g == nil || g.allowedBy("/everyone") {
		t.Fatalf("sitelens 应命中 * 组并封禁 /everyone: %+v", g)
	}
	// 未命中的路径都放行
	if g := f.selectGroup("sitelens"); !g.allowedBy("/public") {
		t.Fatal("/public 应放行")
	}
}

func TestRobotsMultipleAgentsShareRules(t *testing.T) {
	f := parseRobots(`
User-agent: a
User-agent: b
Disallow: /shared
`)
	if g := f.selectGroup("a"); g == nil || g.allowedBy("/shared") {
		t.Fatal("a 应共享规则")
	}
	if g := f.selectGroup("b"); g == nil || g.allowedBy("/shared") {
		t.Fatal("b 应共享规则")
	}
	if g := f.selectGroup("c"); g != nil {
		t.Fatal("c 无适用组，应为 nil")
	}
}

func TestRobotsCommentsAndCRLF(t *testing.T) {
	f := parseRobots("User-agent: * # all bots\r\nDisallow: /admin/ # block\r\n")
	g := f.selectGroup("*")
	if g == nil || g.allowedBy("/admin/x") {
		t.Fatalf("行内注释与 CRLF 应正确解析: %+v", g)
	}
	if !g.allowedBy("/public") {
		t.Fatal("/public 应放行")
	}
}

func TestRobotsSitemapCollection(t *testing.T) {
	f := parseRobots("Sitemap: https://a.com/sitemap.xml\nUser-agent: *\nDisallow:\n")
	if len(f.sitemaps) != 1 || f.sitemaps[0] != "https://a.com/sitemap.xml" {
		t.Fatalf("Sitemap 收集失败: %v", f.sitemaps)
	}
}

// TestCrawlBlanketRobotsGuardrail 复刻真实目标 pentest-ground.com:4280 的
// robots.txt（Disallow: /）：爬取按策略塌缩到入口页（不违反 respect_robots），
// 但结果必须显式标记 RobotsAll，而不是无声无息地只爬一页。
func TestCrawlBlanketRobotsGuardrail(t *testing.T) {
	srv := newRobotsSite(t, "User-agent: *\nDisallow: /\n")
	opts := config.CrawlerConfig{MaxPages: 20, RespectRobots: true, MaxLinksPerPage: 40}
	c := New(testClient(), opts, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)

	if !res.RobotsAll {
		t.Fatal("Disallow: / 应显式标记 RobotsAll=true")
	}
	if len(res.Pages) != 1 {
		t.Fatalf("遵循 robots 时应只爬入口页: %d", len(res.Pages))
	}
	// 放行为 true 时恢复完整爬取
	opts.RespectRobots = false
	c2 := New(testClient(), opts, srv.URL+"/")
	res2 := c2.Crawl(mustGet(t, srv.URL+"/"), nil)
	if len(res2.Pages) < 3 {
		t.Fatalf("respect_robots=false 应恢复完整爬取: %d", len(res2.Pages))
	}
	if res2.RobotsAll {
		t.Fatal("respect_robots=false 不应标记 RobotsAll")
	}
}

// TestCrawlRobotsAllowsSpecificPath robots 只封禁子路径时，其余页面照常爬取。
func TestCrawlRobotsAllowsSpecificPath(t *testing.T) {
	srv := newRobotsSite(t, "User-agent: *\nDisallow: /blocked/\n")
	opts := config.CrawlerConfig{MaxPages: 20, RespectRobots: true, MaxLinksPerPage: 40}
	c := New(testClient(), opts, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)
	if res.RobotsAll {
		t.Fatal("仅封禁子路径不应标记 RobotsAll")
	}
	if len(res.Pages) < 3 {
		t.Fatalf("应正常爬取其余页面: %d", len(res.Pages))
	}
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "/blocked/") {
			t.Fatalf("被封禁路径不应进入结果: %s", p.URL)
		}
	}
}

// newRobotsSite 搭一个带自定义 robots.txt 的多页站：/ 链到 /a、/b、/blocked/x。
func newRobotsSite(t *testing.T, robots string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, robots)
	})
	pages := map[string]string{
		"/":          `<html><a href="/a">A</a><a href="/b">B</a><a href="/blocked/x">X</a></html>`,
		"/a":         `<html><a href="/c">C</a></html>`,
		"/b":         `<html>b</html>`,
		"/c":         `<html>c</html>`,
		"/blocked/x": `<html>blocked</html>`,
	}
	for p, body := range pages {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
