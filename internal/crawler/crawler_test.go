package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// newSite 搭一个多页测试站：首页链到 /a 与 /b，/a 链到 /c，/off 是外链。
func newSite(t *testing.T, withRobots bool) *httptest.Server {
	mux := http.NewServeMux()
	pages := map[string]string{
		"/":    `<html><a href="/a?x=1">A</a><a href="/b">B</a><a href="http://ext.example.com/off">外</a></html>`,
		"/a":   `<html><a href="/c">C</a><a href="/">回</a></html>`,
		"/b":   `<html><form action="/login" method="post"><input name="u"><input type="password" name="p"></form></html>`,
		"/c":   `<html>leaf</html>`,
		"/404": `not found`,
	}
	for p, body := range pages {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		})
	}
	if withRobots {
		mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "User-agent: *\nDisallow: /private/\n")
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testClient() *httpx.Client {
	return httpx.New(0) // 不限速
}

func TestCrawlBFSCapsAndSameHost(t *testing.T) {
	srv := newSite(t, false)
	opts := config.CrawlerConfig{MaxPages: 10, RespectRobots: false, MaxLinksPerPage: 20}
	c := New(testClient(), opts, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)

	if len(res.Pages) != 4 { // / a b c
		t.Fatalf("应爬满 4 页: %d", len(res.Pages))
	}
	extFound := false
	for _, l := range res.AllLinks {
		if hasHost(l, "ext.example.com") {
			extFound = true
		}
	}
	if extFound {
		t.Fatalf("外链不应进入 AllLinks: %v", res.AllLinks)
	}
	if len(res.ParamLinks) != 1 || !containsSub(res.ParamLinks[0], "/a?x=1") {
		t.Fatalf("带参链接收集失败: %v", res.ParamLinks)
	}
	if len(res.Forms) != 1 || !res.Forms[0].HasPwd {
		t.Fatalf("表单收集失败: %+v", res.Forms)
	}
}

func TestCrawlMaxPagesCap(t *testing.T) {
	srv := newSite(t, false)
	opts := config.CrawlerConfig{MaxPages: 2, RespectRobots: false, MaxLinksPerPage: 20}
	c := New(testClient(), opts, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)
	if len(res.Pages) != 2 {
		t.Fatalf("MaxPages=2 应只爬 2 页: %d", len(res.Pages))
	}
}

func TestRobotsDisallowed(t *testing.T) {
	srv := newSite(t, true)
	// /private/ 被 robots 禁止：站上没有该页，直接验证 allowed 逻辑
	opts := config.CrawlerConfig{MaxPages: 10, RespectRobots: true, MaxLinksPerPage: 20}
	c := New(testClient(), opts, srv.URL+"/")
	c.loadRobots(srv.URL + "/")
	if !c.allowed(srv.URL + "/public/x") {
		t.Fatal("/public/x 应放行")
	}
	if c.allowed(srv.URL + "/private/admin") {
		t.Fatal("/private/admin 应被 robots 拦截")
	}
}

func TestNormalizeDedup(t *testing.T) {
	if normalize("http://a.com/x") != normalize("http://a.com/x#frag") {
		t.Fatal("fragment 差异应归一")
	}
	if normalize("http://a.com/x") == normalize("http://a.com/y") {
		t.Fatal("不同路径不应归一")
	}
}

func TestPhaseTimeout(t *testing.T) {
	srv := newSite(t, false)
	opts := config.CrawlerConfig{MaxPages: 10, RespectRobots: false,
		MaxLinksPerPage: 20, TimeoutSec: 1}
	c := New(testClient(), opts, srv.URL+"/")
	c.start = time.Now().Add(-2 * time.Second) // 已超时 2 秒
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)
	if len(res.Pages) != 1 { // 只有首页（已采到的），后续全部超时终止
		t.Fatalf("超时应终止爬取: %d", len(res.Pages))
	}
}

// ---- helpers ----

func mustGet(t *testing.T, url string) *httpx.Response {
	t.Helper()
	resp, err := testClient().GetFollow(url)
	if err != nil || resp == nil {
		t.Fatalf("测试站请求失败: %v", err)
	}
	return resp
}

func containsSub(s, sub string) bool { return strings.Contains(s, sub) }

func hasHost(raw, host string) bool { return strings.Contains(raw, host) }
