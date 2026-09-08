// 认证爬虫回归：登录墙站点 + 客户端 Cookie，爬虫应越过登录页采集
// 菜单链接（相对无斜杠形态，DVWA 类）。
package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func TestCrawlWithAuthCookie(t *testing.T) {
	mux := http.NewServeMux()
	// 登录墙：无 Cookie 访问任意页 → 302 到 /login
	guard := func(next func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") == "" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=1; Path=/")
		w.Write([]byte(`<html><a href="/login">login</a></html>`))
	})
	mux.HandleFunc("/", guard(func(w http.ResponseWriter, r *http.Request) {
		// DVWA 式相对无斜杠菜单链接
		w.Write([]byte(`<html><a href="vulnerabilities/sqli/">sqli</a><a href="security.php">sec</a></html>`))
	}))
	mux.HandleFunc("/vulnerabilities/sqli/", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><form action="#" method="get"><input name="id"><input name="Submit"></form></html>`))
	}))
	mux.HandleFunc("/security.php", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>security page</html>`))
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client2 := httpx.NewWithOptions(httpx.ClientOptions{AuthCookie: "sid=1"})
	opts := config.CrawlerConfig{MaxPages: 10, RespectRobots: false, MaxLinksPerPage: 20}
	c := New(client2, opts, srv.URL+"/")
	res := c.Crawl(mustGetWith(client2, srv.URL+"/"), nil)

	if len(res.Pages) < 3 {
		t.Fatalf("带 Cookie 应爬到多个页面: %d", len(res.Pages))
		for _, p := range res.Pages {
			t.Logf("  page: %s", p.FinalURL)
		}
	}
	found := false
	for _, f := range res.Forms {
		if f.Action != "" && len(f.Names) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("sqli 表单字段未采集")
	}
}

func mustGetWith(c *httpx.Client, url string) *httpx.Response {
	resp, err := c.GetFollow(url)
	if err != nil || resp == nil {
		panic("fetch fail")
	}
	return resp
}
