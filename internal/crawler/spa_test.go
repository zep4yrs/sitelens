package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// fakeRenderer 无头渲染器替身：返回预置 HTML。
type fakeRenderer struct{ html string }

func (f fakeRenderer) Render(string) (string, bool) { return f.html, true }

func newTinySite(t *testing.T, pages map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for p, body := range pages {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExtraSeedsFeedCrawler(t *testing.T) {
	srv := newTinySite(t, map[string]string{
		"/":             `<html>home</html>`,
		"/api/v1/users": `<html>endpoint page</html>`,
	})
	c := New(httpx.New(0), config.CrawlerConfig{MaxPages: 5, RespectRobots: false}, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), []string{srv.URL + "/api/v1/users"})

	found := false
	for _, p := range res.Pages {
		if p.FinalURL == srv.URL+"/api/v1/users" {
			found = true
		}
	}
	if !found {
		t.Fatalf("外部种子页应被抓取: %+v", res.Pages)
	}
}

func TestNextRoutesEnqueue(t *testing.T) {
	srv := newTinySite(t, map[string]string{
		"/": `<html><script id="__NEXT_DATA__" type="application/json">` +
			`{"page":"/spa/page-1","props":{"route":"/spa/page-2"},"noise":"x"}</script></html>`,
		"/spa/page-1": `<html>one</html>`,
		"/spa/page-2": `<html>two</html>`,
	})
	c := New(httpx.New(0), config.CrawlerConfig{MaxPages: 5, RespectRobots: false}, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)

	hit := 0
	for _, p := range res.Pages {
		if p.FinalURL == srv.URL+"/spa/page-1" || p.FinalURL == srv.URL+"/spa/page-2" {
			hit++
		}
	}
	if hit != 2 {
		t.Fatalf("SPA 路由应入队抓取: %+v", res.Pages)
	}
}

func TestRendererExtendsHomeLinks(t *testing.T) {
	srv := newTinySite(t, map[string]string{
		"/":         `<html>empty shell</html>`, // 静态 HTML 无链接
		"/rendered": `<html>rendered content</html>`,
	})
	c := New(httpx.New(0), config.CrawlerConfig{MaxPages: 5, RespectRobots: false}, srv.URL+"/")
	c.SetRenderer(fakeRenderer{html: `<html><a href="/rendered">r</a></html>`})
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)

	found := false
	for _, p := range res.Pages {
		if p.FinalURL == srv.URL+"/rendered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("渲染器提供的链接应被跟进: %+v", res.Pages)
	}
}

func TestSitemapSeedsSameHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<urlset>
  <url><loc>/from-sitemap-1</loc></url>
  <url><loc>https://other.example.com/outside</loc></url>
  <url><loc>/from-sitemap-2</loc></url>
</urlset>`)
	})
	mux.HandleFunc("/from-sitemap-1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "one")
	})
	mux.HandleFunc("/from-sitemap-2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "two")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(httpx.New(0), config.CrawlerConfig{MaxPages: 10, RespectRobots: false}, srv.URL+"/")
	res := c.Crawl(mustGet(t, srv.URL+"/"), nil)

	hit1, hit2 := false, false
	for _, p := range res.Pages {
		if p.FinalURL == srv.URL+"/from-sitemap-1" {
			hit1 = true
		}
		if p.FinalURL == srv.URL+"/from-sitemap-2" {
			hit2 = true
		}
	}
	if !hit1 || !hit2 {
		t.Fatalf("sitemap 同域条目应被抓取: %+v", res.Pages)
	}
}
