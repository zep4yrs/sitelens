// CP-01 回归：JS 路由发现、深度分层、链接归一化、上限与跳过计数。
package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func simpleSite(t *testing.T, pages map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for p, body := range pages {
		body := body
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func crawlSite(t *testing.T, srv *httptest.Server, mutate func(*Crawler)) *Result {
	t.Helper()
	client := httpx.New(0)
	home, err := client.GetFollow(srv.URL + "/")
	if err != nil || home == nil {
		t.Fatalf("首页采集失败: %v", err)
	}
	c := New(client, config.CrawlerConfig{MaxPages: 30, RespectRobots: false, MaxLinksPerPage: 100}, srv.URL+"/")
	if mutate != nil {
		mutate(c)
	}
	return c.Crawl(home, nil)
}

func pageURLs(res *Result) []string {
	out := make([]string, 0, len(res.Pages))
	for _, p := range res.Pages {
		out = append(out, p.FinalURL)
	}
	return out
}

func hasPage(res *Result, path string) bool {
	for _, p := range res.Pages {
		if strings.HasSuffix(p.FinalURL, path) {
			return true
		}
	}
	return false
}

// TestJSRouteExtractionUnit 路由字符串提取：过滤噪音/静态资源/协议相对地址，
// 按出现顺序去重。
func TestJSRouteExtractionUnit(t *testing.T) {
	js := `
var a = { path: "/user/list" };
router.push('/user/detail');
const api = "/api/v1/users";
const bad1 = "/logo.png";
const bad2 = "//cdn.example.com/x";
const bad3 = "/user/${id}";
const bad4 = "/";
const dup = "/user/list";
const rel = "relative/no-slash";
`
	got := extractJSRoutes(js)
	want := []string{"/user/list", "/user/detail", "/api/v1/users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("JS 路由提取不符: got=%v want=%v", got, want)
	}

	// inline script 正文抽取（含无 src 的 <script>）。
	html := `<html><script>var p="/x";</script><script src="/app.js"></script></html>`
	inline := extractInlineScripts(html)
	if len(inline) != 1 || !strings.Contains(inline[0], `"/x"`) {
		t.Fatalf("内联脚本提取失败: %v", inline)
	}
	if srcs := extractScriptSrcs(html); len(srcs) != 1 || srcs[0] != "/app.js" {
		t.Fatalf("外链脚本地址提取失败: %v", srcs)
	}

	// 上限：超过 MaxJSRoutes 时截断。
	var b strings.Builder
	for i := 0; i < MaxJSRoutes+20; i++ {
		fmt.Fprintf(&b, `"/r/%d",`, i)
	}
	if n := len(extractJSRoutes(b.String())); n != MaxJSRoutes {
		t.Fatalf("JS 路由提取应截断到 %d，实际 %d", MaxJSRoutes, n)
	}
}

// TestCrawlJSExternalAndInlineRoutes 内联与外链 JS 的路由都成为同域候选页。
func TestCrawlJSExternalAndInlineRoutes(t *testing.T) {
	srv := simpleSite(t, map[string]string{
		"/": `<html><body>
<script>var inlineRoutes=[{path:"/spa/inline-1"},{path:"/spa/inline-2"}];</script>
<script src="/static/app.js"></script>
<a href="/plain">plain</a>
</body></html>`,
		"/static/app.js": `var routes=[{path:"/spa/ext-1"}];router.push('/spa/ext-2');`,
		"/spa/inline-1":  `<html>1</html>`,
		"/spa/inline-2":  `<html>2</html>`,
		"/spa/ext-1":     `<html>3</html>`,
		"/spa/ext-2":     `<html>4</html>`,
		"/plain":         `<html>plain</html>`,
	})
	res := crawlSite(t, srv, nil)
	for _, p := range []string{"/spa/inline-1", "/spa/inline-2", "/spa/ext-1", "/spa/ext-2", "/plain"} {
		if !hasPage(res, p) {
			t.Fatalf("JS 路由候选页 %s 未抓取: %v", p, pageURLs(res))
		}
	}
	// 候选进入 AllLinks（供 DAST/目录探测复用）。
	all := strings.Join(res.AllLinks, " ")
	for _, p := range []string{"/spa/inline-1", "/spa/ext-2"} {
		if !strings.Contains(all, p) {
			t.Fatalf("JS 路由应进入 AllLinks: %s missing", p)
		}
	}
}

// TestCrawlMountDepth 深度分层：默认 2 层；MaxDepth 可覆盖；DepthHistogram 可读；
// 超深度候选计入 Skipped。
func TestCrawlMountDepth(t *testing.T) {
	pages := map[string]string{
		"/":   `<html><a href="/l1">l1</a></html>`,
		"/l1": `<html><a href="/l2">l2</a></html>`,
		"/l2": `<html><a href="/l3">l3</a></html>`,
		"/l3": `<html><a href="/l4">l4</a></html>`,
		"/l4": `<html>deep</html>`,
	}
	srv := simpleSite(t, pages)

	// 默认 MaxDepth = 2：首页 + l1 + l2；l2 上的 /l3 超深被跳过。
	res := crawlSite(t, srv, nil)
	if len(res.Pages) != 3 || !hasPage(res, "/l2") || hasPage(res, "/l3") {
		t.Fatalf("默认深度应为 2（首页+l1+l2），实际: %v", pageURLs(res))
	}
	if res.DepthHistogram[0] != 1 || res.DepthHistogram[1] != 1 || res.DepthHistogram[2] != 1 {
		t.Fatalf("DepthHistogram 不符: %+v", res.DepthHistogram)
	}
	if res.Skipped < 1 {
		t.Fatalf("超深度链接应计入 Skipped: %d", res.Skipped)
	}

	// MaxDepth = 1：只有首页 + l1。
	res1 := crawlSite(t, srv, func(c *Crawler) { c.MaxDepth = 1 })
	if len(res1.Pages) != 2 || hasPage(res1, "/l2") {
		t.Fatalf("MaxDepth=1 应只爬 2 页，实际: %v", pageURLs(res1))
	}

	// MaxDepth = 3：到 l3。
	res3 := crawlSite(t, srv, func(c *Crawler) { c.MaxDepth = 3 })
	if len(res3.Pages) != 4 || !hasPage(res3, "/l3") {
		t.Fatalf("MaxDepth=3 应爬 4 页，实际: %v", pageURLs(res3))
	}
}

// TestLinkNormalization 归一化：fragment/默认端口/query 顺序/主机大小写/末尾斜杠。
func TestLinkNormalization(t *testing.T) {
	same := [][2]string{
		{"http://a.com/x", "http://a.com/x#frag"},
		{"http://a.com:80/x", "http://a.com/x"},
		{"https://a.com:443/x", "https://a.com/x"},
		{"http://a.com/x?b=2&a=1", "http://a.com/x?a=1&b=2"},
		{"http://A.COM/x", "http://a.com/x"},
		{"http://a.com/x/", "http://a.com/x"},
		{"http://a.com", "http://a.com/"},
	}
	for _, pair := range same {
		if normalize(pair[0]) != normalize(pair[1]) {
			t.Fatalf("应归一为同一去重键: %q vs %q（%q / %q）",
				pair[0], pair[1], normalize(pair[0]), normalize(pair[1]))
		}
	}
	diff := [][2]string{
		{"http://a.com/x", "http://a.com/y"},
		{"http://a.com:8080/x", "http://a.com:9090/x"},
		{"http://a.com/x?a=1", "http://a.com/x?a=2"},
	}
	for _, pair := range diff {
		if normalize(pair[0]) == normalize(pair[1]) {
			t.Fatalf("不应归一: %q vs %q", pair[0], pair[1])
		}
	}

	// resolve：跳过 mailto/javascript/tel 与二进制后缀并标记 filtered；
	// 外域不标记（预期噪音）；相对路径正确解析。
	c := New(httpx.New(0), config.CrawlerConfig{}, "https://site.example.com/app/")
	base, _ := url.Parse("https://site.example.com/app/page")
	cases := []struct {
		href     string
		wantAbs  string
		filtered bool
	}{
		{"sub/x?b=2&a=1", "https://site.example.com/app/sub/x?a=1&b=2", false},
		{"../up", "https://site.example.com/up", false},
		{"#anchor", "", false},
		{"mailto:a@b.com", "", true},
		{"JAVASCRIPT:void(0)", "", true},
		{"tel:123", "", true},
		{"/static/logo.png", "", true},
		{"https://other.example.com/x", "", false},
	}
	for _, tc := range cases {
		abs, filtered := c.resolve(base, tc.href)
		if abs != tc.wantAbs || filtered != tc.filtered {
			t.Fatalf("resolve(%q) = (%q,%v)，期望 (%q,%v)", tc.href, abs, filtered, tc.wantAbs, tc.filtered)
		}
	}
}

// TestCrawlNormalizedDedupeAndSkipped 同一目标的不同写法只抓一次；协议/二进制
// 候选计入 Skipped；外域链接不计入。
func TestCrawlNormalizedDedupeAndSkipped(t *testing.T) {
	srv := simpleSite(t, map[string]string{
		"/": `<html>
<a href="/q?a=1&b=2">q1</a>
<a href="/q?b=2&a=1#x">q2</a>
<a href="/static/app.js">js</a>
<a href="/img/logo.png">png</a>
<a href="mailto:x@y.com">mail</a>
<a href="javascript:void(0)">js-void</a>
<a href="tel:123">tel</a>
<a href="http://other.example.com/nope">ext</a>
</html>`,
		"/q":             `<html>q</html>`,
		"/static/app.js": `var x=1;`,
		"/img/logo.png":  "PNG",
	})
	res := crawlSite(t, srv, nil)
	n := 0
	for _, p := range res.Pages {
		if strings.Contains(p.FinalURL, "/q?") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("带 query 的同页（顺序不同）应去重为 1 次，实际 %d: %v", n, pageURLs(res))
	}
	// mailto/javascript/tel + png 共 4 个被过滤候选；外域不计。
	if res.Skipped < 4 {
		t.Fatalf("Skiooed 应至少 4（3 协议 + 1 二进制），实际 %d", res.Skipped)
	}
	for _, p := range res.Pages {
		if strings.Contains(p.FinalURL, "logo.png") || strings.Contains(p.FinalURL, "app.js") {
			t.Fatalf("静态资源不应作为页面抓取: %s", p.FinalURL)
		}
	}
}

// TestJSRouteCapSharedAcrossPages 全局 JS 路由预算 200：第一页吃满后，
// 后续页面的路由候选计入 Skipped 且不再入队。
func TestJSRouteCapSharedAcrossPages(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<html><script>var r=[`)
	for i := 0; i < MaxJSRoutes; i++ {
		fmt.Fprintf(&b, `"/cap/%d",`, i)
	}
	b.WriteString(`];</script><a href="/second">s</a></html>`)
	second := `<html><script>var r=["/over-1","/over-2","/over-3"];</script></html>`
	pages := map[string]string{"/": b.String(), "/second": second}
	for i := 0; i < 3; i++ {
		pages[fmt.Sprintf("/over-%d", i+1)] = `<html>o</html>`
	}
	srv := simpleSite(t, pages)
	res := crawlSite(t, srv, nil)
	if res.Skipped < 3 {
		t.Fatalf("路由预算耗尽的候选应计入 Skipped: %d", res.Skipped)
	}
	if hasPage(res, "/over-1") {
		t.Fatalf("超预算路由不应入队: %v", pageURLs(res))
	}
}

// TestDefaultMaxDepthConstant 显式校准默认深度常量（engine 接线依赖）。
func TestDefaultMaxDepthConstant(t *testing.T) {
	if DefaultMaxDepth != 2 {
		t.Fatalf("DefaultMaxDepth 应为 2: %d", DefaultMaxDepth)
	}
	// 0 值 = 默认 2 的行为由 TestCrawlMountDepth 覆盖。
}
