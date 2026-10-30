// SetPageHook（引擎流式分析 additive 钩子）回归测试：
//   - 默认 nil 时爬取行为/结果与既有完全一致（不改变抓取顺序/去重/页数）；
//   - 挂载后每页恰好回调一次、顺序与 Result.Pages 一致；
//   - 回调不额外发请求。
package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// newHookSite 首页链到 /a、/b，/a 再链到 /c：共 4 页。
func newHookSite(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var reqs int32
	mux := http.NewServeMux()
	pages := map[string]string{
		"/":  `<html><body><a href="/a">a</a><a href="/b">b</a></body></html>`,
		"/a": `<html><body><a href="/c">c</a><form method="post" action="/p"><input name="x"></form></body></html>`,
		"/b": `<html><body>b</body></html>`,
		"/c": `<html><body>c</body></html>`,
	}
	for path, body := range pages {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqs, 1)
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func newHookCrawler() *Crawler {
	cfg := config.Default()
	cfg.Crawler.MaxPages = 4
	cfg.Crawler.RespectRobots = false
	return New(httpx.New(0), cfg.Crawler, "")
}

// crawlOnce 用独立 client 从首页响应出发爬一次（复用引擎同款入口）。
func crawlOnce(t *testing.T, srv *httptest.Server, hook func(*httpx.Response)) *Result {
	t.Helper()
	client := httpx.New(0)
	home, err := client.GetFollow(srv.URL + "/")
	if err != nil || home == nil {
		t.Fatalf("首页采集失败: %v", err)
	}
	c := New(client, config.Default().Crawler, srv.URL)
	c.opts.MaxPages = 4
	c.opts.RespectRobots = false
	if hook != nil {
		c.SetPageHook(hook)
	}
	return c.Crawl(home, nil)
}

type hookSummary struct {
	PageURLs   []string
	Statuses   []int
	Bodies     []string
	Titles     []string
	ParamLinks []string
	AllLinks   []string
	Forms      []Form
	Flags      [4]bool
}

// summarize 归一化爬取结果（不同 httptest 端口/Date 头不可直接 DeepEqual，
// 这里只比较与行为相关的字段）。
func summarize(res *Result, srvURL string) hookSummary {
	var s hookSummary
	for _, p := range res.Pages {
		s.PageURLs = append(s.PageURLs, strings.ReplaceAll(p.FinalURL, srvURL, "SRV"))
		s.Statuses = append(s.Statuses, p.Status)
		s.Bodies = append(s.Bodies, p.Body)
		s.Titles = append(s.Titles, p.Title)
	}
	for _, l := range res.ParamLinks {
		s.ParamLinks = append(s.ParamLinks, strings.ReplaceAll(l, srvURL, "SRV"))
	}
	for _, l := range res.AllLinks {
		s.AllLinks = append(s.AllLinks, strings.ReplaceAll(l, srvURL, "SRV"))
	}
	for _, f := range res.Forms {
		f.Action = strings.ReplaceAll(f.Action, srvURL, "SRV")
		s.Forms = append(s.Forms, f)
	}
	s.Flags = [4]bool{res.RobotsHonored, res.RobotsAll}
	return s
}

// TestPageHookDefaultNilEquivalent 默认 nil 与「挂载空操作钩子」的爬取结果
// 逐字段一致；请求数一致（钩子不改变抓取行为、不发额外请求）。
func TestPageHookDefaultNilEquivalent(t *testing.T) {
	srvNil, reqsNil := newHookSite(t)
	resNil := crawlOnce(t, srvNil, nil)

	srvHook, reqsHook := newHookSite(t)
	var hookCalls int
	resHook := crawlOnce(t, srvHook, func(*httpx.Response) { hookCalls++ })

	if a, b := summarize(resNil, srvNil.URL), summarize(resHook, srvHook.URL); !reflect.DeepEqual(a, b) {
		t.Fatalf("挂载 pageHook 改变了爬取结果：\nnil=%+v\nhook=%+v", a, b)
	}
	if gotNil, gotHook := atomic.LoadInt32(reqsNil), atomic.LoadInt32(reqsHook); gotNil != gotHook {
		t.Fatalf("pageHook 引入了额外请求: nil=%d hook=%d", gotNil, gotHook)
	}
	if hookCalls != len(resHook.Pages) {
		t.Fatalf("每页应恰好回调一次: calls=%d pages=%d", hookCalls, len(resHook.Pages))
	}
	if len(resHook.Pages) != 4 {
		t.Fatalf("应爬到 4 页，实际 %d", len(resHook.Pages))
	}
}

// TestPageHookOrderAndResponse 回调顺序与 Result.Pages 一致，且传的是该页响应。
func TestPageHookOrderAndResponse(t *testing.T) {
	srv, _ := newHookSite(t)
	var got []string
	res := crawlOnce(t, srv, func(resp *httpx.Response) {
		got = append(got, fmt.Sprintf("%d|%s", resp.Status, resp.FinalURL))
	})
	if len(got) != len(res.Pages) {
		t.Fatalf("回调数 %d != 页数 %d", len(got), len(res.Pages))
	}
	for i, p := range res.Pages {
		want := fmt.Sprintf("%d|%s", p.Status, p.FinalURL)
		if got[i] != want {
			t.Fatalf("第 %d 页回调顺序不符: got=%q want=%q（全量 %v）", i, got[i], want, got)
		}
	}
}
