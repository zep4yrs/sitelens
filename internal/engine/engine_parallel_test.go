package engine

// 多页指纹识别并行化（engine.go 第 4 阶段）的回归：
//   - 命中结果按页面顺序合并，Technologies 输出稳定（不随 goroutine 完成顺序变化）；
//   - 进度回调不在并行区并发调用；
//   - favicon 指纹整站只采集一次（并行前后都不放大请求数）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// multiPageBody 40KB 拟真页：带 WordPress generator 特征（指纹识别非空跑）。
func multiPageBody(seed int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><head><title>四页站 %d</title>
<meta name="generator" content="WordPress 6.4.2">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body>`, seed)
	for b.Len() < 40*1024 {
		b.WriteString(`<div class="wp-block-group"><p>段落内容，用于模拟真实页面正文体量。</p></div>`)
	}
	b.WriteString(`<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>`)
	b.WriteString("</body></html>")
	return b.String()
}

// newMultiPageSite 首页 + 3 个子页（默认 Crawler.MaxPages=4，正好 4 页）。
func newMultiPageSite(tb testing.TB) (*httptest.Server, *int32) {
	tb.Helper()
	pages := map[string]string{
		"/":  multiPageBody(0),
		"/a": multiPageBody(1),
		"/b": multiPageBody(2),
		"/c": multiPageBody(3),
	}
	var faviconHits int32
	mux := http.NewServeMux()
	for path, body := range pages {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.25.3")
			fmt.Fprint(w, body)
		})
	}
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&faviconHits, 1)
		w.Header().Set("Content-Type", "image/x-icon")
		fmt.Fprint(w, "\x00\x00\x01\x00")
	})
	srv := httptest.NewServer(mux)
	tb.Cleanup(srv.Close)
	return srv, &faviconHits
}

func newMultiPageEngine(tb testing.TB) *Engine {
	tb.Helper()
	m, err := sitelens.LoadMatcher("../../data/go/technologies.json")
	if err != nil {
		tb.Skipf("指纹库不可用，跳过: %v", err)
	}
	cfg := config.Default()
	cfg.Scan.Resolve = false // SSRF 防护保留开启，仅测试放行本机回环
	cfg.Scan.RateIntervalMS = 0
	return New(cfg, m, nil)
}

// TestScanMultiPageTechnologiesStable 多次扫描 4 页站点，Technologies 输出必须一致
// （并行合并若按完成顺序而非页面顺序累加，这里会抖动）。
func TestScanMultiPageTechnologiesStable(t *testing.T) {
	srv, _ := newMultiPageSite(t)
	eng := newMultiPageEngine(t)

	var first []string
	for round := 0; round < 3; round++ {
		res := eng.Scan(srv.URL, Options{Deep: true, Checks: "none"}, nil, nil)
		if res.Error != "" {
			t.Fatalf("扫描不应报错: %s", res.Error)
		}
		if len(res.Pages) != 4 {
			t.Fatalf("应采集 4 页，实际 %d: %+v", len(res.Pages), res.Pages)
		}
		if len(res.Technologies) == 0 {
			t.Fatal("指纹识别不应为空")
		}
		got := make([]string, 0, len(res.Technologies))
		for _, tech := range res.Technologies {
			got = append(got, fmt.Sprintf("%s|%s|%d|%s", tech.Name, tech.Version, tech.Confidence, strings.Join(tech.Evidence, ";")))
		}
		if round == 0 {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("第 %d 轮 Technologies 条数变化: %d vs %d", round, len(got), len(first))
		}
		for i := range first {
			if got[i] != first[i] {
				t.Fatalf("第 %d 轮第 %d 条技术不一致（并行合并顺序不稳定）:\n got=%q\n want=%q",
					round, i, got[i], first[i])
			}
		}
	}
}

// TestScanProgressCallbackSerial 进度回调不得在并行区并发调用。
func TestScanProgressCallbackSerial(t *testing.T) {
	srv, _ := newMultiPageSite(t)
	eng := newMultiPageEngine(t)

	var inFlight, maxInFlight, calls int32
	res := eng.Scan(srv.URL, Options{Deep: true, Checks: "none"},
		func(p int, msg string) {
			cur := atomic.AddInt32(&inFlight, 1)
			for {
				old := atomic.LoadInt32(&maxInFlight)
				if cur <= old || atomic.CompareAndSwapInt32(&maxInFlight, old, cur) {
					break
				}
			}
			atomic.AddInt32(&calls, 1)
			atomic.AddInt32(&inFlight, -1)
		}, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错: %s", res.Error)
	}
	if atomic.LoadInt32(&calls) < 3 {
		t.Fatalf("进度回调过少: %d", calls)
	}
	if got := atomic.LoadInt32(&maxInFlight); got != 1 {
		t.Fatalf("进度回调出现并发调用: maxInFlight=%d", got)
	}
}

// TestScanFaviconFetchedOnce 4 页扫描 favicon 只采集一次（并行化不放大请求）。
func TestScanFaviconFetchedOnce(t *testing.T) {
	srv, faviconHits := newMultiPageSite(t)
	eng := newMultiPageEngine(t)
	res := eng.Scan(srv.URL, Options{Deep: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错: %s", res.Error)
	}
	if got := atomic.LoadInt32(faviconHits); got != 1 {
		t.Fatalf("favicon 请求次数 = %d, want 1", got)
	}
}

// BenchmarkMultiPageScan 4 页 Deep 扫描端到端基准（指纹识别并行化回归口径）。
func BenchmarkMultiPageScan(b *testing.B) {
	srv, _ := newMultiPageSite(b)
	eng := newMultiPageEngine(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Scan(srv.URL, Options{Deep: true, Checks: "none"}, nil, nil)
		if res.Error != "" {
			b.Fatal(res.Error)
		}
		if len(res.Pages) != 4 || len(res.Technologies) == 0 {
			b.Fatalf("扫描结果不完整: pages=%d techs=%d", len(res.Pages), len(res.Technologies))
		}
	}
}
