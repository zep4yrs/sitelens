package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestBudgetDegradesOnTinyLimit：MaxMemoryMB 压到极小值恒超预算，
// 降档动作应记入 Extras["budget"]（爬取减半 + 跳过主动模块）。
func TestBudgetDegradesOnTinyLimit(t *testing.T) {
	ballast := make([]byte, 8<<20) // 8MB 存活基线：保证全程超 1MB 预算
	defer func() { _ = ballast }()
	srv := graphSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Scan.MaxMemoryMB = 1
	e := New(cfg, nil, nil)
	res := e.Scan(srv.URL, Options{Deep: true, Passive: true, DirScan: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	raw, ok := res.Extras["budget"]
	if !ok {
		t.Fatalf("应记录降档动作，Extras 键: %v", res.Extras)
	}
	degr, ok := raw.([]string)
	if !ok || len(degr) == 0 {
		t.Fatalf("budget 应为非空 []string: %#v", raw)
	}
	joined := strings.Join(degr, ";")
	if !strings.Contains(joined, "爬取页数减半") {
		t.Errorf("应有爬取降档: %v", degr)
	}
	if !strings.Contains(joined, "跳过主动模块") {
		t.Errorf("应跳过主动模块: %v", degr)
	}
}

// TestBudgetNoDegradeUnderDefault：默认 768MB 预算下小靶站不应触发降档。
func TestBudgetNoDegradeUnderDefault(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true, Checks: "core"})
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	if _, ok := res.Extras["budget"]; ok {
		t.Fatalf("默认预算不应降档: %v", res.Extras["budget"])
	}
}

// TestPagesRetainedCap：PagesRetained 上限裁剪驻留清单并计数省略页。
func TestPagesRetainedCap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a><a href="/d">d</a></body></html>`))
	})
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><body>page</body></html>"))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Crawler.MaxPages = 6
	cfg.Scan.PagesRetained = 2
	e := New(cfg, nil, nil)
	res := e.Scan(srv.URL, Options{Deep: true, Passive: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	if len(res.Pages) != 2 {
		t.Fatalf("应裁剪到 2 页，实得 %d", len(res.Pages))
	}
	om, _ := res.Extras["pages_omitted"].(int)
	if om < 1 {
		t.Fatalf("应记录省略页数: %v", res.Extras["pages_omitted"])
	}
}

// TestPagesRetainedDefault：默认驻留上限 2000 页（A8 基线）。
func TestPagesRetainedDefault(t *testing.T) {
	if n := config.Default().Scan.PagesRetained; n != 2000 {
		t.Fatalf("PagesRetained 默认应为 2000，实得 %d", n)
	}
}
