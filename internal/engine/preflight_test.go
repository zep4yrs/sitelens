package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestPreflightAndHomeReuse 预检：1 次只读 GET 取标题/服务器/正文；
// 开始扫描时复用该响应 → 目标侧总请求仍为 1（不重复请求首页）。
func TestPreflightAndHomeReuse(t *testing.T) {
	var mu sync.Mutex
	count := 0
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Server", "nginx-test")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><head><title>预检页</title></head><body>ok</body></html>")
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.Resolve = false // 允许 127.0.0.1 夹具
	e := New(cfg, nil, nil)

	pf, err := e.Preflight(srv.URL, Options{})
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if pf.Status != 200 || pf.Title != "预检页" || pf.Server != "nginx-test" {
		t.Fatalf("预检字段错误: %+v", pf)
	}
	if pf.Body == "" || pf.ResponseMS < 0 {
		t.Fatalf("预检正文/耗时缺失: body=%d ms=%d", len(pf.Body), pf.ResponseMS)
	}
	mu.Lock()
	n := count
	mu.Unlock()
	if n != 1 {
		t.Fatalf("预检应只发 1 次请求，实得 %d", n)
	}

	if !pf.ValidFor(srv.URL, "", time.Now()) {
		t.Fatal("刚生成的预检应可复用")
	}
	if pf.ValidFor(srv.URL+"/other", "", time.Now()) {
		t.Fatal("URL 不一致不应复用")
	}
	expired := *pf
	expired.CreatedAt = time.Now().Add(-3 * time.Minute)
	if expired.ValidFor(srv.URL, "", time.Now()) {
		t.Fatal("过期预检不应复用")
	}

	res := e.Scan(srv.URL, Options{Preflight: pf, Deep: false, Checks: "none"},
		func(int, string) {}, func() bool { return false })
	mu.Lock()
	n = count
	gotPaths := append([]string{}, paths...)
	mu.Unlock()
	// 复用预检后：首页不再请求；扫描自身仍可能取 favicon 等附带资源。
	if n != 2 {
		t.Fatalf("复用预检后目标侧总请求应为 2（预检 1 + favicon 1），实得 %d paths=%v", n, gotPaths)
	}
	homeCount := 0
	for _, p := range gotPaths {
		if p == "/" {
			homeCount++
		}
	}
	if homeCount != 1 {
		t.Fatalf("首页应只请求 1 次（预检复用），实得 %d paths=%v", homeCount, gotPaths)
	}
	if res.Diagnostics == nil || !res.Diagnostics.PreflightReused {
		t.Fatalf("诊断应标注 preflight_reused=true: %+v", res.Diagnostics)
	}

	// 不传预检：首页正常抓取 → 再加 1 次首页请求
	_ = e.Scan(srv.URL, Options{Deep: false, Checks: "none"},
		func(int, string) {}, func() bool { return false })
	mu.Lock()
	n = count
	mu.Unlock()
	if n != 4 {
		t.Fatalf("无预检时应重新请求首页（累计 4 次），实得 %d", n)
	}
}

// TestPreflightBlockedResponse 预检被 WAF 拦截时保留 Blocked/BlockReason，
// 复用后扫描按 WAF 终止逻辑处理（不产生判定）。
func TestPreflightBlockedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "abc")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "blocked")
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.Scan.Resolve = false
	e := New(cfg, nil, nil)
	pf, err := e.Preflight(srv.URL, Options{})
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if !pf.Blocked || pf.BlockReason == "" {
		t.Fatalf("应识别为 WAF 拦截: %+v", pf)
	}
	resp := pf.Response()
	if resp == nil || !resp.Blocked || resp.Status != http.StatusForbidden {
		t.Fatalf("复用响应应保留拦截标记: %+v", resp)
	}
}
