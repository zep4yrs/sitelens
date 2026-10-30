// 效率轮 E2 回归：diagnostics 账本、WAF/限流拦截隔离（blocked 不参与判定）。
package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// e2Site 4 页小站：首页链到 /a、/b；/a 有表单；可选把 /blocked 做成 429。
func e2Site(t *testing.T, blockedPath bool, reqs *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if reqs != nil {
				atomic.AddInt32(reqs, 1)
			}
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if reqs != nil {
			atomic.AddInt32(reqs, 1)
		}
		_, _ = w.Write([]byte(`<html><head><title>e2</title></head><body>
<a href="/a">a</a><a href="/b">b</a>
<a href="/refl?q=hello">refl</a>
<form method="post" action="/comment"><input name="text"></form>
</body></html>`))
	})
	mux.HandleFunc("/a", serve(`<html><body><a href="/b">b</a></body></html>`))
	mux.HandleFunc("/b", serve(`<html><body>b</body></html>`))
	// 反射点：q 原样回显（DAST 应命中）；blockedPath 时整点返回 429。
	mux.HandleFunc("/refl", func(w http.ResponseWriter, r *http.Request) {
		if reqs != nil {
			atomic.AddInt32(reqs, 1)
		}
		if blockedPath {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusForbidden) // 403 无 WAF 头不会判 blocked
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		_, _ = w.Write([]byte("<html>" + r.URL.Query().Get("q") + "</html>"))
	})
	mux.HandleFunc("/comment", serve(`<html>comment ok</html>`))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func e2Engine(t *testing.T, rateMS int, rateMode string) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = rateMS
	cfg.Crawler.MaxPages = 4
	if rateMode != "" {
		cfg.Scan.RateMode = rateMode
	}
	return New(cfg, nil, nil)
}

// TestScanDiagnosticsAdditive 诊断账本：每阶段请求/耗时/去重命中/blocked/RPS
// 可读，且 rate 配置按实际生效值回传（additive 键，不影响既有字段）。
func TestScanDiagnosticsAdditive(t *testing.T) {
	srv := e2Site(t, false, nil)
	eng := e2Engine(t, 0, "")
	res := eng.Scan(srv.URL, Options{Deep: true, DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错: %s", res.Error)
	}
	d := res.Diagnostics
	if d == nil {
		t.Fatal("Diagnostics 应存在（additive 诊断输出）")
	}
	if d.Requests <= 0 || d.AvgRPS <= 0 || d.DurationMS <= 0 {
		t.Fatalf("账本总量异常: %+v", d)
	}
	if d.RateMode != "balanced" || d.MaxRPS != 5 {
		t.Fatalf("rate 配置应回传默认 balanced/5: %+v", d)
	}
	need := map[string]bool{"home": false, "crawl": false, "security": false, "dast": false}
	for _, p := range d.Phases {
		if _, ok := need[p.Phase]; ok {
			need[p.Phase] = true
		}
	}
	for name, seen := range need {
		if !seen {
			t.Fatalf("诊断缺阶段 %q: %+v", name, d.Phases)
		}
	}
	// 去重命中应可观测（DAST benign 基线复用至少命中几次）。
	var dastPhase *PhaseDiagnostics
	for i := range d.Phases {
		if d.Phases[i].Phase == "dast" {
			dastPhase = &d.Phases[i]
		}
	}
	if dastPhase == nil || dastPhase.Requests <= 0 {
		t.Fatalf("DAST 阶段账本异常: %+v", d.Phases)
	}
	if d.DedupHits <= 0 {
		t.Fatalf("DAST benign 基线复用应产生去重命中: %+v", d)
	}
}

// TestScanBlockedHomeAborts 首页被 WAF/限流拦截：终止扫描、给出可读原因、
// blocked 计入诊断，且不产出任何发现（挑战页正文不参与判定）。
func TestScanBlockedHomeAborts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("<html>captcha challenge page</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := e2Engine(t, 0, "").Scan(srv.URL, Options{Deep: true, DAST: true}, nil, nil)
	if res.Error == "" || !strings.Contains(res.Error, "WAF") {
		t.Fatalf("首页被拦截应报错并说明原因，实际: %q", res.Error)
	}
	if len(res.Verified) != 0 || len(res.Vulnerabilities) != 0 {
		t.Fatalf("被拦截响应不得参与判定: %+v", res.Verified)
	}
	if res.Diagnostics == nil || res.Diagnostics.Blocked == 0 {
		t.Fatalf("blocked 应计入诊断: %+v", res.Diagnostics)
	}
}

// TestScanBlockedDASTNotJudged 被 WAF/限流拦截的 DAST 响应按「无响应」处理：
// 不产生反射 XSS 发现（WAF 回显 payload 不能当命中），blocked 计入诊断。
func TestScanBlockedDASTNotJudged(t *testing.T) {
	// /refl 对所有请求 429+Retry-After：DAST 的反射点必须判定为被拦截。
	srv := blockedReflSite(t)
	defer srv.Close()

	res := e2Engine(t, 0, "").Scan(srv.URL, Options{Deep: true, DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错（首页正常）: %s", res.Error)
	}
	for _, m := range res.Verified {
		if u, _ := m["url"].(string); strings.Contains(u, "/refl") {
			t.Fatalf("被拦截响应不得产出发现: %+v", m)
		}
	}
	if res.Diagnostics == nil || res.Diagnostics.Blocked == 0 {
		t.Fatalf("blocked 应计入诊断: %+v", res.Diagnostics)
	}
	if res.Diagnostics.WAFReasons == nil {
		t.Fatalf("拦截原因分布应可读: %+v", res.Diagnostics)
	}
}

// blockedReflSite 首页正常，/refl 一律 429（Retry-After 存在 → retry-after）。
func blockedReflSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>waf</title></head><body>
<a href="/refl?q=hello">refl</a></body></html>`))
	})
	mux.HandleFunc("/refl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
