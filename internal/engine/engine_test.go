package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

const homeHTML = `<html><head><title>测试站</title>
<meta name="generator" content="WordPress 6.4.2">
</head><body>
<a href="/about">关于</a>
<a href="https://外部.example.com/x">外链</a>
</body></html>`

func newEngineSite(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Add("Set-Cookie", "wp_test=1; Path=/")
		w.Header().Add("Set-Cookie", "session=abc; Path=/; HttpOnly")
		strings.NewReader(homeHTML).WriteTo(w)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404) // 404 页不再爬
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func loadMatcher(t *testing.T) *sitelens.Matcher {
	t.Helper()
	m, err := sitelens.LoadMatcher("../../data/go/technologies.json")
	if err != nil {
		t.Skipf("指纹库不可用，跳过: %v", err)
	}
	return m
}

func TestScanPipeline(t *testing.T) {
	srv := newEngineSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false // SSRF 防护保留开启，仅测试放行本机回环
	cfg.Scan.RateIntervalMS = 0
	e := New(cfg, loadMatcher(t), nil)

	var msgs []string
	res := e.Scan(srv.URL, Options{Deep: true, Passive: true, Checks: "none"},
		func(p int, msg string) { msgs = append(msgs, msg) }, nil)

	if res.Error != "" {
		t.Fatalf("扫描不应报错: %s", res.Error)
	}
	if res.Title != "测试站" {
		t.Fatalf("标题未提取: %q", res.Title)
	}
	if res.Status != 200 || res.IP == "" || res.Duration < 0 {
		t.Fatalf("页面信息不完整: status=%d ip=%q dur=%v", res.Status, res.IP, res.Duration)
	}
	if len(msgs) < 3 {
		t.Fatalf("进度回调过少: %v", msgs)
	}

	// 指纹：generator meta 应命中 WordPress
	foundWP := false
	for _, tech := range res.Technologies {
		if strings.EqualFold(tech.Name, "WordPress") {
			foundWP = true
			if !strings.Contains(tech.Version, "6.4") {
				t.Fatalf("版本抽取失败: %q", tech.Version)
			}
		}
	}
	if !foundWP {
		t.Fatalf("WordPress 指纹未命中: %+v", res.Technologies)
	}

	// 安全评分：只配了 x-content-type-options 一个头 → 10 分 F 级
	if res.Security == nil || res.Security.Score != 10 || res.Security.Grade != "F" {
		t.Fatalf("安全评分不符: %+v", res.Security)
	}

	// 页面：外链不爬；/about 是 404 会被 GetFollow 返回后仍记录（首页已采，爬虫不跟进 404）
	if len(res.Pages) != 1 {
		t.Fatalf("404 子页不应入结果页: %+v", res.Pages)
	}

	// JSON 键位契约：与 Python to_dict() 对齐的关键键必须存在
	raw := mustJSON(t, res)
	for _, key := range []string{
		`"url"`, `"host"`, `"title"`, `"status"`, `"ip"`, `"response_time_ms"`,
		`"scanned_at"`, `"duration"`, `"error"`, `"security"`, `"technologies"`,
		`"vulnerabilities"`, `"verified"`, `"extras"`, `"pages"`,
	} {
		if !strings.Contains(raw, key) {
			t.Fatalf("结果 JSON 缺键 %s: %s", key, raw[:min(300, len(raw))])
		}
	}
}

func TestScanBadTarget(t *testing.T) {
	e := New(nil, nil, nil)
	res := e.Scan("ftp://x", Options{}, nil, nil)
	if res.Error == "" {
		t.Fatal("非法协议应报错")
	}
	res = e.Scan("", Options{}, nil, nil)
	if res.Error == "" {
		t.Fatal("空目标应报错")
	}
}

func TestScanUnreachable(t *testing.T) {
	e := New(nil, nil, nil)
	// 本机保留端口的未监听地址：连接失败进 Error 不 panic
	res := e.Scan("http://127.0.0.1:1/", Options{Deep: false}, nil, nil)
	if res.Error == "" {
		t.Fatal("不可达目标应报错")
	}
}

func TestTechAccMerge(t *testing.T) {
	acc := newTechAcc()
	acc.add("WordPress", "https://wordpress.org", "6.4", "meta generator", 60, []string{"cms"})
	acc.add("WordPress", "", "", "header x-powered", 60, nil) // 二次命中：+5
	acc.add("Nginx", "", "1.24", "header server", 80, nil)
	list := acc.list()
	if len(list) != 2 {
		t.Fatalf("同名技术未合并: %+v", list)
	}
	wp := list[0]
	if wp.Name != "WordPress" || wp.Confidence != 65 || len(wp.Evidence) != 2 {
		t.Fatalf("证据/置信合并失败: %+v", wp)
	}
	if wp.Version != "6.4" {
		t.Fatalf("版本应取首识别: %q", wp.Version)
	}
}

func TestNucleiWiring(t *testing.T) {
	srv := newEngineSite(t)
	// 临时模板库：一条必然命中的 nuclei 模板（目标首页含 "engineSite" 标记词）
	dir := t.TempDir()
	tpl := `id: engine-site-marker
info:
  name: Engine Site Marker
  severity: low
  tags: enginesite
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "engineSiteMarkerXYZ"
`
	if err := os.WriteFile(filepath.Join(dir, "marker.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	// 目标页面写入标记词：newEngineSite 的页面不含它，这里单起一个
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		strings.NewReader("<html>engineSiteMarkerXYZ present</html>").WriteTo(w)
	})
	site2 := httptest.NewServer(mux)
	defer site2.Close()

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Store.DataDir = t.TempDir()
	cfg.Checks.NucleiDir = dir
	cfg.Checks.NucleiCap = 5
	e := New(cfg, nil, nil)

	res := e.Scan(site2.URL, Options{Checks: "all"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描报错: %s", res.Error)
	}
	found := false
	for _, v := range res.Verified {
		if v["src"] == "nuclei" {
			found = true
			if v["check"] != "nuclei-engine-site-marker" {
				t.Fatalf("nuclei check id 异常: %v", v["check"])
			}
		}
	}
	if !found {
		t.Fatalf("nuclei 模板未命中: %+v", res.Verified)
	}
	_ = srv
}

// ---- helpers ----

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("JSON 序列化失败: %v", err)
	}
	return string(b)
}
