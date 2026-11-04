package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
)

// dirFindingSite 靶站：首页链接到一个自带目录索引的后台上传目录，
// 以及一个可直读的备份文件（词表里都没有这些路径）。
func dirFindingSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
<a href="/upload/">上传中心</a><a href="/db-backup.sql">备份</a>
</body></html>`))
	})
	mux.HandleFunc("/upload/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload/" {
			_, _ = w.Write([]byte("<html><title>Pass-01</title>upload page</html>"))
			return
		}
		_, _ = w.Write([]byte("<html><head><title>Index of /upload/</title></head>" +
			"<body><h1>Index of /upload/</h1><a href=\"../\">../</a></body></html>"))
	})
	mux.HandleFunc("/db-backup.sql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("-- MySQL dump\nCREATE TABLE users(id int);\n" + strings.Repeat("x", 40)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestDirFindingsEnterVerified：目录/端点类发现必须进 verified
// （此前只落 Extras["dir"]，报告主体看不见 = 等于没报）。
func TestDirFindingsEnterVerified(t *testing.T) {
	srv := dirFindingSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Crawler.MaxPages = 8
	e := New(cfg, nil, nil)
	res := e.Scan(srv.URL, Options{Deep: true, DirScan: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}

	byCheck := map[string]string{} // check → url
	for _, v := range res.Verified {
		check, _ := v["check"].(string)
		url, _ := v["url"].(string)
		if check == "dir-listing" || check == "exposed-endpoint" {
			byCheck[check] = url
		}
	}
	if !strings.Contains(byCheck["dir-listing"], "/upload") {
		t.Fatalf("目录列表未进 verified：%v", byCheck)
	}
	if !strings.Contains(byCheck["exposed-endpoint"], "db-backup.sql") {
		t.Fatalf("可直读备份未进 verified：%v", byCheck)
	}
	// 证据链要带来源回链
	for _, v := range res.Verified {
		if v["check"] == "exposed-endpoint" {
			if ev, _ := v["evidence"].(string); !strings.Contains(ev, "来源") {
				t.Errorf("端点发现缺少来源回链：%q", ev)
			}
		}
	}
}

// TestDirFindingFiltered：只有「路径存在」语义的命中（普通目录/入口页）
// 不进 verified——发现列表要有缺陷语义，不是路径清单。
func TestDirFindingFiltered(t *testing.T) {
	cases := []struct {
		h     modules.PageHit
		check string
	}{
		{modules.PageHit{Path: "/admin", Status: 200}, ""},
		{modules.PageHit{Path: "/api/", Status: 200}, ""},
		{modules.PageHit{Path: "/upload.php", Status: 200}, ""},
		{modules.PageHit{Path: "/upload/index.php", Status: 200}, ""},
		{modules.PageHit{Path: "/x.zip", Status: 200}, "exposed-endpoint"},
		{modules.PageHit{Path: "/x.env", Status: 200}, "exposed-endpoint"},
		// 5.2.3：敏感形态路径返回 HTML = 兜底/拦截页，不是文件。
		{modules.PageHit{Path: "/x.zip", Status: 200, ContentType: "text/html; charset=utf-8"}, ""},
		{modules.PageHit{Path: "/x.yml", Status: 200, ContentType: "text/html"}, ""},
		{modules.PageHit{Path: "/x.zip", Status: 200, ContentType: "application/zip"}, "exposed-endpoint"},
		{modules.PageHit{Path: "/x.yml", Status: 200, ContentType: "text/yaml"}, "exposed-endpoint"},
		{modules.PageHit{Path: "/dir", Status: 200, DirIndex: true}, "dir-listing"},
		{modules.PageHit{Path: "/a", Status: 403, Bypass: "X-Forwarded-For"}, "dir-bypass-403"},
	}
	for _, c := range cases {
		got, _ := dirFindingOf(c.h)
		if got != c.check {
			t.Fatalf("dirFindingOf(%+v)=%q want %q", c.h, got, c.check)
		}
	}
}

// TestFullWordlistUnion：全量词表并集非空且覆盖 upload 端点族
// （默认 1887 条保守词表里 upload 端点一个都没有）。
func TestFullWordlistUnion(t *testing.T) {
	words := fullWordlistUnion("../../data/wordlists")
	found := false
	for _, w := range words {
		if w == "upload.php" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("全量词表并集应含 upload.php，实得 %d 条", len(words))
	}
}

// TestDirScanCatchAllNotVerified 5.2.3 回归：站点对所有路径返回 200 同一
// 兜底页（WAF/Next.js catch-all 实测形态）时，不得产生目录/端点类发现。
func TestDirScanCatchAllNotVerified(t *testing.T) {
	const page = `<html><head><title>404</title></head><body>` +
		`<a href="/db-backup.sql">backup</a><a href="/upload/">upload</a></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Crawler.MaxPages = 4
	e := New(cfg, nil, nil)
	res := e.Scan(srv.URL, Options{Deep: true, DirScan: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	for _, v := range res.Verified {
		switch v["check"] {
		case "exposed-endpoint", "dir-listing":
			t.Fatalf("catch-all 兜底页不应产生目录类发现：%v", v)
		}
	}
}

// TestDirVerifiedEntryLowConfidence B2-01 接线：模块层标记 LowConfidence 的
// 目录命中必须"保留但降级"——severity 降为 low、标题与证据标注低置信、
// 并带 low_confidence 标记；可确证的命中保持原有严重度（不能被一起降级）。
func TestDirVerifiedEntryLowConfidence(t *testing.T) {
	// 低置信：敏感后缀 200，但无法确证是真文件（无魔数/拦截特征/非 JSON 信封）。
	h := modules.PageHit{
		URL: "http://t.example/config.yml", Path: "/config.yml",
		Status: 200, ContentType: "text/plain", LowConfidence: true,
	}
	m := dirVerifiedEntry(h)
	if m == nil {
		t.Fatalf("低置信命中不应被丢弃（漏报同样有代价）")
	}
	if m["severity"] != "low" {
		t.Fatalf("低置信命中 severity 应为 low，实际 %v", m["severity"])
	}
	if m["low_confidence"] != true {
		t.Fatalf("应带 low_confidence 标记：%v", m)
	}
	if title, _ := m["title"].(string); !strings.Contains(title, "低置信") {
		t.Fatalf("标题应标注低置信：%q", title)
	}
	if ev, _ := m["evidence"].(string); !strings.Contains(ev, "低置信") {
		t.Fatalf("证据应标注低置信：%q", ev)
	}

	// 非低置信：同样路径但内容类型可确证，严重度保持 high（不被误降级）。
	h2 := modules.PageHit{
		URL: "http://t.example/config.yml", Path: "/config.yml",
		Status: 200, ContentType: "text/yaml",
	}
	m2 := dirVerifiedEntry(h2)
	if m2 == nil {
		t.Fatalf("可确证命中不应被丢弃")
	}
	if m2["severity"] != "high" {
		t.Fatalf("可确证命中 severity 应保持 high，实际 %v", m2["severity"])
	}
	if _, ok := m2["low_confidence"]; ok {
		t.Fatalf("可确证命中不应带 low_confidence：%v", m2)
	}

	// 无缺陷语义的普通入口页仍返回 nil（不因低置信标记而进发现）。
	if got := dirVerifiedEntry(modules.PageHit{Path: "/index.php", Status: 200}); got != nil {
		t.Fatalf("普通入口页不应进发现：%v", got)
	}
}
