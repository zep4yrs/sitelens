package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func benchCfg(wordlistDir string) config.ActiveConfig {
	return config.ActiveConfig{
		DirMaxPaths: 300, SubMaxWords: 2000, SubWorkers: 4,
		ShellMaxPaths: 200, WordlistDir: wordlistDir,
	}
}

func client() *httpx.Client { return httpx.New(0) }

// writeWordlist 自建确定性强的小字典（仓库字典是 SecLists 原始导入，
// 关键词位置不可控，测试用自备字典）。
func writeWordlist(t *testing.T, name string, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name),
		[]byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDirScanFindsAndFilters(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{
		"admin", "backup.zip", "sl-nope-probe", "# 注释行", "",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>后台</title>real admin page content</html>")
	})
	mux.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	// 其余路径：软404 形态（200 + 固定尺寸）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("notfound", 10))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := benchCfg(dir)
	hits := DirScan(client(), srv.URL, cfg, nil, nil)

	var admin, backup *PageHit
	for i := range hits {
		switch hits[i].Path {
		case "/admin":
			admin = &hits[i]
		case "/backup.zip":
			backup = &hits[i]
		}
	}
	if admin == nil || admin.Status != 200 || admin.Title != "后台" {
		t.Fatalf("/admin 应命中: %+v", hits)
	}
	if backup == nil || backup.Status != 403 {
		t.Fatalf("/backup.zip 应以 403 命中: %+v", backup)
	}
	for _, h := range hits {
		if strings.Contains(h.Path, "sl-nope-probe") {
			t.Fatalf("软404 基线未过滤: %+v", h)
		}
	}
}

func TestDirScanBypass403(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{"secret"})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 改写头绕过：请求根路径、声明真实路径，后端按头路由
		if r.Header.Get("X-Original-URL") == "/secret" {
			fmt.Fprint(w, "<html>bypassed secret content</html>")
			return
		}
		if r.URL.Path == "/secret" {
			w.WriteHeader(403)
			fmt.Fprint(w, "denied")
			return
		}
		fmt.Fprint(w, strings.Repeat("roothome", 10))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := benchCfg(dir)
	cfg.DirBypass403 = true
	hits := DirScan(client(), srv.URL, cfg, nil, nil)
	if len(hits) != 1 || hits[0].Status != 200 {
		t.Fatalf("绕过后应 200 命中: %+v", hits)
	}
	if hits[0].Bypass == "" {
		t.Fatalf("绕过成功应记录技术名: %+v", hits[0])
	}
}

func TestWebshellProbe(t *testing.T) {
	dir := writeWordlist(t, "shell_default.txt", []string{"shell.php", "cmd.jsp"})
	mux := http.NewServeMux()
	mux.HandleFunc("/shell.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "webshell body")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hits := WebshellProbe(client(), srv.URL, benchCfg(dir), nil, nil)
	if len(hits) != 1 || hits[0].Path != "/shell.php" || hits[0].Size == 0 {
		t.Fatalf("shell.php 应命中且 cmd.jsp 不应命中: %+v", hits)
	}
}

func TestSubdomainEnumWithFakeResolver(t *testing.T) {
	dir := writeWordlist(t, "subs_default.txt", []string{
		"www", "mail", "vpn", "ns1", "api",
	})
	cfg := benchCfg(dir)
	allow := map[string]bool{"www": true, "mail": true}
	resolve := func(host string) ([]string, error) {
		if allow[strings.TrimSuffix(host, ".example.com")] {
			return []string{"93.184.216.34"}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	found := SubdomainEnumWith("example.com", cfg, nil, nil, resolve)
	if len(found) != 2 {
		t.Fatalf("应恰好解析出 2 个子域: %+v", found)
	}
	for _, f := range found {
		if f != "www.example.com" && f != "mail.example.com" {
			t.Fatalf("结果域名异常: %s", f)
		}
	}
}

func TestCancelStopsDirScan(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{"a", "b", "c", "d"})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := benchCfg(dir)
	calls := 0
	hits := DirScan(client(), srv.URL, cfg, nil, func() bool {
		calls++
		return calls > 2
	})
	_ = hits // 提前取消不 panic 即可
}

// B18 回归：并发 worker 直接调用不加锁的消费者不得产生数据竞争
// （CI -race 下此前必报 WARNING: DATA RACE）。串行化由模块内部保证。
func TestProgressSerialized(t *testing.T) {
	dir := writeWordlist(t, "subs_default.txt", []string{"a", "b", "c", "d", "e", "f", "g", "h"})
	cfg := benchCfg(dir)
	cfg.SubWorkers = 8
	var seen []string // 故意不加锁的消费者：内部串行化后安全（race 探测点）
	_ = SubdomainEnumWith("example.com", cfg, func(done, total int, msg string) {
		seen = append(seen, msg)
	}, nil, func(host string) ([]string, error) {
		return nil, fmt.Errorf("no such host")
	})
	_ = seen
}

// fakeDirIndex 服务器：/upload/ 返回目录索引，/upload/evil.php 是可直读端点，
// /upload.php 也是端点（模拟 upload-labs 关卡页），词表里一个都没有。
func dirIndexServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/upload/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload/" {
			fmt.Fprint(w, "<html><title>Pass-01</title>请选择要上传的文件</html>")
			return
		}
		// Nginx 风格目录索引
		fmt.Fprint(w, "<html><head><title>Index of /upload/</title></head>"+
			"<body><h1>Index of /upload/</h1><a href=\"../\">../</a></body></html>")
	})
	mux.HandleFunc("/upload.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>Pass-01</title>upload labs level page</html>")
	})
	mux.HandleFunc("/dump.sql", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "-- MySQL dump\nCREATE TABLE users(id int);")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("notfound", 10))
	})
	return httptest.NewServer(mux)
}

// TestDirScanExtraFindsCrawledEndpoint 端点扩展：词表猜不到的端点
// （upload-labs 关卡这种自定义上传点）必须靠爬取到的链接补进来命中。
func TestDirScanExtraFindsCrawledEndpoint(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{"admin", "login"})
	srv := dirIndexServer(t)
	defer srv.Close()
	cfg := benchCfg(dir)

	// 旧路径（无扩展）：upload 端点一个都不在词表里 → 命中 0
	base := DirScan(client(), srv.URL, cfg, nil, nil)
	for _, h := range base {
		if strings.HasPrefix(h.Path, "/upload") {
			t.Fatalf("无扩展时不应命中 upload 端点，实得 %+v", h)
		}
	}

	// 扩展路径：爬取到的链接交进来 → 命中 upload 关卡页 + upload 目录索引
	extra := []string{srv.URL + "/upload.php", srv.URL + "/upload/"}
	viaOf := func(string) string { return srv.URL + "/index.php" }
	hits := DirScanExtra(client(), srv.URL, cfg, extra, viaOf, nil, nil)

	var gotIndex, gotLevel, gotVia bool
	for _, h := range hits {
		switch h.Path {
		case "/upload", "/upload/":
			gotIndex = h.DirIndex
			gotVia = h.Via != ""
		case "/upload.php":
			gotLevel = true
		}
	}
	if !gotIndex {
		t.Fatalf("upload 目录索引未识别为目录列表，hits=%+v", hits)
	}
	if !gotLevel {
		t.Fatalf("爬取到的 upload 端点未命中，hits=%+v", hits)
	}
	if !gotVia {
		t.Fatal("扩展命中缺少来源回链（Via）")
	}
}

// TestDirScanExtraDedupAndFilter 扩展候选的归一与过滤：
// 词表内重复请求要去掉、静态资源不探、跨域不探。
func TestDirScanExtraDedupAndFilter(t *testing.T) {
	inWords := map[string]bool{"admin": true}
	got := normalizeExtras([]string{
		"http://example.com/admin",          // 词表内 → 丢
		"http://example.com/assets/a.css",   // 静态资源 → 丢
		"http://other.com/x.php",            // 跨域 → 丢
		"http://example.com/upload.php",     // 收
		"http://example.com/upload.php?a=1", // 同路径去重 → 丢
		"http://example.com/deep/nested/x",  // 收
	}, nil, "http://example.com", inWords)
	if len(got) != 2 {
		t.Fatalf("扩展候选归一错误：%+v", got)
	}
	if got[0].Path != "/upload.php" || got[1].Path != "/deep/nested/x" {
		t.Fatalf("候选路径错误：%+v", got)
	}
}

// TestDirIndexMarkNegative 目录列表判定的反例：普通 HTML 页 / 非 HTML 响应
// 都不算目录索引（防"有 index 字样就报"）。
func TestDirIndexMarkNegative(t *testing.T) {
	cases := []struct {
		status int
		body   string
		ct     string
		want   bool
	}{
		{200, "<html><title>Index of /xyz</title></html>", "text/html; charset=utf-8", true},
		{200, "<html><h1>Index of /</h1><a href=\"../\">Parent Directory</a></html>", "text/html", true},
		{403, "<html><title>Index of /</title></html>", "text/html", false},           // 非 200
		{200, `{"index":"of /"}`, "application/json", false},                          // 非 HTML
		{200, "<html><title>首页</title>欢迎访问 index of / 目录</html>", "text/html", false}, // 无索引标记
	}
	for _, c := range cases {
		if got := dirIndexMark(c.status, c.body, c.ct); got != c.want {
			t.Fatalf("dirIndexMark(%d,%q,%q)=%v want %v", c.status, c.body, c.ct, got, c.want)
		}
	}
}
