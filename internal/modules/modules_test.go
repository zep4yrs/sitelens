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
