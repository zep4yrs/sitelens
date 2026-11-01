package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// genericHTML 典型的「200 兜底/拦截页」：状态码不是 404，正文是通用错误页。
const genericHTML = `<html><head><title>404</title></head><body>not found</body></html>`

func respOf(status int, ct, body string) *httpx.Response {
	return &httpx.Response{
		Status:  status,
		Headers: map[string]string{"Content-Type": ct},
		Body:    body,
	}
}

// TestLooksGenericPageTable 5.2.3 误报修复：200 + 通用兜底页不得当成真实文件。
func TestLooksGenericPageTable(t *testing.T) {
	base := soft404Baseline{
		sizes:  map[int]bool{7371: true},
		hashes: map[string]bool{bodyDigest(strings.Repeat("x", 7371)): true},
	}
	cases := []struct {
		name string
		path string
		r    *httpx.Response
		want bool
	}{
		{"HTML 冒充 yml", "/.codacy.yml", respOf(200, "text/html; charset=utf-8", genericHTML), true},
		{"HTML 冒充 zip", "/www.zip", respOf(200, "text/html", genericHTML), true},
		{"无 CT 的 HTML 冒充 env", "/.env", respOf(200, "", "<!DOCTYPE html><html></html>"), true},
		{"真实 yaml", "/.codacy.yml", respOf(200, "text/yaml", "rules:\n  - id: 1\n"), false},
		{"真实 zip", "/www.zip", respOf(200, "application/zip", "PK\x03\x04rest"), false},
		{"JSON 冒充 zip", "/www.zip", respOf(200, "application/json", `{"code":403}`), true},
		{"命中软404基线哈希", "/db.sql", respOf(200, "text/plain", strings.Repeat("x", 7371)), true},
		{"WAF 拦截响应", "/.env", &httpx.Response{Status: 200, Blocked: true, Body: "anything"}, true},
		{"非敏感路径的目录索引页", "/upload/",
			respOf(200, "text/html", "<html><title>Index of /upload/</title><h1>Index of /upload/</h1></html>"), false},
	}
	for _, c := range cases {
		if got := looksGenericPage(c.path, c.r, base); got != c.want {
			t.Fatalf("%s: looksGenericPage=%v want %v", c.name, got, c.want)
		}
	}
}

// TestSoft404BaselineCapturesSensitiveShape 基线必须探测敏感后缀形态路径：
// WAF/兜底页常只对这种路径回 200，纯随机名拿不到它的尺寸/正文。
func TestSoft404BaselineCapturesSensitiveShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, genericHTML)
	}))
	defer srv.Close()

	b := soft404BaselineOf(client(), srv.URL)
	if !b.hashes[bodyDigest(genericHTML)] || !b.sizes[len(genericHTML)] {
		t.Fatalf("基线未收录 200 兜底页：sizes=%v hashes=%v", b.sizes, b.hashes)
	}
}

// TestDirScanSuppressesCatchAll 任意路径都回同一 200 兜底页的站点，
// 不得产生任何目录/端点命中。
func TestDirScanSuppressesCatchAll(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{"a.yml", "b.env", "www.zip"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, genericHTML)
	}))
	defer srv.Close()

	hits := DirScan(client(), srv.URL, benchCfg(dir), nil, nil)
	if len(hits) != 0 {
		t.Fatalf("catch-all 站点不应产生命中，got %d: %+v", len(hits), hits)
	}
}

// TestDirScanKeepsRealSensitiveFiles 真实 yml/zip 仍必须命中（不能过度过滤）。
func TestDirScanKeepsRealSensitiveFiles(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{".codacy.yml", "www.zip"})
	mux := http.NewServeMux()
	mux.HandleFunc("/.codacy.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		fmt.Fprint(w, "rules:\n  - id: 1\n")
	})
	mux.HandleFunc("/www.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		fmt.Fprint(w, "PK\x03\x04"+strings.Repeat("z", 40))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, genericHTML)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hits := DirScan(client(), srv.URL, benchCfg(dir), nil, nil)
	got := map[string]PageHit{}
	for _, h := range hits {
		got[h.Path] = h
	}
	if _, ok := got["/.codacy.yml"]; !ok {
		t.Fatalf("真实 yml 应命中：%+v", hits)
	}
	if _, ok := got["/www.zip"]; !ok {
		t.Fatalf("真实 zip 应命中：%+v", hits)
	}
	for _, h := range hits {
		if h.ContentType == "" || h.BodySHA256 == "" {
			t.Fatalf("命中应带内容类型与正文哈希（证据留痕）：%+v", h)
		}
	}
}
