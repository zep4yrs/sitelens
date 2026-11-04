package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// F14/B2 复扫回归：catch-all 404 站（正文回显请求路径，"404: /xxx" 形态）。
// 目标路径与探针路径不等长 → 原始长度门失配 → 此前必误报。
// 修正后以「剔除回显后」长度+前缀判定，命中必须被抑制。
func TestSoft404CatchAllEchoSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><h1>Not Found</h1><p>404: %s</p></html>", r.URL.Path)
	}))
	defer srv.Close()

	list := []Check{{
		ID:    "f14-probe",
		Path:  "/admin/wp-admin",
		Match: Match{Status: 200, Contains: []string{"Not Found"}},
		Title: "探测管理后台",
		Sev:   "high",
	}}

	hits := RunList(httpx.New(0), srv.URL, list, 4, nil, nil, nil)
	if len(hits) != 0 {
		t.Fatalf("catch-all 回显站应被软 404 抑制，实际命中: %+v", hits)
	}
}

// 对照组：真实存在的路径（内容与基线不同）不受软 404 抑制。
func TestSoft404RealPageNotSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/login" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>管理登录</title><form><input name=user><input name=pass type=password></form></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><h1>Not Found</h1><p>404: %s</p></html>", r.URL.Path)
	}))
	defer srv.Close()

	list := []Check{{
		ID:    "f14-real",
		Path:  "/admin/login",
		Match: Match{Status: 200, Contains: []string{"管理登录"}},
		Title: "管理登录页",
		Sev:   "medium",
	}}

	hits := RunList(httpx.New(0), srv.URL, list, 4, nil, nil, nil)
	if len(hits) != 1 {
		t.Fatalf("真实页面不应被软 404 误杀: %+v", hits)
	}
}

// TestSoft404DynamicLengthSuppressed B-01 回归：404 页中段含逐次变化的渲染耗时。
//
// 这是旧判据的致命场景：正文长度每次不同 → `len(body) == baseStripped`
// 恒失配 → 软 404 整站失效 → 任何 status-only check（bak-dump 等 high 级）
// 对任意 200 响应命中。新判据（前缀主判据 + 数字折叠 + 长度容差）必须抑制。
func TestSoft404DynamicLengthSuppressed(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 中段数字长度逐次变化：0.1s / 0.11s / 0.111s / 0.1111s
		fmt.Fprintf(w,
			"<html><head><title>Not Found</title></head><body><h1>404</h1><p>耗时 0.%s 秒</p></body></html>",
			strings.Repeat("1", int(n.Add(1)%4)+1))
	}))
	defer srv.Close()

	// 等价于内置 bak-dump：只有状态码，没有任何正文条件。
	list := []Check{{
		ID:    "bak-dump",
		Path:  "/dump.sql",
		Match: Match{Status: 200},
		Title: "数据库 dump 文件暴露",
		Sev:   "high",
	}}

	hits := RunList(httpx.New(0), srv.URL, list, 4, nil, nil, nil)
	if len(hits) != 0 {
		t.Fatalf("动态 404 页应被软 404 抑制（旧判据在此误报），实际命中: %+v", hits)
	}
}

// TestSoft404RealPageWithDigitsNotSuppressed 反例：真实页面即使含数字，
// 前缀与 404 页不同则不得被抑制（防「数字折叠」把真实页误杀）。
func TestSoft404RealPageWithDigitsNotSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/phpinfo.php" {
			fmt.Fprint(w, "<html><body><h1>PHP Version 8.2.1</h1><table>phpinfo()</table></body></html>")
			return
		}
		fmt.Fprint(w, "<html><head><title>Not Found</title></head><body><h1>404</h1></body></html>")
	}))
	defer srv.Close()

	list := []Check{{
		ID:    "phpinfo",
		Path:  "/phpinfo.php",
		Match: Match{Status: 200, Contains: []string{"phpinfo()"}},
		Title: "phpinfo 页面暴露",
		Sev:   "high",
	}}
	hits := RunList(httpx.New(0), srv.URL, list, 4, nil, nil, nil)
	if len(hits) != 1 {
		t.Fatalf("真实页面不应被软 404 误杀: %+v", hits)
	}
}
