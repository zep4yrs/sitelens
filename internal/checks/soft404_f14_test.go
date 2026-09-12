package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
