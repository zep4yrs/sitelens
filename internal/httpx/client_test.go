// httpx 客户端测试：重定向逐跳校验的 resolve 姿态、Cookie 透传。
package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRedirectFollowLocalDefault 默认姿态（resolve=false，本地靶场矩阵
// 用途）：回环目标的重定向正常跟随——修复前逐跳校验写死 resolve=true，
// 私网/回行目标一跳就被 SSRF 拦截。
func TestRedirectFollowLocalDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(0)
	resp, err := c.GetFollow(srv.URL + "/a")
	if err != nil {
		t.Fatalf("回环重定向应正常跟随: %v", err)
	}
	if !strings.Contains(resp.Body, "done") {
		t.Fatalf("未到达最终页: %+v", resp)
	}
}

// TestRedirectSSRFBlockOnResolve resolve=true（公网默认）时回环重定向
// 目标必须被拦截——防公网目标重定向进内网的 SSRF。
func TestRedirectSSRFBlockOnResolve(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewWithOptions(ClientOptions{Resolve: true})
	if _, err := c.GetFollow(srv.URL + "/a"); err == nil {
		t.Fatal("resolve=true 时回环重定向目标应被拦截")
	}
}

// TestAuthCookiePassthrough 授权 Cookie 附加到每个请求。
func TestAuthCookiePassthrough(t *testing.T) {
	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewWithOptions(ClientOptions{AuthCookie: "security=low; PHPSESSID=abc"})
	if _, err := c.GetFollow(srv.URL); err != nil {
		t.Fatal(err)
	}
	if seen != "security=low; PHPSESSID=abc" {
		t.Fatalf("Cookie 未透传: %q", seen)
	}
}
