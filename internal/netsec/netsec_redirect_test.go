package netsec

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCheckHTTPCrossHostRedirectNotFollowed V-07：跨主机 302 不再跟随。
// 此前 CheckHTTP 用裸 http.Client 自动跟随，被扫站点一个 302 就能让本服务
// 去请求内网/云元数据端点（绕过 target.Validate）。
func TestCheckHTTPCrossHostRedirectNotFollowed(t *testing.T) {
	var hit int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	// 用 localhost vs 127.0.0.1 构造"跨主机名"（同 IP，可验证确实没发出请求）
	_, port, err := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	redirectTo := "http://localhost:" + port + "/internal"
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}))
	defer public.Close()

	hits := CheckHTTP(public.URL)
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("跨主机重定向被跟随了：内部端点收到了请求")
	}
	// 未跟随 → 停留在初始 302（http），报"未跳转 HTTPS"；关键是没有继续外发请求
	if len(hits) != 1 || hits[0].Check != "http-https-redirect" {
		t.Fatalf("应停在 302 并报未跳转 HTTPS，实际 %+v", hits)
	}
}
