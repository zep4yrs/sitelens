package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestScopeGuardAllowedHosts 拨号层 ScopeGuard：白名单外的主机零请求拒绝。
func TestScopeGuardAllowedHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// 白名单不含 127.0.0.1 → 请求在拨号层被拒，服务端不应收到请求。
	blocked := NewWithOptions(ClientOptions{AllowedHosts: []string{"example.com"}, Timeout: 2 * time.Second})
	if _, err := blocked.GetFollow(srv.URL + "/"); err == nil ||
		!strings.Contains(err.Error(), "allow_hosts") {
		t.Fatalf("白名单外目标应被拒绝，实际 err=%v", err)
	}

	// 白名单命中 → 正常请求。
	allowed := NewWithOptions(ClientOptions{AllowedHosts: []string{"127.0.0.1"}, Timeout: 2 * time.Second})
	resp, err := allowed.GetFollow(srv.URL + "/")
	if err != nil {
		t.Fatalf("白名单内目标应放行：%v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("状态码 = %d，期望 200", resp.Status)
	}
}

// TestScopeGuardDialLayer 拨号层是最后一道闸：任何 host（含重定向逐跳、解析后的
// 连接地址）都要命中 allow_hosts。这里直接调 dialContext，不依赖网络。
func TestScopeGuardDialLayer(t *testing.T) {
	c := NewWithOptions(ClientOptions{AllowedHosts: []string{"example.com"}})
	for _, addr := range []string{"evil.example.org:443", "127.0.0.1:80", "10.0.0.1:22"} {
		if _, err := c.dialContext(context.Background(), "tcp", addr); err == nil ||
			!strings.Contains(err.Error(), "allow_hosts") {
			t.Fatalf("拨号层应拒绝白名单外地址 %s，实际 err=%v", addr, err)
		}
	}
}
