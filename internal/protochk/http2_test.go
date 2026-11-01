package protochk

// G10-2 HTTP/2 检查测试：h2c Upgrade 101 / 426 判定、普通 HTTP/1.1 不误报、
// TLS ALPN h2 协商（httptest EnableHTTP2）、仅 HTTP/1.1 的 TLS 站点不误报。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// h2cAcceptHandler 模拟接受 h2c Upgrade 的服务端（101 + 关闭）。
func h2cAcceptHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "h2c") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
}

// h2cRequiredHandler 模拟要求 h2c 的服务端（426 + Upgrade: h2c）。
func h2cRequiredHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Upgrade", "h2c")
	w.WriteHeader(http.StatusUpgradeRequired)
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

func TestCheckHTTP2H2CEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(h2cAcceptHandler))
	defer srv.Close()
	fs, err := CheckHTTP2(context.Background(), srv.URL, Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(fs) != 1 || fs[0].Kind != KindH2CEnabled {
		t.Fatalf("应报 h2c-enabled，实得 %+v", fs)
	}
	if fs[0].Severity == "" || fs[0].Detail == "" {
		t.Fatalf("Finding 字段不完整：%+v", fs[0])
	}
}

func TestCheckHTTP2H2CRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(h2cRequiredHandler))
	defer srv.Close()
	fs, err := CheckHTTP2(context.Background(), srv.URL, Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(fs) != 1 || fs[0].Kind != KindH2CEnabled || !strings.Contains(fs[0].Detail, "426") {
		t.Fatalf("426+Upgrade: h2c 应报 h2c-enabled，实得 %+v", fs)
	}
}

func TestCheckHTTP2NoH2C(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(okHandler))
	defer srv.Close()
	fs, err := CheckHTTP2(context.Background(), srv.URL, Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("普通 HTTP/1.1 站点不应报 h2c：%+v", fs)
	}
	// 同一站点经 Check 分派也应无 Finding。
	if fs, err := Check(context.Background(), srv.URL, Options{}); err != nil || len(fs) != 0 {
		t.Fatalf("Check 分派 HTTP/2 检查异常：fs=%+v err=%v", fs, err)
	}
}

func TestCheckHTTP2TLSH1Only(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(okHandler))
	defer srv.Close()
	fs, err := CheckHTTP2(context.Background(), srv.URL, Options{Insecure: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("只支持 HTTP/1.1 的 TLS 站点不应报 h2：%+v", fs)
	}
}

func TestCheckHTTP2TLSALPN(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(okHandler))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	fs, err := CheckHTTP2(context.Background(), srv.URL, Options{Insecure: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(fs) != 1 || fs[0].Kind != KindH2ALPNEnabled {
		t.Fatalf("启用 HTTP/2 的站点应报 h2-alpn-enabled，实得 %+v", fs)
	}
	if !strings.Contains(strings.ToLower(fs[0].Detail), "h2") {
		t.Fatalf("Detail 应说明 ALPN/HTTP2 证据：%+v", fs[0])
	}
}

func TestCheckHTTP2InvalidInput(t *testing.T) {
	if _, err := CheckHTTP2(context.Background(), "wss://example.com", Options{}); err == nil {
		t.Fatal("非 http/https URL 应报错")
	}
	if _, err := CheckHTTP2(context.Background(), "", Options{}); err == nil {
		t.Fatal("空 URL 应报错")
	}
	if _, err := Check(context.Background(), "not a url", Options{}); err == nil {
		t.Fatal("非法 URL 应报错")
	}
}

func TestCheckHTTP2Unreachable(t *testing.T) {
	// 关闭的服务端 → 连接失败返回错误（不 panic、不误报）。
	srv := httptest.NewServer(http.HandlerFunc(okHandler))
	addr := srv.URL
	srv.Close()
	_, err := CheckHTTP2(context.Background(), addr, Options{Timeout: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("不可达目标应返回错误")
	}
}
