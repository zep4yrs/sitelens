package server

// CP-09 资产提醒后端测试：证书到期成功/失败、端口探测、SSRF 校验与
// allow_hosts 授权白名单（错误必须 400 且零网络探测）。
//
// 路由由 Lead/server-store 接线，本测试直接调用 handler（hCertExpiry/hAssetPorts）。

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// tlsServerHostPort 起一个自签 TLS 测试站，返回 (host, port)。
func tlsServerHostPort(t *testing.T) (string, int) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析 TLS 测试站 URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("拆分 host/port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// freeClosedPort 返回一个刚释放、大概率无监听的本地端口。
func freeClosedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("申请空闲端口: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// assetURL 构造带 host 查询参数的请求路径。
func assetURL(ep, host string) string {
	return ep + "?host=" + url.QueryEscape(host)
}

// TestAssetCertExpiryOK 证书到期查询：自签 TLS 站应返回 ok=true 与 RFC3339 时间。
func TestAssetCertExpiryOK(t *testing.T) {
	s := newTasksTestServer(t, nil)
	host, port := tlsServerHostPort(t)

	code, m := callHandler(t, s.hCertExpiry, assetURL("/api/assets/cert-expiry", host+":"+strconv.Itoa(port)))
	if code != 200 {
		t.Fatalf("hCertExpiry = %d: %v", code, m)
	}
	if ok, _ := m["ok"].(bool); !ok {
		t.Fatalf("自签 TLS 站应探测成功: %v", m)
	}
	if got, _ := m["host"].(string); got != host {
		t.Fatalf("host 回显应为校验后主机名 %q，实际 %q", host, got)
	}
	notAfter, _ := m["not_after"].(string)
	if _, err := time.Parse(time.RFC3339, notAfter); err != nil {
		t.Fatalf("not_after 应为 RFC3339: %q", notAfter)
	}
	if days, _ := m["days_left"].(float64); days <= 0 {
		t.Fatalf("days_left 应 > 0（测试证书一年有效）: %v", m["days_left"])
	}
}

// TestAssetCertExpiryFail 端口无监听：ok=false 且字段齐全（查询结果非请求错误）。
func TestAssetCertExpiryFail(t *testing.T) {
	s := newTasksTestServer(t, nil)
	port := freeClosedPort(t)
	code, m := callHandler(t, s.hCertExpiry, assetURL("/api/assets/cert-expiry", "127.0.0.1:"+strconv.Itoa(port)))
	if code != 200 {
		t.Fatalf("探测失败应返回 200 查询结果，实际 %d: %v", code, m)
	}
	if ok, _ := m["ok"].(bool); ok {
		t.Fatalf("无监听端口不应探测成功: %v", m)
	}
	if notAfter, _ := m["not_after"].(string); notAfter != "" {
		t.Fatalf("失败时 not_after 应为空: %v", m)
	}
	for _, key := range []string{"host", "ok"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("响应缺字段 %q: %v", key, m)
		}
	}
}

// TestAssetAPIValidation SSRF/参数校验：空 host、政府站均 400。
func TestAssetAPIValidation(t *testing.T) {
	s := newTasksTestServer(t, nil)
	for _, h := range []http.HandlerFunc{s.hCertExpiry, s.hAssetPorts} {
		code, m := callHandler(t, h, "/api/assets/x")
		if code != 400 || !strings.Contains(strings.ToLower(mustStr(m["error"])), "host") {
			t.Fatalf("缺 host 应 400: code=%d %v", code, m)
		}
	}
	// gov.cn 为代码级硬保护（不受 resolve 开关影响）。
	code, m := callHandler(t, s.hCertExpiry, assetURL("/api/assets/cert-expiry", "www.gov.cn"))
	if code != 400 || !strings.Contains(mustStr(m["error"]), "gov.cn") {
		t.Fatalf("政府站应被拦截: code=%d %v", code, m)
	}
}

// TestAssetAllowHosts allow_hosts 白名单外目标返回 400（不发起探测）。
func TestAssetAllowHosts(t *testing.T) {
	s := newTasksTestServer(t, func(cfg *config.Config) {
		cfg.Scan.AllowHosts = []string{"example.com"}
	})
	port := freeClosedPort(t)
	for _, h := range []http.HandlerFunc{s.hCertExpiry, s.hAssetPorts} {
		code, m := callHandler(t, h, assetURL("/api/assets/x", "127.0.0.1:"+strconv.Itoa(port)))
		if code != 400 || !strings.Contains(mustStr(m["error"]), "allow_hosts") {
			t.Fatalf("白名单外应 400: code=%d %v", code, m)
		}
	}
}

// TestAssetPortsAPI 默认端口集探测：监听中的端口应出现在结果里。
func TestAssetPortsAPI(t *testing.T) {
	s := newTasksTestServer(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	hasListener := err == nil
	if hasListener {
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	code, m := callHandler(t, s.hAssetPorts, assetURL("/api/assets/ports", "127.0.0.1"))
	if code != 200 {
		t.Fatalf("hAssetPorts = %d: %v", code, m)
	}
	if got, _ := m["host"].(string); got != "127.0.0.1" {
		t.Fatalf("host 回显异常: %q", got)
	}
	raw, ok := m["ports"].([]any)
	if !ok {
		t.Fatalf("ports 应为数组: %#v", m["ports"])
	}
	if count, _ := m["count"].(float64); int(count) != len(raw) {
		t.Fatalf("count 与 ports 长度不一致: %v", m)
	}
	if hasListener {
		found := false
		for _, v := range raw {
			if item, ok := v.(map[string]any); ok {
				if u, _ := item["url"].(string); strings.Contains(u, "8080") {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("8080 已监听但未出现在端口探测结果: %v", raw)
		}
	}
}

// TestAssetHostQueryUnit assetHostQuery 纯函数口径：默认 TLS 端口/显式端口/校验错误。
func TestAssetHostQueryUnit(t *testing.T) {
	s := newTasksTestServer(t, nil)
	req := func(q string) *http.Request {
		return httptest.NewRequest(http.MethodGet, assetURL("/api/assets/cert-expiry", q), nil)
	}
	if _, vhost, tlsPort, err := s.assetHostQuery(req("127.0.0.1")); err != nil || vhost != "127.0.0.1" || tlsPort != 443 {
		t.Fatalf("无端口应默认 443: vhost=%q port=%d err=%v", vhost, tlsPort, err)
	}
	if _, _, tlsPort, err := s.assetHostQuery(req("127.0.0.1:8443")); err != nil || tlsPort != 8443 {
		t.Fatalf("显式端口应保留: port=%d err=%v", tlsPort, err)
	}
	if _, _, _, err := s.assetHostQuery(req("")); err == nil {
		t.Fatal("空 host 应报错")
	}
}

// mustStr 取 map 字符串值（缺失返回空串），测试辅助。
func mustStr(v any) string {
	s, _ := v.(string)
	return s
}
