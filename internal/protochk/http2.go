package protochk

// HTTP/2（G10-2）：TLS ALPN h2 协商 + h2c 明文 Upgrade 探测 + 简单 GET 复核。
// 只读、每 URL ≤2 次连接、不发送请求体。

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// h2cSettings h2c Upgrade 的 HTTP2-Settings 头值：RFC 7540 §3.2.1 要求为
// SETTINGS 帧 payload 的 base64url 编码；空 payload（无参数）合法。
const h2cSettings = ""

// CheckHTTP2 探测目标 HTTP/2 暴露，返回暴露项：
//   - https：TLS ALPN 协商到 h2（并用一次简单 GET 复核响应协议）→ h2-alpn-enabled（info）；
//   - http：明文 h2c Upgrade 被接受（101，或 426 + Upgrade: h2c）→ h2c-enabled（low）。
//
// 非 http/https URL、非法 URL 返回错误；网络失败返回错误（无 Finding）。
func CheckHTTP2(ctx context.Context, rawURL string, opts Options) ([]Finding, error) {
	u, err := parseTarget(rawURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return checkH2TLS(ctx, u, opts)
	case "http":
		return checkH2C(ctx, u, opts)
	}
	return nil, fmt.Errorf("不是 http/https URL：%q", rawURL)
}

// checkH2TLS 先做一次带 ALPN 的 TLS 握手判断 h2 协商，再发一次简单 GET 复核
// 响应协议（ALPN 声明与实际是否一致）。
func checkH2TLS(ctx context.Context, u *url.URL, opts Options) ([]Finding, error) {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &net.Dialer{Timeout: opts.timeout()}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	cfg := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: opts.Insecure,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(opts.timeout()))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	alpn := strings.ToLower(tc.ConnectionState().NegotiatedProtocol)
	_ = tc.Close()

	detail := ""
	if alpn == "h2" {
		detail = "TLS ALPN 协商到 h2"
	}
	// 简单 GET 复核（h2 可用时 Go transport 自动走 h2）：确认响应协议确实是 HTTP/2。
	client := &http.Client{
		Timeout: opts.timeout(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         u.Hostname(),
				InsecureSkipVerify: opts.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if resp, gerr := client.Get(u.String()); gerr == nil {
		proto2 := resp.ProtoMajor == 2
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		if proto2 {
			if detail == "" {
				detail = "简单 GET 响应协议为 HTTP/2.0"
			} else {
				detail += "，且 GET 响应协议为 HTTP/2.0"
			}
			return []Finding{{
				Kind:     KindH2ALPNEnabled,
				Severity: "info",
				URL:      u.String(),
				Detail:   detail,
			}}, nil
		}
	}
	if detail == "" {
		return nil, nil // 未协商 h2 且 GET 非 h2：服务器未启用 HTTP/2
	}
	return []Finding{{
		Kind:     KindH2ALPNEnabled,
		Severity: "info",
		URL:      u.String(),
		Detail:   detail,
	}}, nil
}

// checkH2C 发一次明文 HTTP/1.1 h2c Upgrade 请求（无 body）：
// 101 Switching Protocols → 接受升级；426 + Upgrade: h2c → 要求 h2c（同样暴露）。
func checkH2C(ctx context.Context, u *url.URL, opts Options) ([]Finding, error) {
	conn, r, err := dialHTTP1(ctx, u, opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	headers := [][2]string{
		{"Connection", "Upgrade, HTTP2-Settings"},
		{"Upgrade", "h2c"},
		{"HTTP2-Settings", h2cSettings},
		{"User-Agent", opts.userAgent()},
	}
	if err := writeHTTP1Request(conn, "GET", u, headers); err != nil {
		return nil, err
	}
	status, hdr, err := readHTTP1Response(r)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusSwitchingProtocols:
		return []Finding{{
			Kind:     KindH2CEnabled,
			Severity: "low",
			URL:      u.String(),
			Detail:   "明文 HTTP/1.1 h2c Upgrade 被接受（101 Switching Protocols）：暴露明文 HTTP/2 面",
		}}, nil
	case http.StatusUpgradeRequired:
		if strings.Contains(strings.ToLower(hdr.Get("Upgrade")), "h2c") {
			return []Finding{{
				Kind:     KindH2CEnabled,
				Severity: "low",
				URL:      u.String(),
				Detail:   "明文 HTTP/1.1 请求被要求升级到 h2c（426 + Upgrade: h2c）：暴露明文 HTTP/2 面",
			}}, nil
		}
	}
	return nil, nil
}
