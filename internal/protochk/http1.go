package protochk

// 最小只读 HTTP/1.1 客户端：只用 net.Conn + 手写状态行/头解析，避免
// net/http 客户端对 Upgrade / 101 / 重定向的隐式处理，保证探测可控、只读。

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// dialHTTP1 建立到目标的一次 TCP/TLS 连接（ws/wss 分别按 http/https 处理），
// 设置整体 deadline 防止半开连接挂住；TLS 不主动声明 ALPN（HTTP/1.1 Upgrade
// 语义只在 HTTP/1.1 上成立）。
func dialHTTP1(ctx context.Context, u *url.URL, opts Options) (net.Conn, *bufio.Reader, error) {
	addr := u.Host
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "http", "ws":
			addr = net.JoinHostPort(u.Hostname(), "80")
		case "https", "wss":
			addr = net.JoinHostPort(u.Hostname(), "443")
		}
	}
	d := &net.Dialer{Timeout: opts.timeout()}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(opts.timeout()))
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		cfg := &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: opts.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		return tc, bufio.NewReader(tc), nil
	default:
		return conn, bufio.NewReader(conn), nil
	}
}

// writeHTTP1Request 写一条无 body 的 HTTP/1.1 请求（Host + 指定头）。
func writeHTTP1Request(w io.Writer, method string, u *url.URL, headers [][2]string) error {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(path)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(u.Host)
	b.WriteString("\r\n")
	for _, h := range headers {
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// readHTTP1Response 解析状态行与响应头（不读 body）。
// 101 之后的数据属于切换后的协议，由调用方关闭连接即可。
func readHTTP1Response(r *bufio.Reader) (int, http.Header, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, nil, fmt.Errorf("读取状态行失败：%w", err)
	}
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
		return 0, nil, fmt.Errorf("非法状态行：%q", strings.TrimSpace(line))
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 599 {
		return 0, nil, fmt.Errorf("非法状态码：%q", strings.TrimSpace(line))
	}
	hdr := http.Header{}
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return 0, nil, fmt.Errorf("读取响应头失败：%w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		hdr.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return status, hdr, nil
}
