// Package target 实现 URL 安全校验：协议白名单 + 保留主机黑名单 +
// 私网/保留地址拒绝 + DNS 解析逐 IP 校验。移植自 scanner/target.py。
package target

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Error 校验失败（消息可直接展示给用户）。
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

var blockedHosts = map[string]bool{
	"localhost":                true,
	"localhost.localdomain":    true,
	"ip6-localhost":            true,
	"metadata.google.internal": true,
}

// Validate 校验并规范化 URL，返回 (scheme, host, port)。
// resolve=true 时做 DNS 解析并逐 IP 校验私网/保留地址。
func Validate(rawURL string, resolve bool) (string, string, int, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", "", 0, &Error{"请输入网址"}
	}
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(strings.ToLower(rawURL), "http://") &&
		!strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", 0, &Error{"URL 解析失败"}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", 0, &Error{"仅支持 http/https 协议"}
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", 0, &Error{"URL 缺少主机名"}
	}
	if blockedHosts[host] || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", "", 0, &Error{"不允许扫描内网或保留主机名"}
	}
	port := 0
	if p := u.Port(); p != "" {
		if n, perr := net.LookupPort("tcp", p); perr != nil || n <= 0 || n >= 65536 {
			return "", "", 0, &Error{"端口号不合法"}
		} else {
			port = n
		}
	}
	if resolve {
		if verr := ensurePublicHost(host); verr != nil {
			return "", "", 0, verr
		}
	}
	return scheme, host, port, nil
}

// ensurePublicHost DNS 解析后逐 IP 校验：任一地址落在私网/保留段即拒绝。
func ensurePublicHost(host string) error {
	ips, err := net.LookupHost(host)
	if err != nil {
		return &Error{"域名解析失败：" + host}
	}
	for _, s := range ips {
		addr, aerr := netip.ParseAddr(s)
		if aerr != nil {
			continue
		}
		if isBlockedIP(addr) {
			return &Error{"目标解析到内网/保留地址，已拦截"}
		}
	}
	return nil
}

func isBlockedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10 运营商级 NAT
	prefix, err := netip.ParsePrefix("100.64.0.0/10")
	if err != nil {
		return false
	}
	return prefix.Contains(addr.Unmap())
}
