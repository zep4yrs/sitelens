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

// isGovCn gov.cn 政府网站代码级硬保护：本工具禁止被用于对政府网站
// 发起任何请求。这是产品红线，不提供配置开关、不受任何选项影响；
// 除本工具外的合规授权测试请使用其他途径。命中即整单拒绝。
func isGovCn(host string) bool {
	return host == "gov.cn" || strings.HasSuffix(host, ".gov.cn")
}

// Validate 校验并规范化 URL，返回 (scheme, host, port)。
// resolve=true 时做 DNS 解析并逐 IP 校验私网/保留地址。
func Validate(rawURL string, resolve bool) (string, string, int, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", "", 0, &Error{"请输入网址"}
	}
	rawURL = strings.TrimSpace(rawURL)
	// 显式带协议的按其协议判定（拒绝 ftp:// 等被误拼成 https://ftp 的隐患），
	// 不带协议的默认补 https://
	if i := strings.Index(rawURL, "://"); i >= 0 {
		scheme := strings.ToLower(rawURL[:i])
		if scheme != "http" && scheme != "https" {
			return "", "", 0, &Error{"仅支持 http/https 协议"}
		}
	} else {
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
	if isGovCn(host) {
		return "", "", 0, &Error{"gov.cn 政府网站受代码级保护，SiteLens 拒绝扫描（不可通过配置关闭）"}
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

// netxSchemes 非 HTTP 协议（internal/netx）允许的 scheme 白名单。
var netxSchemes = map[string]bool{
	"tcp": true, "tls": true, "udp": true, "dns": true,
}

// ValidateHostPort 非 HTTP 协议目标闸：协议白名单（tcp/tls/udp/dns）+
// 主机黑名单/保留后缀拒绝 + DNS 解析逐 IP 公网校验。端口规则与
// Validate 一致（dns 可为 0 = 使用系统解析器，不直连目标端口）。
func ValidateHostPort(scheme, host string, port int, resolve bool) error {
	scheme = strings.ToLower(scheme)
	if !netxSchemes[scheme] {
		return &Error{"仅支持 tcp/tls/udp/dns 协议"}
	}
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), ".")))
	if host == "" {
		return &Error{"目标缺少主机名"}
	}
	if blockedHosts[host] || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return &Error{"不允许扫描内网或保留主机名"}
	}
	if isGovCn(host) {
		return &Error{"gov.cn 政府网站受代码级保护，SiteLens 拒绝探测（不可通过配置关闭）"}
	}
	if scheme != "dns" {
		if port <= 0 || port >= 65536 {
			return &Error{"端口号不合法"}
		}
	}
	// 字面 IP 无条件校验（零成本）；域名才受 resolve 开关控制
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		if isBlockedIP(addr) {
			return &Error{"目标是内网/保留地址，已拦截"}
		}
		return nil
	}
	if resolve {
		if verr := ensurePublicHost(host); verr != nil {
			return verr
		}
	}
	return nil
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
