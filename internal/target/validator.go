// Package target 实现 URL 安全校验：协议白名单 + 保留主机黑名单 +
// 私网/保留地址拒绝 + DNS 解析逐 IP 校验。移植自 scanner/target.py。
package target

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
)

// Error 校验失败（消息可直接展示给用户）。
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// alwaysBlockedHosts 永久阻断主机名（任何开关都不放宽）：云厂商 metadata
// 端点等 SSRF 关键攻击面。
var alwaysBlockedHosts = map[string]bool{
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"instance-data.ec2.internal": true,
}

// alwaysBlockedIPs 永久阻断的 IP（任何开关都不放宽）：云厂商实例元数据端点。
//
// 为什么必须与 allowPrivate 解耦：allow_private 是「允许扫私网/本机」的
// **授权**开关，而元数据端点不是授权目标，是**凭证泄漏面**——实例元数据
// 服务里放着临时 IAM 凭证，被扫到即等于把凭证交出去。
//
// 此前 metadata 的永久保护只覆盖主机名（metadata.google.internal），IP 侧
// （169.254.169.254 等）落在 isBlockedIP 里、随 allow_private 一起被跳过
// ——授权内网扫描时就能把云凭证抓回本地（BUG-003）。
var alwaysBlockedIPs = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS / GCP / Azure / 阿里云
	netip.MustParsePrefix("100.100.100.200/32"), // 阿里云 ECS 元数据
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6
}

// isAlwaysBlockedIP 判断地址是否落在永久阻断段（不受 allow_private 影响）。
func isAlwaysBlockedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	for _, p := range alwaysBlockedIPs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// blockedHosts 本地/保留主机名（target.allow_private 开启时放宽——
// 本机靶场/授权内网场景由操作者显式担责）。
var blockedHosts = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"ip6-localhost":         true,
}

// hostBlocked 主机名闸：永久阻断名单优先；allow_private 开启时放宽
// 本地/保留主机名。
func hostBlocked(host string) bool {
	if alwaysBlockedHosts[host] {
		return true
	}
	if allowPrivate.Load() {
		return false
	}
	return blockedHosts[host] || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal")
}

// isGovCn gov.cn 政府网站代码级硬保护：本工具禁止被用于对政府网站
// 发起任何请求。这是产品红线，不提供配置开关、不受任何选项影响；
// 除本工具外的合规授权测试请使用其他途径。命中即整单拒绝。
func isGovCn(host string) bool {
	return host == "gov.cn" || strings.HasSuffix(host, ".gov.cn")
}

// allowPrivate 本机靶场/授权内网目标开关（默认 false = 拒绝私网/保留地址，
// 行为与既往版本一致）。由引擎装配层按 target.allow_private 配置置位；
// 开启后仅放宽私网/保留地址与本地主机名校验——云厂商 metadata 端点与
// gov.cn 硬保护不受本开关影响、永不放宽。
var allowPrivate atomic.Bool

// SetAllowPrivate 装配层接线（engine.New / server 装配按配置调用）。
// atomic：装配层可能与其他扫描 goroutine 并发执行（server 多实例/测试并发），
// 普通 bool 会触发数据竞争（CI -race 已实抓）。
func SetAllowPrivate(v bool) { allowPrivate.Store(v) }

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
	if hostBlocked(host) {
		return "", "", 0, &Error{"不允许扫描内网或保留主机名"}
	}
	// 云元数据端点：永久阻断，**不受 resolve / allow_private 任何开关影响**。
	// 字面 IP 必须在此处单独判——下方的 IP 校验只在 resolve=true 时才走
	// （ensurePublicHost），resolve=false 时元数据地址会整个漏过去（BUG-003）。
	if addr, aerr := netip.ParseAddr(host); aerr == nil && isAlwaysBlockedIP(addr) {
		return "", "", 0, &Error{"云厂商元数据端点受代码级保护，SiteLens 拒绝探测（不可通过配置关闭）"}
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
	if hostBlocked(host) {
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
	// 字面 IP 无条件校验（零成本）；域名才受 resolve 开关控制。
	// allow_private 开启时放宽私网/保留地址（本机靶场/授权内网），
	// 但云元数据端点永久阻断（不受任何开关影响）。
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		if isAlwaysBlockedIP(addr) {
			return &Error{"云厂商元数据端点受代码级保护，SiteLens 拒绝探测（不可通过配置关闭）"}
		}
		if !allowPrivate.Load() && isBlockedIP(addr) {
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
	ips, err := ResolveHostIPs(context.Background(), host)
	if err != nil {
		return err
	}
	return ValidateIPs(ips)
}

// ResolveHostIPs 解析主机名为 IP 列表（单次系统解析，本身不做安全判定）。
//
// 供「一次解析 → 校验 IP 集合 → 按已校验 IP 拨号」链路复用（httpx 的
// DialContext，BUG-021）：校验与拨号必须基于同一份解析结果。此前的
// ensurePublicHost 解析校验完即丢弃结果，实际连接由 transport 再次调用
// 系统解析器解析，中间的 DNS 查询窗口可被 DNS 重绑定（先回公网、再回私网）
// 绕过 SSRF 闸。
//
// ctx 透传解析器：拨号层用它承接单请求超时，避免挂起的 DNS 拖过 Timeout。
func ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	raw, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, &Error{"域名解析失败：" + host}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		addr, aerr := netip.ParseAddr(s)
		if aerr != nil {
			continue
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, &Error{"域名解析失败：" + host}
	}
	return out, nil
}

// ValidateIP 校验单个 IP 是否允许连接：云厂商元数据端点**永久**阻断
// （不受 allow_private 影响）；allow_private 关闭时拒绝私网/保留地址。
func ValidateIP(addr netip.Addr) error {
	if isAlwaysBlockedIP(addr) {
		return &Error{"云厂商元数据端点受代码级保护，SiteLens 拒绝探测（不可通过配置关闭）"}
	}
	if !allowPrivate.Load() && isBlockedIP(addr) {
		return &Error{"目标解析到内网/保留地址，已拦截"}
	}
	return nil
}

// ValidateIPs 全量校验一组解析结果：任一 IP 不合规即整体拒绝。
//
// 不能「挑一个合规的 IP 去拨」：DNS 轮询/重绑定场景下，答案集合里混入
// 私网地址本身就说明目标不可信（宁少报不误报），放过一个等于给攻击者
// 留一条确定性可用路径。
func ValidateIPs(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return &Error{"域名解析失败：无有效 IP"}
	}
	for _, addr := range addrs {
		if err := ValidateIP(addr); err != nil {
			return err
		}
	}
	return nil
}

// AllowPrivate 返回当前 allow_private 姿态（拨号层与测试复用）。
func AllowPrivate() bool { return allowPrivate.Load() }

// reservedPrefixes 特殊用途/保留地址段（V-19）：既不是合法的公网扫描目标，
// 也可能被当作 SSRF 跳板。重点说明几条：
//   - 64:ff9b::/96  NAT64 知名前缀：64:ff9b::7f00:1 在启用 NAT64 的网络上
//     就是 127.0.0.1（实测可通过 Go 的 IsLoopback/IsPrivate 判定，是真实缺口）；
//   - 2002::/16     6to4（内嵌任意 IPv4，含私网/回环）；
//   - 198.18.0.0/15 基准测试保留段；192.0.0.0/24 / 192.0.2.0/24 /
//     198.51.100.0/24 / 203.0.113.0/24 为 IETF 文档与保留段；
//   - fec0::/10     站点本地（RFC 3879 已废弃，部分栈仍可能路由）。
//
// 这些段在 allow_private 打开时**同样拒绝**（它们不是"授权内网靶场"的
// 合理目标），但与恒久阻断的云 metadata 端点不同，仍归入私网/保留地址闸。
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("fec0::/10"),
}

func isBlockedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	// 100.64.0.0/10 运营商级 NAT
	prefix, err := netip.ParsePrefix("100.64.0.0/10")
	if err != nil {
		return true // 兜底拒绝：解析失败属编程错误，不放行
	}
	unmapped := addr.Unmap()
	if prefix.Contains(unmapped) {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(unmapped) {
			return true
		}
	}
	// 兜底：非全局单播（其余保留/组播/未分配空间）一律拒绝。
	return !unmapped.IsGlobalUnicast()
}
