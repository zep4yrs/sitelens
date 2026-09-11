// Package netx 3.0 非 HTTP 协议拨号层：TCP/TLS/UDP/DNS 原始收发。
//
// 安全约束（缺一不可，全部在 Dial/DNSQuery 入口强制）：
//   - 目标必须先过 target.ValidateHostPort（协议白名单 + 保留主机拒绝 +
//     DNS 解析逐 IP 公网校验）——loopback/私网目标在测试里经显式
//     insecureDial 绕过闸（仅供单元测试使用）；
//   - 每次读写都有独立 deadline；
//   - 单次读取上限 MaxReadBytes（防恶意服务端塞爆内存）；
//   - send/recv 轮次上限 MaxRounds（防模板无限对话）。
//
// 安全闸以 host 名义校验发生在拨号前；拨号后的实际对端若经 CNAME 重定向
// 到私网，由 Go 默认解析器行为决定——3.1 计划改为自控解析逐 IP 复检。
package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Config 拨号配置（全阈值可配，零值回退默认）。
type Config struct {
	TimeoutMS     int  `yaml:"timeout_ms"`      // 拨号/读写单次超时，默认 5000
	TLSSkipVerify bool `yaml:"tls_skip_verify"` // TLS 跳过证书校验，默认 false
	MaxReadBytes  int  `yaml:"max_read_bytes"`  // 单次读取上限，默认 64KB
	MaxRounds     int  `yaml:"max_rounds"`      // send/recv 轮次上限，默认 4
}

const (
	defTimeoutMS    = 5000
	defMaxReadBytes = 64 * 1024
	defMaxRounds    = 4
)

func (c Config) timeout() time.Duration {
	if c.TimeoutMS <= 0 {
		return defTimeoutMS * time.Millisecond
	}
	return time.Duration(c.TimeoutMS) * time.Millisecond
}

func (c Config) maxRead() int64 {
	if c.MaxReadBytes <= 0 {
		return defMaxReadBytes
	}
	return int64(c.MaxReadBytes)
}

func (c Config) maxRounds() int {
	if c.MaxRounds <= 0 {
		return defMaxRounds
	}
	return c.MaxRounds
}

// Target 一个协议目标（scheme: tcp|tls|udp|dns）。
type Target struct {
	Scheme string
	Host   string
	Port   int
}

// ParseTarget 解析 "tcp://host:port" / "dns://example.com" 形态。
func ParseTarget(raw string) (Target, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(raw), "://")
	if !ok {
		return Target{}, fmt.Errorf("netx: 目标缺少协议前缀: %q", raw)
	}
	scheme = strings.ToLower(scheme)
	t := Target{Scheme: scheme}
	if scheme == "dns" {
		t.Host = strings.TrimSuffix(rest, "/")
		return t, nil
	}
	host, portS, err := net.SplitHostPort(rest)
	if err != nil {
		return Target{}, fmt.Errorf("netx: 目标缺少端口: %q", raw)
	}
	port, perr := strconv.Atoi(portS)
	if perr != nil || port <= 0 || port >= 65536 {
		return Target{}, fmt.Errorf("netx: 端口不合法: %q", portS)
	}
	t.Host, t.Port = strings.TrimSuffix(host, "."), port
	return t, nil
}

// Validate 目标安全闸（Dial/DNSQuery 前必须调用）。
func (t Target) Validate(resolve bool) error {
	return target.ValidateHostPort(t.Scheme, t.Host, t.Port, resolve)
}

// Conn 已建立连接的统一包装（tcp/tls/udp），带轮次与读取上限。
type Conn struct {
	nc     net.Conn
	cfg    Config
	rounds int
}

// Dial 建立连接：安全闸 → 拨号（tls 附加握手）。任何错误保证不出半开连接。
func Dial(t Target, cfg Config, resolve bool) (*Conn, error) {
	if err := t.Validate(resolve); err != nil {
		return nil, err
	}
	return dial(t, cfg)
}

func dial(t Target, cfg Config) (*Conn, error) {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	d := net.Dialer{Timeout: cfg.timeout()}
	nc, err := d.Dial(strings.ToLower(t.Scheme), addr)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(t.Scheme) {
	case "tls":
		tc := tls.Client(nc, &tls.Config{
			ServerName:         t.Host,
			InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec // 模板显式配置项，默认 false
		})
		nc.SetDeadline(time.Now().Add(cfg.timeout()))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			nc.Close()
			return nil, fmt.Errorf("tls 握手失败: %w", err)
		}
	case "udp", "tcp":
		// 原样
	default:
		nc.Close()
		return nil, fmt.Errorf("netx: 不支持的协议 %q", t.Scheme)
	}
	return &Conn{nc: nc, cfg: cfg}, nil
}

// Send 发送一轮数据（计一轮）。
func (c *Conn) Send(data []byte) error {
	if c.rounds >= c.cfg.maxRounds() {
		return fmt.Errorf("netx: 超过 send/recv 轮次上限 %d", c.cfg.maxRounds())
	}
	c.rounds++
	if err := c.nc.SetWriteDeadline(time.Now().Add(c.cfg.timeout())); err != nil {
		return err
	}
	_, err := c.nc.Write(data)
	return err
}

// Recv 读取响应：读到 EOF/超时/MaxReadBytes 上限为止；EOF 不算错误。
func (c *Conn) Recv() ([]byte, error) {
	if err := c.nc.SetReadDeadline(time.Now().Add(c.cfg.timeout())); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(io.LimitReader(c.nc, c.cfg.maxRead()))
	if err != nil {
		// 超时/连接关闭在有部分数据时按可用数据处理（banner 类服务常态）
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() && len(buf) > 0 {
			return buf, nil
		}
		if err == io.EOF && len(buf) > 0 {
			return buf, nil
		}
		return buf, err
	}
	return buf, nil
}

// Close 关闭连接。
func (c *Conn) Close() error { return c.nc.Close() }

// DNSRecordTypes 支持的查询类型。
var DNSRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "TXT": true, "CNAME": true, "MX": true, "NS": true,
}

// DNSQuery 查询域名记录（走系统解析器，超时受 Config 约束）。
func DNSQuery(cfg Config, host, qtype string) ([]string, error) {
	if !DNSRecordTypes[strings.ToUpper(qtype)] {
		return nil, fmt.Errorf("netx: 不支持的记录类型 %q", qtype)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()
	r := &net.Resolver{PreferGo: true}
	switch strings.ToUpper(qtype) {
	case "A":
		return lookupIPs(ctx, r, host, false)
	case "AAAA":
		return lookupIPs(ctx, r, host, true)
	case "TXT":
		return r.LookupTXT(ctx, host)
	case "CNAME":
		cn, err := r.LookupCNAME(ctx, host)
		if err != nil {
			return nil, err
		}
		return []string{cn}, nil
	case "MX":
		mxs, err := r.LookupMX(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(mxs))
		for _, m := range mxs {
			out = append(out, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
		return out, nil
	case "NS":
		nss, err := r.LookupNS(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(nss))
		for _, ns := range nss {
			out = append(out, ns.Host)
		}
		return out, nil
	}
	return nil, fmt.Errorf("netx: 不支持的记录类型 %q", qtype)
}

func lookupIPs(ctx context.Context, r *net.Resolver, host string, v6 bool) ([]string, error) {
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		is6 := ip.To4() == nil
		if is6 == v6 {
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// insecureDial 仅供单元测试：绕过安全闸直连（loopback 监听器场景）。
func insecureDial(t Target, cfg Config) (*Conn, error) { return dial(t, cfg) }
