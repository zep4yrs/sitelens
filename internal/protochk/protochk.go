// Package protochk 提供 WebSocket / HTTP2 协议面覆盖检查（G10）。
//
// 设计纪律（与扫描器红线一致）：
//   - 只读：只做协议握手 / 探测请求，不发送业务 payload、不修改目标状态；
//   - 次数受控：WS 每 URL ≤2 次握手（首个被拒才补一次匿名基线）；HTTP/2 每
//     URL ≤2 次连接；不重试、不递归、不跟随重定向；
//   - 纯函数：显式 Options、不读全局配置、不依赖 engine/server；接线方负责把
//     Finding 转成自身结果类型（本包不 import 其他 internal 包）。
package protochk

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Finding 单个协议面暴露项（本包自有类型，避免与 engine/intel 类型耦合）。
type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Detail   string `json:"detail"`
}

// 暴露项类型（供接线方分支处理 / 白名单）。
const (
	KindCleartextWS      = "cleartext-ws"       // ws:// 明文传输
	KindWSNoAuth         = "ws-no-auth"         // 匿名握手被接受（无 Cookie/Authorization）
	KindOriginNotChecked = "origin-not-checked" // 未校验 Origin（跨站 WebSocket 劫持面）
	KindH2CEnabled       = "h2c-enabled"        // 明文 h2c Upgrade 被接受
	KindH2ALPNEnabled    = "h2-alpn-enabled"    // TLS ALPN / 响应协议为 HTTP/2（信息项）
)

// 严重度口径：cleartext-ws / origin-not-checked = medium；ws-no-auth / h2c-enabled
// = low（是否可利用取决于业务上下文）；h2-alpn-enabled = info（仅能力暴露）。
const (
	defaultTimeout = 5 * time.Second
	// defaultForgedOrigin 伪造 Origin：不是目标站点的来源。服务端接受带该
	// Origin 的握手即说明没做 Origin 校验（CSWSH 面）。
	defaultForgedOrigin = "https://protochk.invalid"
	defaultUserAgent    = "SiteLens/5.3.0 (+https://cnb.cool/feng-qiao/sitelens)"
)

// Options 探测参数（零值 = 默认：5s 超时、校验 TLS 证书、固定伪造 Origin）。
type Options struct {
	Timeout   time.Duration // 单次连接/握手的整体超时，0 = 5s
	Insecure  bool          // 跳过 TLS 证书校验（自签证书的授权资产/测试用）
	Origin    string        // 伪造 Origin（空 = defaultForgedOrigin）
	UserAgent string        // 空 = SiteLens 自报 UA
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return defaultTimeout
	}
	return o.Timeout
}

func (o Options) origin() string {
	if s := strings.TrimSpace(o.Origin); s != "" {
		return s
	}
	return defaultForgedOrigin
}

func (o Options) userAgent() string {
	if s := strings.TrimSpace(o.UserAgent); s != "" {
		return s
	}
	return defaultUserAgent
}

// Check 按 URL scheme 分派探测：
//
//	ws / wss   → CheckWebSocket
//	http / https → CheckHTTP2
//
// 其它 scheme 返回错误（由调用方决定是否跳过）。
func Check(ctx context.Context, rawURL string, opts Options) ([]Finding, error) {
	u, err := parseTarget(rawURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
		return CheckWebSocket(ctx, rawURL, opts)
	case "http", "https":
		return CheckHTTP2(ctx, rawURL, opts)
	}
	return nil, fmt.Errorf("不支持的 scheme %q（仅 ws/wss/http/https）", u.Scheme)
}

// parseTarget 解析并校验 URL 具备 host；scheme 白名单由各 Check 自行判断。
func parseTarget(rawURL string) (*url.URL, error) {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return nil, fmt.Errorf("空 URL")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("非法 URL：%q", rawURL)
	}
	return u, nil
}
