package protochk

// WebSocket（G10-1）：手写 RFC 6455 客户端握手校验（stdlib 无 ws 客户端），
// 只读、不发送任何 WebSocket 帧。
//
// 探测策略（每 URL ≤2 次握手）：
//  1) 带伪造 Origin、不带任何凭据的一次握手：101 + 合法 Sec-WebSocket-Accept
//     即同时证明「未授权握手被接受」与「Origin 未校验」；
//  2) 若第 1 次被拒，再补一次「不带 Origin」的匿名基线握手（仅一次）：用于
//     识别「Origin 有校验、但匿名可直接连」的服务端。
//
// 限制（显式记录，宁少报不误报）：第 1 次被拒且第 2 次也失败时不产出 WS
// Finding；服务端要求真实凭据时不会误报 ws-no-auth。

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// wsGUID RFC 6455 §1.3 握手用的固定 GUID。
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsAccept 计算服务器应答的 Sec-WebSocket-Accept。
func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// wsProbeKey 生成 16 字节随机 Sec-WebSocket-Key。
func wsProbeKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("生成 WebSocket Key 失败：%w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// wsHandshake 发一次 WebSocket Upgrade 握手（只读），校验 101 状态与
// Sec-WebSocket-Accept；origin 为空时不发送 Origin 头。请求不携带 Cookie /
// Authorization（「未授权」语义由调用方文档说明）。
func wsHandshake(ctx context.Context, u *url.URL, opts Options, origin string) (status int, upgraded bool, err error) {
	key, err := wsProbeKey()
	if err != nil {
		return 0, false, err
	}
	conn, r, err := dialHTTP1(ctx, u, opts)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close() // 101 后的协议数据不读，直接断开
	headers := [][2]string{
		{"Upgrade", "websocket"},
		{"Connection", "Upgrade"},
		{"Sec-WebSocket-Version", "13"},
		{"Sec-WebSocket-Key", key},
		{"User-Agent", opts.userAgent()},
	}
	if s := strings.TrimSpace(origin); s != "" {
		headers = append(headers, [2]string{"Origin", s})
	}
	if err := writeHTTP1Request(conn, "GET", u, headers); err != nil {
		return 0, false, err
	}
	status, hdr, err := readHTTP1Response(r)
	if err != nil {
		return 0, false, err
	}
	if status != 101 {
		return status, false, nil
	}
	got := strings.TrimSpace(hdr.Get("Sec-WebSocket-Accept"))
	return status, strings.EqualFold(got, wsAccept(key)), nil
}

// CheckWebSocket 对 ws:// / wss:// 做只读握手检查，返回暴露项：
//   - ws:// → cleartext-ws；
//   - 匿名 + 伪造 Origin 握手被接受 → ws-no-auth 且 origin-not-checked；
//   - 伪造 Origin 被拒、无 Origin 匿名握手被接受 → 仅 ws-no-auth。
//
// 非 ws/wss URL / 非法 URL 返回错误；网络失败返回已有 Finding 与错误
// （cleartext-ws 在连接前就能确定，故仍返回）。
func CheckWebSocket(ctx context.Context, rawURL string, opts Options) ([]Finding, error) {
	u, err := parseTarget(rawURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("不是 ws/wss URL：%q", rawURL)
	}

	var out []Finding
	if strings.EqualFold(u.Scheme, "ws") {
		out = append(out, Finding{
			Kind:     KindCleartextWS,
			Severity: "medium",
			URL:      rawURL,
			Detail:   "WebSocket 使用明文 ws://，链路可被窃听/篡改",
		})
	}

	// 第 1 次：伪造 Origin + 无凭据。
	status, upgraded, err := wsHandshake(ctx, u, opts, opts.origin())
	if err != nil {
		return out, err
	}
	if upgraded {
		out = append(out,
			Finding{
				Kind:     KindWSNoAuth,
				Severity: "low",
				URL:      rawURL,
				Detail:   "未携带任何凭据（无 Cookie/Authorization）的 WebSocket 握手被接受（101 + 合法 Sec-WebSocket-Accept）",
			},
			Finding{
				Kind:     KindOriginNotChecked,
				Severity: "medium",
				URL:      rawURL,
				Detail:   "携带伪造 Origin（" + opts.origin() + "）的握手仍被接受：未校验 Origin，存在跨站 WebSocket 劫持风险",
			},
		)
		return out, nil
	}
	if status != 403 && status != 401 {
		// 不是「有闸门」的拒绝（如 400/426/404）：不做第二次探测，避免噪声。
		return out, nil
	}

	// 第 2 次（仅当伪造 Origin 被拒）：不带 Origin 的匿名基线。
	_, upgraded, err = wsHandshake(ctx, u, opts, "")
	if err != nil {
		return out, nil // 第二次失败不影响已确认结论
	}
	if upgraded {
		out = append(out, Finding{
			Kind:     KindWSNoAuth,
			Severity: "low",
			URL:      rawURL,
			Detail:   "无 Origin 头、无凭据的匿名 WebSocket 握手被接受（服务端校验 Origin 但允许匿名直连）",
		})
	}
	return out, nil
}
