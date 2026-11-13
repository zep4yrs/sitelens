package mcp

// 危险操作确认令牌（5.3 P0，借鉴 ARES 的 MCP 安全模型）。
//
// 问题：MCP 工具面此前只有 --allow-active 一个总闸，智能体（或注入到模型上下文
// 的恶意指令）一旦拿到主动工具，就能直接发起扫描/协议探测，没有「单次授权」概念，
// 也无法把一次授权绑定到具体工具+参数。
//
// 方案：
//  1. 危险工具（scan / graphql_introspect / assets）必须携带一次性确认令牌；
//  2. 令牌由 confirm_action 工具签发：先做 Pre-flight 范围检查（allow_hosts），
//     再对「工具名 + 规范化参数」做 HMAC 绑定，TTL 60s、单次使用；
//  3. 令牌校验不通过/过期/重放/参数被改，一律拒绝执行（fail-closed）；
//  4. 未配置 allow_hosts 时拒绝签发（无范围 = 无授权，与引擎 allow_hosts 口径一致）。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const confirmTokenTTL = 60 * time.Second

type confirmRec struct {
	tool     string
	params   string // 规范化参数哈希
	expireAt time.Time
	used     bool
}

// confirmer 单次确认令牌签发/核销器（进程内、随机密钥）。
type confirmer struct {
	secret []byte
	mu     sync.Mutex
	tokens map[string]*confirmRec
}

func newConfirmer() (*confirmer, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("确认令牌密钥生成失败: %w", err)
	}
	return &confirmer{secret: secret, tokens: make(map[string]*confirmRec)}, nil
}

// canonicalParams 规范化参数：JSON 反序列化再序列化（encoding/json 对 map key
// 排序输出，保证同一参数的不同书写顺序得到同一哈希）。
func canonicalParams(raw json.RawMessage) (string, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "{}", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("参数不是合法 JSON: %w", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func paramsDigest(tool, canonical string) string {
	h := sha256.Sum256([]byte(tool + "\x00" + canonical))
	return hex.EncodeToString(h[:])
}

func (c *confirmer) sign(nonce string, expireAt time.Time, tool, digest string) string {
	mac := hmac.New(sha256.New, c.secret)
	fmt.Fprintf(mac, "%s\x00%s\x00%s\x00%d", tool, digest, nonce, expireAt.Unix())
	return hex.EncodeToString(mac.Sum(nil))
}

// Issue 为一次危险调用签发令牌（绑定工具+参数，单次使用，TTL 60s）。
func (c *confirmer) Issue(tool string, raw json.RawMessage) (string, int, error) {
	canonical, err := canonicalParams(raw)
	if err != nil {
		return "", 0, err
	}
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		return "", 0, fmt.Errorf("确认令牌生成失败: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	expireAt := time.Now().Add(confirmTokenTTL)
	digest := paramsDigest(tool, canonical)
	sig := c.sign(nonce, expireAt, tool, digest)
	token := nonce + "." + fmt.Sprint(expireAt.Unix()) + "." + sig

	c.mu.Lock()
	defer c.mu.Unlock()
	// 顺带清理过期令牌，避免长会话无界增长。
	now := time.Now()
	for k, rec := range c.tokens {
		if now.After(rec.expireAt) {
			delete(c.tokens, k)
		}
	}
	c.tokens[nonce] = &confirmRec{tool: tool, params: digest, expireAt: expireAt}
	return token, int(confirmTokenTTL.Seconds()), nil
}

// Consume 校验并核销令牌：工具/参数/过期/重放任一不符即失败。
func (c *confirmer) Consume(tool string, raw json.RawMessage, token string) error {
	canonical, err := canonicalParams(raw)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return fmt.Errorf("确认令牌格式非法")
	}
	nonce, expStr, sig := parts[0], parts[1], parts[2]
	var expUnix int64
	if _, err := fmt.Sscanf(expStr, "%d", &expUnix); err != nil {
		return fmt.Errorf("确认令牌格式非法")
	}
	expireAt := time.Unix(expUnix, 0)
	if time.Now().After(expireAt) {
		return fmt.Errorf("确认令牌已过期（TTL %ds），请重新调用 confirm_action", int(confirmTokenTTL.Seconds()))
	}
	digest := paramsDigest(tool, canonical)
	want := c.sign(nonce, expireAt, tool, digest)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return fmt.Errorf("确认令牌与本次调用不匹配（工具或参数被修改）")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.tokens[nonce]
	if !ok {
		return fmt.Errorf("确认令牌无效或已被使用")
	}
	if rec.used {
		return fmt.Errorf("确认令牌已被使用（单次有效），请重新调用 confirm_action")
	}
	if rec.tool != tool || rec.params != digest {
		return fmt.Errorf("确认令牌与本次调用不匹配（工具或参数被修改）")
	}
	rec.used = true
	return nil
}
