// Token / 会话：Claims 最小声明集 + HMAC-SHA256 签发/验证（仅标准库）。
//
// 令牌格式（非 JWT，刻意不引入算法协商，避免 alg=none 类问题）：
//
//	base64url_nopad(claimsJSON) "." base64url_nopad(HMAC-SHA256(secret, payloadB64))
//
// 验证顺序：secret 非空 → 结构 → 签名（常量时间比较）→ claims 结构 → 过期。
// 错误均可 errors.Is 判定；错误信息与日志不包含 secret/token/claims 值。
package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims 会话声明（企业版最小集）。
// ExpiresAt 为绝对过期时间；建议签发时用 UTC、并给调用方留时钟偏差余量。
type Claims struct {
	Subject   string    `json:"sub"`    // 主体（用户/服务账号 ID）
	Tenant    string    `json:"tenant"` // 租户 ID（与 Tenant.ID 同规范）
	Role      Role      `json:"role"`   // 角色（viewer/operator/admin 或自定义角色）
	ExpiresAt time.Time `json:"exp"`    // 过期时间
}

// 明确错误（不含 secret/token/claims 值；errors.Is 判定）。
var (
	ErrTokenSecretEmpty = errors.New("authz: 令牌 secret 为空")
	ErrTokenMalformed   = errors.New("authz: 令牌格式错误")
	ErrTokenSignature   = errors.New("authz: 令牌签名无效")
	ErrTokenExpired     = errors.New("authz: 令牌已过期")
	ErrTokenClaims      = errors.New("authz: 令牌 claims 非法")
	ErrTenantMismatch   = errors.New("authz: 租户不匹配")
)

// Validate claims 结构校验（不查时钟：过期由 VerifyToken 判定）。
// Role 只校验结构（未知角色是否放行由 Authorize 判定，默认拒绝）。
func (c Claims) Validate() error {
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("%w: subject 为空", ErrTokenClaims)
	}
	tenant := normalizeSegment(c.Tenant)
	if tenant == "" || !validSegment(tenant, false) || len(c.Tenant) > 64 {
		return fmt.Errorf("%w: tenant 非法", ErrTokenClaims)
	}
	if normalizeRole(c.Role) == "" {
		return fmt.Errorf("%w: role 为空或非法", ErrTokenClaims)
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: exp 为空", ErrTokenClaims)
	}
	return nil
}

// IssueToken 签发令牌。
//   - secret 为空 → ErrTokenSecretEmpty；claims 结构非法 → ErrTokenClaims；
//   - 不校验 ExpiresAt 是否已过（过期由 VerifyToken 按时钟判定，便于测试/时钟偏差）；
//   - 不写日志，返回的 token 只在内存/响应中使用。
func IssueToken(secret []byte, claims Claims) (string, error) {
	if len(secret) == 0 {
		return "", ErrTokenSecretEmpty
	}
	if err := claims.Validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil { // 结构固定，理论不可达；仍兜底不泄露内容
		return "", fmt.Errorf("%w: claims 编码失败", ErrTokenClaims)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return payloadB64 + "." + signToken(secret, payloadB64), nil
}

// VerifyToken 验证令牌并返回 claims。
// 错误：ErrTokenSecretEmpty / ErrTokenMalformed / ErrTokenSignature /
// ErrTokenClaims / ErrTokenExpired（可用 errors.Is 区分）。
// 签名先于 payload 解码，且用 hmac.Equal 常量时间比较；错误不含敏感值。
func VerifyToken(secret []byte, token string) (Claims, error) {
	if len(secret) == 0 {
		return Claims{}, ErrTokenSecretEmpty
	}
	payloadB64, sigB64, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok || payloadB64 == "" || sigB64 == "" || strings.Contains(sigB64, ".") {
		return Claims{}, ErrTokenMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return Claims{}, ErrTokenMalformed
	}
	if !hmac.Equal(sig, tokenMAC(secret, payloadB64)) {
		return Claims{}, ErrTokenSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Claims{}, ErrTokenMalformed
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, ErrTokenMalformed
	}
	if err := c.Validate(); err != nil {
		return Claims{}, err
	}
	if !c.ExpiresAt.After(time.Now()) {
		return Claims{}, ErrTokenExpired
	}
	return c, nil
}

// VerifyTokenForTenant 验证令牌并强制租户匹配（多租户入口标准用法）：
// 签名/结构/过期任一失败原样返回；claims.Tenant 与 tenantID 不一致 →
// ErrTenantMismatch（不回显两个租户值）。
func VerifyTokenForTenant(secret []byte, token, tenantID string) (Claims, error) {
	c, err := VerifyToken(secret, token)
	if err != nil {
		return Claims{}, err
	}
	if !Isolate(c.Tenant, tenantID) {
		return Claims{}, ErrTenantMismatch
	}
	return c, nil
}

// TokenFingerprint 令牌不可逆指纹（SHA-256 前 8 字节 hex）。
// 供审计日志关联同一令牌的多次使用，不泄露令牌本身。
func TokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// ---- 内部工具 ----

// signToken 计算 payloadB64 的 HMAC-SHA256 并 base64url 编码。
func signToken(secret []byte, payloadB64 string) string {
	return base64.RawURLEncoding.EncodeToString(tokenMAC(secret, payloadB64))
}

// tokenMAC 返回 HMAC-SHA256 原始摘要（签名/校验共用，保证同源）。
func tokenMAC(secret []byte, payloadB64 string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payloadB64))
	return mac.Sum(nil)
}
