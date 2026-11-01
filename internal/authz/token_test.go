package authz

// 令牌签发/验证：往返、篡改、过期、租户不匹配、凭据不落日志/错误。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
	"time"
)

func testClaims() Claims {
	return Claims{
		Subject:   "user-42",
		Tenant:    "tenant-a",
		Role:      RoleOperator,
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
}

// rawToken 用真实签名算法构造任意 claims 令牌（用于测试「签名合法但 claims 非法」）。
func rawToken(t *testing.T, secret []byte, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + signToken(secret, p)
}

// TestIssueVerifyToken 签发→验证往返，声明一致。
func TestIssueVerifyToken(t *testing.T) {
	secret := []byte("verify-secret-value-0123456789abcdef")
	claims := testClaims()
	token, err := IssueToken(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(token, "."); len(parts) != 2 {
		t.Fatalf("令牌应为 payload.signature 两段: %q", token)
	}
	if strings.Contains(token, string(secret)) {
		t.Fatal("令牌不得包含 secret 明文")
	}
	got, err := VerifyToken(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != claims.Subject || got.Tenant != claims.Tenant || got.Role != claims.Role {
		t.Fatalf("claims 往返不一致: %+v vs %+v", got, claims)
	}
	if !got.ExpiresAt.Equal(claims.ExpiresAt) {
		t.Fatalf("ExpiresAt 往返不一致: %v vs %v", got.ExpiresAt, claims.ExpiresAt)
	}
}

// TestTokenWrongSecret 错误 secret → 签名无效。
func TestTokenWrongSecret(t *testing.T) {
	token, err := IssueToken([]byte("secret-A-0123456789"), testClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken([]byte("secret-B-0123456789"), token); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("错误 secret 应返回 ErrTokenSignature, got %v", err)
	}
}

// TestTokenTampered 篡改 payload / 签名 → 签名无效。
func TestTokenTampered(t *testing.T) {
	secret := []byte("tamper-secret-0123456789")
	token, err := IssueToken(secret, testClaims())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	payloadB64 := []byte(parts[0])
	if payloadB64[0] == 'A' {
		payloadB64[0] = 'B'
	} else {
		payloadB64[0] = 'A'
	}
	if _, err := VerifyToken(secret, string(payloadB64)+"."+parts[1]); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("篡改 payload 应返回 ErrTokenSignature, got %v", err)
	}

	sigB64 := []byte(parts[1])
	if sigB64[0] == 'A' {
		sigB64[0] = 'B'
	} else {
		sigB64[0] = 'A'
	}
	if _, err := VerifyToken(secret, parts[0]+"."+string(sigB64)); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("篡改签名应返回 ErrTokenSignature, got %v", err)
	}
}

// TestTokenMalformed 结构错误 → ErrTokenMalformed。
func TestTokenMalformed(t *testing.T) {
	secret := []byte("malformed-secret-0123456789")
	for _, bad := range []string{"", "   ", "no-dot-token", "a.b.c", ".abc", "abc.", "abc.!!!"} {
		if _, err := VerifyToken(secret, bad); !errors.Is(err, ErrTokenMalformed) {
			t.Fatalf("VerifyToken(%q) 应返回 ErrTokenMalformed, got %v", bad, err)
		}
	}
}

// TestTokenEmptySecret secret 为空 → ErrTokenSecretEmpty（签发/验证都明确报错）。
func TestTokenEmptySecret(t *testing.T) {
	if _, err := IssueToken(nil, testClaims()); !errors.Is(err, ErrTokenSecretEmpty) {
		t.Fatalf("IssueToken(nil) 应返回 ErrTokenSecretEmpty, got %v", err)
	}
	if _, err := VerifyToken(nil, "a.b"); !errors.Is(err, ErrTokenSecretEmpty) {
		t.Fatalf("VerifyToken(nil) 应返回 ErrTokenSecretEmpty, got %v", err)
	}
}

// TestTokenExpired 过期令牌 → ErrTokenExpired（签名仍须有效）。
func TestTokenExpired(t *testing.T) {
	secret := []byte("expired-secret-0123456789")
	c := testClaims()
	c.ExpiresAt = time.Now().Add(-time.Hour)
	token, err := IssueToken(secret, c) // 签发只做结构校验，允许已过期时间
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(secret, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("过期令牌应返回 ErrTokenExpired, got %v", err)
	}
}

// TestTokenClaimsInvalid 结构非法 claims：签发拒绝；签名合法时验证也拒绝。
func TestTokenClaimsInvalid(t *testing.T) {
	secret := []byte("claims-secret-0123456789")
	base := testClaims()

	bad := []Claims{
		{Subject: "", Tenant: base.Tenant, Role: base.Role, ExpiresAt: base.ExpiresAt},
		{Subject: base.Subject, Tenant: "", Role: base.Role, ExpiresAt: base.ExpiresAt},
		{Subject: base.Subject, Tenant: "a/b", Role: base.Role, ExpiresAt: base.ExpiresAt},
		{Subject: base.Subject, Tenant: base.Tenant, Role: "", ExpiresAt: base.ExpiresAt},
		{Subject: base.Subject, Tenant: base.Tenant, Role: "bad*role", ExpiresAt: base.ExpiresAt},
		{Subject: base.Subject, Tenant: base.Tenant, Role: base.Role},
	}
	for _, c := range bad {
		if _, err := IssueToken(secret, c); !errors.Is(err, ErrTokenClaims) {
			t.Fatalf("IssueToken(%+v) 应返回 ErrTokenClaims, got %v", c, err)
		}
		if _, err := VerifyToken(secret, rawToken(t, secret, c)); !errors.Is(err, ErrTokenClaims) {
			t.Fatalf("VerifyToken(签名合法但 claims 非法 %+v) 应返回 ErrTokenClaims, got %v", c, err)
		}
	}
}

// TestTokenTenantMismatch 租户不匹配 → ErrTenantMismatch；匹配时不报错。
func TestTokenTenantMismatch(t *testing.T) {
	secret := []byte("tenant-secret-0123456789")
	token, err := IssueToken(secret, testClaims())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTokenForTenant(secret, token, "tenant-a"); err != nil {
		t.Fatalf("同租户校验不应失败: %v", err)
	}
	for _, tenant := range []string{"tenant-b", ""} {
		if _, err := VerifyTokenForTenant(secret, token, tenant); !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("租户 %q 不匹配应返回 ErrTenantMismatch, got %v", tenant, err)
		}
	}
	// 签名错误优先于租户判定
	if _, err := VerifyTokenForTenant([]byte("other-secret-0123456789"), token, "tenant-a"); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("错误 secret 应优先返回 ErrTokenSignature, got %v", err)
	}
}

// TestTokenFingerprint 指纹可用于审计关联且不泄露令牌/secret。
func TestTokenFingerprint(t *testing.T) {
	secret := []byte("fingerprint-secret-0123456789")
	token, err := IssueToken(secret, testClaims())
	if err != nil {
		t.Fatal(err)
	}
	fp := TokenFingerprint(token)
	if len(fp) != 16 || !isHex(fp) {
		t.Fatalf("指纹应为 16 位 hex, got %q", fp)
	}
	if strings.Contains(fp, token) || strings.Contains(fp, string(secret)) || fp == token {
		t.Fatal("指纹不得包含/等于令牌或 secret")
	}
	if TokenFingerprint(token) != fp {
		t.Fatal("同一令牌指纹应稳定")
	}
	if TokenFingerprint(token+"x") == fp {
		t.Fatal("不同令牌指纹应不同")
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// TestNoCredentialsInLogsAndErrors 凭据不落日志：包内不写日志；错误与指纹均不含 secret/令牌。
func TestNoCredentialsInLogsAndErrors(t *testing.T) {
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldWriter)

	secret := []byte("super-secret-DO-NOT-LOG-0123456789")
	otherSecret := []byte("wrong-secret-0123456789")
	claims := testClaims()
	token, err := IssueToken(secret, claims)
	if err != nil {
		t.Fatal(err)
	}

	// 覆盖各失败路径（签名/篡改/过期/租户/结构）
	expired := claims
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	expiredToken, err := IssueToken(secret, expired)
	if err != nil {
		t.Fatal(err)
	}
	errs := []error{}
	if _, err := VerifyToken(otherSecret, token); err != nil {
		errs = append(errs, err)
	}
	if _, err := VerifyToken(secret, token+"x"); err != nil {
		errs = append(errs, err)
	}
	if _, err := VerifyToken(secret, expiredToken); err != nil {
		errs = append(errs, err)
	}
	if _, err := VerifyTokenForTenant(secret, token, "tenant-b"); err != nil {
		errs = append(errs, err)
	}
	if _, err := VerifyToken(secret, "garbage"); err != nil {
		errs = append(errs, err)
	}
	if _, err := IssueToken(secret, Claims{}); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 6 {
		t.Fatalf("失败路径应全部报错: %d", len(errs))
	}

	if buf.Len() != 0 {
		t.Fatalf("包内不应写日志，实际输出: %q", buf.String())
	}
	for _, err := range errs {
		msg := err.Error()
		if strings.Contains(msg, string(secret)) || strings.Contains(msg, token) {
			t.Fatalf("错误信息泄露凭据/令牌: %q", msg)
		}
	}
	if fp := TokenFingerprint(token); strings.Contains(fp, string(secret)) {
		t.Fatal("指纹泄露 secret")
	}
}
