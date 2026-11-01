// 企业化 6.x：RBAC 鉴权（config.Web.AuthMode=token）。
//
// 流程：Authorization: Bearer <token> → authz.VerifyToken →
// 租户隔离（X-Tenant-ID 与令牌租户一致）→ authz.Authorize(role, 动作, 资源)。
// 动作映射：GET/HEAD/OPTIONS = read，其余（POST/PUT/PATCH/DELETE）= write；
// 资源映射：/api/<resource>/... 的第一段（scan/history/batch/export/...）。
//
// 默认 none 模式完全不走本文件（沿用 api_token/X-Token 旧行为）。
package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/authz"
)

// authzClaimsKey 请求上下文中的 claims（供后续 handler 读取租户/角色，additive）。
type authzClaimsKey struct{}

// claimsFromContext 取 RBAC claims（none 模式/未鉴权时 false）。
func claimsFromContext(ctx context.Context) (authz.Claims, bool) {
	c, ok := ctx.Value(authzClaimsKey{}).(authz.Claims)
	return c, ok
}

// authMode 归一认证模式（空 = none）。
func (s *Server) authMode() string {
	if s == nil || s.cfg == nil {
		return "none"
	}
	return strings.ToLower(strings.TrimSpace(s.cfg.Web.AuthMode))
}

// authorizeRBAC token 模式鉴权；通过返回 true，失败已写响应并返回 false。
func (s *Server) authorizeRBAC(w http.ResponseWriter, r *http.Request) bool {
	secret := []byte(s.cfg.Web.AuthSecret)
	if len(secret) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "服务端认证未配置（web.auth_secret 为空）",
		})
		return false
	}
	token := bearerTokenFromHeader(r.Header.Get("Authorization"))
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "未授权：缺少 Authorization: Bearer 令牌",
		})
		return false
	}
	claims, err := authz.VerifyToken(secret, token)
	if err != nil {
		// 不区分签名/过期/格式（避免给探测者额外信息）；错误值不落日志。
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "未授权：令牌无效或已过期",
		})
		return false
	}
	// 租户隔离：请求显式声明租户（X-Tenant-ID）时必须与令牌租户一致。
	if want := strings.TrimSpace(r.Header.Get("X-Tenant-ID")); want != "" &&
		!authz.Isolate(claims.Tenant, want) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "租户不匹配：令牌租户无权访问该租户资源",
		})
		return false
	}
	action := actionOfMethod(r.Method)
	resource := apiResourceOf(r.URL.Path)
	if !authz.Authorize(claims.Role, action, resource) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("无权限：角色 %s 不能执行 %s:%s", claims.Role, resource, action),
		})
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), authzClaimsKey{}, claims))
	return true
}

// actionOfMethod HTTP 方法 → 权限动作。
func actionOfMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read"
	default:
		return "write"
	}
}

// apiResourceOf /api/<resource>/... → <resource>（根 /api → "api"）。
func apiResourceOf(path string) string {
	p := strings.TrimPrefix(path, "/api/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if p = strings.TrimSpace(p); p == "" {
		return "api"
	}
	return p
}

// bearerTokenFromHeader 解析 "Bearer <token>"（大小写不敏感）。
func bearerTokenFromHeader(v string) string {
	v = strings.TrimSpace(v)
	const prefix = "bearer "
	if len(v) >= len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}
