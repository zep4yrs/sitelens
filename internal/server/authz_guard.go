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

// tenantFromRequest 当前请求的数据租户（BL-5/A-04 数据面隔离）。
//
//   - token 模式：取令牌 claims.Tenant（X-Tenant-ID 一致性已在 authorizeRBAC
//     校验过；这里以令牌为准，不信任请求头）；
//   - none 模式（默认单机部署）/ 未鉴权：空字符串 = 全局（legacy 记录可见，
//     既有行为不变）。
//
// 所有按 {id} 读取/删除业务数据的 handler 都必须用该值做归属校验：不匹配
// 一律 404（不泄露存在性）。
func tenantFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, ok := claimsFromContext(r.Context()); ok {
		return strings.TrimSpace(c.Tenant)
	}
	return ""
}

// isAdminRequest 请求是否具备管理员视角。
//   - token 模式：仅 admin 角色为真（operator/viewer 一律 false）；
//   - none 模式（默认，单用户本机部署）：按本机管理员处理，保持既有行为。
//
// 用于 V-11 的 config_path 可见性等敏感配置回显分级。
func isAdminRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if c, ok := claimsFromContext(r.Context()); ok {
		return c.Role == authz.RoleAdmin
	}
	return true
}

// authMode 归一认证模式（空 = none）。
func (s *Server) authMode() string {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	if s == nil || cfg == nil {
		return "none"
	}
	return strings.ToLower(strings.TrimSpace(cfg.Web.AuthMode))
}

// authorizeRBAC token 模式鉴权；通过返回 true，失败已写响应并返回 false。
func (s *Server) authorizeRBAC(w http.ResponseWriter, r *http.Request) bool {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	secret := []byte(cfg.Web.AuthSecret)
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

// apiResourceAliases 路由首段 → RBAC 资源名（A-03）。
//
// 背景：默认矩阵里 operator 的 Allow 是 scan/report/asset/triage，而真实路由
// 首段是 job/history/batch/export/assets —— 直接取首段会让 operator（文档定义
// "发起扫描、处理复核、导出"）几乎全部 403（连自己任务的进度/结果都读不到）。
// 这里把"业务上同属一类数据"的路由归一到矩阵资源名：
//   - 扫描作业与其产物（job/history/batch/graph/diff/replay/verified/...）→ scan；
//   - 报告导出 → report；资产 → asset；复核 → triage。
var apiResourceAliases = map[string]string{
	"scan": "scan", "job": "scan", "history": "scan", "batch": "scan",
	"preflight": "scan", "diff": "scan", "graph": "scan", "replay": "scan",
	"verified": "scan", "vuln-search": "scan", "tasks": "scan",
	"proof":  "scan", // 5.3 P1：目标/证明链属于扫描产物
	"report": "report", "export": "report",
	"asset": "asset", "assets": "asset",
	"triage": "triage", "whitelist": "whitelist",
}

// apiResourceDirect 首段即资源名、无需别名映射的路由。
// 新增路由若首段不在别名表也不在此表，TestAPIResourceMapCoversAllRoutes 会
// 直接失败——强制作者显式决定该路由属于哪个资源，避免"新路由悄悄落到
// 未授权/过宽资源"。
var apiResourceDirect = map[string]bool{
	"version": true, "stats": true, "categories": true, "osv-sync": true,
	"settings": true, "diagnostics": true, "feedback": true, "admin": true,
	"netsec": true, "loginbrute": true, "captcha": true, "audit": true,
	"apispec": true, "api": true,
}

// apiDangerousPathResource 单路径覆盖映射：个别路径的破坏力远超其首段语义
// （清空全部历史 ≠ 一次扫描写操作），钉死为 admin 专属，避免 operator 的
// scan:* 顺带拿到清库能力。
var apiDangerousPathResource = map[string]string{
	"/api/history/clear": "admin",
}

// apiResourceOf /api/<resource>/... → RBAC 资源名（含别名归一与危险路径覆盖）。
func apiResourceOf(path string) string {
	if r, ok := apiDangerousPathResource[path]; ok {
		return r
	}
	p := strings.TrimPrefix(path, "/api/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return "api"
	}
	if mapped, ok := apiResourceAliases[p]; ok {
		return mapped
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
