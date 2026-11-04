// SiteLens 企业版 6.x 授权基座（RBAC + 多租户 + 会话令牌）。
//
// 定位
//   - 纯函数 / 纯数据模型：不依赖 engine/server/config/web，不写库、不发网络；
//   - 调用方（server 中间件、任务/报告链路）在入口处按顺序组合：
//     VerifyToken →（Tenant+Role）→ Authorize(action, resource) → Isolate(claims.Tenant, 资源租户)
//
// 安全口径（红线）
//   - 默认拒绝：未知角色、未知动作/资源、空租户、跨租户一律 false；
//   - 拒绝优先：同一请求命中 Deny 模式即拒绝，Allow 再宽也不翻案；
//   - 通配符只用于内置/配置侧的权限模式（"scan:*" / "*:*"），不把请求方输入的
//     字符串当 pattern 使用（防宽授权注入）；
//   - 令牌 HMAC-SHA256（仅标准库），签名常量时间比较；错误信息不回显 secret/token/claims 值；
//   - 本包不写日志；调用方记录拒绝事件时只用 Role/Action/Resource 等非敏感字段。
package authz

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Role 角色名（小写；合法字符 [A-Za-z0-9._-]）。
type Role string

const (
	// RoleViewer 只读：查阅扫描结果/报告/资产（"*:read"）。
	RoleViewer Role = "viewer"
	// RoleOperator 运营：发起扫描、处理复核、导出；不可删除扫描记录、不可管租户/用户。
	RoleOperator Role = "operator"
	// RoleAdmin 管理员：全权限（"*:*"）；跨租户例外仍需显式开启（见 IsolationPolicy）。
	RoleAdmin Role = "admin"
)

// Permission 权限模式，格式 "<resource>:<action>"；两段均支持 '*' 通配：
//   - "scan:read" 精确匹配；
//   - "scan:*"    scan 资源全部动作；
//   - "*:read"    全部资源只读；
//   - "*:*"       全部资源全部动作（内置仅 admin 默认拥有）。
type Permission string

// PermissionOf 构造规范权限串（resource/action 去空白并小写）。
func PermissionOf(resource, action string) Permission {
	return Permission(normalizeSegment(resource) + ":" + normalizeSegment(action))
}

// ValidPermission 权限模式是否合法（供 NewAuthorizer 与配置校验）。
func ValidPermission(p Permission) bool {
	_, _, ok := splitPermission(p)
	return ok
}

// MatchPermission pattern 是否匹配 (resource, action)；pattern 非法或输入为空 → false。
func MatchPermission(pattern Permission, action, resource string) bool {
	act, res := normalizeSegment(action), normalizeSegment(resource)
	if act == "" || res == "" {
		return false
	}
	pres, pact, ok := splitPermission(pattern)
	if !ok {
		return false
	}
	return matchSegment(pres, res) && matchSegment(pact, act)
}

// RoleDef 角色权限定义：Deny 优先于 Allow（同一请求命中 Deny 即拒绝）。
type RoleDef struct {
	Role  Role         `json:"role"`
	Allow []Permission `json:"allow,omitempty"`
	Deny  []Permission `json:"deny,omitempty"`
}

// DefaultRoleDefs 内置默认权限矩阵（返回副本，调用方修改不会污染包级默认）：
//
//	viewer   Allow "*:read"
//	         Deny  "settings:*" "diagnostics:*" "admin:*" "whitelist:*"
//	               （配置/诊断/管理/白名单属管理面，只读角色也不该看：
//	                诊断含主机与运行事实、settings 含配置路径）
//	operator Allow "scan:*" "report:*" "asset:*" "triage:*"
//	         Deny  "scan:delete"（删除归档记录属管理动作）、管理面四类
//	admin    Allow "*:*"
//
// operator 的 Deny 同时作为「拒绝优先」的默认演示：即使日后给 operator 加
// 宽 Allow（如 "*:*"），"scan:delete" 与管理面仍被拒绝。
func DefaultRoleDefs() []RoleDef {
	defs := []RoleDef{
		{
			Role:  RoleViewer,
			Allow: []Permission{PermissionOf("*", "read")},
			Deny: []Permission{
				PermissionOf("settings", "*"), PermissionOf("diagnostics", "*"),
				PermissionOf("admin", "*"), PermissionOf("whitelist", "*"),
			},
		},
		{
			Role:  RoleOperator,
			Allow: []Permission{PermissionOf("scan", "*"), PermissionOf("report", "*"), PermissionOf("asset", "*"), PermissionOf("triage", "*")},
			Deny: []Permission{
				PermissionOf("scan", "delete"), PermissionOf("tenant", "*"), PermissionOf("user", "*"),
				PermissionOf("settings", "*"), PermissionOf("diagnostics", "*"),
				PermissionOf("admin", "*"), PermissionOf("whitelist", "*"),
			},
		},
		{Role: RoleAdmin, Allow: []Permission{PermissionOf("*", "*")}},
	}
	out := make([]RoleDef, len(defs))
	for i, d := range defs {
		out[i] = RoleDef{
			Role:  d.Role,
			Allow: append([]Permission(nil), d.Allow...),
			Deny:  append([]Permission(nil), d.Deny...),
		}
	}
	return out
}

var (
	// ErrInvalidPermission 权限模式非法（不是 <resource>:<action> 或含非法字符）。
	ErrInvalidPermission = errors.New("authz: 非法权限模式")
	// ErrInvalidRoleName 角色名非法（空或含非法字符）。
	ErrInvalidRoleName = errors.New("authz: 非法角色名")
)

// Authorizer 授权器：内置默认矩阵 + 可覆盖/扩展角色定义。
// 并发安全：构造后只读。
type Authorizer struct {
	defs map[Role]*roleRule
}

type roleRule struct {
	allow []Permission
	deny  []Permission
}

// NewAuthorizer 构造授权器：
//   - defs 为空 → 全部内置默认角色；
//   - defs 中与内置同名角色「整体覆盖」（不合并），其余内置角色保留；
//   - 自定义角色直接追加。
//
// 非法权限模式/角色名返回错误（错误信息不含调用方传入之外的敏感值；
// 权限模式本身是配置项，允许回显以便定位配置错误）。
func NewAuthorizer(defs []RoleDef) (*Authorizer, error) {
	merged := make(map[Role]RoleDef, len(defs)+3)
	for _, d := range DefaultRoleDefs() {
		merged[d.Role] = d
	}
	for _, d := range defs {
		role := normalizeRole(d.Role)
		if role == "" {
			return nil, fmt.Errorf("%w: role=%q", ErrInvalidRoleName, string(d.Role))
		}
		for _, p := range append(append([]Permission{}, d.Allow...), d.Deny...) {
			if !ValidPermission(p) {
				return nil, fmt.Errorf("%w: %q（角色 %s）", ErrInvalidPermission, string(p), role)
			}
		}
		merged[role] = RoleDef{
			Role:  role,
			Allow: append([]Permission(nil), d.Allow...),
			Deny:  append([]Permission(nil), d.Deny...),
		}
	}
	a := &Authorizer{defs: make(map[Role]*roleRule, len(merged))}
	for role, d := range merged {
		a.defs[role] = &roleRule{allow: normalizePermissions(d.Allow), deny: normalizePermissions(d.Deny)}
	}
	return a, nil
}

// Authorize 角色对 (action, resource) 是否放行：
//  1. 角色/动作/资源归一（去空白小写），未知角色 → false；
//  2. Deny 命中 → false（拒绝优先）；
//  3. Allow 命中 → true；
//  4. 都未命中 → false（默认拒绝）。
func (a *Authorizer) Authorize(role Role, action, resource string) bool {
	if a == nil {
		return false
	}
	act, res := normalizeSegment(action), normalizeSegment(resource)
	if act == "" || res == "" {
		return false
	}
	rule := a.defs[normalizeRole(role)]
	if rule == nil {
		return false
	}
	for _, p := range rule.deny {
		if MatchPermission(p, act, res) {
			return false
		}
	}
	for _, p := range rule.allow {
		if MatchPermission(p, act, res) {
			return true
		}
	}
	return false
}

// RoleDef 返回角色当前生效定义（第二返回值为 false 表示未知角色）。
func (a *Authorizer) RoleDef(role Role) (RoleDef, bool) {
	if a == nil {
		return RoleDef{}, false
	}
	r := normalizeRole(role)
	rule := a.defs[r]
	if rule == nil {
		return RoleDef{}, false
	}
	return RoleDef{
		Role:  r,
		Allow: append([]Permission(nil), rule.allow...),
		Deny:  append([]Permission(nil), rule.deny...),
	}, true
}

// Roles 全部已注册角色（字典序，稳定输出，供权限矩阵报表/审计）。
func (a *Authorizer) Roles() []Role {
	if a == nil {
		return nil
	}
	out := make([]Role, 0, len(a.defs))
	for r := range a.defs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// defaultAuthorizer 包级默认矩阵（内置定义必须合法；否则包初始化即失败）。
var defaultAuthorizer, defaultAuthorizerErr = NewAuthorizer(nil)

// Authorize 默认矩阵下的授权判定（便捷入口，等价 NewAuthorizer(nil).Authorize）。
// 未知角色/空动作/空资源 → false。
func Authorize(role Role, action, resource string) bool {
	if defaultAuthorizerErr != nil || defaultAuthorizer == nil {
		return false // 内置矩阵非法属编程错误：兜底默认拒绝
	}
	return defaultAuthorizer.Authorize(role, action, resource)
}

// ---- 内部工具 ----

// normalizeSegment 去空白小写（动作/资源/角色归一）。
func normalizeSegment(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// normalizeRole 角色归一；非法角色名返回空串（后续按未知角色拒绝）。
func normalizeRole(r Role) Role {
	s := normalizeSegment(string(r))
	if !validSegment(s, false) {
		return ""
	}
	return Role(s)
}

// validSegment 段是否合法：allowStar 时允许单独 "*"；否则 [a-z0-9._-]+。
func validSegment(s string, allowStar bool) bool {
	if s == "*" {
		return allowStar
	}
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// splitPermission 拆分 "<resource>:<action>"，两段非空且合法（允许 '*'）。
func splitPermission(p Permission) (resource, action string, ok bool) {
	s := normalizeSegment(string(p))
	if s == "" || strings.Count(s, ":") != 1 {
		return "", "", false
	}
	res, act, _ := strings.Cut(s, ":")
	if !validSegment(res, true) || !validSegment(act, true) {
		return "", "", false
	}
	return res, act, true
}

// matchSegment 通配匹配："*" 匹配任意；否则精确相等。
func matchSegment(pattern, value string) bool { return pattern == "*" || pattern == value }

// normalizePermissions 规范化权限列表（构造时已校验，失败项丢弃）。
func normalizePermissions(ps []Permission) []Permission {
	out := make([]Permission, 0, len(ps))
	for _, p := range ps {
		if res, act, ok := splitPermission(p); ok {
			out = append(out, Permission(res+":"+act))
		}
	}
	return out
}
