// 多租户模型：租户、资源键命名规范、跨租户隔离判定（默认拒绝）。
//
// 命名规范（企业版 6.x 全局约定，报告/审计/对象存储键共用）：
//
//	tenant/{tenantID}/{kind}/{id}
//
// 例：tenant/tenant-a/scan/17、tenant/beta/asset/host-1、tenant/acme/report/2026-Q4。
// 三段均只允许 [A-Za-z0-9._-] 且非空（拒绝 "/"、"."、".."，防键歧义与路径穿越）。
//
// 隔离口径：
//   - Isolate 是"数据面"默认判定：只有同租户（且非空）才可见；
//   - admin 例外必须显式通过 IsolationPolicy{AdminCrossTenant:true} 开启，
//     且仅对 admin 生效——默认配置下管理员也不能跨租户读数据。
package authz

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidTenant 租户 ID/名称模型非法。
var ErrInvalidTenant = errors.New("authz: 非法租户")

// ErrInvalidResourceKey 资源键非法（前缀/段数/字符集不符）。
var ErrInvalidResourceKey = errors.New("authz: 非法资源键")

// Tenant 租户最小模型。Plan 仅作标识（配额/功能分级由调用方执行，本包不做计费/限额）。
type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Plan string `json:"plan,omitempty"`
}

// Validate 校验租户 ID：非空、[A-Za-z0-9._-]{1,64}、非 "."/".."；Name/Plan 可为空。
func (t Tenant) Validate() error {
	if !validSegment(normalizeSegment(t.ID), false) || len(t.ID) > 64 {
		return fmt.Errorf("%w: id 必须为 1-64 位 [A-Za-z0-9._-] 且非 . / ..", ErrInvalidTenant)
	}
	return nil
}

// ResourceKeyPrefix 资源键固定前缀。
const ResourceKeyPrefix = "tenant"

// ResourceKeyParts 解析后的资源键。
type ResourceKeyParts struct {
	TenantID string // 资源所属租户
	Kind     string // 资源类型（scan/asset/report/…）
	ID       string // 资源 ID
}

// ResourceKey 构造函数约定的资源键：tenant/{tenantID}/{kind}/{id}。
// 任一段非法（空、含 "/"、"."、".."、非 [A-Za-z0-9._-]）返回 ErrInvalidResourceKey。
func ResourceKey(tenantID, kind, id string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	kind = strings.TrimSpace(kind)
	id = strings.TrimSpace(id)
	for _, seg := range []string{tenantID, kind, id} {
		if !validSegment(strings.ToLower(seg), false) {
			return "", fmt.Errorf("%w: 段 %q 非法", ErrInvalidResourceKey, seg)
		}
	}
	return ResourceKeyPrefix + "/" + tenantID + "/" + kind + "/" + id, nil
}

// ScanResourceKey scan 资源键便捷构造：tenant/{tenantID}/scan/{scanID}。
func ScanResourceKey(tenantID string, scanID int64) (string, error) {
	return ResourceKey(tenantID, "scan", strconv.FormatInt(scanID, 10))
}

// ParseResourceKey 解析资源键；段数/前缀/字符集不符返回 ErrInvalidResourceKey。
func ParseResourceKey(key string) (ResourceKeyParts, error) {
	k := strings.TrimSpace(key)
	parts := strings.Split(k, "/")
	if len(parts) != 4 || strings.ToLower(parts[0]) != ResourceKeyPrefix {
		return ResourceKeyParts{}, fmt.Errorf("%w: 需要 %s/{tenant}/{kind}/{id}", ErrInvalidResourceKey, ResourceKeyPrefix)
	}
	for _, seg := range parts[1:] {
		if !validSegment(strings.ToLower(seg), false) {
			return ResourceKeyParts{}, fmt.Errorf("%w: 段 %q 非法", ErrInvalidResourceKey, seg)
		}
	}
	return ResourceKeyParts{TenantID: parts[1], Kind: strings.ToLower(parts[2]), ID: parts[3]}, nil
}

// Isolate 默认跨租户隔离判定：同租户（且非空）→ true；空/不同租户 → false（默认拒绝）。
// admin 例外不在这里开放，必须显式用 IsolationPolicy（可配，默认也关闭）。
func Isolate(tenantID, resourceTenantID string) bool {
	a := strings.TrimSpace(tenantID)
	b := strings.TrimSpace(resourceTenantID)
	if a == "" || b == "" {
		return false
	}
	return a == b
}

// IsolationPolicy 跨租户访问策略。零值 = 最严（任何人不得跨租户）。
type IsolationPolicy struct {
	// AdminCrossTenant 允许 admin 跨租户访问（默认 false；仅对 RoleAdmin 生效）。
	AdminCrossTenant bool `json:"admin_cross_tenant"`
}

// Isolate 组合租户隔离 + 角色例外：
//   - 同租户 → true（不依赖角色）；
//   - 跨租户 → 仅当 AdminCrossTenant && role==admin && 两侧租户均非空；
//   - 其余 → false（默认拒绝）。
func (p IsolationPolicy) Isolate(role Role, tenantID, resourceTenantID string) bool {
	if Isolate(tenantID, resourceTenantID) {
		return true
	}
	if !p.AdminCrossTenant {
		return false
	}
	// admin 例外也不接受空租户：空租户属非法声明，不得借例外放大。
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(resourceTenantID) == "" {
		return false
	}
	return normalizeRole(role) == RoleAdmin
}

// VisibleTo 按资源键做隔离判定（解析失败 → false，默认拒绝），供 server 接线：
//
//	key, _ := authz.ScanResourceKey(claims.Tenant, scanID)
//	if !policy.VisibleTo(claims.Role, claims.Tenant, key) { 403 }
func (p IsolationPolicy) VisibleTo(role Role, tenantID, resourceKey string) bool {
	parts, err := ParseResourceKey(resourceKey)
	if err != nil {
		return false
	}
	return p.Isolate(role, tenantID, parts.TenantID)
}
