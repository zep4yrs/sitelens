package authz

// RBAC 权限矩阵 / 通配符 / 拒绝优先 / 授权器校验的单测。

import (
	"errors"
	"testing"
)

// TestDefaultRoleMatrix 默认三角色权限矩阵（viewer/operator/admin）。
func TestDefaultRoleMatrix(t *testing.T) {
	cases := []struct {
		role     Role
		action   string
		resource string
		want     bool
	}{
		// viewer：只读
		{RoleViewer, "read", "scan", true},
		{RoleViewer, "read", "report", true},
		{RoleViewer, "read", "tenant", true}, // "*:read" 覆盖所有资源只读
		{RoleViewer, "write", "scan", false},
		{RoleViewer, "delete", "scan", false},
		// operator：扫描/报告/资产/复核全动作，但不可删扫描、不可管租户/用户
		{RoleOperator, "read", "scan", true},
		{RoleOperator, "write", "scan", true},
		{RoleOperator, "delete", "scan", false}, // 命中 Deny（拒绝优先）
		{RoleOperator, "read", "report", true},
		{RoleOperator, "write", "report", true},
		{RoleOperator, "read", "asset", true},
		{RoleOperator, "write", "triage", true},
		{RoleOperator, "manage", "tenant", false},
		{RoleOperator, "read", "tenant", false},
		{RoleOperator, "write", "user", false},
		{RoleOperator, "read", "misc", false}, // 未授权资源默认拒绝
		// admin：全权限
		{RoleAdmin, "delete", "scan", true},
		{RoleAdmin, "manage", "tenant", true},
		{RoleAdmin, "anything", "unknown-thing", true},
		// 未知/空角色：默认拒绝
		{Role("guest"), "read", "scan", false},
		{Role(""), "read", "scan", false},
		{Role("VIEWER"), "READ", "SCAN", true}, // 大小写归一
	}
	for _, c := range cases {
		if got := Authorize(c.role, c.action, c.resource); got != c.want {
			t.Fatalf("Authorize(%q, %q, %q)=%v, want %v", c.role, c.action, c.resource, got, c.want)
		}
	}
}

// TestMatchPermission 通配符与非法 pattern。
func TestMatchPermission(t *testing.T) {
	cases := []struct {
		pattern  Permission
		action   string
		resource string
		want     bool
	}{
		{"*:*", "delete", "tenant", true},
		{"scan:*", "write", "scan", true},
		{"scan:*", "read", "report", false},
		{"*:read", "read", "anything", true},
		{"*:read", "write", "anything", false},
		{"scan:read", "read", "scan", true},
		{"scan:read", "READ", "SCAN", true}, // 输入归一
		{"scan", "read", "scan", false},     // 缺 ':'
		{"scan::read", "read", "scan", false},
		{"scan:", "read", "scan", false},
		{":read", "read", "scan", false},
		{"sc an:read", "read", "scan", false}, // 非法字符
		{"scan:re*ad", "read", "scan", false}, // '*' 只能整段
		{"", "read", "scan", false},
	}
	for _, c := range cases {
		if got := MatchPermission(c.pattern, c.action, c.resource); got != c.want {
			t.Fatalf("MatchPermission(%q, %q, %q)=%v, want %v", c.pattern, c.action, c.resource, got, c.want)
		}
	}
}

// TestDenyFirst 拒绝优先：命中 Deny 即拒绝，即便 Allow 匹配。
func TestDenyFirst(t *testing.T) {
	// 默认 operator：Allow scan:* 但 Deny scan:delete
	if Authorize(RoleOperator, "delete", "scan") {
		t.Fatal("默认 operator 不应能删除扫描记录（Deny 优先）")
	}
	if !Authorize(RoleOperator, "read", "scan") {
		t.Fatal("operator 应能读扫描")
	}

	// 自定义：Allow *:* + Deny scan:delete → 删除仍拒绝，其他放行
	a, err := NewAuthorizer([]RoleDef{{
		Role:  RoleOperator,
		Allow: []Permission{PermissionOf("*", "*")},
		Deny:  []Permission{PermissionOf("scan", "delete")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Authorize(RoleOperator, "delete", "scan") {
		t.Fatal("自定义 operator Allow *:* 时 Deny scan:delete 仍应拒绝")
	}
	if !a.Authorize(RoleOperator, "delete", "report") {
		t.Fatal("Deny 只应作用于 scan:delete")
	}

	// 自定义角色 auditor：允许读所有但禁止读 tenant
	a, err = NewAuthorizer([]RoleDef{{
		Role:  Role("auditor"),
		Allow: []Permission{PermissionOf("*", "read")},
		Deny:  []Permission{PermissionOf("tenant", "*")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Authorize(Role("auditor"), "read", "scan") {
		t.Fatal("auditor 应能读扫描")
	}
	if a.Authorize(Role("auditor"), "read", "tenant") {
		t.Fatal("auditor 不应能读租户（Deny 优先）")
	}
}

// TestNewAuthorizerValidation 构造校验：非法权限/角色名明确报错。
func TestNewAuthorizerValidation(t *testing.T) {
	if _, err := NewAuthorizer([]RoleDef{{Role: RoleAdmin, Allow: []Permission{"scan"}}}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("非法权限模式应返回 ErrInvalidPermission, got %v", err)
	}
	if _, err := NewAuthorizer([]RoleDef{{Role: Role(""), Allow: []Permission{"scan:read"}}}); !errors.Is(err, ErrInvalidRoleName) {
		t.Fatalf("空角色名应返回 ErrInvalidRoleName, got %v", err)
	}
	if _, err := NewAuthorizer([]RoleDef{{Role: Role("bad*role"), Allow: []Permission{"scan:read"}}}); !errors.Is(err, ErrInvalidRoleName) {
		t.Fatalf("非法角色名应返回 ErrInvalidRoleName, got %v", err)
	}
	// 空 defs 等价默认矩阵
	a, err := NewAuthorizer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Authorize(RoleViewer, "read", "scan") {
		t.Fatal("空 defs 应保留默认矩阵")
	}
}

// TestRoleDefsAndRoles 生效定义查询与角色列表（供矩阵报表）。
func TestRoleDefsAndRoles(t *testing.T) {
	a, err := NewAuthorizer(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := a.RoleDef(RoleViewer)
	if !ok || len(d.Allow) != 1 || d.Allow[0] != PermissionOf("*", "read") {
		t.Fatalf("RoleDef(viewer) 不符: %+v ok=%v", d, ok)
	}
	if _, ok := a.RoleDef(Role("nobody")); ok {
		t.Fatal("未知角色应返回 false")
	}
	roles := a.Roles()
	if len(roles) != 3 || roles[0] != RoleAdmin || roles[1] != RoleOperator || roles[2] != RoleViewer {
		t.Fatalf("Roles() 应为字典序三角色: %v", roles)
	}
}

// TestDefaultRoleDefsCopy 默认矩阵返回副本，外部修改不污染包级默认。
func TestDefaultRoleDefsCopy(t *testing.T) {
	defs := DefaultRoleDefs()
	defs[0].Allow[0] = PermissionOf("hacked", "write")
	defs[0].Deny = append(defs[0].Deny, PermissionOf("scan", "*"))
	if Authorize(RoleViewer, "write", "hacked") {
		t.Fatal("修改 DefaultRoleDefs 副本污染了包级默认矩阵")
	}
	if !Authorize(RoleViewer, "read", "scan") {
		t.Fatal("默认 viewer 只读权限被破坏")
	}
}
