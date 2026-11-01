package authz

// 多租户：租户模型 / 资源键命名规范 / 跨租户隔离（默认拒绝 + admin 例外可配）。

import (
	"errors"
	"strings"
	"testing"
)

// TestTenantValidate 租户 ID 规范。
func TestTenantValidate(t *testing.T) {
	valid := []string{"tenant-a", "T-1", "a.b_c-d", "t1"}
	for _, id := range valid {
		if err := (Tenant{ID: id, Name: "Acme", Plan: "enterprise"}).Validate(); err != nil {
			t.Fatalf("合法租户 %q 不应报错: %v", id, err)
		}
	}
	invalid := []string{"", ".", "..", "a/b", "a b", "t*1", strings.Repeat("a", 65)}
	for _, id := range invalid {
		if err := (Tenant{ID: id}).Validate(); !errors.Is(err, ErrInvalidTenant) {
			t.Fatalf("非法租户 %q 应返回 ErrInvalidTenant, got %v", id, err)
		}
	}
}

// TestIsolate 默认隔离：同租户可见，跨租户/空租户一律拒绝。
func TestIsolate(t *testing.T) {
	cases := []struct {
		tenant, resource string
		want             bool
	}{
		{"tenant-a", "tenant-a", true},
		{" tenant-a ", "tenant-a", true}, // 去空白
		{"tenant-a", "tenant-b", false},
		{"", "tenant-a", false},
		{"tenant-a", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := Isolate(c.tenant, c.resource); got != c.want {
			t.Fatalf("Isolate(%q, %q)=%v, want %v", c.tenant, c.resource, got, c.want)
		}
	}
}

// TestIsolationPolicy admin 跨租户例外必须显式配置，且只对 admin 生效。
func TestIsolationPolicy(t *testing.T) {
	strict := IsolationPolicy{} // 零值最严
	if strict.Isolate(RoleAdmin, "tenant-a", "tenant-b") {
		t.Fatal("零值策略下 admin 也不得跨租户")
	}
	if !strict.Isolate(RoleAdmin, "tenant-a", "tenant-a") {
		t.Fatal("同租户应可见")
	}

	policy := IsolationPolicy{AdminCrossTenant: true}
	cases := []struct {
		role     Role
		tenant   string
		resource string
		want     bool
	}{
		{RoleAdmin, "tenant-a", "tenant-b", true},
		{RoleAdmin, "tenant-a", "tenant-a", true},
		{RoleOperator, "tenant-a", "tenant-b", false},
		{RoleViewer, "tenant-a", "tenant-b", false},
		{Role("custom"), "tenant-a", "tenant-b", false},
		{RoleAdmin, "", "tenant-b", false}, // 空租户仍拒绝
		{RoleAdmin, "tenant-a", "", false},
	}
	for _, c := range cases {
		if got := policy.Isolate(c.role, c.tenant, c.resource); got != c.want {
			t.Fatalf("policy.Isolate(%q, %q, %q)=%v, want %v", c.role, c.tenant, c.resource, got, c.want)
		}
	}
}

// TestResourceKey 资源键命名规范：tenant/{tenantID}/{kind}/{id}。
func TestResourceKey(t *testing.T) {
	key, err := ResourceKey("tenant-a", "scan", "17")
	if err != nil {
		t.Fatal(err)
	}
	if key != "tenant/tenant-a/scan/17" {
		t.Fatalf("ResourceKey=%q, want tenant/tenant-a/scan/17", key)
	}
	scanKey, err := ScanResourceKey("tenant-a", 17)
	if err != nil || scanKey != key {
		t.Fatalf("ScanResourceKey(%q)=%q, %v", "tenant-a", scanKey, err)
	}

	parts, err := ParseResourceKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if parts.TenantID != "tenant-a" || parts.Kind != "scan" || parts.ID != "17" {
		t.Fatalf("ParseResourceKey 不符: %+v", parts)
	}
	// kind 归一为小写，ID/TenantID 保留原样
	parts, err = ParseResourceKey("tenant/Acme/Scan/AbC")
	if err != nil || parts.TenantID != "Acme" || parts.Kind != "scan" || parts.ID != "AbC" {
		t.Fatalf("ParseResourceKey 大小写口径不符: %+v, err=%v", parts, err)
	}

	// 构造非法段
	for _, c := range [][3]string{
		{"", "scan", "1"}, {"a/b", "scan", "1"}, {"a", "", "1"},
		{"a", "scan", ""}, {"a", "scan", ".."}, {"a", "scan", "x y"},
	} {
		if _, err := ResourceKey(c[0], c[1], c[2]); !errors.Is(err, ErrInvalidResourceKey) {
			t.Fatalf("ResourceKey(%q,%q,%q) 应返回 ErrInvalidResourceKey, got %v", c[0], c[1], c[2], err)
		}
	}

	// 解析非法键
	for _, bad := range []string{
		"", "scan/1", "tenant/a/scan", "tenant/a/scan/1/2",
		"tenant/a//1", "tenant/../scan/1", "other/a/scan/1", "tenant/a/scan/..",
	} {
		if _, err := ParseResourceKey(bad); !errors.Is(err, ErrInvalidResourceKey) {
			t.Fatalf("ParseResourceKey(%q) 应返回 ErrInvalidResourceKey, got %v", bad, err)
		}
	}
}

// TestVisibleTo 按资源键做隔离判定（接线入口）：解析失败默认拒绝。
func TestVisibleTo(t *testing.T) {
	key, err := ScanResourceKey("tenant-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	strict := IsolationPolicy{}
	if !strict.VisibleTo(RoleAdmin, "tenant-a", key) {
		t.Fatal("同租户资源应可见")
	}
	if strict.VisibleTo(RoleAdmin, "tenant-b", key) {
		t.Fatal("默认策略下跨租户不可见")
	}
	policy := IsolationPolicy{AdminCrossTenant: true}
	if !policy.VisibleTo(RoleAdmin, "tenant-b", key) {
		t.Fatal("开启 admin 跨租户后 admin 应可见")
	}
	if policy.VisibleTo(RoleOperator, "tenant-b", key) {
		t.Fatal("operator 不得跨租户")
	}
	if policy.VisibleTo(RoleAdmin, "tenant-a", "not-a-key") {
		t.Fatal("非法资源键应默认拒绝")
	}
}
