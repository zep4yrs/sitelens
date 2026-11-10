package checks

import (
	"strings"
	"testing"
)

// 内置验证型 check 的结构性门禁（5.3 借鉴 ARES 扩容时补）。
//
// 为什么要有：check 是「验证型」资产——每条都直接决定是否向目标发请求、
// 命中是否算已验证漏洞。字段写错（重复 ID / 路径缺前导斜杠 / 无条件 Match）
// 轻则漏跑、重则全站误报；这里把不变量固化成测试，扩容时不会静默破坏。
func TestBuiltinChecksInvariants(t *testing.T) {
	list := builtinChecks()
	if len(list) < 60 {
		t.Fatalf("内置 check 数量回退：%d（5.3 扩容后应 >= 60）", len(list))
	}
	seen := make(map[string]bool, len(list))
	for _, c := range list {
		if c.ID == "" {
			t.Fatalf("存在空 ID 的 check：%+v", c)
		}
		if seen[c.ID] {
			t.Fatalf("check ID 重复：%s", c.ID)
		}
		seen[c.ID] = true
		if !strings.HasPrefix(c.Path, "/") {
			t.Fatalf("%s 的 Path 必须以 / 开头：%q", c.ID, c.Path)
		}
		if c.Lv != 0 && c.Lv != 1 {
			t.Fatalf("%s 的 Lv 只能取 0/1：%d", c.ID, c.Lv)
		}
		if !c.Match.hasAnyCondition() {
			t.Fatalf("%s 的 Match 无任何判定条件（会变成全站误报）", c.ID)
		}
		if c.Title == "" || c.Sev == "" || c.Advice == "" {
			t.Fatalf("%s 缺少 Title/Sev/Advice：%+v", c.ID, c)
		}
	}
}

// 5.3 新增的扩展集 check：必须 Lv=1（只在「全面」档运行），默认扫描请求量不变。
func TestExtendedChecksStayExtended(t *testing.T) {
	want := []string{
		"git-config", "git-logs", "env-local", "env-prod", "backup-sql",
		"heapdump", "actuator-health", "actuator-mappings",
		"swagger-json", "openapi-json", "v3-api-docs", "graphql-introspect",
		"k8s-version", "k8s-namespaces", "docker-registry", "nginx-status",
		"phpmyadmin", "gitlab",
	}
	byID := make(map[string]Check, len(builtinChecks()))
	for _, c := range builtinChecks() {
		byID[c.ID] = c
	}
	for _, id := range want {
		c, ok := byID[id]
		if !ok {
			t.Fatalf("缺少扩展集 check：%s", id)
		}
		if c.Lv != 1 {
			t.Fatalf("%s 应为扩展集（Lv=1，避免默认扫描请求量变化），实际 Lv=%d", id, c.Lv)
		}
	}
}
