package checks

import (
	"regexp"
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
	if len(list) < 1000 {
		t.Fatalf("内置 check 数量回退：%d（5.3 扩容后应 >= 1000）", len(list))
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

// TestTplChecksQuality 模板转译门禁：只允许「GET 静态路径 + 强判据 + 非利用类」。
// 转译管线见 tools/tpl2check；生成文件 tpl_generated.go 必须过这道门。
func TestTplChecksQuality(t *testing.T) {
	if len(tplChecks) < 40 {
		t.Fatalf("转译 check 数量不足：%d（目标 >= 40）", len(tplChecks))
	}
	seenID := make(map[string]bool, len(tplChecks))
	for _, c := range tplChecks {
		if c.Lv != 1 {
			t.Fatalf("%s 必须 Lv=1（扩展集，仅完整/穷尽档运行）", c.ID)
		}
		if !strings.HasPrefix(c.ID, "tpl-") {
			t.Fatalf("%s 缺少 tpl- 前缀", c.ID)
		}
		if seenID[c.ID] {
			t.Fatalf("转译 check ID 重复：%s", c.ID)
		}
		seenID[c.ID] = true
		if !strings.HasPrefix(c.Path, "/") || strings.Contains(c.Path, "{{") {
			t.Fatalf("%s 路径必须是无变量静态路径：%q", c.ID, c.Path)
		}
		if q := strings.Index(c.Path, "?"); q >= 0 {
			if !regexp.MustCompile(`^[A-Za-z0-9._~%=&+-]*$`).MatchString(c.Path[q+1:]) {
				t.Fatalf("%s 路径 query 含非法字符：%q", c.ID, c.Path)
			}
		}
		if !c.Match.hasAnyCondition() {
			t.Fatalf("%s 无判定条件", c.ID)
		}
		strong := false
		for _, h := range c.Match.HeaderContains {
			if len(strings.TrimSpace(h)) >= 12 {
				strong = true
			}
		}
		for _, w := range append(append([]string{}, c.Match.Contains...), c.Match.ContainsAny...) {
			if len(w) >= 4 {
				strong = true
			}
		}
		for _, rx := range c.Match.RegexBody {
			if len(rx) >= 8 {
				strong = true
			}
		}
		if !strong {
			t.Fatalf("%s 缺少强特征（word>=8 或 regex>=12 或 header）", c.ID)
		}
		if c.Title == "" || c.Sev == "" || c.Advice == "" {
			t.Fatalf("%s 缺少 Title/Sev/Advice", c.ID)
		}
	}
}

// TestTplChecksNoGenericHit 零误报门禁：通用页面不得命中任何转译 check。
func TestTplChecksNoGenericHit(t *testing.T) {
	pages := []struct {
		status int
		body   string
		ctype  string
	}{
		{200, `<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>`, "text/html"},
		{200, `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>`, "text/html"},
		{200, `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error.</p></body></html>`, "text/html"},
		{200, `{"status":"ok","data":[],"message":"success"}`, "application/json"},
		{200, `{"code":0,"msg":"success","data":null}`, "application/json"},
		{401, `{"error":"unauthorized","message":"Authentication required"}`, "application/json"},
		{403, `<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>`, "text/html"},
		{404, `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>`, "text/html"},
		{500, `<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>`, "text/html"},
	}
	for _, c := range tplChecks {
		for _, p := range pages {
			if matchBody(c.Match, p.status, p.body, map[string]string{"Content-Type": p.ctype}, "example.com") {
				t.Fatalf("%s 命中通用页面（零误报门禁失败）", c.ID)
			}
		}
	}
}

// TestBuiltinChecksUniquePaths 手写 check 路径唯一；转译集允许同路径（runner 会聚类共享请求），
// 但 ID 必须唯一。
func TestBuiltinChecksUniquePaths(t *testing.T) {
	seen := make(map[string]string, 200)
	tplIDs := make(map[string]bool, 900)
	for _, c := range builtinChecks() {
		if strings.HasPrefix(c.ID, "tpl-") {
			if tplIDs[c.ID] {
				t.Fatalf("转译 check ID 重复：%s", c.ID)
			}
			tplIDs[c.ID] = true
			continue
		}
		if prev, ok := seen[c.Path]; ok {
			t.Fatalf("手写 check 路径重复：%s（%s 与 %s）", c.Path, prev, c.ID)
		}
		seen[c.Path] = c.ID
	}
}

// TestExtraChecksQuality 手写扩展集：扩展集、强判据、非空字段。
func TestExtraChecksQuality(t *testing.T) {
	if len(extraChecks) < 70 {
		t.Fatalf("手写扩展集数量不足：%d（目标 >= 70）", len(extraChecks))
	}
	for _, c := range extraChecks {
		if c.Lv != 1 {
			t.Fatalf("%s 必须 Lv=1", c.ID)
		}
		if !strings.HasPrefix(c.Path, "/") {
			t.Fatalf("%s 路径非法：%q", c.ID, c.Path)
		}
		if !c.Match.hasAnyCondition() {
			t.Fatalf("%s 无判定条件", c.ID)
		}
		strong := false
		for _, h := range c.Match.HeaderContains {
			if len(strings.TrimSpace(h)) >= 12 {
				strong = true
			}
		}
		for _, w := range c.Match.Contains {
			if len(w) >= 4 {
				strong = true
			}
		}
		for _, rx := range c.Match.RegexBody {
			if len(rx) >= 8 {
				strong = true
			}
		}
		if !strong {
			t.Fatalf("%s 缺少强特征", c.ID)
		}
	}
}
