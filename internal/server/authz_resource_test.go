package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/authz"
)

// TestAPIResourceMapCoversAllRoutes 守护"路由 → RBAC 资源名"映射（A-03）。
//
// 扫描本包全部非测试源码里的 API 路由字符串，要求每个路由首段要么在别名表
// （apiResourceAliases），要么在直通表（apiResourceDirect）。新增路由忘记登记
// 时本测试会失败——避免路由悄悄落到"未映射资源"被默认拒绝（operator 全 403
// 的老问题）或落到过宽资源。
func TestAPIResourceMapCoversAllRoutes(t *testing.T) {
	re := regexp.MustCompile(`"(?:(?:GET|POST|PUT|PATCH|DELETE) )?(/api/[^"\s]*)"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			path := m[1]
			first := firstAPISegment(path)
			if first == "" {
				continue
			}
			seen++
			if _, ok := apiResourceAliases[first]; ok {
				continue
			}
			if apiResourceDirect[first] || apiResourceDirect[apiResourceOf(path)] {
				continue
			}
			t.Errorf("%s: 路由 %q 首段 %q 未登记到 RBAC 资源映射表（apiResourceAliases/apiResourceDirect）", f, path, first)
		}
	}
	if seen == 0 {
		t.Fatal("未从源码中解析到任何 /api/ 路由，正则失配？")
	}
}

// firstAPISegment 取 /api/<seg>/... 的 <seg>。
func firstAPISegment(path string) string {
	p := strings.TrimPrefix(path, "/api/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSpace(p)
}

// TestAPIResourceMapping 关键路由的资源归一（A-03 修复点）。
func TestAPIResourceMapping(t *testing.T) {
	cases := map[string]string{
		"/api/job/abc":            "scan",
		"/api/job/abc/results":    "scan",
		"/api/history":            "scan",
		"/api/history/1":          "scan",
		"/api/batch":              "scan",
		"/api/batch/jobs":         "scan",
		"/api/scan":               "scan",
		"/api/graph/1":            "scan",
		"/api/diff":               "scan",
		"/api/replay/1":           "scan",
		"/api/export/1":           "report",
		"/api/assets/ports":       "asset",
		"/api/assets/cert-expiry": "asset",
		"/api/triage/1":           "triage",
		"/api/whitelist":          "whitelist",
		"/api/settings":           "settings",
		"/api/diagnostics":        "diagnostics",
		"/api/history/clear":      "admin", // 破坏性路径单独钉死为 admin
		"/api/version":            "version",
	}
	for path, want := range cases {
		if got := apiResourceOf(path); got != want {
			t.Errorf("apiResourceOf(%q)=%q, want %q", path, got, want)
		}
	}
}

// TestOperatorRoleCanReadScanProducts A-03 核心回归：operator（运营）必须能
// 读自己发起任务的进度/结果、导出报告、看资产、做复核——此前这些路由首段
// （job/history/export/assets）都没在 operator 的 Allow 里，全部 403。
func TestOperatorRoleCanReadScanProducts(t *testing.T) {
	readable := []string{
		"/api/job/abc", "/api/job/abc/results", "/api/history", "/api/history/1",
		"/api/batch/jobs", "/api/export/1", "/api/assets/ports",
		"/api/assets/cert-expiry", "/api/triage/1", "/api/graph/1",
	}
	for _, path := range readable {
		if res := apiResourceOf(path); !authz.Authorize(authz.RoleOperator, "read", res) {
			t.Errorf("operator 应能读 %s（资源 %s）", path, res)
		}
	}
	writable := []string{"/api/scan", "/api/batch", "/api/preflight", "/api/replay/1"}
	for _, path := range writable {
		if res := apiResourceOf(path); !authz.Authorize(authz.RoleOperator, "write", res) {
			t.Errorf("operator 应能写 %s（资源 %s）", path, res)
		}
	}
	// 管理面仍是 admin 专属（viewer/operator 都不行）
	adminOnly := []string{"/api/history/clear", "/api/admin/reload", "/api/settings", "/api/whitelist", "/api/diagnostics"}
	for _, path := range adminOnly {
		for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator} {
			res := apiResourceOf(path)
			if authz.Authorize(role, "write", res) {
				t.Errorf("%s 不应能写 %s（资源 %s）", role, path, res)
			}
		}
	}
	// viewer 只读角色也不能读管理面（A-03：viewer 的 *:read 此前覆盖了 settings）
	for _, path := range []string{"/api/settings", "/api/diagnostics", "/api/admin/reload", "/api/whitelist"} {
		res := apiResourceOf(path)
		if authz.Authorize(authz.RoleViewer, "read", res) {
			t.Errorf("viewer 不应能读管理面 %s（资源 %s）", path, res)
		}
	}
}
