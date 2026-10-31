// AU-03 回归：SCA 依赖清单解析（go.mod/package-lock.json/requirements.txt）
// + 本地 OSV 库查询（无库时 status=unknown，不臆造漏洞）。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// scaFind 在 SCA 结果里按 ecosystem+name 找依赖。
func scaFind(t *testing.T, rep *SCAReport, eco, name string) *SCADependency {
	t.Helper()
	for i := range rep.Dependencies {
		if rep.Dependencies[i].Ecosystem == eco && rep.Dependencies[i].Name == name {
			return &rep.Dependencies[i]
		}
	}
	return nil
}

// TestScanDependenciesParsers 三类清单解析：名称/版本/生态/来源/去重、间接
// 依赖标记、requirements 非精确约束（Version 空、Spec 原文）、vendor 跳过。
func TestScanDependenciesParsers(t *testing.T) {
	// 无本地 OSV 库：强制指向不存在路径，确保走 unknown 分支
	t.Setenv(scaOSVDBEnv, filepath.Join(t.TempDir(), "no-osv.json"))

	dir := t.TempDir()
	writeAuditFile(t, dir, "go.mod", `module example.com/app

go 1.22

require golang.org/x/text v0.3.5

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.7.0 // indirect
)
`)
	writeAuditFile(t, dir, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/@scope/pkg": {"version": "1.2.3"},
    "node_modules/lodash": {"version": "4.17.21"}
  },
  "dependencies": {
    "old-dep": {"version": "1.0.0"}
  }
}`)
	writeAuditFile(t, dir, "requirements.txt", `# comment
requests==2.31.0
flask>=2.0
-r other.txt
urllib3[secure]==2.0.7
`)
	// vendor 内的清单不得被解析（跳过依赖目录）
	if err := os.MkdirAll(filepath.Join(dir, "vendor", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAuditFile(t, filepath.Join(dir, "vendor", "x"), "go.mod", "module v\nrequire bad/dep v1.0.0\n")

	rep := ScanDependencies(dir)
	if rep.Status != "unknown" {
		t.Fatalf("无本地 OSV 库应 status=unknown，实际 %q", rep.Status)
	}
	if len(rep.Files) != 3 {
		t.Fatalf("应发现 3 个清单文件，实际 %v", rep.Files)
	}
	if rep.Total != 9 {
		t.Fatalf("依赖总数 = %d，期望 9（Go 3 + npm 3 + PyPI 3）: %+v", rep.Total, rep.Dependencies)
	}
	// Go
	if d := scaFind(t, rep, "Go", "golang.org/x/text"); d == nil || d.Version != "v0.3.5" || !d.Direct {
		t.Fatalf("go.mod 单行 require 解析异常: %+v", d)
	}
	if d := scaFind(t, rep, "Go", "golang.org/x/net"); d == nil || d.Direct || d.Version != "v0.7.0" {
		t.Fatalf("// indirect 标记异常: %+v", d)
	}
	if d := scaFind(t, rep, "Go", "bad/dep"); d != nil {
		t.Fatalf("vendor 内清单不应被解析: %+v", d)
	}
	// npm
	if d := scaFind(t, rep, "npm", "@scope/pkg"); d == nil || d.Version != "1.2.3" {
		t.Fatalf("package-lock packages 解析异常: %+v", d)
	}
	if d := scaFind(t, rep, "npm", "old-dep"); d == nil || d.Version != "1.0.0" {
		t.Fatalf("package-lock dependencies 解析异常: %+v", d)
	}
	// PyPI
	if d := scaFind(t, rep, "PyPI", "requests"); d == nil || d.Version != "2.31.0" {
		t.Fatalf("requirements 精确版本解析异常: %+v", d)
	}
	if d := scaFind(t, rep, "PyPI", "urllib3"); d == nil || d.Version != "2.0.7" {
		t.Fatalf("requirements extras 未剥离: %+v", d)
	}
	if d := scaFind(t, rep, "PyPI", "flask"); d == nil || d.Version != "" || d.Spec != ">=2.0" {
		t.Fatalf("非精确约束应保留 Spec 且 Version 空: %+v", d)
	}
	// 无库：所有依赖漏洞状态 unknown（不臆造）
	for _, d := range rep.Dependencies {
		if d.Status != "unknown" || len(d.Vulns) != 0 {
			t.Fatalf("无 OSV 库时依赖状态应 unknown: %+v", d)
		}
	}
	if rep.Note == "" || rep.ByEcosystem["Go"] != 3 || rep.ByEcosystem["npm"] != 3 {
		t.Fatalf("统计/说明异常: %+v", rep)
	}
}

// TestScanDependenciesWithLocalOSVDB 本地 OSV 库存在时按生态+包名+版本区间
// 查漏洞；无精确版本/区间不匹配的依赖不报。
func TestScanDependenciesWithLocalOSVDB(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "go.mod", "module m\n\nrequire golang.org/x/text v0.3.5\n")
	writeAuditFile(t, dir, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {"node_modules/lodash": {"version": "4.17.21"}}
}`)
	writeAuditFile(t, dir, "requirements.txt", "flask>=2.0\n")

	dbPath := filepath.Join(t.TempDir(), "osv_db.json")
	db := map[string]any{"vulns": []map[string]any{
		{"id": "GHSA-hit", "summary": "DoS", "severity": "high",
			"ecosystem": "Go", "package": "golang.org/x/text",
			"affected": ">=0.3.0,<0.3.8"},
		{"id": "GHSA-not-hit", "summary": "旧版本问题", "severity": "high",
			"ecosystem": "Go", "package": "golang.org/x/text",
			"affected": ">=0.9.0"},
		{"id": "GHSA-npm", "summary": "原型污染", "severity": "high",
			"ecosystem": "npm", "package": "lodash", "affected": ""},
	}}
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(scaOSVDBEnv, dbPath)

	rep := ScanDependencies(dir)
	if rep.Status != "queried" || rep.OSVSource != dbPath {
		t.Fatalf("应使用本地 OSV 库: %+v", rep)
	}
	if rep.Total != 3 || rep.Vulnerable != 2 {
		t.Fatalf("依赖数/漏洞数 = %d/%d，期望 3/2: %+v", rep.Total, rep.Vulnerable, rep.Dependencies)
	}
	textDep := scaFind(t, rep, "Go", "golang.org/x/text")
	if textDep == nil || textDep.Status != "checked" || len(textDep.Vulns) != 1 ||
		textDep.Vulns[0].ID != "GHSA-hit" {
		t.Fatalf("Go 依赖漏洞命中异常: %+v", textDep)
	}
	lodash := scaFind(t, rep, "npm", "lodash")
	if lodash == nil || len(lodash.Vulns) != 1 || lodash.Vulns[0].ID != "GHSA-npm" {
		t.Fatalf("npm affected 为空应命中所有版本: %+v", lodash)
	}
	flask := scaFind(t, rep, "PyPI", "flask")
	if flask == nil || flask.Status != "unknown" || len(flask.Vulns) != 0 {
		t.Fatalf("无精确版本应 unknown 且不报漏洞: %+v", flask)
	}
}

// TestScanDependenciesNoManifests 无清单：空清单报告（unknown + 说明）。
func TestScanDependenciesNoManifests(t *testing.T) {
	t.Setenv(scaOSVDBEnv, filepath.Join(t.TempDir(), "no-osv.json"))
	rep := ScanDependencies(t.TempDir())
	if rep.Status != "unknown" || rep.Total != 0 {
		t.Fatalf("无清单报告异常: %+v", rep)
	}
	if rep.Note == "" {
		t.Fatal("应说明未发现依赖清单")
	}
}

// TestRunWithOptionsSCA --sca additive 字段：审计报告挂 SCA 清单，主流程
// 发现不受影响。
func TestRunWithOptionsSCA(t *testing.T) {
	t.Setenv(scaOSVDBEnv, filepath.Join(t.TempDir(), "no-osv.json"))
	dir := t.TempDir()
	writeAuditFile(t, dir, "go.mod", "module m\n\nrequire golang.org/x/text v0.3.5\n")
	writeAuditFile(t, dir, "a.py", "eval(x)\n")
	rep, err := RunWithOptions(dir, config.AuditConfig{}, RunOptions{SCA: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SCA == nil {
		t.Fatal("--sca 应输出 sca 字段")
	}
	if rep.SCA.Status != "unknown" || rep.SCA.Total != 1 {
		t.Fatalf("SCA 结果异常: %+v", rep.SCA)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("SCA 不应影响主审计发现")
	}
}
