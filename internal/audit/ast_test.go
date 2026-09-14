package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/astx"
	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// pyVulnSource 一个含清晰污点链的 Python 样本（运行时写入临时目录）。
// source 与 sink 同处一个函数，保证行级 TAINT-lite（无函数作用域但按行扫）
// 与 AST 分析都能命中——用于对照。
const pyVulnSource = `import os


def handler(request):
    cmd = request.args.get("name")
    os.system(cmd)
    print("hi")
`

// pySafeSource 无污点链的对照样本。
const pySafeSource = `def safe(request):
    print("hi")
`

// TestASTFlagOffMatchesLegacy：AST 默认关时，审计结果与 3.0 行级行为一致
// （不出现 AST-* 发现）——保证默认路径零变化。
func TestASTFlagOffMatchesLegacy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v.py", pyVulnSource)
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "AST-") {
			t.Fatalf("AST 默认关时不应有 AST 发现：%+v", f)
		}
	}
	// 行级 TAINT 仍在（3.0 行为）。
	hasTaint := false
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "TAINT-") {
			hasTaint = true
		}
	}
	if !hasTaint {
		t.Error("行级 TAINT 发现应存在（3.0 行为）")
	}
}

// TestASTEnabledAddsFindings：开启 AST 后，附加 AST-* 发现，且行级发现不消失。
func TestASTEnabledAddsFindings(t *testing.T) {
	if !astx.Available() {
		t.Skip("需 CGO 构建（AST 解析器）")
	}
	dir := t.TempDir()
	writeFile(t, dir, "v.py", pyVulnSource)
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var astCount, taintCount int
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "AST-") {
			astCount++
			if f.Line == 0 {
				t.Error("AST 发现应带行号")
			}
			if !strings.Contains(f.Advice, "函数") {
				t.Errorf("AST 建议应含函数作用域：%q", f.Advice)
			}
		}
		if strings.HasPrefix(f.Rule, "TAINT-") {
			taintCount++
		}
	}
	if astCount == 0 {
		t.Fatalf("开启 AST 应有 AST-* 发现：%+v", rep.Findings)
	}
	if taintCount == 0 {
		t.Error("行级 TAINT 应作为兜底仍在（additive，不替换）")
	}
}

// TestASTUnsupportedFileFallsBack：AST 不支持的语言（如 Ruby）在 AST 开启时
// 仍由行级规则覆盖——验证「AST 是附加，行级兜底始终在」。
func TestASTUnsupportedFileFallsBack(t *testing.T) {
	dir := t.TempDir()
	// Ruby 不在 AST 支持语言内 → 必须回退行级（这里用通用规则 GEN-IP 验证覆盖）。
	writeFile(t, dir, "v.rb", "host = \"192.168.1.10\"\n")
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "AST-") {
			t.Fatalf("Ruby 无 AST 支持，不应有 AST 发现：%+v", f)
		}
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "GEN-IP" {
			found = true
		}
	}
	if !found {
		t.Error("行级规则应对不支持语言兜底命中")
	}
}

// TestPHPNowHasAST：PHP 现由第一方 phpgram 支持 AST，应产出 AST-* 发现，
// 且行级 PHP-* 规则作为兜底仍在（additive）。需 CGO。
func TestPHPNowHasAST(t *testing.T) {
	if !astx.Available() {
		t.Skip("需 CGO 构建（AST 解析器）")
	}
	dir := t.TempDir()
	// 同一函数内既有 SQL 注入（AST 能建流），又有命令执行（行级 PHP-CMD 命中）。
	writeFile(t, dir, "v.php",
		"<?php\nfunction h() {\n    $id = $_GET['id'];\n    mysql_query($id);\n    system($_GET['c']);\n}\n")
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var astCount, phpLineRule int
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "AST-") {
			astCount++
		}
		if strings.HasPrefix(f.Rule, "PHP-") {
			phpLineRule++
		}
	}
	if astCount == 0 {
		t.Fatalf("PHP 应产出 AST 发现：%+v", rep.Findings)
	}
	if phpLineRule == 0 {
		t.Error("PHP 行级规则应作为兜底仍在")
	}
}

// writeFile 在目录下写一个文件（测试辅助）。
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestASTEnabledFlowDetail：AST 发现应含 source 行与函数名（真实作用域信息）。
func TestASTEnabledFlowDetail(t *testing.T) {
	if !astx.Available() {
		t.Skip("需 CGO 构建（AST 解析器）")
	}
	dir := t.TempDir()
	writeFile(t, dir, "v.py", pyVulnSource)
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ast *Finding
	for i := range rep.Findings {
		if strings.HasPrefix(rep.Findings[i].Rule, "AST-") {
			ast = &rep.Findings[i]
			break
		}
	}
	if ast == nil {
		t.Fatal("未产出 AST 发现")
	}
	if ast.Rule != "AST-exec_cmd" {
		t.Errorf("AST 规则名 = %q，期望 AST-exec_cmd", ast.Rule)
	}
	if !strings.Contains(ast.Advice, "handler") {
		t.Errorf("建议应含函数名 handler：%q", ast.Advice)
	}
	if !strings.Contains(ast.Advice, "source 在第") {
		t.Errorf("建议应含 source 行号：%q", ast.Advice)
	}
}
