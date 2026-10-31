// AU-02/03：audit 子命令的参数解析与端到端（基线/diff/SCA）。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestParseAuditArgsFull 全部 audit 参数：目标位置、--sarif/--baseline/
// --update-baseline/--diff/--sca 的空格与等号形态、布尔取反、缺值报错、
// 未知开关忽略、多开关组合。
func TestParseAuditArgsFull(t *testing.T) {
	cases := []struct {
		name  string
		argv  []string
		want  auditCLIArgs
		isErr bool
	}{
		{name: "仅目标", argv: []string{"src"}, want: auditCLIArgs{Root: "src"}},
		{name: "baseline 空格", argv: []string{"src", "--baseline", "b.json"},
			want: auditCLIArgs{Root: "src", BaselinePath: "b.json"}},
		{name: "baseline 等号", argv: []string{"--baseline=b.json", "src"},
			want: auditCLIArgs{Root: "src", BaselinePath: "b.json"}},
		{name: "update-baseline", argv: []string{"src", "--update-baseline", "new.json"},
			want: auditCLIArgs{Root: "src", UpdateBaselinePath: "new.json"}},
		{name: "diff", argv: []string{"src", "--diff=old.json"},
			want: auditCLIArgs{Root: "src", DiffPath: "old.json"}},
		{name: "sca", argv: []string{"src", "--sca"}, want: auditCLIArgs{Root: "src", SCA: true}},
		{name: "sca 单横线", argv: []string{"src", "-sca"}, want: auditCLIArgs{Root: "src", SCA: true}},
		{name: "sca=false", argv: []string{"src", "--sca=false"}, want: auditCLIArgs{Root: "src"}},
		{name: "多开关", argv: []string{"--baseline", "b.json", "src", "--sca", "--diff=d.json", "--sarif", "s.sarif"},
			want: auditCLIArgs{Root: "src", BaselinePath: "b.json", DiffPath: "d.json",
				SarifPath: "s.sarif", SCA: true}},
		{name: "目标在开关后", argv: []string{"--sca", "src"},
			want: auditCLIArgs{Root: "src", SCA: true}},
		{name: "baseline 缺值", argv: []string{"src", "--baseline"}, isErr: true},
		{name: "diff 空值", argv: []string{"src", "--diff="}, isErr: true},
		{name: "update-baseline 缺值", argv: []string{"src", "--update-baseline"}, isErr: true},
		{name: "sca 非法布尔", argv: []string{"src", "--sca=maybe"}, isErr: true},
		{name: "未知开关忽略", argv: []string{"src", "--verbose"}, want: auditCLIArgs{Root: "src"}},
		{name: "空参数", argv: nil, want: auditCLIArgs{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAuditArgsFull(c.argv)
			if c.isErr {
				if err == nil {
					t.Fatalf("%v 应报错", c.argv)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v 不应报错: %v", c.argv, err)
			}
			if got != c.want {
				t.Errorf("参数解析 = %+v，期望 %+v", got, c.want)
			}
		})
	}
}

// runAuditJSON 执行一次 audit 并把 stdout 解析为报告。
func runAuditJSON(t *testing.T, cfg *config.Config, a auditCLIArgs) (*audit.Report, string) {
	t.Helper()
	stdout, stderr := captureOutput(t, func() { runAuditWithOptions(cfg, a) })
	var rep audit.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout 不是 JSON 报告: %v\n%s\nstderr=%s", err, stdout, stderr)
	}
	return &rep, stderr
}

// TestRunAuditBaselineCLI 端到端：--update-baseline 落盘 → --baseline 只报新增，
// 报告 additive 字段 baseline_ignored 与 stderr 提示都正确。
func TestRunAuditBaselineCLI(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.py"), []byte("eval(x)\ndebug = True\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	basePath := filepath.Join(t.TempDir(), "baseline.json")

	rep1, stderr1 := runAuditJSON(t, cfg, auditCLIArgs{Root: src, UpdateBaselinePath: basePath})
	if len(rep1.Findings) == 0 {
		t.Fatal("首轮应有发现")
	}
	if rep1.BaselineIgnored != nil {
		t.Fatal("未指定 --baseline 时不应输出 baseline_ignored")
	}
	if !strings.Contains(stderr1, "基线已更新") {
		t.Errorf("应提示基线已更新，stderr=%q", stderr1)
	}
	if _, err := os.Stat(basePath); err != nil {
		t.Fatalf("基线文件未写出: %v", err)
	}

	rep2, stderr2 := runAuditJSON(t, cfg, auditCLIArgs{Root: src, BaselinePath: basePath})
	if len(rep2.Findings) != 0 {
		t.Fatalf("基线内发现应全部忽略: %+v", rep2.Findings)
	}
	if rep2.BaselineIgnored == nil || *rep2.BaselineIgnored != len(rep1.Findings) {
		t.Fatalf("baseline_ignored = %v，期望 %d", rep2.BaselineIgnored, len(rep1.Findings))
	}
	if !strings.Contains(stderr2, "基线过滤") {
		t.Errorf("应提示基线过滤，stderr=%q", stderr2)
	}

	// 新增问题只报新增
	if err := os.WriteFile(filepath.Join(src, "b.py"), []byte("os.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep3, _ := runAuditJSON(t, cfg, auditCLIArgs{Root: src, BaselinePath: basePath})
	if len(rep3.Findings) == 0 {
		t.Fatal("新增问题应报出")
	}
	for _, f := range rep3.Findings {
		if f.File != "b.py" {
			t.Fatalf("只应报新增文件的问题: %+v", f)
		}
	}
}

// TestRunAuditDiffCLI 端到端：--diff 读上一次 JSON，报告 diff.new/fixed。
func TestRunAuditDiffCLI(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.py"), []byte("eval(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()

	// 首轮输出留档为旧报告
	stdout, _ := captureOutput(t, func() { runAudit(cfg, src, "") })
	oldPath := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(oldPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}

	// 源码变化：新增命令执行 → diff.new>=1
	if err := os.WriteFile(filepath.Join(src, "a.py"), []byte("eval(x)\nos.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, stderr := runAuditJSON(t, cfg, auditCLIArgs{Root: src, DiffPath: oldPath})
	if rep.Diff == nil {
		t.Fatal("--diff 应输出 diff 字段")
	}
	if rep.Diff.New < 1 {
		t.Fatalf("应有新增发现: %+v", rep.Diff)
	}
	if !strings.Contains(stderr, "diff：新增") {
		t.Errorf("应提示 diff 摘要，stderr=%q", stderr)
	}
}

// TestRunAuditSCACLI 端到端：--sca 输出依赖清单（无本地 OSV 库 → unknown）。
func TestRunAuditSCACLI(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"),
		[]byte("module m\n\nrequire golang.org/x/text v0.3.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	t.Setenv("SITLENS_OSV_DB", filepath.Join(t.TempDir(), "no-osv.json"))

	rep, stderr := runAuditJSON(t, cfg, auditCLIArgs{Root: src, SCA: true})
	if rep.SCA == nil {
		t.Fatal("--sca 应输出 sca 字段")
	}
	if rep.SCA.Status != "unknown" || rep.SCA.Total != 1 {
		t.Fatalf("SCA 结果异常: %+v", rep.SCA)
	}
	if !strings.Contains(stderr, "SCA：") {
		t.Errorf("应提示 SCA 摘要，stderr=%q", stderr)
	}
}
