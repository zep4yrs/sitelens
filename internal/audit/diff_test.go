// AU-02 回归：审计 diff（按指纹输出 new/fixed）。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestDiffReports 指纹对比：同一发现（同 rule/file/line/match）不算新增，
// 消失的算已修复，多出来的算新增。
func TestDiffReports(t *testing.T) {
	old := &Report{Findings: []Finding{
		{Rule: "PY-EVAL", Severity: "high", File: "a.py", Line: 1, Match: "eval("},
		{Rule: "PY-DEBUG", Severity: "low", File: "a.py", Line: 2, Match: "debug = True"},
	}}
	cur := &Report{Findings: []Finding{
		{Rule: "PY-EVAL", Severity: "high", File: "a.py", Line: 1, Match: "eval("},
		{Rule: "PY-OSPOPEN", Severity: "high", File: "a.py", Line: 3, Match: "os.system("},
	}}
	d := DiffReports(cur, old)
	if d.New != 1 || d.Fixed != 1 {
		t.Fatalf("new=%d fixed=%d，期望 1/1", d.New, d.Fixed)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Rule != "PY-OSPOPEN" {
		t.Fatalf("新增列表异常: %+v", d.NewFindings)
	}
	if len(d.FixedFindings) != 1 || d.FixedFindings[0].Rule != "PY-DEBUG" {
		t.Fatalf("已修复列表异常: %+v", d.FixedFindings)
	}
	// nil 安全
	if d2 := DiffReports(nil, nil); d2.New != 0 || d2.Fixed != 0 {
		t.Fatalf("空报告 diff 应为 0/0: %+v", d2)
	}
	if d3 := DiffReports(cur, nil); d3.New != len(cur.Findings) || d3.Fixed != 0 {
		t.Fatalf("无旧报告时全部算新增: %+v", d3)
	}
}

// TestRunWithOptionsDiffEndToEnd 端到端：旧 JSON 报告 vs 新源码，
// new/fixed 数与列表均正确，且报告 diff 字段 additive 输出。
func TestRunWithOptionsDiffEndToEnd(t *testing.T) {
	src := t.TempDir()
	writeAuditFile(t, src, "a.py", "eval(x)\ndebug = True\n")
	rep1, err := Run(src, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep1.Findings) != 2 {
		t.Fatalf("首轮应有 2 条发现: %+v", rep1.Findings)
	}
	oldJSON, err := json.Marshal(rep1)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(oldPath, oldJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	// 移除 debug（固定），新增命令执行（新增）；eval 行号不变
	writeAuditFile(t, src, "a.py", "eval(x)\nos.system(cmd)\n")
	rep2, err := RunWithOptions(src, config.AuditConfig{}, RunOptions{DiffPath: oldPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Diff == nil {
		t.Fatal("指定 --diff 后应输出 diff 字段")
	}
	if rep2.Diff.New != 1 {
		t.Fatalf("应有 1 条新增: %+v", rep2.Diff)
	}
	if rep2.Diff.Fixed != 1 {
		t.Fatalf("应有 1 条已修复: %+v", rep2.Diff)
	}
	if rep2.Diff.NewFindings[0].Rule != "PY-OSPOPEN" ||
		rep2.Diff.FixedFindings[0].Rule != "PY-DEBUG" {
		t.Fatalf("diff 列表规则不符: new=%+v fixed=%+v",
			rep2.Diff.NewFindings, rep2.Diff.FixedFindings)
	}
}

// TestLoadReportFileErrors --diff 输入缺失/损坏必须报错。
func TestLoadReportFileErrors(t *testing.T) {
	if _, err := LoadReportFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("缺失报告应报错")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReportFile(bad); err == nil {
		t.Fatal("损坏报告应报错")
	}
}
