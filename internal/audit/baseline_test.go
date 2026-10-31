// AU-02 回归：基线/忽略（指纹与 SARIF 同源、过滤、更新、端到端）。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestFingerprintMatchesSARIF 基线指纹必须与 SARIF partialFingerprints 同源
// （ruleId|uri|line|match 哈希）——跨 JSON/SARIF/基线同一身份。
func TestFingerprintMatchesSARIF(t *testing.T) {
	rep := &Report{Findings: []Finding{
		{Rule: "PY-EVAL", Severity: "high", File: "src/app.py", Line: 12,
			Match: "eval(", Snippet: "eval(x)"},
		{Rule: "GO-TLS", Severity: "high", File: "cmd/main.go", Line: 3,
			Match: "InsecureSkipVerify", Snippet: "InsecureSkipVerify: true"},
	}}
	data, err := ToSARIF(rep, "test")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID              string            `json:"ruleId"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results
	if len(results) != len(rep.Findings) {
		t.Fatalf("SARIF results=%d, findings=%d", len(results), len(rep.Findings))
	}
	for i, f := range rep.Findings {
		want := Fingerprint(f)
		if got := results[i].PartialFingerprints["primaryLocationLineHash"]; got != want {
			t.Errorf("#%d(%s) SARIF 指纹 %q != Fingerprint %q", i, f.Rule, got, want)
		}
	}
}

// TestBaselineRoundTripAndFilter 基线保存/加载/过滤：只报基线外新增，计数
// baseline_ignored，并按过滤后结果重算 by_severity。
func TestBaselineRoundTripAndFilter(t *testing.T) {
	old := &Report{
		Findings: []Finding{
			{Rule: "PY-EVAL", Severity: "high", File: "a.py", Line: 1, Match: "eval("},
			{Rule: "PY-DEBUG", Severity: "low", File: "a.py", Line: 2, Match: "debug = True"},
		},
		BySeverity: map[string]int{"high": 1, "medium": 0, "low": 1},
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := NewBaseline(old).Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Fingerprints) != 2 {
		t.Fatalf("基线指纹数 = %d，期望 2", len(b.Fingerprints))
	}
	// 同一发现 + 1 条新增
	cur := &Report{Findings: []Finding{
		{Rule: "PY-EVAL", Severity: "high", File: "a.py", Line: 1, Match: "eval("},
		{Rule: "PY-DEBUG", Severity: "low", File: "a.py", Line: 2, Match: "debug = True"},
		{Rule: "PY-OSPOPEN", Severity: "high", File: "a.py", Line: 3, Match: "os.system("},
	}}
	ignored := ApplyBaseline(cur, b)
	if ignored != 2 {
		t.Fatalf("应忽略 2 条基线内发现，实际 %d", ignored)
	}
	if len(cur.Findings) != 1 || cur.Findings[0].Rule != "PY-OSPOPEN" {
		t.Fatalf("应只保留新增发现: %+v", cur.Findings)
	}
	if cur.BySeverity["high"] != 1 || cur.BySeverity["low"] != 0 {
		t.Fatalf("by_severity 未按过滤后重算: %+v", cur.BySeverity)
	}
	// 空基线（文件存在但 fingerprints 空）→ 不过滤
	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`{"version":1,"fingerprints":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	b2, err := LoadBaseline(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := ApplyBaseline(cur, b2); n != 0 {
		t.Fatalf("空基线不应忽略发现: %d", n)
	}
}

// TestLoadBaselineErrors 显式基线损坏/缺失必须报错（不能静默当空基线）。
func TestLoadBaselineErrors(t *testing.T) {
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("基线缺失应报错")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil {
		t.Fatal("基线损坏应报错")
	}
}

// TestRunWithOptionsBaselineEndToEnd --update-baseline 落盘 → --baseline 过滤，
// 新增文件只报新发现（含 Report.BaselineIgnored additive 字段）。
func TestRunWithOptionsBaselineEndToEnd(t *testing.T) {
	src := t.TempDir()
	writeAuditFile(t, src, "a.py", "eval(x)\ndebug = True\n")
	basePath := filepath.Join(t.TempDir(), "baseline.json")

	rep1, err := RunWithOptions(src, config.AuditConfig{}, RunOptions{UpdateBaselinePath: basePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep1.Findings) == 0 {
		t.Fatal("首次审计应有发现")
	}
	if _, statErr := os.Stat(basePath); statErr != nil {
		t.Fatalf("基线未写出: %v", statErr)
	}
	if rep1.BaselineIgnored != nil {
		t.Fatal("未指定 --baseline 时不应有 baseline_ignored")
	}

	// 第二次：基线内全部忽略
	rep2, err := RunWithOptions(src, config.AuditConfig{}, RunOptions{BaselinePath: basePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.BaselineIgnored == nil || *rep2.BaselineIgnored != len(rep1.Findings) {
		t.Fatalf("baseline_ignored = %v，期望 %d", rep2.BaselineIgnored, len(rep1.Findings))
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("基线内发现应全部忽略: %+v", rep2.Findings)
	}

	// 第三次：写入新问题 → 只报新增
	writeAuditFile(t, src, "b.py", "os.system(cmd)\n")
	rep3, err := RunWithOptions(src, config.AuditConfig{}, RunOptions{BaselinePath: basePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep3.Findings) == 0 {
		t.Fatal("新问题应报出")
	}
	for _, f := range rep3.Findings {
		if f.File != "b.py" {
			t.Fatalf("只应报新增文件的问题: %+v", f)
		}
	}
}
