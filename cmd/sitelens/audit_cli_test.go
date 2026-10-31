// AU-01：audit 子命令的 --sarif 参数解析与端到端导出用例。
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/server"
)

// TestParseAuditArgs audit 子命令参数：首个非开关为审计目标；--sarif 支持
// 空格与等号两种形态；缺值/空值报错；未知开关沿用旧行为忽略。
func TestParseAuditArgs(t *testing.T) {
	cases := []struct {
		name      string
		argv      []string
		wantRoot  string
		wantSarif string
		wantErr   bool
	}{
		{"仅目标（旧用法）", []string{"src"}, "src", "", false},
		{"目标 + --sarif 空格", []string{"src", "--sarif", "out.sarif"}, "src", "out.sarif", false},
		{"--sarif 在目标前", []string{"--sarif", "out.sarif", "src"}, "src", "out.sarif", false},
		{"等号形态", []string{"src", "--sarif=out.sarif"}, "src", "out.sarif", false},
		{"单横线", []string{"-sarif", "out.sarif", "src"}, "src", "out.sarif", false},
		{"含空格路径", []string{"src", "--sarif", "a b/out.sarif"}, "src", "a b/out.sarif", false},
		{"缺值", []string{"src", "--sarif"}, "", "", true},
		{"空值", []string{"src", "--sarif="}, "", "", true},
		{"未知开关忽略", []string{"src", "--verbose"}, "src", "", false},
		{"空参数", nil, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, sarifPath, err := parseAuditArgs(c.argv)
			if c.wantErr {
				if err == nil {
					t.Fatalf("%v 应报错", c.argv)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v 不应报错: %v", c.argv, err)
			}
			if root != c.wantRoot || sarifPath != c.wantSarif {
				t.Errorf("root=%q sarif=%q，期望 %q/%q", root, sarifPath, c.wantRoot, c.wantSarif)
			}
		})
	}
}

// captureOutput 捕获 fn 执行期间的 stdout/stderr（测试串行，无并发干扰）。
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, rOut) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, rErr) }()

	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	wg.Wait()
	_ = rOut.Close()
	_ = rErr.Close()
	return outBuf.String(), errBuf.String()
}

// TestRunAuditWritesSARIF 端到端：audit 的 JSON 报告逐字节不变，另写出
// 可解析的 SARIF 2.1.0（版本/工具名/结果条数/level 映射）。
func TestRunAuditWritesSARIF(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "bad.py"),
		[]byte("eval(x)\ndebug = True\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sarifPath := filepath.Join(t.TempDir(), "out.sarif")

	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	stdout, stderr := captureOutput(t, func() { runAudit(cfg, src, sarifPath) })

	// 1) 既有 JSON 报告不变：与直接调用 audit.Run 的序列化结果逐字节一致
	var rep audit.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout 不是 JSON 报告: %v\n%s", err, stdout)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("样本应至少命中 1 条规则")
	}
	ref, err := audit.Run(src, cfg.Audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != string(want) {
		t.Fatalf("JSON 报告应逐字节不变（AU-01 additive）")
	}
	if !strings.Contains(stderr, "SARIF 已写出") {
		t.Errorf("应提示 SARIF 已写出，实际 stderr: %q", stderr)
	}

	// 2) SARIF 文件：schema 版本/工具名/条数/level
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("SARIF 未写出: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF 不是合法 JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("SARIF version 应为 2.1.0，实际 %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs 应 1 个，实际 %d", len(doc.Runs))
	}
	if doc.Runs[0].Tool.Driver.Name != "SiteLens" {
		t.Errorf("工具名应为 SiteLens，实际 %q", doc.Runs[0].Tool.Driver.Name)
	}
	if doc.Runs[0].Tool.Driver.Version != server.Version {
		t.Errorf("工具版本应透传 %q，实际 %q", server.Version, doc.Runs[0].Tool.Driver.Version)
	}
	if len(doc.Runs[0].Results) != len(rep.Findings) {
		t.Fatalf("results 应 %d 条，实际 %d", len(rep.Findings), len(doc.Runs[0].Results))
	}
	// level 映射与报告严重度一一对应（high→error / medium→warning / low→note）
	wantLevel := map[string]string{"high": "error", "medium": "warning", "low": "note"}
	for i, f := range rep.Findings {
		if got, want := doc.Runs[0].Results[i].Level, wantLevel[f.Severity]; got != want {
			t.Errorf("#%d(%s/%s) level 应为 %q，实际 %q", i, f.Rule, f.Severity, want, got)
		}
	}
}

// TestRunAuditGraphUnaffected -graph 行为不变：仍输出白盒图 JSONL，且可与
// --sarif 同时使用（两者互不影响）。
func TestRunAuditGraphUnaffected(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "bad.py"),
		[]byte("eval(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	sarifPath := filepath.Join(t.TempDir(), "out.sarif")
	cfg := config.Default()
	cfg.Store.DataDir = dataDir
	cfg.Scan.Graph = true // 等价 -graph

	stdout, stderr := captureOutput(t, func() { runAudit(cfg, src, sarifPath) })
	if !strings.Contains(stdout, `"findings"`) {
		t.Fatal("stdout 应仍为 JSON 报告")
	}
	graphPath := filepath.Join(dataDir, "whitebox.graph.jsonl")
	if _, err := os.Stat(graphPath); err != nil {
		t.Fatalf("-graph 行为应保持不变（应写出 %s）: %v", graphPath, err)
	}
	if !strings.Contains(stderr, "白盒图已写出") {
		t.Errorf("应提示白盒图已写出，实际 stderr: %q", stderr)
	}
	if _, err := os.Stat(sarifPath); err != nil {
		t.Fatalf("--sarif 与 -graph 应可同时使用: %v", err)
	}
}
