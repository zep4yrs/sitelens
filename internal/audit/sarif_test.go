package audit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// ---- 测试用 SARIF 反序列化结构（只覆盖断言字段） ----

type tSarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []tSarifRun `json:"runs"`
}

type tSarifRun struct {
	Tool struct {
		Driver struct {
			Name    string       `json:"name"`
			Version string       `json:"version"`
			Rules   []tSarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []tSarifResult `json:"results"`
}

type tSarifRule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	ShortDescription tSarifText  `json:"shortDescription"`
	Help             *tSarifText `json:"help"`
	HelpURI          string      `json:"helpUri"`
}

type tSarifText struct {
	Text string `json:"text"`
}

type tSarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             tSarifText        `json:"message"`
	Locations           []tSarifLocation  `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type tSarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

func decodeSARIF(t *testing.T, data []byte) tSarifLog {
	t.Helper()
	var doc tSarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF 不是合法 JSON: %v\n%s", err, data)
	}
	return doc
}

// sampleSARIFReport 一份覆盖三档严重度 + 同规则多条 + 动态规则（AST-）的报告。
func sampleSARIFReport() *Report {
	return &Report{
		Findings: []Finding{
			{Rule: "PY-EVAL", Severity: "high", Title: "使用 eval 动态执行",
				File: "src/app.py", Line: 12, Snippet: "eval(user_input)",
				Match: "eval(", Advice: "改用 ast.literal_eval"},
			{Rule: "JS-INNERHTML", Severity: "medium", Title: "innerHTML 直接赋值",
				File: "web/ui.js", Line: 7, Snippet: "el.innerHTML = html",
				Match: ".innerHTML", Advice: "改用 textContent"},
			{Rule: "PY-DEBUG", Severity: "low", Title: "调试残留",
				File: "src/app.py", Line: 3, Snippet: "debug = True",
				Match: "debug = True", Advice: "生产关闭 debug"},
			{Rule: "PY-EVAL", Severity: "high", Title: "使用 eval 动态执行",
				File: "src/util.py", Line: 42, Snippet: "eval(cmd)",
				Match: "eval(", Advice: "改用 ast.literal_eval"},
			{Rule: "AST-os.system", Severity: "high", Title: "污点数据流：CWE-78 命令注入",
				File: "src/sink.py", Line: 9, Snippet: "os.system(cmd)",
				Match: "cmd", Advice: "参数化"},
		},
		Files: 5, Lines: 300,
		BySeverity: map[string]int{"high": 3, "medium": 1, "low": 1},
	}
}

// TestToSARIFSchema AU-01 核心：SARIF 2.1.0 的必备骨架字段齐全且自洽。
func TestToSARIFSchema(t *testing.T) {
	rep := sampleSARIFReport()
	data, err := ToSARIF(rep, "9.9.9-test")
	if err != nil {
		t.Fatalf("ToSARIF: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("输出不是合法 JSON")
	}
	doc := decodeSARIF(t, data)

	if doc.Version != "2.1.0" {
		t.Errorf("version 应为 2.1.0，实际 %q", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-2.1.0") {
		t.Errorf("$schema 应指向 SARIF 2.1.0 schema，实际 %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs 应恰有 1 个，实际 %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "SiteLens" {
		t.Errorf("tool.driver.name 应为 SiteLens，实际 %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "9.9.9-test" {
		t.Errorf("tool.driver.version 应透传工具版本，实际 %q", run.Tool.Driver.Version)
	}

	// rules[]：按 ruleId 升序去重（5 条发现 → 4 条规则、同一规则多条发现只登记一次）
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules 应为 4 条（去重后），实际 %d: %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}
	prev := ""
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "" || r.Name == "" || r.ShortDescription.Text == "" {
			t.Errorf("规则缺少 id/name/shortDescription: %+v", r)
		}
		if r.HelpURI != "" {
			t.Errorf("本项目无规则元数据 URI，helpUri 应省略，实际 %q", r.HelpURI)
		}
		if r.ID < prev {
			t.Errorf("rules 未按 ruleId 升序: %q 在 %q 之后", r.ID, prev)
		}
		prev = r.ID
	}

	// results[]：每条发现一条结果，ruleIndex 指回 rules[]，location 与指纹齐备
	if len(run.Results) != len(rep.Findings) {
		t.Fatalf("results 应 %d 条，实际 %d", len(rep.Findings), len(run.Results))
	}
	wantLevel := map[int]string{0: "error", 1: "warning", 2: "note", 3: "error", 4: "error"}
	for i, res := range run.Results {
		if res.RuleID != rep.Findings[i].Rule {
			t.Errorf("#%d ruleId 应为 %q，实际 %q", i, rep.Findings[i].Rule, res.RuleID)
		}
		if res.Level != wantLevel[i] {
			t.Errorf("#%d level 应为 %q，实际 %q", i, wantLevel[i], res.Level)
		}
		if strings.TrimSpace(res.Message.Text) == "" {
			t.Errorf("#%d message.text 为空", i)
		}
		if res.RuleIndex == nil || *res.RuleIndex < 0 || *res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("#%d ruleIndex 越界/缺失: %v", i, res.RuleIndex)
		}
		if got := run.Tool.Driver.Rules[*res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("#%d ruleIndex 指向 %q，应为 %q", i, got, res.RuleID)
		}
		if len(res.Locations) != 1 {
			t.Fatalf("#%d 应有 1 个 location，实际 %d", i, len(res.Locations))
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI == "" || strings.Contains(loc.ArtifactLocation.URI, `\`) {
			t.Errorf("#%d uri 应为非空相对斜杠路径，实际 %q", i, loc.ArtifactLocation.URI)
		}
		if strings.HasPrefix(loc.ArtifactLocation.URI, "/") ||
			(len(loc.ArtifactLocation.URI) >= 2 && loc.ArtifactLocation.URI[1] == ':') {
			t.Errorf("#%d uri 不应为绝对路径: %q", i, loc.ArtifactLocation.URI)
		}
		if loc.Region.StartLine != rep.Findings[i].Line {
			t.Errorf("#%d startLine 应为 %d，实际 %d", i, rep.Findings[i].Line, loc.Region.StartLine)
		}
		fp, ok := res.PartialFingerprints[sarifFingerprintKey]
		if !ok || len(fp) != 64 {
			t.Fatalf("#%d 指纹缺失或长度不符: %v", i, res.PartialFingerprints)
		}
		if _, derr := hex.DecodeString(fp); derr != nil {
			t.Errorf("#%d 指纹应为十六进制: %v", i, derr)
		}
	}
}

// TestSARIFLevelMapping 严重度映射：high→error / medium→warning / low→note；
// 未知值回退 warning（不静默压成 note）。
func TestSARIFLevelMapping(t *testing.T) {
	cases := map[string]string{
		"high": "error", "HIGH": "error", " high ": "error",
		"medium": "warning", "low": "note",
		"": "warning", "critical": "warning", "unknown": "warning",
	}
	for in, want := range cases {
		if got := sarifLevel(in); got != want {
			t.Errorf("sarifLevel(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestSARIFFingerprintStable 同一输入两次导出逐字节一致；指纹只由
// ruleId+uri+line+match 决定（改 snippet/advice 不影响，改行号/命中/规则则变）。
func TestSARIFFingerprintStable(t *testing.T) {
	rep := sampleSARIFReport()
	a, err := ToSARIF(rep, "5.2.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ToSARIF(rep, "5.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("同一报告两次导出应逐字节一致")
	}

	f := rep.Findings[0]
	base := sarifFingerprint(f, "src/app.py", f.Line)
	if base != sarifFingerprint(f, "src/app.py", f.Line) {
		t.Fatal("同一发现两次计算指纹应一致")
	}
	// snippet/advice 不参与指纹（同一问题在建议文案调整后仍是同一告警）
	changed := f
	changed.Snippet = "eval(other)"
	changed.Advice = "改法二"
	if got := sarifFingerprint(changed, "src/app.py", f.Line); got != base {
		t.Errorf("snippet/advice 变化不应改变指纹: %s vs %s", got, base)
	}
	// 行号 / 命中 / 规则 / 文件 任一变 → 不同告警
	if sarifFingerprint(f, "src/app.py", f.Line+1) == base {
		t.Error("行号变化应改变指纹")
	}
	m := f
	m.Match = "eval2("
	if sarifFingerprint(m, "src/app.py", f.Line) == base {
		t.Error("match 变化应改变指纹")
	}
	r := f
	r.Rule = "PY-EXEC"
	if sarifFingerprint(r, "src/app.py", f.Line) == base {
		t.Error("规则变化应改变指纹")
	}
	if sarifFingerprint(f, "src/other.py", f.Line) == base {
		t.Error("文件变化应改变指纹")
	}
}

// TestSARIFEmptyReport 空报告/ nil 报告都产出 schema 合法的空 results
// （results 必须是 [] 而不是 null）。
func TestSARIFEmptyReport(t *testing.T) {
	for name, rep := range map[string]*Report{
		"nil":   nil,
		"zero":  {},
		"empty": {Findings: []Finding{}},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := ToSARIF(rep, "")
			if err != nil {
				t.Fatalf("ToSARIF: %v", err)
			}
			if !json.Valid(data) {
				t.Fatal("输出不是合法 JSON")
			}
			if !bytes.Contains(data, []byte(`"results": []`)) {
				t.Errorf("空报告 results 应序列化为 []，实际:\n%s", data)
			}
			doc := decodeSARIF(t, data)
			if doc.Version != "2.1.0" {
				t.Errorf("version 应为 2.1.0，实际 %q", doc.Version)
			}
			if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 0 {
				t.Fatalf("空报告应 1 个 run、0 条 results: %+v", doc.Runs)
			}
			if v := doc.Runs[0].Tool.Driver.Version; v != "" {
				t.Errorf("toolVersion 为空时应省略 driver.version，实际 %q", v)
			}
		})
	}
}

// TestSARIFURINormalization uri 规范化：反斜杠→斜杠、去 "./"、绝对路径退化
// 为基名、越界退化、特殊字符百分号编码；无效路径不产出 uri。
func TestSARIFURINormalization(t *testing.T) {
	cases := map[string]string{
		`a\b\c.py`:        "a/b/c.py",
		`./d/e.php`:       "d/e.php",
		"sub//dir/x.go":   "sub/dir/x.go",
		"/abs/root/x.py":  "x.py",
		`C:\Users\u\y.go`: "y.go",
		"a b/c d.py":      "a%20b/c%20d.py",
		"../x.py":         "x.py",
		"":                "",
		".":               "",
		"..":              "",
	}
	for in, want := range cases {
		if got := normalizeSARIFURI(in); got != want {
			t.Errorf("normalizeSARIFURI(%q) = %q，期望 %q", in, got, want)
		}
	}
	// 中文/空格：百分号编码后仍可无损反解回原相对路径
	got := normalizeSARIFURI("目录/子 目录/文件.py")
	if !strings.Contains(got, "%") {
		t.Errorf("含非 ASCII/空格的路径应百分号编码: %q", got)
	}
	if back, err := url.PathUnescape(got); err != nil || back != "目录/子 目录/文件.py" {
		t.Errorf("uri 百分号编码应可无损反解: %q → %q (%v)", got, back, err)
	}
}

// TestToSARIFFromRun 端到端：真实审计产出的报告（相对斜杠路径）直接可导出。
func TestToSARIFFromRun(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "eval(x)\n")
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("样本应至少命中 1 条规则")
	}
	data, err := ToSARIF(rep, "5.2.0")
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeSARIF(t, data)
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != len(rep.Findings) {
		t.Fatalf("results 条数应与发现一致: %d vs %d", len(doc.Runs[0].Results), len(rep.Findings))
	}
	for i, res := range doc.Runs[0].Results {
		if res.RuleID != rep.Findings[i].Rule {
			t.Errorf("#%d ruleId 不匹配: %q vs %q", i, res.RuleID, rep.Findings[i].Rule)
		}
		loc := res.Locations[0].PhysicalLocation
		if strings.Contains(loc.ArtifactLocation.URI, `\`) || strings.HasPrefix(loc.ArtifactLocation.URI, "/") {
			t.Errorf("#%d uri 应为相对斜杠路径: %q", i, loc.ArtifactLocation.URI)
		}
		if loc.Region.StartLine < 1 {
			t.Errorf("#%d startLine 必须 >=1: %d", i, loc.Region.StartLine)
		}
	}
}

// TestRunSingleFileUsesBaseName 单文件审计：Rel(root, file) 为 "."，
// 报告 file 不能是 "."（JSON 标注与 SARIF uri 都要求可用路径）。
func TestRunSingleFileUsesBaseName(t *testing.T) {
	dir := t.TempDir()
	file := write(t, dir, "one.py", "eval(x)\n")
	rep, err := Run(file, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("单文件审计应有发现")
	}
	for _, f := range rep.Findings {
		if f.File == "." || f.File == "" || strings.Contains(f.File, `\`) {
			t.Fatalf("单文件审计的 file 应为基名斜杠路径，实际 %q", f.File)
		}
		if f.File != "one.py" {
			t.Fatalf("file 应为 one.py，实际 %q", f.File)
		}
	}
}
