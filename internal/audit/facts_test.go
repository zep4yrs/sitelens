package audit

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/astx"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// TestRunWithFactsEmitsLineFacts：行级命中被实体化（evidence + whitebox vuln_node）。
func TestRunWithFactsEmitsLineFacts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v.py", "PASSWORD = \"super-secret-123\"\n")
	wb := model.NewGraph("")
	rep, err := RunWithFacts(dir, config.AuditConfig{MaxFindingsPerRule: 20}, wb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("应有行级发现")
	}
	if len(wb.VulnNodes) == 0 {
		t.Fatal("应产出白盒 vuln_node")
	}
	white := 0
	for _, v := range wb.VulnNodes {
		if v.Origin != model.OriginWhitebox {
			t.Errorf("节点 origin 应为 whitebox：%s", v.Origin)
		}
		if v.File == "" || v.Line == 0 {
			t.Error("白盒节点应带文件与行号")
		}
		if len(v.EvidenceIDs) == 0 {
			t.Error("白盒节点应带证据")
		}
		white++
	}
	if len(wb.Evidences) == 0 {
		t.Error("应产出白盒证据")
	}
	if err := wb.Validate(); err != nil {
		t.Fatalf("白盒图应通过校验：%v", err)
	}
}

// TestRunWithFactsNilGraphIsLegacy：wb=nil 时行为与 Run 一致（零副作用）。
func TestRunWithFactsNilGraphIsLegacy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "v.py", "import os\nos.system(x)\n")
	cfg := config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}
	a, err := Run(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RunWithFacts(dir, cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Findings) != len(b.Findings) {
		t.Errorf("nil 图时发现数应一致：%d vs %d", len(a.Findings), len(b.Findings))
	}
}

// TestRunWithFactsASTEmitsDataflow：AST 开启时产出 dataflow 实体（需 CGO）。
func TestRunWithFactsASTEmitsDataflow(t *testing.T) {
	if !astx.Available() {
		t.Skip("需 CGO 构建（AST 解析器）")
	}
	dir := t.TempDir()
	writeFile(t, dir, "v.py", "import os\n\ndef h(request):\n    cmd = request.args.get(\"c\")\n    os.system(cmd)\n")
	wb := model.NewGraph("")
	_, err := RunWithFacts(dir, config.AuditConfig{MaxFindingsPerRule: 20, ASTEnabled: true}, wb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(wb.Dataflows) == 0 {
		t.Fatalf("AST 开启应产出 dataflow 实体：%+v", wb.Counts())
	}
	df := wb.Dataflows[0]
	if df.File == "" || df.Func == "" {
		t.Errorf("dataflow 应带文件与函数：%+v", df)
	}
	if df.Source == nil || df.Sink == nil {
		t.Error("dataflow 应带 source/sink 端点")
	}
	if len(df.EvidenceIDs) == 0 {
		t.Error("dataflow 必须可追溯到证据")
	}
	if df.VulnID == "" {
		t.Error("dataflow 应关联白盒 vuln_node")
	}
	if err := wb.Validate(); err != nil {
		t.Fatalf("白盒图应通过校验：%v", err)
	}
	// 存在与 dataflow 对应的白盒节点。
	found := false
	for _, v := range wb.VulnNodes {
		if v.ID == df.VulnID && strings.HasPrefix(v.RuleID, "AST-") {
			found = true
		}
	}
	if !found {
		t.Error("dataflow 的 vuln_id 应指向 AST-* 白盒节点")
	}
}
