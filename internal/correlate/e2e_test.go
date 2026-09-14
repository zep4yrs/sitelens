package correlate_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/astx"
	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/correlate"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// TestEndToEndBlackWhiteCorrelation 是 P4 的验收测试：真实白盒审计 + 真实
// 黑盒扫描 → 用稳定 ID 把两边缝起来。
//
// 场景：同一个参数名 `cmd` 既是白盒源码里流入 os.system 的污点变量，
// 又是黑盒 DAST 命中的反射点。correlate 应以 basis=param 建立 evidence_link。
//
// 该测试需要 CGO（AST 解析 Python）；非 CGO 构建下跳过。
func TestEndToEndBlackWhiteCorrelation(t *testing.T) {
	if !astxAvailable() {
		t.Skip("需 CGO 构建（AST 解析器）")
	}

	// ---- 1) 白盒：审计源码，产出带 dataflow 的白盒图 ----
	srcDir := t.TempDir()
	src := "import os\nfrom flask import request\n\n\ndef handler():\n    cmd = request.args.get(\"cmd\")\n    os.system(cmd)\n"
	if err := os.WriteFile(filepath.Join(srcDir, "user.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	wb := model.NewGraph("")
	if _, err := audit.RunWithFacts(srcDir, config.AuditConfig{
		MaxFindingsPerRule: 20, ASTEnabled: true}, wb, nil); err != nil {
		t.Fatal(err)
	}
	if len(wb.Dataflows) == 0 {
		t.Fatal("白盒应产出 dataflow")
	}
	// 该 dataflow 的参数应为 cmd。
	var dfParam string
	for _, d := range wb.Dataflows {
		if d.Param == "cmd" {
			dfParam = d.Param
		}
	}
	if dfParam == "" {
		t.Fatalf("未找到 param=cmd 的数据流：%+v", wb.Dataflows)
	}

	// ---- 2) 黑盒：扫描靶站，产出带 param=cmd 的黑盒图 ----
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("cmd"); q != "" {
			// 未转义回显 → 反射型 XSS（DAST 命中，param=cmd）。
			_, _ = w.Write([]byte("<html><body>hello " + q + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte(`<html><body><a href="/?cmd=1">go</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.DAST.MaxParams = 4
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	eng := engine.New(cfg, nil, nil)
	res := eng.Scan(srv.URL, engine.Options{Deep: true, DAST: true, Graph: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("黑盒扫描失败：%s", res.Error)
	}
	if res.Graph == nil {
		t.Fatal("黑盒应产出图")
	}
	// 至少有一个 param=cmd 的黑盒节点（DAST 命中）。
	hasBlackCmd := false
	for _, v := range res.Graph.VulnNodes {
		if v.Param == "cmd" && v.Origin == model.OriginBlackbox {
			hasBlackCmd = true
		}
	}
	if !hasBlackCmd {
		t.Fatalf("黑盒未产出 param=cmd 的发现：verified=%d", len(res.Verified))
	}

	// ---- 3) 合并 + 关联 ----
	merged := model.NewGraph("")
	for _, e := range wb.SortedEntities() {
		merged.Add(e)
	}
	for _, e := range res.Graph.SortedEntities() {
		merged.Add(e)
	}
	out := correlate.Run(merged, correlate.Options{})
	if len(out.Links) == 0 {
		t.Fatal("应产出黑白盒 evidence_link")
	}

	// ---- 4) 断言：存在 param 依据的边，两端可解析、带证据 ----
	var paramLink *model.EvidenceLink
	for i := range out.Links {
		if out.Links[i].Basis == "param" {
			paramLink = &out.Links[i]
		}
	}
	if paramLink == nil {
		t.Fatalf("应按 param 依据关联；links=%+v", out.Links)
	}
	if paramLink.BlackboxVulnID == "" || paramLink.WhiteboxDataflowID == "" {
		t.Errorf("关联两端应分别为黑盒节点与白盒数据流：%+v", paramLink)
	}
	if len(paramLink.EvidenceIDs) == 0 {
		t.Error("关联边必须带证据")
	}
	ids := map[string]bool{}
	for _, e := range merged.SortedEntities() {
		ids[e.EntityID()] = true
	}
	if !ids[paramLink.BlackboxVulnID] || !ids[paramLink.WhiteboxDataflowID] {
		t.Error("关联两端必须能在合并图内解析")
	}
	if err := merged.Validate(); err != nil {
		t.Fatalf("合并后图应通过校验：%v", err)
	}
}

// astxAvailable 探测 AST 是否可用（测试专用；astx 不 import 本包，无环）。
func astxAvailable() bool { return astx.Available() }
