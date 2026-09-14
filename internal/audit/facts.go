// 白盒发现实体化（4.0 P4）。
//
// Run 保持原签名（3.0 兼容）；新增 RunWithFacts 允许调用方传入一个
// model.ScanGraph，审计过程顺带把白盒发现转成图实体：
//
//	行级规则命中 → evidence(snippet) + vuln_node(whitebox, rule_id)
//	AST 数据流   → evidence(source/sink) + dataflow + vuln_node(whitebox)
//
// 这些实体带 origin=whitebox，供 P4 的 correlate 层与黑盒节点用稳定 ID
// 建立 evidence_link。不传图时行为与 3.0 完全一致（零副作用）。
package audit

import (
	"path/filepath"
	"strconv"

	"cnb.cool/feng-qiao/sitelens/internal/astx"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/cwe"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// RunWithFacts 在审计的同时把发现实体化进 wb（白盒图）。
// wb 为 nil 时等价于 Run。
func RunWithFacts(root string, cfg config.AuditConfig, wb *model.ScanGraph,
	onProgress func(done, total int, msg string)) (*Report, error) {
	return run(root, cfg, onProgress, wb)
}

// emitLineFact 把一条行级规则命中转成白盒实体。
// 证据是行片段（内容寻址 → 同片段跨文件/跨扫描复用同一证据实体）。
func emitLineFact(wb *model.ScanGraph, file, ruleID, sev, title, snippet string, line int) {
	ev := model.NewEvidence("snippet", model.OriginWhitebox, "audit", "",
		"", file, line, snippet)
	wb.Add(ev)

	vn := model.NewVulnNode(model.OriginWhitebox, "", ruleID, "", "", file, line,
		model.ObsPositive, "detected", model.ConfProbable, []string{ev.ID})
	vn.Title, vn.Severity = title, sev
	wb.Add(vn)

	if cwe := ruleCWE(ruleID); cwe != "" {
		wb.Add(model.NewCWERel(model.KindVulnNode, vn.ID, cwe, "mapping",
			model.ConfProbable, []string{ev.ID}))
	}
}

// emitASTFacts 把 AST 分析结果转成白盒实体：dataflow + 两端证据 +
// 白盒 vuln_node（同一函数内多个 flow 合并为一个节点）。
func emitASTFacts(wb *model.ScanGraph, file string, an *astx.Analysis) {
	if an == nil {
		return
	}
	// 按 (函数, sink 行) 去重，避免 AST 与行级双报时实体爆炸。
	seen := map[string]bool{}
	// 函数内 sinkLine → 白盒 vuln_node ID（供 dataflow 挂载）。
	nodeOf := map[string]string{}

	for i := range an.Flows {
		fl := an.Flows[i]
		key := fl.Func + "|" + strconv.Itoa(fl.Sink.Line) + "|" + fl.Sink.Sink
		if seen[key] {
			continue
		}
		seen[key] = true

		// 白盒漏洞节点（按函数+行定位）。
		nodeKey := fl.Func + "|" + strconv.Itoa(fl.Sink.Line)
		vnID, ok := nodeOf[nodeKey]
		if !ok {
			sinkEv := model.NewEvidence("sink", model.OriginWhitebox, "audit", "",
				"", file, fl.Sink.Line, fl.Sink.Expr)
			wb.Add(sinkEv)
			vn := model.NewVulnNode(model.OriginWhitebox, "", "AST-"+fl.Sink.Sink,
				"", "", file, fl.Sink.Line, model.ObsPositive, "detected",
				model.ConfProbable, []string{sinkEv.ID})
			vn.Title = "污点数据流 " + fl.Sink.Sink
			vn.Severity = "high"
			vn.CWEs = cweList(fl.Sink.CWE)
			vn.Func = fl.Func
			wb.Add(vn)
			vnID = vn.ID
			nodeOf[nodeKey] = vnID
			if fl.Sink.CWE != "" {
				wb.Add(model.NewCWERel(model.KindVulnNode, vnID, fl.Sink.CWE,
					"mapping", model.ConfProbable, []string{sinkEv.ID}))
			}
		}

		// 两端证据 + 数据流实体。
		srcEv := model.NewEvidence("source", model.OriginWhitebox, "audit", "",
			"", file, fl.Source.Line, fl.Source.Expr)
		sinkEv := model.NewEvidence("sink", model.OriginWhitebox, "audit", "",
			"", file, fl.Sink.Line, fl.Sink.Expr)
		wb.Add(srcEv)
		wb.Add(sinkEv)

		steps := make([]model.FlowStep, 0, len(fl.Steps))
		for _, s := range fl.Steps {
			steps = append(steps, model.FlowStep{Ordinal: s.Line, File: file,
				Func: fl.Func, Line: s.Line, Expr: s.Expr})
		}
		df := model.NewDataflow(string(an.Lang), file, fl.Func, fl.Var,
			fl.Sink.Line,
			&model.FlowNode{Kind: "source", File: file, Func: fl.Func,
				Line: fl.Source.Line, Expr: fl.Source.Expr},
			&model.FlowNode{Kind: "sink", File: file, Func: fl.Func,
				Line: fl.Sink.Line, Expr: fl.Sink.Expr},
			steps, model.ConfProbable, []string{srcEv.ID, sinkEv.ID})
		df.VulnID = vnID
		wb.Add(df)
	}
}

// ruleCWE 行级规则 id → CWE（P4 引入，P5 归口 internal/cwe 权威表）。
func ruleCWE(ruleID string) string {
	if cs := cwe.ForRule(ruleID); len(cs) > 0 {
		return cs[0]
	}
	return ""
}

// cweList 把单 CWE 包成切片（空则返回 nil）。
func cweList(cwe string) []string {
	if cwe == "" {
		return nil
	}
	return []string{cwe}
}

// baseName 返回路径的文件名（供关联键使用）。
func baseName(p string) string { return filepath.Base(p) }
