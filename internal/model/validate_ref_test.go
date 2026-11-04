package model

// C2-08 回归：Validate 的跨实体引用必须校验类型（不只是存在性）。
//
// 旧实现用 allIDSet（全类型混装）只看 ref 是否存在，于是把「证据 ID 填进
// vuln_node.entry_id」「影响节点 ID 填进 chain_edge.from」这类类型错配图
// 判为合法，契约自检形同虚设；下游图视图/5.0 事实流会按错误类型消费。

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateRejectsWrongRefType 类型错配的跨实体引用必须被报出。
func TestValidateRejectsWrongRefType(t *testing.T) {
	g := NewGraph("scan-typed")
	ev := NewEvidence("response", OriginBlackbox, "check", "scan-typed",
		"http://t/", "", 0, "HTTP/1.1 200")
	g.Add(ev)

	// entry_id 指向 evidence：存在但类型不符。
	vn := NewVulnNode(OriginBlackbox, "xss-reflect", "", "http://t/?q=1", "q", "", 0,
		ObsPositive, "detected", ConfProbable, []string{ev.ID})
	vn.EntryID = ev.ID
	g.Add(vn)

	// chain_edge.from/to 指向非 chain_node：链路端点必须是链节点。
	cn := NewChainNode("entry", ev.ID, "入口", nil)
	g.Add(cn) // cn 本身合法（entry → entry_point），但下面用证据 ID 建边
	ce, err := NewChainEdge(vn.ID, ev.ID, "sequence", []string{ev.ID}, ConfProbable)
	if err != nil {
		t.Fatalf("构造 chain_edge 失败: %v", err)
	}
	g.Add(ce)

	err = g.Validate()
	if err == nil {
		t.Fatal("类型错配的跨实体引用应被判为非法")
	}
	msg := err.Error()
	if !strings.Contains(msg, "引用类型不符") {
		t.Fatalf("错误信息未指出类型不符: %v", err)
	}
	// 三个错配点都应被抓到：entry_id、chain_edge.from、chain_node.ref_id。
	for _, want := range []string{"entry_id", "from", "ref_id"} {
		if !strings.Contains(msg, want) {
			t.Errorf("未报告 %s 的类型错配: %v", want, msg)
		}
	}
}

// TestValidateRejectsKindPrefixMismatch 实体的 ID 前缀必须与声明类型一致
// （wantPrefix 真正使用）。
func TestValidateRejectsKindPrefixMismatch(t *testing.T) {
	g := NewGraph("scan-prefix")
	// 用 entry_point 的前缀造一个 vuln_node：ID 形态合法但类型前缀不符。
	vn := NewVulnNode(OriginBlackbox, "slack", "", "http://t/", "", "", 0,
		ObsNegative, "", ConfUnresolved, nil)
	vn.ID = EntryPointID(OriginBlackbox, "url", "http://t/", "GET", "", "", "")
	g.Add(vn)
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "前缀") {
		t.Fatalf("ID 前缀与类型不符应报错，实得: %v", err)
	}
}

// TestValidateAcceptsProducerShape 生产方真实形态的图必须通过（防止修过严）。
func TestValidateAcceptsProducerShape(t *testing.T) {
	g := NewGraph("scan-ok")
	ev := NewEvidence("response", OriginBlackbox, "dast", "scan-ok",
		"http://t/a?x=1", "", 0, "root:x:0:0")
	g.Add(ev)
	ep := NewEntryPoint(OriginBlackbox, "param", "http://t/a", "GET", "x", "", "", []string{ev.ID})
	g.Add(ep)
	vn := NewVulnNode(OriginBlackbox, "sqli-error", "", "http://t/a?x=1", "x", "", 0,
		ObsPositive, "detected", ConfProbable, []string{ev.ID})
	vn.EntryID = ep.ID
	vn.CVE = "CVE-2020-0001"
	g.Add(vn)
	// 生产方 privat_change 的 finding_id 两种形态（vuln_node / entry_point）
	g.Add(NewPrivChange("anonymous", "restricted-resource", "bypass-403", ep.ID,
		ConfProbable, []string{ev.ID}))
	g.Add(NewPrivChange("anonymous", "authenticated", "credential", vn.ID,
		ConfProbable, []string{ev.ID}))
	im := NewImpact("disclosure", "proven", vn.ID, "", nil, ConfProbable, []string{ev.ID})
	g.Add(im)
	cn1 := NewChainNode("entry", ep.ID, "入口", []string{ev.ID})
	cn2 := NewChainNode("exploit", vn.ID, "注入", []string{ev.ID})
	cn3 := NewChainNode("impact", im.ID, "影响", []string{ev.ID})
	g.Add(cn1)
	g.Add(cn2)
	g.Add(cn3)
	if e, err := NewChainEdge(cn1.ID, cn2.ID, "sequence", []string{ev.ID}, ConfProbable); err == nil {
		g.Add(e)
	}
	if e, err := NewChainEdge(cn2.ID, cn3.ID, "exploit_impact", []string{ev.ID}, ConfProbable); err == nil {
		g.Add(e)
	}
	g.Add(NewCWERel(KindVulnNode, vn.ID, "CWE-89", "mapping", ConfProbable, []string{ev.ID}))
	if err := g.Validate(); err != nil {
		var multi interface{ Unwrap() []error }
		if errors.As(err, &multi) {
			t.Fatalf("生产方形态应通过校验，实得 %d 条问题: %v", len(multi.Unwrap()), err)
		}
		t.Fatalf("生产方形态应通过校验: %v", err)
	}
}
