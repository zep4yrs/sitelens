package chain

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// buildGraph 构造含真实证据的黑盒图（两个发现 + 一个 impact + 一条黑白盒关联）。
func buildGraph() (*model.ScanGraph, map[string]string) {
	g := model.NewGraph("scan-1")
	ids := map[string]string{}

	// 证据（信任根）。
	ev1 := model.NewEvidence("response", model.OriginBlackbox, "check", "scan-1",
		"http://t/.git/HEAD", "", 0, "ref: refs/heads/main")
	ev2 := model.NewEvidence("response", model.OriginBlackbox, "dast", "scan-1",
		"http://t/?id=1", "", 0, "sql syntax error")
	g.Add(ev1)
	g.Add(ev2)

	// 两个黑盒发现（同 host）。
	v1 := model.NewVulnNode(model.OriginBlackbox, "git-leak", "", "http://t/.git/HEAD",
		"", "", 0, model.ObsPositive, "detected", model.ConfConfirmed, []string{ev1.ID})
	v2 := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "", "http://t/?id=1",
		"id", "", 0, model.ObsPositive, "proven", model.ConfConfirmed, []string{ev2.ID})
	g.Add(v1)
	g.Add(v2)
	ids["v1"], ids["v2"] = v1.ID, v2.ID

	// impact（exploit 证明）。
	im := model.NewImpact("modification", "proven", v2.ID, "可改库", nil,
		model.ConfProbable, []string{ev2.ID})
	g.Add(im)
	ids["impact"] = im.ID

	// 白盒事实 + 黑白盒关联边。
	wEv := model.NewEvidence("sink", model.OriginWhitebox, "audit", "", "", "u.py", 5, "cursor.execute(sql)")
	g.Add(wEv)
	vnW := model.NewVulnNode(model.OriginWhitebox, "", "PY-SQLFMT", "", "", "u.py", 5,
		model.ObsPositive, "detected", model.ConfProbable, []string{wEv.ID})
	g.Add(vnW)
	link, err := model.NewEvidenceLink(v2.ID, "", vnW.ID, "param", model.ConfProbable, []string{ev2.ID, wEv.ID})
	if err == nil {
		g.Add(link)
	}
	ids["whitebox"] = vnW.ID
	return g, ids
}

// TestBuildProducesEvidenceDrivenChain：建链产出的每条边都带真实证据。
func TestBuildProducesEvidenceDrivenChain(t *testing.T) {
	g, _ := buildGraph()
	res := Build(g, Options{})
	if len(res.Nodes) == 0 {
		t.Fatal("应产出链节点")
	}
	if len(res.Edges) == 0 {
		t.Fatal("应产出链边")
	}
	evset := map[string]bool{}
	for _, e := range g.Evidences {
		evset[e.ID] = true
	}
	for _, e := range res.Edges {
		if len(e.DerivedFrom) == 0 {
			t.Errorf("链边 %s 缺 derived_from（红线：无证据不成边）", e.ID)
		}
		for _, ev := range e.DerivedFrom {
			if !evset[ev] {
				t.Errorf("链边 %s 引用了不存在的证据 %s", e.ID, ev)
			}
		}
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("建链后图应通过校验：%v", err)
	}
}

// TestBuildExploitImpactEdge：vuln → impact 边存在（exploit_impact）。
func TestBuildExploitImpactEdge(t *testing.T) {
	g, _ := buildGraph()
	res := Build(g, Options{})
	found := false
	for _, e := range res.Edges {
		if e.Kind == "exploit_impact" {
			found = true
		}
	}
	if !found {
		t.Errorf("应有 exploit_impact 边；edges=%+v", res.Edges)
	}
}

// TestBuildEvidenceLinkEdge：黑白盒关联边纳入链（evidence_link）。
func TestBuildEvidenceLinkEdge(t *testing.T) {
	g, _ := buildGraph()
	res := Build(g, Options{})
	found := false
	for _, e := range res.Edges {
		if e.Kind == "evidence_link" {
			found = true
		}
	}
	if !found {
		t.Errorf("应有 evidence_link 边；edges=%+v", res.Edges)
	}
}

// TestBuildIdempotent：重复建链不重复加边。
func TestBuildIdempotent(t *testing.T) {
	g, _ := buildGraph()
	first := len(Build(g, Options{}).Edges)
	second := len(Build(g, Options{}).Edges)
	if first == 0 {
		t.Fatal("首次应有边")
	}
	if second != 0 {
		t.Errorf("二次建链应零新增，实得 %d", second)
	}
}

// TestBuildSkipsWithoutEvidence：无证据的节点不建边（宁缺不造）。
func TestBuildSkipsWithoutEvidence(t *testing.T) {
	g := model.NewGraph("s")
	// 无证据的 positive 节点（合法图不允许，故用 negative 规避校验，仍无证据）。
	g.Add(model.VulnNode{
		ID:     model.VulnNodeID(model.OriginBlackbox, "x", "", "http://t/a", "", "", 0),
		Origin: model.OriginBlackbox, CheckID: "x", URL: "http://t/a",
		Observation: model.ObsNegative, Confidence: model.ConfProbable,
	})
	res := Build(g, Options{})
	// 单节点无法成边：edges 应为空，且不应 panic。
	if len(res.Edges) != 0 {
		t.Errorf("无证据不应成边，实得 %+v", res.Edges)
	}
}

// TestBuildDifferentHostsNotChained：不同 host 的节点不连成一条时序链
// （批量扫描不能把不同目标混为一条攻击路径）。
func TestBuildDifferentHostsNotChained(t *testing.T) {
	g := model.NewGraph("s")
	e1 := model.NewEvidence("response", model.OriginBlackbox, "check", "s", "http://a/x", "", 0, "b1")
	e2 := model.NewEvidence("response", model.OriginBlackbox, "check", "s", "http://b/y", "", 0, "b2")
	g.Add(e1)
	g.Add(e2)
	g.Add(model.NewVulnNode(model.OriginBlackbox, "c1", "", "http://a/x", "", "", 0,
		model.ObsPositive, "detected", model.ConfProbable, []string{e1.ID}))
	g.Add(model.NewVulnNode(model.OriginBlackbox, "c2", "", "http://b/y", "", "", 0,
		model.ObsPositive, "detected", model.ConfProbable, []string{e2.ID}))

	res := Build(g, Options{})
	for _, e := range res.Edges {
		if e.Kind == "sequence" {
			t.Errorf("不同 host 不应有时序边：%+v", e)
		}
	}
}

// TestBuildEmptyGraph：空图/nil 安全。
func TestBuildEmptyGraph(t *testing.T) {
	if r := Build(nil, Options{}); len(r.Edges) != 0 || len(r.Nodes) != 0 {
		t.Error("nil 图应返回空")
	}
	g := model.NewGraph("s")
	if r := Build(g, Options{}); len(r.Edges) != 0 {
		t.Error("空图应无边")
	}
}

// TestBuildPrivChangeEdge：权限变化边纳入链（finding 在链上时）。
func TestBuildPrivChangeEdge(t *testing.T) {
	g, ids := buildGraph()
	// 用 v2 作为 finding 锚（该节点在链上），并带证据。
	pc := model.NewPrivChange("anonymous", "admin", "exploit-proven", ids["v2"],
		model.ConfProbable, g.VulnNodes[1].EvidenceIDs)
	g.Add(pc)

	res := Build(g, Options{})
	found := false
	for _, e := range res.Edges {
		if e.Kind == "priv_change" {
			found = true
		}
	}
	if !found {
		t.Errorf("应有 priv_change 边；edges=%+v", res.Edges)
	}
}

// TestKindForVuln：链节点类型归类（情报=recon，命中=exploit，白盒=exploit）。
func TestKindForVuln(t *testing.T) {
	cases := []struct {
		v    model.VulnNode
		want string
	}{
		{model.VulnNode{Origin: model.OriginWhitebox}, "exploit"},
		{model.VulnNode{Origin: model.OriginBlackbox, CheckID: "intel:nvd:CVE-1"}, "recon"},
		{model.VulnNode{Origin: model.OriginBlackbox, Observation: model.ObsPositive}, "exploit"},
		{model.VulnNode{Origin: model.OriginBlackbox, Observation: model.ObsUnknown}, "recon"},
	}
	for i, c := range cases {
		if got := kindForVuln(c.v); got != c.want {
			t.Errorf("case %d: kindForVuln = %q，期望 %q", i, got, c.want)
		}
	}
}

// TestSequenceViaEntryPoint：序列边 = 入口点 → 该入口上的发现（经 EntryID，真实因果）。
func TestSequenceViaEntryPoint(t *testing.T) {
	g := model.NewGraph("s")
	ev := model.NewEvidence("response", model.OriginBlackbox, "dast", "s",
		"http://t/?q=1", "", 0, "echo <script>")
	g.Add(ev)
	ep := model.NewEntryPoint(model.OriginBlackbox, "param", "http://t/", "GET", "q", "", "",
		[]string{ev.ID})
	g.Add(ep)
	vn := model.NewVulnNode(model.OriginBlackbox, "xss-reflect", "", "http://t/?q=1", "q", "", 0,
		model.ObsPositive, "detected", model.ConfConfirmed, []string{ev.ID})
	vn.EntryID = ep.ID
	g.Add(vn)

	res := Build(g, Options{})
	var seq *model.ChainEdge
	for i := range res.Edges {
		if res.Edges[i].Kind == "sequence" {
			seq = &res.Edges[i]
		}
	}
	if seq == nil {
		t.Fatalf("应产出入口→发现的序列边；edges=%+v", res.Edges)
	}
	if len(seq.DerivedFrom) == 0 {
		t.Error("序列边必须带证据")
	}
	// 边应为 entry chain_node → vuln chain_node。
	var fromKind, toKind string
	for _, n := range g.ChainNodes {
		if n.ID == seq.From {
			fromKind = n.Kind
		}
		if n.ID == seq.To {
			toKind = n.Kind
		}
	}
	if fromKind != "entry" || toKind != "exploit" {
		t.Errorf("边方向应为 entry→exploit，实得 %s→%s", fromKind, toKind)
	}
}

// TestIntelNodesNotChained：情报节点（recon）不参与序列串联——防止
// 「同技术共享指纹证据」把几十条 possible CVE 串成无意义的噪声链（P8 修正）。
func TestIntelNodesNotChained(t *testing.T) {
	g := model.NewGraph("s")
	// 同一条指纹证据被 5 条情报节点共享（真实场景：同技术命中多个 CVE）。
	ev := model.NewEvidence("fingerprint", model.OriginBlackbox, "fingerprint", "s",
		"", "", 0, "Python: generator")
	g.Add(ev)
	for i := 0; i < 5; i++ {
		ck := "intel:tpl:CVE-2024-000" + string(rune('1'+i))
		g.Add(model.NewVulnNode(model.OriginBlackbox, ck, "", "", "", "", 0,
			model.ObsUnknown, "possible", model.ConfPossible, []string{ev.ID}))
	}
	res := Build(g, Options{})
	for _, e := range res.Edges {
		if e.Kind == "sequence" {
			t.Errorf("情报节点不应产生序列边：%+v", e)
		}
	}
	// 但情报节点仍作为上下文出现在节点列表。
	if len(res.Nodes) != 5 {
		t.Errorf("情报节点应保留为链节点（5 条），实得 %d", len(res.Nodes))
	}
}
