// Package chain 攻击链建模（4.0 P6）。
//
// 核心纪律（开发文档第 10 节红线）：**证据驱动**——每条边都必须由真实
// evidence 支撑，`derived_from` 非空。本包**不依据 CVSS / CVE / 规则名称
// 或模型猜测制造攻击路径**，只做三件事：
//
//  1. 把图内已有的真实事实（发现 / 入口 / 影响 / 权限变化 / 黑白盒关联）
//     组织为链节点与链边；
//  2. 只连「同一次扫描中真实共现」的节点（同 host + 存在证据链）；
//  3. 无证据的候选边一律不建（宁缺不造）。
//
// 三类合法边（与文档一致）：
//
//	sequence        攻击面时序：recon → entry → exploit（同 host，证据共现）
//	exploit_impact  exploit 已证明的影响：vuln_node → impact（proven/observed）
//	evidence_link   黑白盒关联边（P4 产出，此处纳入链）
//	priv_change     权限变化边（P7 产出，此处纳入链）
//
// 依赖：只依赖 internal/model（+ 标准库）。
package chain

import (
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// Options 建链参数。
type Options struct {
	// MinEvidence 单条边所需的最少证据数（默认 1；>1 可更严）。
	MinEvidence int
	// MaxNodes 链节点上限（0 = 不限；防大图爆炸）。
	MaxNodes int
}

// Result 建链结果。
type Result struct {
	Nodes []model.ChainNode
	Edges []model.ChainEdge
	// Skipped 因缺证据而放弃的候选边数（诚实记录，便于观察"宁缺不造"）。
	Skipped int
}

// Build 从图内真实事实构建攻击链（幂等：同 ID 不重复加边）。
func Build(g *model.ScanGraph, opts Options) *Result {
	if g == nil {
		return &Result{}
	}
	minEv := opts.MinEvidence
	if minEv < 1 {
		minEv = 1
	}

	res := &Result{}

	// 1) 入口点节点（kind=entry）。
	entryNodes := map[string]string{} // entry_point ID → chain_node ID
	for _, ep := range g.EntryPoints {
		cn := model.NewChainNode("entry", ep.ID, entryLabel(ep), ep.EvidenceIDs)
		g.Add(cn)
		entryNodes[ep.ID] = cn.ID
		res.Nodes = append(res.Nodes, cn)
	}

	// 2) 发现节点（kind 按来源归类；情报=recon、命中/白盒=exploit）。
	//    情报节点作为「上下文」保留在节点列表，但**不参与线性串联**——
	//    同技术的多条情报共享同一指纹证据，若按共享证据连边会把几十条
	//    "possible" 级 CVE 串成一条无意义的链（实测 36 条噪声边）。
	//    这是对 P6 原始启发式的修正：序列边只认真实因果关系。
	vulnNode := map[string]string{} // vuln_node ID → chain_node ID
	for _, v := range g.VulnNodes {
		cn := model.NewChainNode(kindForVuln(v), v.ID, labelFor(v), v.EvidenceIDs)
		g.Add(cn)
		vulnNode[v.ID] = cn.ID
		res.Nodes = append(res.Nodes, cn)
	}

	// 3) 序列边（真实因果）：入口点 → 落在该入口上的发现（经 EntryID）。
	//    证据取「发现自身证据」（发现即证明该入口可达且触发）；无证据不建。
	for _, v := range g.VulnNodes {
		if v.EntryID == "" {
			continue
		}
		from, ok := entryNodes[v.EntryID]
		if !ok {
			continue
		}
		to := vulnNode[v.ID]
		if len(v.EvidenceIDs) < minEv {
			res.Skipped++
			continue
		}
		if e, err := model.NewChainEdge(from, to, "sequence", v.EvidenceIDs,
			model.ConfProbable); err == nil {
			if _, added := g.Add(e); added {
				res.Edges = append(res.Edges, e)
			}
		}
	}

	// exploit_impact：vuln_node → impact（impact 由 exploit 证明产生，自带证据）
	res.Edges = append(res.Edges, linkImpacts(g, minEv, &res.Skipped)...)
	// evidence_link：黑白盒关联边纳入链
	res.Edges = append(res.Edges, linkEvidenceLinks(g)...)
	// priv_change：权限变化边纳入链
	res.Edges = append(res.Edges, linkPrivChanges(g, minEv, &res.Skipped)...)

	if opts.MaxNodes > 0 && len(res.Nodes) > opts.MaxNodes {
		res.Nodes = res.Nodes[:opts.MaxNodes]
	}
	return res
}

// entryLabel 入口节点标签。
func entryLabel(ep model.EntryPoint) string {
	if ep.URL != "" {
		if ep.Param != "" {
			return ep.URL + " ?" + ep.Param
		}
		return ep.URL
	}
	if ep.File != "" {
		return ep.File
	}
	return ep.ID
}

// kindForVuln 按漏洞节点特征决定链节点类型（诚实的粗粒度归类）。
func kindForVuln(v model.VulnNode) string {
	switch {
	case v.Origin == model.OriginWhitebox:
		return "exploit" // 白盒数据流=可利用点
	case strings.HasPrefix(v.CheckID, "intel:"):
		return "recon" // 情报关联=信息面
	case v.Observation == model.ObsPositive:
		return "exploit"
	default:
		return "recon"
	}
}

// labelFor 链节点标签（可读）。
func labelFor(v model.VulnNode) string {
	if v.Title != "" {
		return v.Title
	}
	if v.CheckID != "" {
		return v.CheckID
	}
	if v.RuleID != "" {
		return v.RuleID
	}
	return v.ID
}

// linkImpacts 连接 vuln_node → impact（impact 由 exploit 证明产生，自带证据）。
func linkImpacts(g *model.ScanGraph, minEv int, skipped *int) []model.ChainEdge {
	nodeID := chainNodeIndex(g)
	var out []model.ChainEdge
	for _, im := range g.Impacts {
		if im.VulnID == "" || len(im.EvidenceIDs) < minEv {
			*skipped++
			continue
		}
		fromID := ensureChainNode(g, nodeID, im.VulnID, "exploit", "可利用点", im.EvidenceIDs)
		toID := ensureChainNode(g, nodeID, im.ID, "impact", "影响："+im.Kind, im.EvidenceIDs)
		if e, err := model.NewChainEdge(fromID, toID, "exploit_impact",
			im.EvidenceIDs, model.ConfProbable); err == nil {
			if _, added := g.Add(e); added {
				out = append(out, e)
			}
		}
	}
	return out
}

// chainNodeIndex 建 引用ID → 链节点ID 索引。
func chainNodeIndex(g *model.ScanGraph) map[string]string {
	m := map[string]string{}
	for i := range g.ChainNodes {
		m[g.ChainNodes[i].RefID] = g.ChainNodes[i].ID
	}
	return m
}

// ensureChainNode 取（或补建）某引用实体的链节点，返回其 ID。
// 复用传入的索引，避免重复扫描。
func ensureChainNode(g *model.ScanGraph, idx map[string]string,
	refID, kind, label string, evidenceIDs []string) string {
	if id, ok := idx[refID]; ok {
		return id
	}
	cn := model.NewChainNode(kind, refID, label, evidenceIDs)
	g.Add(cn)
	idx[refID] = cn.ID
	return cn.ID
}

// linkEvidenceLinks 把黑白盒关联边纳入链（evidence_link 已有证据）。
func linkEvidenceLinks(g *model.ScanGraph) []model.ChainEdge {
	if len(g.EvidenceLinks) == 0 {
		return nil
	}
	// 建索引：vuln/dataflow ID → 链节点 ID
	nodeID := map[string]string{}
	for i := range g.ChainNodes {
		nodeID[g.ChainNodes[i].RefID] = g.ChainNodes[i].ID
	}
	// dataflow 索引：P4 关联的白盒端是 dataflow（自身无链节点），需经其
	// VulnID 映射到白盒 vuln_node 的链节点（audit 产出的 dataflow 均带）。
	dfs := map[string]model.Dataflow{}
	for _, d := range g.Dataflows {
		dfs[d.ID] = d
	}
	var out []model.ChainEdge
	for _, l := range g.EvidenceLinks {
		if len(l.EvidenceIDs) == 0 {
			continue
		}
		bb := nodeID[l.BlackboxVulnID]
		wb := nodeID[l.WhiteboxDataflowID]
		if wb == "" {
			wb = nodeID[l.WhiteboxVulnID]
		}
		if wb == "" && l.WhiteboxDataflowID != "" {
			// dataflow 端在链上无节点：先映射到其白盒 vuln_node 的链节点；
			// 无 VulnID 可映射时为 dataflow 补建 exploit 链节点（不丢关联）。
			if d, ok := dfs[l.WhiteboxDataflowID]; ok && d.VulnID != "" {
				wb = nodeID[d.VulnID]
			}
			if wb == "" {
				wb = ensureChainNode(g, nodeID, l.WhiteboxDataflowID, "exploit",
					"白盒数据流", l.EvidenceIDs)
			}
		}
		if bb == "" || wb == "" {
			continue
		}
		if e, err := model.NewChainEdge(bb, wb, "evidence_link", l.EvidenceIDs,
			model.ConfProbable); err == nil {
			if _, added := g.Add(e); added {
				out = append(out, e)
			}
		}
	}
	return out
}

// linkPrivChanges 把权限变化边纳入链（P7 产出；P6 在此消费）。
func linkPrivChanges(g *model.ScanGraph, minEv int, skipped *int) []model.ChainEdge {
	nodeID := map[string]string{}
	for i := range g.ChainNodes {
		nodeID[g.ChainNodes[i].RefID] = g.ChainNodes[i].ID
	}
	var out []model.ChainEdge
	for _, p := range g.PrivChanges {
		if len(p.EvidenceIDs) < minEv || p.FindingID == "" {
			*skipped++
			continue
		}
		cn := model.NewChainNode("priv", p.ID, "权限变化："+p.Mechanism, p.EvidenceIDs)
		g.Add(cn)
		fromID := nodeID[p.FindingID]
		if fromID == "" {
			// finding 未在链上则跳过（不凭空连）。
			*skipped++
			continue
		}
		if e, err := model.NewChainEdge(fromID, cn.ID, "priv_change", p.EvidenceIDs,
			model.ConfProbable); err == nil {
			if _, added := g.Add(e); added {
				out = append(out, e)
			}
		}
	}
	return out
}
