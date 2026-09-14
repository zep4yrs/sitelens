// Package correlate 黑白盒证据关联（4.0 P4）。
//
// 定位：把黑盒扫描发现（vuln_node，origin=blackbox）与白盒源码事实
// （dataflow / vuln_node，origin=whitebox）用**稳定 ID** 建立 evidence_link，
// 这是 4.0「黑白盒打通」的核心承诺。两边各自的内部实现互不 import——
// engine 与 audit 都只依赖 internal/model，本包也只依赖 internal/model。
//
// 关联依据（basis）按证据强度排序，宁少报不误报：
//
//	param  黑盒命中的参数名 == 白盒 source/sink 涉及的参数名（最强）
//	url    黑盒 URL 路径 == 白盒文件路径（路径/文件名重合）
//	tech   黑盒识别技术 == 白盒语言/框架特征（弱关联）
//	manual 人工确认通道（不由本包自动产生）
//
// **硬约束**：无真实依据不建边；每条 link 至少带一条证据引用；
// 自动产出最高给 probable（不给 confirmed——跨黑白盒的强结论应由人确认）。
package correlate

import (
	"path"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// Options 关联参数。
type Options struct {
	// IncludeTech 启用 tech 依据（弱关联，默认关）。
	IncludeTech bool
	// MinScore 最低关联分（0 = 不限制；用于调参与降噪）。
	MinScore int
}

// Result 关联结果。
type Result struct {
	Links []model.EvidenceLink
}

// Match 一条命中明细（便于测试与报表解释）。
type Match struct {
	BlackboxVulnID string
	WhiteboxID     string
	Basis          string
	Score          int
}

// Run 对一张图内的黑盒/白盒实体做关联，返回新建的 evidence_link。
// 幂等：同 (黑盒, 白盒, basis) 三元组只产出一条边。
func Run(g *model.ScanGraph, opts Options) *Result {
	if g == nil {
		return &Result{}
	}
	blacks := blackboxNodes(g)
	whites := whiteboxFacts(g)
	if len(blacks) == 0 || len(whites) == 0 {
		return &Result{}
	}

	res := &Result{}
	seen := map[string]bool{}
	for _, b := range blacks {
		for _, w := range whites {
			basis, score := judge(b, w, opts)
			if basis == "" {
				continue
			}
			if opts.MinScore > 0 && score < opts.MinScore {
				continue
			}
			key := b.Vuln.ID + "|" + w.id() + "|" + basis
			if seen[key] {
				continue
			}
			seen[key] = true

			ev := evidenceFor(b, w)
			link, err := model.NewEvidenceLink(b.Vuln.ID, w.dataflowID(), w.vulnID(),
				basis, model.ConfProbable, ev)
			if err != nil {
				continue
			}
			// 仅当图实际新增（图内按 ID 幂等去重）才计入结果，
			// 使重复 Run 的报告与图状态一致。
			if _, added := g.Add(link); added {
				res.Links = append(res.Links, link)
			}
		}
	}
	return res
}

// blackboxNode 一个带定位信息的黑盒节点。
type blackboxNode struct {
	Vuln   model.VulnNode
	Params map[string]bool // 参数名（小写）
	Paths  map[string]bool // URL 路径段集合
	Techs  map[string]bool // 关联技术/来源标签
}

// whiteboxFact 一条白盒事实（数据流或白盒节点）。
type whiteboxFact struct {
	df        *model.Dataflow
	vn        *model.VulnNode
	Params    map[string]bool
	FileBase  string
	PathParts map[string]bool
	Lang      string
}

func (w whiteboxFact) id() string {
	if w.df != nil {
		return w.df.ID
	}
	return w.vn.ID
}

func (w whiteboxFact) dataflowID() string {
	if w.df != nil {
		return w.df.ID
	}
	return ""
}

func (w whiteboxFact) vulnID() string {
	if w.vn != nil {
		return w.vn.ID
	}
	return ""
}

// blackboxNodes 抽出黑盒节点及其定位信息。
func blackboxNodes(g *model.ScanGraph) []blackboxNode {
	out := make([]blackboxNode, 0, len(g.VulnNodes))
	for _, v := range g.VulnNodes {
		if v.Origin != model.OriginBlackbox {
			continue
		}
		b := blackboxNode{Vuln: v, Params: map[string]bool{}, Paths: map[string]bool{},
			Techs: map[string]bool{}}
		if v.Param != "" {
			b.Params[strings.ToLower(v.Param)] = true
		}
		for _, seg := range splitPath(v.URL) {
			b.Paths[seg] = true
		}
		if v.CheckID != "" {
			b.Techs[strings.ToLower(v.CheckID)] = true
		}
		if base := strings.ToLower(path.Base(v.URL)); base != "" && base != "/" {
			b.Paths[base] = true
		}
		out = append(out, b)
	}
	return out
}

// whiteboxFacts 抽出白盒事实（dataflow + 白盒 vuln_node）。
func whiteboxFacts(g *model.ScanGraph) []whiteboxFact {
	var out []whiteboxFact
	for i := range g.Dataflows {
		d := g.Dataflows[i]
		out = append(out, whiteboxFact{
			df:        &d,
			Params:    paramSet(d.Param),
			FileBase:  strings.ToLower(path.Base(d.File)),
			PathParts: segSet(d.File),
			Lang:      strings.ToLower(d.Lang),
		})
	}
	for i := range g.VulnNodes {
		v := g.VulnNodes[i]
		if v.Origin != model.OriginWhitebox {
			continue
		}
		w := whiteboxFact{
			vn:        &v,
			FileBase:  strings.ToLower(path.Base(v.File)),
			PathParts: segSet(v.File),
			Params:    map[string]bool{},
		}
		if v.RuleID != "" {
			w.Params[strings.ToLower(v.RuleID)] = true
		}
		out = append(out, w)
	}
	return out
}

// judge 判定一对黑白盒事实的关联依据与分数。basis=="" 表示不关联。
func judge(b blackboxNode, w whiteboxFact, opts Options) (string, int) {
	// param：参数名交集（最强，score 100）
	if inter := intersect(b.Params, w.Params); len(inter) > 0 {
		return "param", 100
	}
	// url：文件路径/路径段与 URL 路径段交集（score 60）
	if inter := intersect(b.Paths, w.PathParts); len(inter) > 0 {
		return "url", 60
	}
	// url：文件名与 URL 基名一致（score 55）
	if w.FileBase != "" && b.Paths[w.FileBase] {
		return "url", 55
	}
	// tech：技术/语言弱关联（score 20，默认关）
	if opts.IncludeTech && w.Lang != "" && b.Techs[w.Lang] {
		return "tech", 20
	}
	return "", 0
}

// evidenceFor 汇总两端已有证据作为关联边证据（去重、保序）。
func evidenceFor(b blackboxNode, w whiteboxFact) []string {
	var out []string
	out = append(out, b.Vuln.EvidenceIDs...)
	if w.df != nil {
		out = append(out, w.df.EvidenceIDs...)
	} else if w.vn != nil {
		out = append(out, w.vn.EvidenceIDs...)
	}
	return out
}

// ---- 小工具 ----

func paramSet(p string) map[string]bool {
	m := map[string]bool{}
	if p != "" && p != "<direct>" {
		m[strings.ToLower(p)] = true
	}
	return m
}

// splitPath 取 URL 的路径段（小写、去空）。
func splitPath(rawURL string) []string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j >= 0 {
			s = s[j:]
		} else {
			s = ""
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return segList(s)
}

// segSet 文件路径的路径段集合（小写）。
func segSet(p string) map[string]bool {
	m := map[string]bool{}
	for _, s := range segList(p) {
		m[s] = true
	}
	return m
}

func segList(s string) []string {
	var out []string
	for _, seg := range strings.Split(s, "/") {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "" || seg == "." {
			continue
		}
		out = append(out, seg)
	}
	return out
}

func intersect(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if b[k] {
			out = append(out, k)
		}
	}
	return out
}
