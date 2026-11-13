package model

// 攻击图路径查询（5.3 P1，设计稿 §4.2）：只读，不触发扫描、不发请求。
//
// 输入是 chain.Build 产出的 ChainNodes / ChainEdges；输出到某个目标的
// 最短路径、瓶颈节点（多条路径共享）、证据缺口边（DerivedFrom 为空）。

import (
	"sort"
)

// GraphPath 一条链路径（节点 ID 顺序 + 边 ID 顺序）。
type GraphPath struct {
	Nodes  []string `json:"nodes"`
	Edges  []string `json:"edges"`
	Length int      `json:"length"` // 边数
}

// PathsView 路径查询结果。
type PathsView struct {
	From         string      `json:"from,omitempty"`
	To           string      `json:"to,omitempty"`
	Paths        []GraphPath `json:"paths"`
	Bottlenecks  []string    `json:"bottlenecks"`   // 出现在 >=2 条返回路径上的节点（共享瓶颈）
	EvidenceGaps []string    `json:"evidence_gaps"` // 无证据来源（DerivedFrom 空）的边 ID
	Truncated    bool        `json:"truncated,omitempty"`
}

// chainAdj 链图邻接表（按 ChainEdges 构建；只含已存在的节点）。
func (g *ScanGraph) chainAdj() (map[string][]ChainEdge, map[string]bool, []string) {
	nodes := make(map[string]bool, len(g.ChainNodes))
	for _, n := range g.ChainNodes {
		nodes[n.ID] = true
	}
	adj := make(map[string][]ChainEdge, len(g.ChainNodes))
	for _, e := range g.ChainEdges {
		if !nodes[e.From] || !nodes[e.To] {
			continue // 悬空边不参与路径（数据不完整时保持确定性）
		}
		adj[e.From] = append(adj[e.From], e)
	}
	// 边排序保证多次调用输出稳定。
	for k := range adj {
		es := adj[k]
		sort.Slice(es, func(i, j int) bool {
			if es[i].To != es[j].To {
				return es[i].To < es[j].To
			}
			return es[i].ID < es[j].ID
		})
		adj[k] = es
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return adj, nodes, ids
}

// chainRoots 入度为 0 的链节点（侦察/入口起点）；没有则退回全部节点。
func (g *ScanGraph) chainRoots() []string {
	_, nodes, ids := g.chainAdj()
	hasIn := make(map[string]bool, len(nodes))
	for _, e := range g.ChainEdges {
		if nodes[e.To] {
			hasIn[e.To] = true
		}
	}
	roots := make([]string, 0, len(ids))
	for _, id := range ids {
		if !hasIn[id] {
			roots = append(roots, id)
		}
	}
	if len(roots) == 0 {
		return ids
	}
	return roots
}

// ShortestPaths 从 from 到 to 的所有最短路径（BFS + 最短路径 DAG 枚举），
// 最多 maxPaths 条；maxPaths<=0 时默认 16。from/to 任一为空则用根节点/汇节点。
func (g *ScanGraph) ShortestPaths(from, to string, maxPaths int) PathsView {
	if maxPaths <= 0 {
		maxPaths = 16
	}
	adj, nodes, ids := g.chainAdj()
	view := PathsView{From: from, To: to}
	if len(ids) == 0 {
		return view
	}
	starts := []string{from}
	if from == "" || !nodes[from] {
		starts = g.chainRoots()
		view.From = ""
	}
	// 目标为空：取所有出度为 0 的汇节点。
	targets := map[string]bool{}
	if to != "" && nodes[to] {
		targets[to] = true
	} else {
		hasOut := make(map[string]bool, len(nodes))
		for _, e := range g.ChainEdges {
			if nodes[e.From] {
				hasOut[e.From] = true
			}
		}
		for _, id := range ids {
			if !hasOut[id] {
				targets[id] = true
			}
		}
		if len(targets) == 0 {
			targets[ids[len(ids)-1]] = true
		}
		view.To = ""
	}
	// 多起点 BFS：dist 为到起点的最短边数；parent 记录最短路径前驱边。
	dist := make(map[string]int, len(nodes))
	parents := make(map[string][]ChainEdge, len(nodes))
	queue := make([]string, 0, len(nodes))
	for _, s := range starts {
		if _, ok := dist[s]; ok {
			continue
		}
		dist[s] = 0
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur] {
			nd := dist[cur] + 1
			if d, ok := dist[e.To]; !ok || nd < d {
				dist[e.To] = nd
				parents[e.To] = []ChainEdge{e}
				queue = append(queue, e.To)
			} else if nd == d {
				parents[e.To] = append(parents[e.To], e)
			}
		}
	}
	// 从每个目标沿最短路径前驱回溯枚举（限制条数）。
	targetList := make([]string, 0, len(targets))
	for t := range targets {
		if _, ok := dist[t]; ok && dist[t] > 0 {
			targetList = append(targetList, t)
		}
	}
	sort.Strings(targetList)
	for _, t := range targetList {
		if len(view.Paths) >= maxPaths {
			view.Truncated = true
			break
		}
		enumerateShortest(parents, t, nil, nil, &view.Paths, maxPaths)
	}
	// 瓶颈节点：出现在 >=2 条返回路径上的节点。
	count := map[string]int{}
	for _, p := range view.Paths {
		seen := map[string]bool{}
		for _, n := range p.Nodes {
			if !seen[n] {
				seen[n] = true
				count[n]++
			}
		}
	}
	for n, c := range count {
		if c >= 2 {
			view.Bottlenecks = append(view.Bottlenecks, n)
		}
	}
	sort.Strings(view.Bottlenecks)
	// 证据缺口：路径上 DerivedFrom 为空的边。
	gapSet := map[string]bool{}
	for _, p := range view.Paths {
		for _, id := range p.Edges {
			for _, e := range g.ChainEdges {
				if e.ID == id && len(e.DerivedFrom) == 0 {
					gapSet[id] = true
				}
			}
		}
	}
	for id := range gapSet {
		view.EvidenceGaps = append(view.EvidenceGaps, id)
	}
	sort.Strings(view.EvidenceGaps)
	return view
}

// enumerateShortest 沿最短路径前驱回溯（节点顺序反转后写出）。
func enumerateShortest(parents map[string][]ChainEdge, cur string,
	nodesRev, edgesRev []string, out *[]GraphPath, maxPaths int) {
	if len(*out) >= maxPaths {
		return
	}
	ps := parents[cur]
	if len(ps) == 0 {
		nodes := reverseCopy(append(nodesRev, cur))
		edges := reverseCopy(edgesRev)
		*out = append(*out, GraphPath{Nodes: nodes, Edges: edges, Length: len(edges)})
		return
	}
	for _, e := range ps {
		enumerateShortest(parents, e.From,
			append(nodesRev, cur), append(edgesRev, e.ID), out, maxPaths)
	}
}

func reverseCopy(in []string) []string {
	out := make([]string, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}
