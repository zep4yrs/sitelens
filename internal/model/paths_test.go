package model

import "testing"

// buildPathGraph 构造：r → e1 → x → e2 → impact；r → y → impact（两条路径共享 r/impact）。
func buildPathGraph() *ScanGraph {
	g := NewGraph("1")
	nodes := []ChainNode{
		{ID: "n-r", Kind: "recon", RefID: "host:1", EvidenceIDs: []string{"ev-r"}},
		{ID: "n-e1", Kind: "entry", RefID: "ep:1", EvidenceIDs: []string{"ev-e1"}},
		{ID: "n-x", Kind: "exploit", RefID: "vuln:1", EvidenceIDs: []string{"ev-x"}},
		{ID: "n-y", Kind: "exploit", RefID: "vuln:2", EvidenceIDs: nil},
		{ID: "n-z", Kind: "recon", RefID: "host:2", EvidenceIDs: []string{"ev-z"}},
		{ID: "n-i", Kind: "impact", RefID: "impact:1", EvidenceIDs: []string{"ev-i"}},
	}
	for _, n := range nodes {
		g.Add(n)
	}
	edges := []ChainEdge{
		{ID: "e-r-e1", From: "n-r", To: "n-e1", Kind: "sequence", DerivedFrom: []string{"ev-r"}},
		{ID: "e-e1-x", From: "n-e1", To: "n-x", Kind: "sequence", DerivedFrom: []string{"ev-e1"}},
		{ID: "e-x-i", From: "n-x", To: "n-i", Kind: "exploit_impact", DerivedFrom: []string{"ev-x"}},
		{ID: "e-r-y", From: "n-r", To: "n-y", Kind: "sequence", DerivedFrom: []string{"ev-r"}},
		{ID: "e-y-z", From: "n-y", To: "n-z", Kind: "sequence", DerivedFrom: []string{"ev-y"}},
		{ID: "e-z-i", From: "n-z", To: "n-i", Kind: "sequence", DerivedFrom: nil}, // 证据缺口
	}
	for _, e := range edges {
		g.Add(e)
	}
	return g
}

func TestShortestPathsBottlenecksAndGaps(t *testing.T) {
	g := buildPathGraph()
	v := g.ShortestPaths("n-r", "n-i", 8)
	if len(v.Paths) != 2 {
		t.Fatalf("应有 2 条最短路径，实际 %d: %+v", len(v.Paths), v.Paths)
	}
	for _, p := range v.Paths {
		if p.Nodes[0] != "n-r" || p.Nodes[len(p.Nodes)-1] != "n-i" {
			t.Fatalf("路径端点错误: %+v", p)
		}
		if p.Length != len(p.Edges) {
			t.Fatalf("长度与边数不一致: %+v", p)
		}
	}
	if len(v.Bottlenecks) != 2 { // n-r 与 n-i 被两条路径共享
		t.Fatalf("瓶颈节点应为 2 个，实际 %v", v.Bottlenecks)
	}
	if len(v.EvidenceGaps) != 1 || v.EvidenceGaps[0] != "e-z-i" {
		t.Fatalf("证据缺口应只有 e-z-i，实际 %v", v.EvidenceGaps)
	}
}

func TestShortestPathsEmptyGraph(t *testing.T) {
	g := NewGraph("1")
	v := g.ShortestPaths("", "", 4)
	if len(v.Paths) != 0 {
		t.Fatalf("空图不应有路径: %+v", v)
	}
}
