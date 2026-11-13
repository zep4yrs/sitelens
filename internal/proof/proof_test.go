package proof

import (
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

func testGraph() *model.ScanGraph {
	g := model.NewGraph("1")
	g.Add(model.ChainNode{ID: "n-r", Kind: "recon", RefID: "host:1", EvidenceIDs: []string{"ev-r"}})
	g.Add(model.ChainNode{ID: "n-x", Kind: "exploit", RefID: "vuln:1", EvidenceIDs: []string{"ev-x"}})
	g.Add(model.ChainNode{ID: "n-i", Kind: "impact", RefID: "impact:1", EvidenceIDs: []string{"ev-i"}})
	g.Add(model.ChainEdge{ID: "e1", From: "n-r", To: "n-x", Kind: "sequence", DerivedFrom: []string{"ev-r"}})
	g.Add(model.ChainEdge{ID: "e2", From: "n-x", To: "n-i", Kind: "exploit_impact", DerivedFrom: []string{"ev-x"}})
	return g
}

func TestPlanCompleteChain(t *testing.T) {
	goal := Goal{ID: "g1", Title: "证明可读取数据", Target: "example.com", Level: LevelProve}
	chains := Plan(goal, testGraph(), time.Unix(0, 0))
	if len(chains) != 1 {
		t.Fatalf("应有 1 条链，实际 %d", len(chains))
	}
	c := chains[0]
	if !c.Complete || c.Proven != c.Total {
		t.Fatalf("全证据链应 complete：proven=%d total=%d", c.Proven, c.Total)
	}
	if c.Steps[0].Kind != "goal" {
		t.Fatalf("首步应为 goal: %+v", c.Steps[0])
	}
	if c.Coverage != 1 {
		t.Fatalf("coverage 应为 1，实际 %v", c.Coverage)
	}
}

func TestPlanGapChain(t *testing.T) {
	g := testGraph()
	g.ChainNodes[1].EvidenceIDs = nil // n-x 无证据
	goal := Goal{ID: "g2", Title: "证明可利用", Target: "example.com", Level: LevelProve}
	chains := Plan(goal, g, time.Unix(0, 0))
	if len(chains) != 1 {
		t.Fatalf("应有 1 条链，实际 %d", len(chains))
	}
	c := chains[0]
	if c.Complete {
		t.Fatal("有 gap 的链不应 complete")
	}
	if c.Coverage >= 1 {
		t.Fatalf("coverage 应 <1，实际 %v", c.Coverage)
	}
	foundGap := false
	for _, s := range c.Steps {
		if s.Status == "gap" {
			foundGap = true
			if s.Hypothesis == "" {
				t.Fatalf("gap 步骤应有假设/下一步提示: %+v", s)
			}
		}
	}
	if !foundGap {
		t.Fatal("应存在 gap 步骤")
	}
}

func TestPlanEmptyGraph(t *testing.T) {
	goal := Goal{ID: "g3", Title: "x", Target: "example.com", Level: LevelReach}
	chains := Plan(goal, nil, time.Unix(0, 0))
	if len(chains) != 1 || chains[0].Complete {
		t.Fatalf("空图应返回 1 条未完成链: %+v", chains)
	}
}

func TestNormalizeLevel(t *testing.T) {
	cases := map[string]string{"prove": LevelProve, "PROOF": LevelProve, "可利用": LevelProve, "reach": LevelReach, "": LevelReach, "unknown": LevelReach}
	for in, want := range cases {
		if got := NormalizeLevel(in); got != want {
			t.Fatalf("NormalizeLevel(%q)=%q want %q", in, got, want)
		}
	}
}
