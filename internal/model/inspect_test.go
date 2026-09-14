package model

import (
	"strings"
	"testing"
)

// TestInspectFixture：参考读端（Go）能读取进仓样例并给出正确摘要。
func TestInspectFixture(t *testing.T) {
	res, err := InspectGraph("testdata/sample.graph.jsonl")
	if err != nil {
		t.Fatalf("读取样例失败：%v", err)
	}
	if !res.Exists {
		t.Fatal("样例应存在")
	}
	if !res.OK() {
		t.Fatalf("样例不应有契约违规：%v", res.Problems)
	}
	if res.Schema != SchemaVersion {
		t.Errorf("schema = %q", res.Schema)
	}
	if res.Entities == 0 {
		t.Error("实体计数应 > 0")
	}
	if res.Counts[KindChainEdge] != 1 {
		t.Errorf("链边计数 = %d，期望 1", res.Counts[KindChainEdge])
	}
	// 5.0 关心的分布字段应填充。
	if res.ObservationDist[string(ObsPositive)] == 0 {
		t.Error("应给出 observation 分布")
	}
	if len(res.ChainEdgeKinds) == 0 {
		t.Error("应给出链边类型分布")
	}
	if len(res.CWEs) == 0 {
		t.Error("应给出 CWE 列表")
	}
}

// TestInspectMissing：不存在的文件 → Exists=false，不报错。
func TestInspectMissing(t *testing.T) {
	res, err := InspectGraph("testdata/__nope__.graph.jsonl")
	if err != nil {
		t.Fatalf("文件缺失不应报错：%v", err)
	}
	if res.Exists {
		t.Error("应报告 Exists=false")
	}
}

// TestInspectCatchesViolations：参考读端与契约校验一致——违规必须被检出。
// 覆盖恒不变式 2（ID 形态）、3（positive 必备证据）、4（链边必备证据）、5（引用可解析）。
func TestInspectCatchesViolations(t *testing.T) {
	jsonl := strings.Join([]string{
		`{"schema":"sitelens.graph/v1","kind":"header","version":"sitelens.graph/v1"}`,
		// 恒不变式 3：positive 无证据。
		`{"schema":"sitelens.graph/v1","kind":"vuln_node","entity":{"id":"vn_000000000001","origin":"blackbox","observation":"positive","confidence":"probable"}}`,
		// 恒不变式 4：链边无 derived_from。
		`{"schema":"sitelens.graph/v1","kind":"chain_edge","entity":{"id":"ce_000000000001","from":"cn_a","to":"cn_b","kind":"sequence","derived_from":[],"confidence":"probable"}}`,
		// 恒不变式 2：ID 形态非法。
		`{"schema":"sitelens.graph/v1","kind":"impact","entity":{"id":"BADID","kind":"disclosure","confidence":"probable"}}`,
		// 恒不变式 5：引用不存在的证据。
		`{"schema":"sitelens.graph/v1","kind":"vuln_node","entity":{"id":"vn_000000000002","origin":"blackbox","observation":"positive","confidence":"probable","evidence_ids":["ev_000000000009"]}}`,
	}, "\n") + "\n"

	res, err := Inspect(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if res.OK() {
		t.Fatal("违规图不应通过自检")
	}
	joined := strings.Join(res.Problems, "\n")
	for _, want := range []string{"positive", "derived_from", "非法稳定 ID", "不存在的证据"} {
		if !strings.Contains(joined, want) {
			t.Errorf("未检出 %q 类违规；实际：\n%s", want, joined)
		}
	}
}

// TestInspectSchemaMismatch：主版本不匹配 → 报错（不得静默误读）。
func TestInspectSchemaMismatch(t *testing.T) {
	jsonl := `{"schema":"sitelens.graph/v2","kind":"header"}` + "\n"
	if _, err := Inspect(strings.NewReader(jsonl)); err == nil {
		t.Fatal("主版本不匹配必须报错")
	}
}

// TestKnownKinds：规范 kind 列表稳定且齐全（读端遍历依赖它）。
func TestKnownKinds(t *testing.T) {
	ks := KnownKinds()
	if len(ks) != 10 {
		t.Fatalf("KnownKinds 应有 10 类，实得 %d", len(ks))
	}
	seen := map[string]bool{}
	for _, k := range ks {
		if seen[k] {
			t.Errorf("重复 kind：%s", k)
		}
		seen[k] = true
	}
	for _, want := range []string{KindEntryPoint, KindVulnNode, KindEvidence,
		KindEvidenceLink, KindDataflow, KindCWERel, KindChainNode, KindChainEdge,
		KindPrivChange, KindImpact} {
		if !seen[want] {
			t.Errorf("KnownKinds 缺 %s", want)
		}
	}
}
