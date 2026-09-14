package model

import (
	"os"
	"strings"
	"testing"
)

// 本文件是 4.0 → 5.0 数据接口的**契约测试**（P9）。
//
// 与 graph_test.go 的差异：那里测「读写行为是否正确」，这里测
// 「**线格式字面量是否与 docs/schema-graph-v1.md 一致**」——
// kind 名、ID 前缀、枚举取值都是对外契约，改动即破坏 5.0 读端，
// 因此用字面量断言锁死（改名必红，迫使同步升 schema 版本与更新文档）。

// TestWireFormatKindNames：实体 kind 的字面量是线格式契约。
func TestWireFormatKindNames(t *testing.T) {
	// 期望值直接对照 docs/schema-graph-v1.md §4/§5；改常量即改接口，必须升版本。
	want := map[string]string{
		KindEntryPoint:   "entry_point",
		KindVulnNode:     "vuln_node",
		KindEvidence:     "evidence",
		KindEvidenceLink: "evidence_link",
		KindDataflow:     "dataflow",
		KindCWERel:       "cwe_rel",
		KindChainNode:    "chain_node",
		KindChainEdge:    "chain_edge",
		KindPrivChange:   "priv_change",
		KindImpact:       "impact",
		KindHeader:       "header",
	}
	for got, exp := range want {
		if got != exp {
			t.Errorf("kind 字面量变更（破坏接口）：得到 %q，文档契约为 %q", got, exp)
		}
	}
}

// TestWireFormatSchemaVersion：schema 版本字符串是契约。
func TestWireFormatSchemaVersion(t *testing.T) {
	if SchemaVersion != "sitelens.graph/v1" {
		t.Fatalf("schema 版本变更（破坏接口）：%q", SchemaVersion)
	}
}

// TestWireFormatIDPrefixes：ID 前缀是契约（5.0 按不透明主键使用，但形态需稳定）。
func TestWireFormatIDPrefixes(t *testing.T) {
	// 对照文档 §3 的表格。
	got := map[string]string{
		"entry_point":   PrefixOf(EntryPointID(OriginBlackbox, "param", "u", "GET", "p", "", "")),
		"vuln_node":     PrefixOf(VulnNodeID(OriginBlackbox, "c", "", "u", "p", "", 0)),
		"evidence":      PrefixOf(EvidenceID(OriginBlackbox, "response", "s", "u", "", 0, "b")),
		"evidence_link": PrefixOf(EvidenceLinkID("vn_a", "df_b", "url")),
		"dataflow":      PrefixOf(DataflowID("f.py", "fn", "p", 1)),
		"cwe_rel":       PrefixOf(CWERelID("vuln_node", "vn_a", "CWE-89", "mapping")),
		"chain_node":    PrefixOf(ChainNodeID("entry", "ep_a")),
		"chain_edge":    PrefixOf(ChainEdgeID("cn_a", "cn_b", "sequence")),
		"priv_change":   PrefixOf(PrivChangeID("anonymous", "authenticated", "credential", "vn_a")),
		"impact":        PrefixOf(ImpactID("disclosure", "vn_a")),
	}
	want := map[string]string{
		"entry_point": "ep", "vuln_node": "vn", "evidence": "ev",
		"evidence_link": "lnk", "dataflow": "df", "cwe_rel": "cwe",
		"chain_node": "cn", "chain_edge": "ce", "priv_change": "pc", "impact": "im",
	}
	for kind, exp := range want {
		if got[kind] != exp {
			t.Errorf("%s ID 前缀变更：得到 %q，契约 %q", kind, got[kind], exp)
		}
	}
}

// TestWireFormatEnums：枚举取值是契约（含 observation 四态的语义区分）。
func TestWireFormatEnums(t *testing.T) {
	obs := map[Observation]string{
		ObsUnknown: "unknown", ObsNotExecuted: "not_executed",
		ObsNegative: "negative", ObsPositive: "positive",
	}
	for got, exp := range obs {
		if string(got) != exp {
			t.Errorf("observation 取值变更：%q ≠ %q", got, exp)
		}
	}
	conf := map[Confidence]string{
		ConfConfirmed: "confirmed", ConfProbable: "probable",
		ConfPossible: "possible", ConfUnresolved: "unresolved",
	}
	for got, exp := range conf {
		if string(got) != exp {
			t.Errorf("confidence 取值变更：%q ≠ %q", got, exp)
		}
	}
	if OriginBlackbox != "blackbox" || OriginWhitebox != "whitebox" {
		t.Error("origin 取值变更")
	}
}

// TestFixtureCoversAllKinds：进仓样例必须覆盖全部 10 类实体——
// 它是 5.0 的参照样本，缺类会让 5.0 读端无法验证对应字段。
func TestFixtureCoversAllKinds(t *testing.T) {
	data, err := os.ReadFile("testdata/sample.graph.jsonl")
	if err != nil {
		t.Fatalf("样例缺失（5.0 参照样本）：%v", err)
	}
	g, err := UnmarshalJSONL(data)
	if err != nil {
		t.Fatalf("样例解析失败：%v", err)
	}
	c := g.Counts()
	for _, k := range []string{KindEntryPoint, KindVulnNode, KindEvidence,
		KindEvidenceLink, KindDataflow, KindCWERel, KindChainNode, KindChainEdge,
		KindPrivChange, KindImpact} {
		if c[k] == 0 {
			t.Errorf("样例缺少 %s（5.0 投影需要覆盖）", k)
		}
	}
}

// TestFixtureInvariants：样例必须满足文档 §8 的全部恒不变式。
func TestFixtureInvariants(t *testing.T) {
	data, _ := os.ReadFile("testdata/sample.graph.jsonl")
	g, err := UnmarshalJSONL(data)
	if err != nil {
		t.Fatal(err)
	}
	// 恒不变式 5：全部引用可解析（Validate 已强制，此处作为接口另一侧复验）。
	if err := g.Validate(); err != nil {
		t.Fatalf("样例违反恒不变式：%v", err)
	}
	evset := map[string]bool{}
	for _, e := range g.Evidences {
		evset[e.ID] = true
	}
	// 恒不变式 3：positive 必有证据。
	for _, v := range g.VulnNodes {
		if v.Observation == ObsPositive && len(v.EvidenceIDs) == 0 {
			t.Errorf("%s positive 无证据（违反恒不变式 3）", v.ID)
		}
	}
	// 恒不变式 4：chain_edge.derived_from 非空且指向真实证据。
	for _, e := range g.ChainEdges {
		if len(e.DerivedFrom) == 0 {
			t.Errorf("%s 无 derived_from（违反恒不变式 4）", e.ID)
		}
		for _, ev := range e.DerivedFrom {
			if !evset[ev] {
				t.Errorf("%s 引用不存在的证据 %s", e.ID, ev)
			}
		}
	}
	// 恒不变式 6：confirmed 必有证据。
	for _, v := range g.VulnNodes {
		if v.Confidence == ConfConfirmed && len(v.EvidenceIDs) == 0 {
			t.Errorf("%s confirmed 无证据（违反恒不变式 6）", v.ID)
		}
	}
}

// TestForwardCompatContract：4.0 加字段 / 加 kind 时 5.0 旧读端不得崩。
// 用「未知字段 + 未知 kind + 未来主版本」三种注入验证读端行为契约。
func TestForwardCompatContract(t *testing.T) {
	// (a) 未知字段：容忍。
	withExtra := `{"schema":"sitelens.graph/v1","kind":"header"}` + "\n" +
		`{"schema":"sitelens.graph/v1","kind":"vuln_node","entity":` +
		`{"id":"vn_000000000001","origin":"blackbox","observation":"negative",` +
		`"confidence":"probable","v2_field":"x","nested":{"a":1}}}` + "\n"
	g, err := UnmarshalJSONL([]byte(withExtra))
	if err != nil {
		t.Fatalf("未知字段应容忍：%v", err)
	}
	if len(g.VulnNodes) != 1 || g.VulnNodes[0].ID != "vn_000000000001" {
		t.Error("已知字段应正确解析")
	}

	// (b) 未知 kind：跳过不报错（新增实体类型不升版本）。
	withNewKind := `{"schema":"sitelens.graph/v1","kind":"header"}` + "\n" +
		`{"schema":"sitelens.graph/v1","kind":"future_entity","entity":{"id":"x_1"}}` + "\n" +
		`{"schema":"sitelens.graph/v1","kind":"impact","entity":` +
		`{"id":"im_000000000001","kind":"disclosure","confidence":"probable"}}` + "\n"
	g2, err := UnmarshalJSONL([]byte(withNewKind))
	if err != nil {
		t.Fatalf("未知 kind 应跳过：%v", err)
	}
	if len(g2.Impacts) != 1 {
		t.Error("已知 kind 应正常解析")
	}

	// (c) 未来主版本：必须明确报错（不得静默误读）。
	withV2 := `{"schema":"sitelens.graph/v2","kind":"header"}` + "\n"
	if _, err := UnmarshalJSONL([]byte(withV2)); err == nil {
		t.Error("主版本不匹配必须报错（不得静默误读）")
	} else if !strings.Contains(err.Error(), "schema") {
		t.Errorf("错误应说明 schema 不匹配：%v", err)
	}
}

// TestProjectionKindNamesStable：5.0 Phase 11 期望的 9 类投影名与文档 §6 对齐。
func TestProjectionKindNamesStable(t *testing.T) {
	// 5.0 计划的九类（vuln_node/chain_node/chain_edge/entry_point/cwe_rel/
	// dataflow/priv_change/impact/evidence_link）+ evidence 信任根。
	v40Projection := []string{
		"vuln_node", "chain_node", "chain_edge", "entry_point", "cwe_rel",
		"dataflow", "priv_change", "impact", "evidence_link", "evidence",
	}
	for _, k := range v40Projection {
		if kindOrder[k] < 0 {
			continue // 不存在于排序表（不可能，sort 表有全部 kind）
		}
		if _, ok := kindOrder[k]; !ok {
			t.Errorf("5.0 投影需要的 %q 不在 kindOrder 中", k)
		}
	}
	if len(kindOrder) != 10 {
		t.Errorf("kindOrder 应有 10 类，实得 %d", len(kindOrder))
	}
}
