package model

import (
	"os"
	"path/filepath"
	"testing"
)

// fixturePath 是随仓库提交的 graph JSONL 样例。
// 它同时服务于三件事：
//  1. 读端兼容测试的固定输入（schema 演进时用它做回归）；
//  2. 5.0 ML 读取接口的参照样本（P9）；
//  3. 人工排查 JSONL 形态的样例。
const fixturePath = "testdata/sample.graph.jsonl"

// TestFixtureRoundTrip 读取提交的样例并校验——保证样例始终是合法 v1 图。
func TestFixtureRoundTrip(t *testing.T) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("读取样例失败（可用 SL_WRITE_FIXTURE=1 重新生成）：%v", err)
	}
	g, err := UnmarshalJSONL(data)
	if err != nil {
		t.Fatalf("样例解析失败：%v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("样例校验失败：%v", err)
	}
	if g.Schema != SchemaVersion {
		t.Errorf("样例 schema = %q，期望 %q", g.Schema, SchemaVersion)
	}
	// 样例必须覆盖全部十类实体，才能作为接口参照。
	want := []string{KindEntryPoint, KindVulnNode, KindEvidence, KindEvidenceLink,
		KindDataflow, KindCWERel, KindChainNode, KindChainEdge, KindPrivChange, KindImpact}
	c := g.Counts()
	for _, k := range want {
		if c[k] == 0 {
			t.Errorf("样例缺少 %s 实体", k)
		}
	}
}

// TestWriteFixture 仅在显式设置 SL_WRITE_FIXTURE=1 时重新生成样例。
// 默认跳过——避免测试运行意外改写仓库文件（纪律：测试不产生副作用）。
func TestWriteFixture(t *testing.T) {
	if os.Getenv("SL_WRITE_FIXTURE") != "1" {
		t.Skip("设置 SL_WRITE_FIXTURE=1 才生成样例")
	}
	g := sampleGraph()
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, mustJSONL(t, g), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFixtureSchemaEvolution：样例在只增字段的前提下必须继续可读。
// 这里模拟「v1 读端读 v1+新增字段」——前向兼容不回归。
func TestFixtureSchemaEvolution(t *testing.T) {
	// 在合法样例基础上注入未知字段与未知 kind，读端仍应成功。
	lines := []byte(
		`{"schema":"sitelens.graph/v1","kind":"header","version":"sitelens.graph/v1","entities":1}` + "\n" +
			`{"schema":"sitelens.graph/v1","kind":"vuln_node","entity":{"id":"vn_001122334455","origin":"blackbox","observation":"negative","confidence":"probable","brand_new_field":"x"}}` + "\n" +
			`{"schema":"sitelens.graph/v1","kind":"totally_new_kind","entity":{"whatever":true}}` + "\n")
	g, err := UnmarshalJSONL(lines)
	if err != nil {
		t.Fatalf("v1 读端应容忍新增字段/未知 kind：%v", err)
	}
	if len(g.VulnNodes) != 1 {
		t.Fatalf("vuln 数 = %d，期望 1", len(g.VulnNodes))
	}
}

// mustJSONL 生成 JSONL 或让测试失败。
func mustJSONL(t *testing.T, g *ScanGraph) []byte {
	t.Helper()
	data, err := g.MarshalJSONL()
	if err != nil {
		t.Fatalf("MarshalJSONL：%v", err)
	}
	return data
}
