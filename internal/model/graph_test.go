package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sampleGraph 构造一张含全部十类实体的图，供序列化/JSONL/校验共用。
// 所有引用都是真实可解析的（先加证据，再加引用它的实体）。
func sampleGraph() *ScanGraph {
	g := NewGraph("scan-1")
	g.GeneratedAt = "2026-09-14T10:00:00Z"

	evResp := NewEvidence("response", OriginBlackbox, "dast", "scan-1",
		"http://x/?id=1", "", 0, "<html>mysql syntax error</html>")
	evReq := NewEvidence("request", OriginBlackbox, "dast", "scan-1",
		"http://x/?id=1'", "", 0, "GET /?id=1' HTTP/1.1")
	g.Add(evResp)
	g.Add(evReq)

	ep := NewEntryPoint(OriginBlackbox, "param", "http://x/", "GET", "id", "", "",
		[]string{evReq.ID})
	g.Add(ep)

	vn := NewVulnNode(OriginBlackbox, "sqli-error", "", "http://x/", "id", "", 0,
		ObsPositive, "proven", ConfConfirmed, []string{evResp.ID, evReq.ID})
	vn.EntryID = ep.ID
	g.Add(vn)

	// 白盒：源码证据 + 数据流 + 白盒漏洞节点。
	evSrc := NewEvidence("source", OriginWhitebox, "audit", "", "", "vuln.php", 3, "$id = $_GET['id']")
	evSink := NewEvidence("sink", OriginWhitebox, "audit", "", "", "vuln.php", 7, "mysql_query($id)")
	g.Add(evSrc)
	g.Add(evSink)

	vnWhite := NewVulnNode(OriginWhitebox, "", "PY-SQLFMT", "", "", "vuln.php", 7,
		ObsPositive, "proven", ConfConfirmed, []string{evSink.ID})
	g.Add(vnWhite)

	df := NewDataflow("php", "vuln.php", "getUser", "id", 7,
		&FlowNode{Kind: "source", File: "vuln.php", Func: "getUser", Line: 3, Expr: "$_GET['id']"},
		&FlowNode{Kind: "sink", File: "vuln.php", Func: "getUser", Line: 7, Expr: "mysql_query"},
		[]FlowStep{{Ordinal: 1, Kind: "assign", File: "vuln.php", Line: 4, Expr: "$id = $_GET['id']"}},
		ConfConfirmed, []string{evSrc.ID, evSink.ID})
	df.VulnID = vnWhite.ID
	g.Add(df)

	link, err := NewEvidenceLink(vn.ID, df.ID, "", "param", ConfProbable, nil)
	if err == nil {
		g.Add(link)
	}

	g.Add(NewCWERel(KindVulnNode, vn.ID, "CWE-89", "mapping", ConfProbable, nil))
	g.Add(NewCWERel(KindVulnNode, vnWhite.ID, "CWE-89", "mapping", ConfProbable, nil))

	cnEntry := NewChainNode("entry", ep.ID, "参数 id", []string{evReq.ID})
	cnExploit := NewChainNode("exploit", vn.ID, "报错型 SQLi", []string{evResp.ID})
	g.Add(cnEntry)
	g.Add(cnExploit)

	if ce, err := NewChainEdge(cnEntry.ID, cnExploit.ID, "sequence", []string{evResp.ID}, ConfProbable); err == nil {
		g.Add(ce)
	}

	g.Add(NewPrivChange("anonymous", "unknown", "exploit-proven", vn.ID, ConfProbable, []string{evResp.ID}))
	g.Add(NewImpact("disclosure", "proven", vn.ID, "数据库错误信息泄露", []string{"kev"}, ConfProbable, []string{evResp.ID}))
	return g
}

// TestAddIdempotent：同 ID 重复加入被去重。
func TestAddIdempotent(t *testing.T) {
	g := NewGraph("s")
	e := NewEvidence("response", OriginBlackbox, "dast", "s", "u", "", 0, "b")
	if _, added := g.Add(e); !added {
		t.Fatal("首次加入应成功")
	}
	if _, added := g.Add(e); added {
		t.Fatal("重复加入应被去重")
	}
	if got := len(g.Evidences); got != 1 {
		t.Fatalf("证据数 = %d，期望 1", got)
	}
}

// TestCounts：各类型实体计数正确。
func TestCounts(t *testing.T) {
	g := sampleGraph()
	c := g.Counts()
	want := map[string]int{KindEntryPoint: 1, KindVulnNode: 2, KindEvidence: 4,
		KindEvidenceLink: 1, KindDataflow: 1, KindCWERel: 2, KindChainNode: 2,
		KindChainEdge: 1, KindPrivChange: 1, KindImpact: 1}
	for k, n := range want {
		if c[k] != n {
			t.Errorf("%s 计数 = %d，期望 %d", k, c[k], n)
		}
	}
}

// TestValidateSampleGraph：构造的合法图通过校验。
func TestValidateSampleGraph(t *testing.T) {
	if err := sampleGraph().Validate(); err != nil {
		t.Fatalf("合法图校验失败：%v", err)
	}
}

// TestValidatePositiveNeedsEvidence（需求 9）：positive 无证据必须被拒。
func TestValidatePositiveNeedsEvidence(t *testing.T) {
	g := NewGraph("s")
	g.Add(VulnNode{ID: VulnNodeID(OriginBlackbox, "x", "", "u", "", "", 0),
		Origin: OriginBlackbox, Observation: ObsPositive, Confidence: ConfProbable})
	err := g.Validate()
	if err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("positive 无证据应校验失败，实得 %v", err)
	}
}

// TestValidateConfirmedNeedsEvidence（需求 9）：confirmed 无证据必须被拒。
func TestValidateConfirmedNeedsEvidence(t *testing.T) {
	g := NewGraph("s")
	g.Add(VulnNode{ID: VulnNodeID(OriginBlackbox, "y", "", "u", "", "", 0),
		Origin: OriginBlackbox, Observation: ObsNegative, Confidence: ConfConfirmed})
	if err := g.Validate(); err == nil {
		t.Fatal("confirmed 无证据应校验失败")
	}

	// evidence_link 同规则。
	g2 := NewGraph("s")
	g2.Add(EvidenceLink{ID: EvidenceLinkID("vn_a", "df_b", "url"), BlackboxVulnID: "vn_a",
		WhiteboxDataflowID: "df_b", Basis: "url", Confidence: ConfConfirmed})
	if err := g2.Validate(); err == nil || !strings.Contains(err.Error(), "confirmed") {
		t.Fatalf("link confirmed 无证据应校验失败，实得 %v", err)
	}
}

// TestValidateChainEdgeNeedsEvidence（需求 8）：无证据的链边必须被拒。
func TestValidateChainEdgeNeedsEvidence(t *testing.T) {
	// 构造层拦截：
	if _, err := NewChainEdge("a", "b", "sequence", nil, ConfProbable); err == nil {
		t.Fatal("NewChainEdge 应拒绝无证据建边")
	}
	if _, err := NewChainEdge("", "b", "sequence", []string{"ev_x"}, ConfProbable); err == nil {
		t.Fatal("NewChainEdge 应拒绝空端点")
	}
	// 反序列化绕过构造层时，Validate 兜底拦截：
	g := NewGraph("s")
	g.Add(ChainEdge{ID: ChainEdgeID("cn_a", "cn_b", "sequence"), From: "cn_a", To: "cn_b",
		Kind: "sequence", Confidence: ConfProbable})
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "derived_from") {
		t.Fatalf("无证据链边应校验失败，实得 %v", err)
	}
}

// TestValidateUnresolvedEvidenceRef：引用不存在的证据必须被拒（可追溯性）。
func TestValidateUnresolvedEvidenceRef(t *testing.T) {
	g := NewGraph("s")
	g.Add(NewVulnNode(OriginBlackbox, "x", "", "u", "", "", 0,
		ObsPositive, "proven", ConfProbable, []string{"ev_deadbeef0000"}))
	err := g.Validate()
	if err == nil || !strings.Contains(err.Error(), "不存在的证据") {
		t.Fatalf("悬空证据引用应校验失败，实得 %v", err)
	}
}

// TestValidateDanglingEntityRef：关联边/链端点的悬空实体引用必须被拒。
func TestValidateDanglingEntityRef(t *testing.T) {
	g := NewGraph("s")
	if l, err := NewEvidenceLink("vn_missing", "df_missing", "", "url", ConfProbable, nil); err == nil {
		g.Add(l)
	}
	if err := g.Validate(); err == nil {
		t.Fatal("端点为不存在实体的关联边应校验失败")
	}
}

// TestValidateInvalidBasis：关联依据枚举校验。
func TestValidateInvalidBasis(t *testing.T) {
	g := NewGraph("s")
	if l, err := NewEvidenceLink("vn_x", "", "", "guessed", ConfPossible, nil); err == nil {
		g.Add(l)
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "关联依据") {
		t.Fatalf("非法 basis 应校验失败，实得 %v", err)
	}
}

// TestValidateDataflowNeedsEvidence：白盒数据流必须可追溯。
func TestValidateDataflowNeedsEvidence(t *testing.T) {
	g := NewGraph("s")
	g.Add(Dataflow{ID: DataflowID("a.php", "f", "id", 1), Origin: OriginWhitebox, File: "a.php"})
	if err := g.Validate(); err == nil {
		t.Fatal("无证据数据流应校验失败")
	}
}

// TestJSONRoundTrip：整图 JSON 序列化/反序列化无损。
func TestJSONRoundTrip(t *testing.T) {
	g := sampleGraph()
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("Marshal：%v", err)
	}
	var got ScanGraph
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal：%v", err)
	}
	// 重建索引后校验（反序列化不填充 idx，Add 会惰性重建）。
	if err := got.Validate(); err != nil {
		t.Fatalf("往返后校验失败：%v", err)
	}
	if a, b := g.Counts(), got.Counts(); len(a) != len(b) {
		t.Fatalf("往返后计数不一致：%v vs %v", a, b)
	}
}

// TestJSONLRoundTrip：graph JSONL 写入 → 读取 → 实体集合与校验一致。
func TestJSONLRoundTrip(t *testing.T) {
	g := sampleGraph()
	data, err := g.MarshalJSONL()
	if err != nil {
		t.Fatalf("MarshalJSONL：%v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1+countEntities(g) {
		t.Fatalf("JSONL 行数 = %d，期望 %d", len(lines), 1+countEntities(g))
	}
	// 首行必须是 header。
	if !bytes.Contains(lines[0], []byte(`"kind":"header"`)) {
		t.Fatalf("首行不是 header：%s", lines[0])
	}
	got, err := UnmarshalJSONL(data)
	if err != nil {
		t.Fatalf("UnmarshalJSONL：%v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("读回后校验失败：%v", err)
	}
	if got.Schema != SchemaVersion || got.ScanID != "scan-1" {
		t.Errorf("schema/scan_id 丢失：%q %q", got.Schema, got.ScanID)
	}
	// 逐类型计数一致。
	a, b := g.Counts(), got.Counts()
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("%s 计数往返不一致：%d → %d", k, a[k], b[k])
		}
	}
}

// TestJSONLDeterministic：同图多次序列化字节完全一致（输出确定性）。
func TestJSONLDeterministic(t *testing.T) {
	g := sampleGraph()
	d1, _ := g.MarshalJSONL()
	d2, _ := g.MarshalJSONL()
	if !bytes.Equal(d1, d2) {
		t.Fatal("两次序列化字节不一致（输出不确定）")
	}
	// 顺序打乱加入，输出仍一致。
	g2 := NewGraph("scan-1")
	g2.GeneratedAt = g.GeneratedAt
	for _, e := range g.SortedEntities() {
		g2.Add(e)
	}
	d3, _ := g2.MarshalJSONL()
	// header 的 entities 数一致即可；实体行集合必须一致。
	if !sameEntityLinesIgnoringHeader(t, d1, d3) {
		t.Fatal("不同加入顺序导致实体行输出不一致")
	}
}

// TestJSONLHeaderRequired：缺 header 的 JSONL 必须被拒。
func TestJSONLHeaderRequired(t *testing.T) {
	body := `{"schema":"sitelens.graph/v1","kind":"evidence","entity":{"id":"ev_0123456789ab"}}` + "\n"
	if _, err := UnmarshalJSONL([]byte(body)); err == nil {
		t.Fatal("缺 header 应报错")
	}
}

// TestJSONLSchemaMismatch：不兼容 schema 必须明确报错（不静默误读）。
func TestJSONLSchemaMismatch(t *testing.T) {
	hdr := `{"schema":"sitelens.graph/v9","kind":"header","version":"sitelens.graph/v9"}` + "\n"
	if _, err := UnmarshalJSONL([]byte(hdr)); err == nil {
		t.Fatal("不兼容 schema 应报错")
	}
}

// TestJSONLUnknownKindSkipped：未知 kind 行被跳过（前向兼容）。
func TestJSONLUnknownKindSkipped(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"header","version":"sitelens.graph/v1"}` + "\n")
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"future_thing","entity":{"x":1}}` + "\n")
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"evidence","entity":{"id":"ev_0123456789ab","kind":"response"}}` + "\n")
	g, err := UnmarshalJSONL(buf.Bytes())
	if err != nil {
		t.Fatalf("未知 kind 应被跳过而非报错：%v", err)
	}
	if len(g.Evidences) != 1 {
		t.Fatalf("证据数 = %d，期望 1", len(g.Evidences))
	}
}

// TestJSONLUnknownFieldsTolerated：实体行含未知字段仍可解析（前向兼容）。
func TestJSONLUnknownFieldsTolerated(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"header","version":"sitelens.graph/v1"}` + "\n")
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"vuln_node","entity":` +
		`{"id":"vn_0123456789ab","origin":"blackbox","observation":"negative","confidence":"probable","future_field":42}}` + "\n")
	g, err := UnmarshalJSONL(buf.Bytes())
	if err != nil {
		t.Fatalf("含未知字段应容忍：%v", err)
	}
	if len(g.VulnNodes) != 1 {
		t.Fatalf("vuln 数 = %d，期望 1", len(g.VulnNodes))
	}
	if g.VulnNodes[0].Observation != ObsNegative {
		t.Error("已知字段应正确解析")
	}
}

// TestJSONLBadLine：无法解析的行必须报错（不静默吞错）。
func TestJSONLBadLine(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"schema":"sitelens.graph/v1","kind":"header"}` + "\n")
	buf.WriteString("{not json}\n")
	if _, err := UnmarshalJSONL(buf.Bytes()); err == nil {
		t.Fatal("坏行应报错")
	}
}

// TestEvidenceRefRoundTrip（需求 5）：evidence reference 经往返后仍可解析。
func TestEvidenceRefRoundTrip(t *testing.T) {
	g := sampleGraph()
	data, _ := g.MarshalJSONL()
	got, err := UnmarshalJSONL(data)
	if err != nil {
		t.Fatal(err)
	}
	evset := map[string]bool{}
	for _, e := range got.Evidences {
		evset[e.ID] = true
	}
	// 每个 Positive 节点、每条链边、每条数据流都能指回真实证据。
	for _, v := range got.VulnNodes {
		if v.Observation == ObsPositive {
			if len(v.EvidenceIDs) == 0 || !evset[v.EvidenceIDs[0]] {
				t.Errorf("vuln %s 的 evidence reference 不可解析", v.ID)
			}
		}
	}
	for _, e := range got.ChainEdges {
		if len(e.DerivedFrom) == 0 || !evset[e.DerivedFrom[0]] {
			t.Errorf("chain_edge %s 的 derived_from 不可解析", e.ID)
		}
	}
	for _, d := range got.Dataflows {
		if len(d.EvidenceIDs) == 0 || !evset[d.EvidenceIDs[0]] {
			t.Errorf("dataflow %s 的 evidence reference 不可解析", d.ID)
		}
	}
}

// TestStableIDAcrossSerialization：稳定 ID 经序列化往返不变（关系可重建）。
func TestStableIDAcrossSerialization(t *testing.T) {
	g := sampleGraph()
	data, _ := g.MarshalJSONL()
	got, _ := UnmarshalJSONL(data)
	origIDs := map[string]bool{}
	for _, e := range g.SortedEntities() {
		origIDs[e.EntityID()] = true
	}
	for _, e := range got.SortedEntities() {
		if !origIDs[e.EntityID()] {
			t.Errorf("往返后出现新 ID %s（%s）", e.EntityID(), e.EntityKind())
		}
	}
	if len(origIDs) != countEntities(got) {
		t.Errorf("实体数不一致：%d vs %d", len(origIDs), countEntities(got))
	}
}

// TestCapturedAtIsRFC3339：证据时间戳可被外部（5.0）解析。
func TestCapturedAtIsRFC3339(t *testing.T) {
	e := NewEvidence("response", OriginBlackbox, "dast", "s", "u", "", 0, "b")
	if _, err := time.Parse(time.RFC3339, e.CapturedAt); err != nil {
		t.Fatalf("CapturedAt 非 RFC3339：%q (%v)", e.CapturedAt, err)
	}
}

// ---- 测试辅助 ----

func countEntities(g *ScanGraph) int { return len(g.entities()) }

// sameEntityLinesIgnoringHeader 比较两个 JSONL 的实体行集合（忽略 header 行）。
func sameEntityLinesIgnoringHeader(t *testing.T, a, b []byte) bool {
	t.Helper()
	split := func(d []byte) map[string]bool {
		m := map[string]bool{}
		for _, ln := range bytes.Split(bytes.TrimSpace(d), []byte("\n")) {
			if bytes.Contains(ln, []byte(`"kind":"header"`)) {
				continue
			}
			m[string(ln)] = true
		}
		return m
	}
	ma, mb := split(a), split(b)
	if len(ma) != len(mb) {
		return false
	}
	for k := range ma {
		if !mb[k] {
			return false
		}
	}
	return true
}
