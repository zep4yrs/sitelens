package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ScanGraph 一次分析产出的完整事实图（黑盒 + 白盒 + 关系 + 链）。
//
// 它是 4.0 事实层的载体：P2 在黑盒扫描中收集黑盒实体，P3/P4 补白盒与关联，
// P6 补链；最终由 store 落为 graph JSONL（P8），供 5.0 ML 流式读取（P9）。
type ScanGraph struct {
	Schema      string `json:"schema"`
	ScanID      string `json:"scan_id,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`

	EntryPoints   []EntryPoint   `json:"entry_points,omitempty"`
	VulnNodes     []VulnNode     `json:"vuln_nodes,omitempty"`
	Evidences     []Evidence     `json:"evidences,omitempty"`
	EvidenceLinks []EvidenceLink `json:"evidence_links,omitempty"`
	Dataflows     []Dataflow     `json:"dataflows,omitempty"`
	CWERels       []CWERel       `json:"cwe_rels,omitempty"`
	ChainNodes    []ChainNode    `json:"chain_nodes,omitempty"`
	ChainEdges    []ChainEdge    `json:"chain_edges,omitempty"`
	PrivChanges   []PrivChange   `json:"priv_changes,omitempty"`
	Impacts       []Impact       `json:"impacts,omitempty"`

	// 内部去重索引（不参与 JSON 序列化）。
	idx map[string]bool
}

// NewGraph 创建空图（schema 固定为当前版本）。
func NewGraph(scanID string) *ScanGraph {
	return &ScanGraph{Schema: SchemaVersion, ScanID: scanID, idx: map[string]bool{}}
}

// kindOrder 是 JSONL 输出的规范顺序，保证同一张图多次序列化字节一致。
var kindOrder = map[string]int{
	KindEntryPoint: 0, KindVulnNode: 1, KindEvidence: 2, KindEvidenceLink: 3,
	KindDataflow: 4, KindCWERel: 5, KindChainNode: 6, KindChainEdge: 7,
	KindPrivChange: 8, KindImpact: 9,
}

// Add 加入一个实体。幂等：同 ID 已存在则跳过（返回 false），
// 这让「同一天事实重扫」自然去重，是稳定 ID 的直接收益。
func (g *ScanGraph) Add(e entity) (string, bool) {
	if g.idx == nil {
		g.idx = map[string]bool{}
	}
	id := e.EntityID()
	if id == "" || g.idx[id] {
		return id, false
	}
	switch v := e.(type) {
	case EntryPoint:
		g.EntryPoints = append(g.EntryPoints, v)
	case VulnNode:
		g.VulnNodes = append(g.VulnNodes, v)
	case Evidence:
		g.Evidences = append(g.Evidences, v)
	case EvidenceLink:
		g.EvidenceLinks = append(g.EvidenceLinks, v)
	case Dataflow:
		g.Dataflows = append(g.Dataflows, v)
	case CWERel:
		g.CWERels = append(g.CWERels, v)
	case ChainNode:
		g.ChainNodes = append(g.ChainNodes, v)
	case ChainEdge:
		g.ChainEdges = append(g.ChainEdges, v)
	case PrivChange:
		g.PrivChanges = append(g.PrivChanges, v)
	case Impact:
		g.Impacts = append(g.Impacts, v)
	default:
		return id, false
	}
	g.idx[id] = true
	return id, true
}

// entities 按规范顺序返回全部实体（遍历/序列化统一入口）。
func (g *ScanGraph) entities() []entity {
	out := make([]entity, 0,
		len(g.EntryPoints)+len(g.VulnNodes)+len(g.Evidences)+len(g.EvidenceLinks)+
			len(g.Dataflows)+len(g.CWERels)+len(g.ChainNodes)+len(g.ChainEdges)+
			len(g.PrivChanges)+len(g.Impacts))
	add := func() {
		for _, e := range g.EntryPoints {
			out = append(out, e)
		}
		for _, e := range g.VulnNodes {
			out = append(out, e)
		}
		for _, e := range g.Evidences {
			out = append(out, e)
		}
		for _, e := range g.EvidenceLinks {
			out = append(out, e)
		}
		for _, e := range g.Dataflows {
			out = append(out, e)
		}
		for _, e := range g.CWERels {
			out = append(out, e)
		}
		for _, e := range g.ChainNodes {
			out = append(out, e)
		}
		for _, e := range g.ChainEdges {
			out = append(out, e)
		}
		for _, e := range g.PrivChanges {
			out = append(out, e)
		}
		for _, e := range g.Impacts {
			out = append(out, e)
		}
	}
	add()
	return out
}

// Counts 返回各类型实体数量（含 header 之外的全部）。
func (g *ScanGraph) Counts() map[string]int {
	m := map[string]int{}
	for _, e := range g.entities() {
		m[e.EntityKind()]++
	}
	return m
}

// SortedEntities 按 (kindOrder, ID) 排序后的实体，保证输出确定性。
func (g *ScanGraph) SortedEntities() []entity {
	es := g.entities()
	sort.SliceStable(es, func(i, j int) bool {
		ki, kj := kindOrder[es[i].EntityKind()], kindOrder[es[j].EntityKind()]
		if ki != kj {
			return ki < kj
		}
		return es[i].EntityID() < es[j].EntityID()
	})
	return es
}

// evidenceSet 图上全部 evidence ID 集合（追溯校验用）。
func (g *ScanGraph) evidenceSet() map[string]bool {
	m := make(map[string]bool, len(g.Evidences))
	for _, e := range g.Evidences {
		m[e.ID] = true
	}
	return m
}

// allIDSet 图上全部实体 ID 集合（跨实体引用校验用）。
func (g *ScanGraph) allIDSet() map[string]bool {
	m := map[string]bool{}
	for _, e := range g.entities() {
		m[e.EntityID()] = true
	}
	return m
}

// Validate 校验图的内在一致性。返回 nil 表示通过；否则返回合并后的全部问题
// （errors.Join，逐条可读）。校验项对应 P1 的硬约束：
//
//  1. ID 形态合法且全局唯一；
//  2. 观测态/置信级枚举合法；
//  3. 所有 evidence 引用都能在图上解析（可追溯性，需求 2）；
//  4. Positive 观测必须有证据；confirmed 关系必须有证据（需求 9）；
//  5. chain_edge.derived_from 非空且指向真实证据（需求 8，无假链）；
//  6. 跨实体引用（关联边/链端点/链节点 ref）都能解析。
func (g *ScanGraph) Validate() error {
	evset := g.evidenceSet()
	allIDs := g.allIDSet()

	var issues []error
	seen := map[string]string{} // id → kind（查重复）

	addIssue := func(format string, args ...any) {
		// 上限保护：避免坏图刷屏（保留前 50 条）。
		if len(issues) < 50 {
			issues = append(issues, fmt.Errorf(format, args...))
		}
	}

	checkEvidenceRefs := func(kind, id string, refs []string) {
		for _, r := range refs {
			if !evset[r] {
				addIssue("%s %s 引用了不存在的证据 %s", kind, id, r)
			}
		}
	}
	checkRef := func(kind, id, field, ref string) {
		if ref == "" {
			return
		}
		if !allIDs[ref] {
			addIssue("%s %s 的 %s 引用了不存在的实体 %s", kind, id, field, ref)
		}
	}

	for _, e := range g.entities() {
		id, kind := e.EntityID(), e.EntityKind()
		if err := ValidateID(id, ""); err != nil {
			addIssue("%s 的 ID 非法：%v", kind, err)
		}
		if prev, dup := seen[id]; dup {
			addIssue("ID 重复：%s 同时出现在 %s 与 %s", id, prev, kind)
		} else {
			seen[id] = kind
		}
		checkEvidenceRefs(kind, id, e.EvidenceRefs())
	}

	for _, v := range g.VulnNodes {
		if !v.Observation.Valid() {
			addIssue("vuln_node %s 观测态非法：%q", v.ID, v.Observation)
		}
		if v.Observation == ObsPositive && len(v.EvidenceIDs) == 0 {
			addIssue("vuln_node %s 为 positive 但无证据（不得无证据判定命中）", v.ID)
		}
		if !v.Confidence.Valid() {
			addIssue("vuln_node %s 置信级非法：%q", v.ID, v.Confidence)
		}
		if v.Confidence == ConfConfirmed && len(v.EvidenceIDs) == 0 {
			addIssue("vuln_node %s 为 confirmed 但无证据（需求 9）", v.ID)
		}
		checkRef(kindVuln, v.ID, "entry_id", v.EntryID)
	}

	for _, l := range g.EvidenceLinks {
		if l.BlackboxVulnID == "" && l.WhiteboxDataflowID == "" && l.WhiteboxVulnID == "" {
			addIssue("evidence_link %s 两端全空", l.ID)
		}
		if !l.Confidence.Valid() {
			addIssue("evidence_link %s 置信级非法：%q", l.ID, l.Confidence)
		}
		if l.Confidence == ConfConfirmed && len(l.EvidenceIDs) == 0 {
			addIssue("evidence_link %s 为 confirmed 但无证据（需求 9：无真实证据的关系不得 confirmed）", l.ID)
		}
		checkRef(kindLink, l.ID, "blackbox_vuln_id", l.BlackboxVulnID)
		checkRef(kindLink, l.ID, "whitebox_dataflow_id", l.WhiteboxDataflowID)
		checkRef(kindLink, l.ID, "whitebox_vuln_id", l.WhiteboxVulnID)
		if !validBasis(l.Basis) {
			addIssue("evidence_link %s 关联依据非法：%q", l.ID, l.Basis)
		}
	}

	for _, d := range g.Dataflows {
		if len(d.EvidenceIDs) == 0 {
			addIssue("dataflow %s 无证据引用（白盒数据流必须可追溯到源码证据）", d.ID)
		}
		checkRef(kindDataflow, d.ID, "vuln_id", d.VulnID)
	}

	for _, r := range g.CWERels {
		if r.CWEID == "" {
			addIssue("cwe_rel %s 缺 CWE 编号", r.ID)
		}
		// cve 主体可能是外部编号，未必是图内实体；其余主体必须可解析。
		if r.SubjectKind != "cve" {
			checkRef(kindCWE, r.ID, "subject_id", r.SubjectID)
		}
	}

	for _, n := range g.ChainNodes {
		checkRef(kindChainNode, n.ID, "ref_id", n.RefID)
	}

	for _, e := range g.ChainEdges {
		if len(e.DerivedFrom) == 0 {
			addIssue("chain_edge %s 无 derived_from（需求 8：无真实 evidence 不得建边）", e.ID)
		}
		if !e.Confidence.Valid() {
			addIssue("chain_edge %s 置信级非法：%q", e.ID, e.Confidence)
		}
		checkRef(kindChainEdge, e.ID, "from", e.From)
		checkRef(kindChainEdge, e.ID, "to", e.To)
	}

	for _, p := range g.PrivChanges {
		checkRef(kindPrivChange, p.ID, "finding_id", p.FindingID)
	}
	for _, im := range g.Impacts {
		checkRef(kindImpact, im.ID, "vuln_id", im.VulnID)
	}

	if len(issues) == 0 {
		return nil
	}
	return errors.Join(issues...)
}

// 校验消息里用的实体类型短名（避免与 kind 常量混淆）。
const (
	kindVuln       = "vuln_node"
	kindLink       = "evidence_link"
	kindDataflow   = "dataflow"
	kindCWE        = "cwe_rel"
	kindChainNode  = "chain_node"
	kindChainEdge  = "chain_edge"
	kindPrivChange = "priv_change"
	kindImpact     = "impact"
)

// validBasis 校验关联依据枚举。
func validBasis(b string) bool {
	switch b {
	case "url", "param", "tech", "manual":
		return true
	}
	return false
}

// ---- graph JSONL ----

// Header 是 JSONL 的第一行（元信息，非实体）。
type Header struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	Version     string `json:"version"`
	ScanID      string `json:"scan_id,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
	Entities    int    `json:"entities,omitempty"`
}

// Record 是 JSONL 的实体行：kind 决定 entity 的具体类型。
// entity 用 RawMessage 保留原始字节，读端按 kind 二次解码（前向兼容：
// 未知 kind 的行被跳过而非报错，未知字段被忽略）。
type Record struct {
	Schema string          `json:"schema"`
	Kind   string          `json:"kind"`
	Entity json.RawMessage `json:"entity"`
}

// WriteJSONL 把图写成 graph JSONL：首行 header，随后每个实体一行，
// 顺序为 (类型规范顺序, ID)，保证同图多次输出字节一致。
func (g *ScanGraph) WriteJSONL(w io.Writer) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)

	schema := g.Schema
	if schema == "" {
		schema = SchemaVersion
	}
	es := g.SortedEntities()
	h := Header{Schema: schema, Kind: KindHeader, Version: SchemaVersion,
		ScanID: g.ScanID, GeneratedAt: g.GeneratedAt, Entities: len(es)}
	if err := enc.Encode(h); err != nil {
		return err
	}
	for _, e := range es {
		// 统一以实体本身为载荷；实体自带 id 字段即稳定 ID。
		raw, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("序列化 %s %s 失败：%w", e.EntityKind(), e.EntityID(), err)
		}
		if err := enc.Encode(Record{Schema: schema, Kind: e.EntityKind(), Entity: raw}); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// MarshalJSONL 返回图的 JSONL 字节（测试与导出的便捷封装）。
func (g *ScanGraph) MarshalJSONL() ([]byte, error) {
	var buf bytes.Buffer
	if err := g.WriteJSONL(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadJSONL 从 graph JSONL 重建图。首行必须是 header；实体行按 kind 解码。
// 未知 kind 的行被跳过（前向兼容）；schema 缺失或不匹配时明确报错。
func ReadJSONL(r io.Reader) (*ScanGraph, error) {
	sc := bufio.NewScanner(r)
	// 单行上限放宽到 8MB（响应快照可能较大）。
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	g := NewGraph("")
	sawHeader := false
	first := true
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Schema string `json:"schema"`
			Kind   string `json:"kind"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("JSONL 行解析失败：%w", err)
		}
		if probe.Schema != "" && !compatibleSchema(probe.Schema) {
			return nil, fmt.Errorf("schema 不匹配：文件为 %q，本端支持 %q", probe.Schema, SchemaVersion)
		}
		if first && probe.Kind != KindHeader {
			return nil, fmt.Errorf("JSONL 首行必须是 header，实际为 %q", probe.Kind)
		}
		first = false

		if probe.Kind == KindHeader {
			var h Header
			if err := json.Unmarshal(line, &h); err != nil {
				return nil, fmt.Errorf("header 解析失败：%w", err)
			}
			sawHeader = true
			if h.Schema != "" {
				g.Schema = h.Schema
			}
			g.ScanID = h.ScanID
			g.GeneratedAt = h.GeneratedAt
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("%s 行解析失败：%w", probe.Kind, err)
		}
		if err := g.addRaw(probe.Kind, rec.Entity); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawHeader {
		return nil, errors.New("JSONL 缺少 header")
	}
	return g, nil
}

// UnmarshalJSONL 从字节重建图。
func UnmarshalJSONL(data []byte) (*ScanGraph, error) { return ReadJSONL(bytes.NewReader(data)) }

// addRaw 按 kind 把原始 JSON 解码为具体实体并加入图。
func (g *ScanGraph) addRaw(kind string, raw json.RawMessage) error {
	decode := func(dst any) error {
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("%s 实体解析失败：%w", kind, err)
		}
		return nil
	}
	switch kind {
	case KindEntryPoint:
		var v EntryPoint
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindVulnNode:
		var v VulnNode
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindEvidence:
		var v Evidence
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindEvidenceLink:
		var v EvidenceLink
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindDataflow:
		var v Dataflow
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindCWERel:
		var v CWERel
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindChainNode:
		var v ChainNode
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindChainEdge:
		var v ChainEdge
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindPrivChange:
		var v PrivChange
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	case KindImpact:
		var v Impact
		if err := decode(&v); err != nil {
			return err
		}
		g.Add(v)
	default:
		// 未知 kind：前向兼容，跳过。5.0 reader 同此策略。
		return nil
	}
	return nil
}

// compatibleSchema 报告文件 schema 是否可被本端读取。
// 同主版本（sitelens.graph/v1）视为兼容；未知主版本拒绝，避免静默误读。
func compatibleSchema(s string) bool {
	return strings.HasPrefix(s, "sitelens.graph/v1")
}
