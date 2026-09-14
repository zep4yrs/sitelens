package model

import (
	"fmt"
	"time"
)

// entity 是所有图实体的公共行为：能报出自己的类型、稳定 ID 与证据引用。
// Graph.Validate 借它做统一的引用校验，无需对十类实体各写一套。
type entity interface {
	EntityKind() string
	EntityID() string
	EvidenceRefs() []string
}

// ---- evidence：原始证据（需求 2 的落地锚点）----

// Evidence 一条可追溯的原始证据。它是整张图的「信任根」：
// 其它实体只能通过 EvidenceIDs 指向它，而不能自证。
//
// Kind 取值：request / response / snippet / signals / payload / replay
// （黑盒）| source / sink / trace（白盒）。
type Evidence struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Origin     string `json:"origin"`
	Source     string `json:"source,omitempty"` // 产出方：dast|checks|nuclei|passive|exploit|replay|audit
	ScanID     string `json:"scan_id,omitempty"`
	URL        string `json:"url,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Body       string `json:"body,omitempty"`
	Digest     string `json:"digest,omitempty"` // 正文摘要（内容寻址，比对用）
	CapturedAt string `json:"captured_at,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

func (e Evidence) EntityKind() string { return KindEvidence }
func (e Evidence) EntityID() string   { return e.ID }
func (e Evidence) EvidenceRefs() []string {
	// 证据是信任根，不引用其它证据（避免自引用环）。
	return nil
}

// NewEvidence 构造证据实体。body 参与 ID 计算（经 bodyDigest）。
func NewEvidence(kind, origin, source, scanID, url, file string, line int, body string) Evidence {
	return Evidence{
		ID:         EvidenceID(origin, kind, source, url, file, line, body),
		Kind:       kind,
		Origin:     origin,
		Source:     source,
		ScanID:     scanID,
		URL:        url,
		File:       file,
		Line:       line,
		Body:       body,
		Digest:     bodyDigest(body),
		CapturedAt: time.Now().Format(time.RFC3339),
	}
}

// ---- entry_point：入口点（黑盒 URL/参数/表单，白盒文件/函数）----

// EntryPoint 一个可触达入口。黑盒来自爬取/JS 提取（ParamLinks、Forms）；
// 白盒来自源码函数（P3 起）。
type EntryPoint struct {
	ID          string   `json:"id"`
	Origin      string   `json:"origin"`
	Kind        string   `json:"kind"` // url|param|form|js_endpoint|route|function
	URL         string   `json:"url,omitempty"`
	Method      string   `json:"method,omitempty"`
	Param       string   `json:"param,omitempty"`
	Params      []string `json:"params,omitempty"`
	File        string   `json:"file,omitempty"`
	Func        string   `json:"func,omitempty"`
	Line        int      `json:"line,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func (e EntryPoint) EntityKind() string     { return KindEntryPoint }
func (e EntryPoint) EntityID() string       { return e.ID }
func (e EntryPoint) EvidenceRefs() []string { return e.EvidenceIDs }

// NewEntryPoint 构造入口点实体（ID 由定位字段确定性生成）。
func NewEntryPoint(origin, kind, url, method, param, file, fn string, evidenceIDs []string) EntryPoint {
	return EntryPoint{
		ID:          EntryPointID(origin, kind, url, method, param, file, fn),
		Origin:      origin,
		Kind:        kind,
		URL:         url,
		Method:      method,
		Param:       param,
		File:        file,
		Func:        fn,
		EvidenceIDs: refs(evidenceIDs),
	}
}

// ---- vuln_node：统一漏洞节点（黑盒发现 / 白盒发现）----

// VulnNode 一条漏洞/风险结论的统一表示。3.0 里黑盒的 checks.Hit 与
// dast.Finding、情报的 intel.Finding 结构互不相干；本结构把「定位 + 语义 +
// 证据引用」抽出共性，origin 区分黑盒白盒。
type VulnNode struct {
	ID          string      `json:"id"`
	Origin      string      `json:"origin"`
	CheckID     string      `json:"check_id,omitempty"` // 黑盒 check id
	RuleID      string      `json:"rule_id,omitempty"`  // 白盒规则 id
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	CVE         string      `json:"cve,omitempty"`
	CWEs        []string    `json:"cwes,omitempty"`
	URL         string      `json:"url,omitempty"`
	Param       string      `json:"param,omitempty"`
	File        string      `json:"file,omitempty"`
	Func        string      `json:"func,omitempty"`
	Line        int         `json:"line,omitempty"`
	Observation Observation `json:"observation"`
	Verdict     string      `json:"verdict,omitempty"` // 原始词表，保留不丢信息
	Confidence  Confidence  `json:"confidence"`
	EntryID     string      `json:"entry_id,omitempty"`
	EvidenceIDs []string    `json:"evidence_ids"`
}

func (v VulnNode) EntityKind() string     { return KindVulnNode }
func (v VulnNode) EntityID() string       { return v.ID }
func (v VulnNode) EvidenceRefs() []string { return v.EvidenceIDs }

// NewVulnNode 构造漏洞节点。confidence 经 GuardConfidence 收敛：
// 无证据时不允许 confirmed（需求 9）。
func NewVulnNode(origin, checkID, ruleID, url, param, file string, line int,
	observation Observation, verdict string, confidence Confidence, evidenceIDs []string) VulnNode {
	return VulnNode{
		ID:          VulnNodeID(origin, checkID, ruleID, url, param, file, line),
		Origin:      origin,
		CheckID:     checkID,
		RuleID:      ruleID,
		URL:         url,
		Param:       param,
		File:        file,
		Line:        line,
		Observation: observation,
		Verdict:     verdict,
		Confidence:  guard(confidence, evidenceIDs),
		EvidenceIDs: refs(evidenceIDs),
	}
}

// ---- evidence_link：黑白盒关联（需求 4 的落地）----

// EvidenceLink 把黑盒漏洞节点与白盒数据流/漏洞节点关联起来。
// 这是 4.0「黑白盒打通」的唯一合法桥梁——两端各自的内部实现互不 import。
type EvidenceLink struct {
	ID                 string     `json:"id"`
	BlackboxVulnID     string     `json:"blackbox_vuln_id"`
	WhiteboxDataflowID string     `json:"whitebox_dataflow_id,omitempty"`
	WhiteboxVulnID     string     `json:"whitebox_vuln_id,omitempty"`
	Basis              string     `json:"basis"` // url|param|tech|manual
	Confidence         Confidence `json:"confidence"`
	EvidenceIDs        []string   `json:"evidence_ids"`
}

func (l EvidenceLink) EntityKind() string     { return KindEvidenceLink }
func (l EvidenceLink) EntityID() string       { return l.ID }
func (l EvidenceLink) EvidenceRefs() []string { return l.EvidenceIDs }

// NewEvidenceLink 构造关联边。confidence 必须由调用方按关联依据强度给出；
// 无证据时 GuardConfidence 会强制降到 probable（需求 9）。
// 两端至少有一端非空，否则返回错误（不允许悬空关联边）。
func NewEvidenceLink(blackboxVulnID, whiteboxDataflowID, whiteboxVulnID, basis string,
	confidence Confidence, evidenceIDs []string) (EvidenceLink, error) {
	if blackboxVulnID == "" && whiteboxDataflowID == "" && whiteboxVulnID == "" {
		return EvidenceLink{}, fmt.Errorf("evidence_link 两端不可全空")
	}
	white := whiteboxDataflowID
	if white == "" {
		white = whiteboxVulnID
	}
	return EvidenceLink{
		ID:                 EvidenceLinkID(blackboxVulnID, white, basis),
		BlackboxVulnID:     blackboxVulnID,
		WhiteboxDataflowID: whiteboxDataflowID,
		WhiteboxVulnID:     whiteboxVulnID,
		Basis:              basis,
		Confidence:         guard(confidence, evidenceIDs),
		EvidenceIDs:        refs(evidenceIDs),
	}, nil
}

// ---- dataflow：白盒数据流（source → sink）----

// FlowNode 数据流的一个端点（source 或 sink）。
type FlowNode struct {
	Kind string `json:"kind"` // source|sink
	File string `json:"file,omitempty"`
	Func string `json:"func,omitempty"`
	Line int    `json:"line,omitempty"`
	Expr string `json:"expr,omitempty"`
}

// FlowStep 数据流中间步骤（跨行/跨赋值的近似追踪轨迹）。
type FlowStep struct {
	Ordinal int    `json:"ordinal"`
	Kind    string `json:"kind,omitempty"`
	File    string `json:"file,omitempty"`
	Func    string `json:"func,omitempty"`
	Line    int    `json:"line,omitempty"`
	Expr    string `json:"expr,omitempty"`
}

// Dataflow 一条白盒数据流结论。P3（AST/污点）产出；
// P1 只定义结构与 ID，不产出真实数据流（No fake data）。
type Dataflow struct {
	ID          string     `json:"id"`
	Origin      string     `json:"origin"` // whitebox
	Lang        string     `json:"lang,omitempty"`
	File        string     `json:"file"`
	Func        string     `json:"func,omitempty"`
	Param       string     `json:"param,omitempty"`
	Source      *FlowNode  `json:"source,omitempty"`
	Sink        *FlowNode  `json:"sink,omitempty"`
	Steps       []FlowStep `json:"steps,omitempty"`
	VulnID      string     `json:"vuln_id,omitempty"` // 关联的白盒 vuln_node
	Confidence  Confidence `json:"confidence"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

func (d Dataflow) EntityKind() string     { return KindDataflow }
func (d Dataflow) EntityID() string       { return d.ID }
func (d Dataflow) EvidenceRefs() []string { return d.EvidenceIDs }

// NewDataflow 构造数据流实体。sinkLine 参与 ID 计算（同函数内多个 sink 可区分）。
func NewDataflow(lang, file, fn, param string, sinkLine int,
	source, sink *FlowNode, steps []FlowStep, confidence Confidence, evidenceIDs []string) Dataflow {
	return Dataflow{
		ID:          DataflowID(file, fn, param, sinkLine),
		Origin:      OriginWhitebox,
		Lang:        lang,
		File:        file,
		Func:        fn,
		Param:       param,
		Source:      source,
		Sink:        sink,
		Steps:       steps,
		Confidence:  guard(confidence, evidenceIDs),
		EvidenceIDs: refs(evidenceIDs),
	}
}

// ---- cwe_rel：CWE 关联 ----

// CWERel 一条 CWE 关联。SubjectKind 指向被关联对象（vuln_node / check / rule / cve）。
type CWERel struct {
	ID          string     `json:"id"`
	SubjectKind string     `json:"subject_kind"`
	SubjectID   string     `json:"subject_id"`
	CWEID       string     `json:"cwe_id"`
	Source      string     `json:"source"` // nvd|mapping|manual
	Confidence  Confidence `json:"confidence"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

func (r CWERel) EntityKind() string     { return KindCWERel }
func (r CWERel) EntityID() string       { return r.ID }
func (r CWERel) EvidenceRefs() []string { return r.EvidenceIDs }

// NewCWERel 构造 CWE 关联实体。
func NewCWERel(subjectKind, subjectID, cweID, source string,
	confidence Confidence, evidenceIDs []string) CWERel {
	return CWERel{
		ID:          CWERelID(subjectKind, subjectID, cweID, source),
		SubjectKind: subjectKind,
		SubjectID:   subjectID,
		CWEID:       cweID,
		Source:      source,
		Confidence:  guard(confidence, evidenceIDs),
		EvidenceIDs: refs(evidenceIDs),
	}
}

// ---- chain_node / chain_edge：攻击链（证据驱动）----

// ChainNode 攻击链上的一个节点，通过 RefID 指向其它实体（vuln_node / entry_point…）。
type ChainNode struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // recon|entry|exploit|impact|priv
	RefID       string   `json:"ref_id"`
	Label       string   `json:"label,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func (n ChainNode) EntityKind() string     { return KindChainNode }
func (n ChainNode) EntityID() string       { return n.ID }
func (n ChainNode) EvidenceRefs() []string { return n.EvidenceIDs }

// NewChainNode 构造链节点。
func NewChainNode(kind, refID, label string, evidenceIDs []string) ChainNode {
	return ChainNode{ID: ChainNodeID(kind, refID), Kind: kind, RefID: refID,
		Label: label, EvidenceIDs: refs(evidenceIDs)}
}

// ChainEdge 攻击链的一条边。DerivedFrom 是证据 id 列表——
// **必须非空**（需求 8/9：没有真实 Evidence 不能建边）。
type ChainEdge struct {
	ID          string     `json:"id"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	Kind        string     `json:"kind"` // sequence|exploit_impact|evidence_link|priv_change
	DerivedFrom []string   `json:"derived_from"`
	Confidence  Confidence `json:"confidence"`
}

func (e ChainEdge) EntityKind() string { return KindChainEdge }
func (e ChainEdge) EntityID() string   { return e.ID }
func (e ChainEdge) EvidenceRefs() []string {
	return e.DerivedFrom
}

// NewChainEdge 构造攻击链边。derivedFrom 为空即返回错误——
// 从构造函数层面堵死「凭规则/CVSS 臆造攻击路径」（需求 8）。
func NewChainEdge(from, to, kind string, derivedFrom []string, confidence Confidence) (ChainEdge, error) {
	if from == "" || to == "" {
		return ChainEdge{}, fmt.Errorf("chain_edge 两端不可为空")
	}
	if len(derivedFrom) == 0 {
		return ChainEdge{}, fmt.Errorf("chain_edge 缺少证据：derived_from 为空（无真实 evidence 不得建边）")
	}
	return ChainEdge{
		ID:          ChainEdgeID(from, to, kind),
		From:        from,
		To:          to,
		Kind:        kind,
		DerivedFrom: refs(derivedFrom),
		Confidence:  guard(confidence, derivedFrom),
	}, nil
}

// ---- priv_change：权限变化 ----

// PrivChange 一次权限提升/降级事实。原料来自 3.0 的 403 绕过、登录爆破命中、
// exploit proven（P0 审计已定位这三处），P7 实体化；P1 只定义结构。
type PrivChange struct {
	ID          string     `json:"id"`
	From        string     `json:"from"` // anonymous|user|admin|unknown
	To          string     `json:"to"`
	Mechanism   string     `json:"mechanism"` // bypass-403|credential|exploit-proven|unknown
	FindingID   string     `json:"finding_id,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids"`
	Confidence  Confidence `json:"confidence"`
}

func (p PrivChange) EntityKind() string     { return KindPrivChange }
func (p PrivChange) EntityID() string       { return p.ID }
func (p PrivChange) EvidenceRefs() []string { return p.EvidenceIDs }

// NewPrivChange 构造权限变化实体。
func NewPrivChange(from, to, mechanism, findingID string,
	confidence Confidence, evidenceIDs []string) PrivChange {
	return PrivChange{
		ID:          PrivChangeID(from, to, mechanism, findingID),
		From:        from,
		To:          to,
		Mechanism:   mechanism,
		FindingID:   findingID,
		EvidenceIDs: refs(evidenceIDs),
		Confidence:  guard(confidence, evidenceIDs),
	}
}

// ---- impact：影响面 ----

// Impact 一条影响结论。Priors 携带 KEV/CVSS 等先验标注，
// **仅作解释用途，不作为建链依据**（需求 8）。
type Impact struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"` // disclosure|modification|dos|execution|redirect|unknown
	Description string     `json:"description,omitempty"`
	Verdict     string     `json:"verdict,omitempty"` // proven|observed|none
	Priors      []string   `json:"priors,omitempty"`  // kev|cvss:9.8｜仅标注
	VulnID      string     `json:"vuln_id,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids"`
	Confidence  Confidence `json:"confidence"`
}

func (i Impact) EntityKind() string     { return KindImpact }
func (i Impact) EntityID() string       { return i.ID }
func (i Impact) EvidenceRefs() []string { return i.EvidenceIDs }

// NewImpact 构造影响实体。priors 仅供解释，调用方不得据其建链。
func NewImpact(kind, verdict, vulnID, description string, priors []string,
	confidence Confidence, evidenceIDs []string) Impact {
	return Impact{
		ID:          ImpactID(kind, vulnID),
		Kind:        kind,
		Description: description,
		Verdict:     verdict,
		Priors:      refs(priors),
		VulnID:      vulnID,
		EvidenceIDs: refs(evidenceIDs),
		Confidence:  guard(confidence, evidenceIDs),
	}
}

// ---- 内部辅助 ----

// refs 复制并清理引用列表：去空串、去重、保持首次出现顺序。
// 保证序列化输出稳定（重复引用不产生噪声）。
func refs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// guard 是 GuardConfidence 的简写，丢弃降级标记（结构体内不做日志）。
func guard(c Confidence, evidenceIDs []string) Confidence {
	g, _ := GuardConfidence(c, evidenceIDs)
	return g
}
