// Package model 是 4.0 黑白盒分析的统一数据模型（无依赖叶子包）。
//
// 定位：4.0 Track B 的「事实层」。黑盒扫描（engine/dast/checks/nuclei/passive）、
// 白盒审计（audit）与验证（exploit/replay）各自产出的事实，统一规整为本包定义的
// 实体；实体间用稳定 ID 建立关系，可持久化为 graph JSONL，供 Store / API / 报表 /
// 5.0 ML 读取。
//
// 三条硬约束（P0 审计结论的直接落地）：
//
//  1. 稳定 ID：ID 由内容确定性哈希生成（ids.go），同一天事实重扫 ID 不变，
//     可跨扫描聚合——3.0 的 Result.Verified []map[string]any 无 ID 的问题由此解决。
//  2. 可追溯：每个实体带 evidence_ids / derived_from，指回原始证据；
//     Graph.Validate 校验引用可解析、且「无证据不得 confirmed」。
//  3. 语义不合并：Unknown / Not Executed / Negative / Positive 四态严格区分
//     （Observation），绝不把「没跑」与「跑了没命中」混为一谈。
//
// 本包不 import 4.0 任何内部包（只有标准库），因此 engine/audit/store 都可依赖它，
// 不产生循环依赖；黑盒与白盒通过本包的稳定 ID 建立关系，而非互相 import。
package model

// SchemaVersion 是 graph 数据族的 schema 版本。
// 任何破坏前向兼容的字段变更都必须升版本；纯新增可选字段不升版
// （读端对未知字段容忍，见 graph.go 的 DecodeLine）。
const SchemaVersion = "sitelens.graph/v1"

// Entity kind 取值（graph JSONL 每行的 kind 字段）。
// 与 4.0 开发文档第 13 节「统一数据模型」的十类实体一一对应。
const (
	KindEntryPoint   = "entry_point"
	KindVulnNode     = "vuln_node"
	KindEvidence     = "evidence"
	KindEvidenceLink = "evidence_link"
	KindDataflow     = "dataflow"
	KindCWERel       = "cwe_rel"
	KindChainNode    = "chain_node"
	KindChainEdge    = "chain_edge"
	KindPrivChange   = "priv_change"
	KindImpact       = "impact"
	// KindHeader 仅用于 JSONL 首行元信息（非实体）。
	KindHeader = "header"
)

// KnownKinds 返回全部实体 kind 的规范顺序（不含 header）。
// 供读端/CLI 按稳定顺序遍历与展示（避免各处自行维护列表而漂移）。
func KnownKinds() []string {
	return []string{
		KindEntryPoint, KindVulnNode, KindEvidence, KindEvidenceLink,
		KindDataflow, KindCWERel, KindChainNode, KindChainEdge,
		KindPrivChange, KindImpact,
	}
}

// Origin 事实来源：黑盒（远程扫描）或白盒（本地源码审计）。
// 黑白盒结果靠本字段 + 稳定 ID 在 evidence_link 中缝合，而不是互相 import。
const (
	OriginBlackbox = "blackbox"
	OriginWhitebox = "whitebox"
)

// Observation 观测语义四态——必须严格区分的核心枚举。
//
// 这是 4.0 相对 3.0 的关键修正：3.0 各能力用各自的 verdict 词表
// （exploit 的 none/observed/proven、replay 的 present/gone/unsupported、
// intel 的 confirmed/possible），语义并不对齐；本枚举把「是否有结论、
// 结论是正还是负」抽成统一轴，原始词表保留在 Verdict 字段里不丢信息。
type Observation string

const (
	// ObsUnknown：有该条目的位置，但当前无法判定（如情报版本区间未覆盖）。
	ObsUnknown Observation = "unknown"
	// ObsNotExecuted：该项从未执行（能力未开启/被取消/条件不满足），
	// 与 Negative 语义严格不同——不能把「没跑」当成「跑了没发现」。
	ObsNotExecuted Observation = "not_executed"
	// ObsNegative：已执行且未命中（跑了没发现）。
	ObsNegative Observation = "negative"
	// ObsPositive：已执行且命中/复现（跑了且发现）。
	ObsPositive Observation = "positive"
)

// Valid 判断是否为合法观测态。
func (o Observation) Valid() bool {
	switch o {
	case ObsUnknown, ObsNotExecuted, ObsNegative, ObsPositive:
		return true
	}
	return false
}

// IsEvidenceBacked 报告该观测态是否要求有证据支撑。
// 只有 Positive 必须带证据（Positive 而无证据 = 造假，Validate 会拒绝）。
func (o Observation) IsEvidenceBacked() bool { return o == ObsPositive }

// Confidence 关系/结论的置信分级。
//
// 硬规则（需求 9）：没有真实 Evidence 的关系不得标记为 ConfConfirmed；
// 由 GuardConfidence 强制收敛，并在 Graph.Validate 中兜底校验。
type Confidence string

const (
	// ConfConfirmed：有可直接解析的真实现证据支撑，结论确定。
	ConfConfirmed Confidence = "confirmed"
	// ConfProbable：有证据但不完整/间接（如仅 URL 路径匹配的关联）。
	ConfProbable Confidence = "probable"
	// ConfPossible：弱关联（如技术名+版本区间推断，尚无直接证据）。
	ConfPossible Confidence = "possible"
	// ConfUnresolved：尚无任何判定依据。
	ConfUnresolved Confidence = "unresolved"
)

// Valid 判断是否为合法置信级。
func (c Confidence) Valid() bool {
	switch c {
	case ConfConfirmed, ConfProbable, ConfPossible, ConfUnresolved:
		return true
	}
	return false
}

// GuardConfidence 收敛置信级：无证据时把 ConfConfirmed 降为 ConfProbable，
// 保证「没有真实 Evidence 的关系不能被标记为 confirmed」（需求 9）。
// 返回值一并发回是否发生了降级，便于调用方记录审计痕迹。
func GuardConfidence(c Confidence, evidenceIDs []string) (Confidence, bool) {
	if c == ConfConfirmed && len(evidenceIDs) == 0 {
		return ConfProbable, true
	}
	return c, false
}

// ObservationForVerdict 把 3.0 各能力的历史 verdict 词表映射到统一观测态。
//
// 映射依据为各能力源码中的真实枚举（P0 审计已核实）：
//   - exploit.Verdict：none / observed / proven（internal/exploit/exploit.go:31-33）
//   - replay 三分：present / gone / unsupported（internal/replay/replay.go:1-6）
//   - intel.Verdict：confirmed / possible（internal/intel/intel.go:83）
//   - checks.Hit.Confirmed 布尔：独立二次确认位
//
// ok=false 表示该词表项尚未纳入映射（保守起见调用方应落 ObsUnknown，
// 而不是猜测）。原始 verdict 字符串应原样保留在实体的 Verdict 字段中。
func ObservationForVerdict(verdict string) (Observation, bool) {
	switch verdict {
	case "proven", "observed", "confirmed", "present", "positive":
		return ObsPositive, true
	case "gone", "negative":
		return ObsNegative, true
	case "unsupported", "not_executed", "skipped":
		return ObsNotExecuted, true
	case "none", "unknown", "", "possible":
		// possible 属情报先验（产品命中但版本区间未确认），无直接证据 →
		// 归入 unknown，避免与已执行的 Positive/Negative 混同。
		return ObsUnknown, true
	}
	return ObsUnknown, false
}
