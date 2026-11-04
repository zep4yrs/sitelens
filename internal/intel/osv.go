// OSV.dev 情报同步（1.0 运营链路）：为 vuln_kb 的 CVE 补全受影响区间
// 与 CVSS 评分。公开 API（api.osv.dev）无需凭据；结果写入 overrides
// 文件，intel.Load 启动时合并——静态情报快照保持不可变，更新走旁路。
package intel

import (
	"encoding/json"
	"log"
	"sort"
	"strings"
)

// OsvVuln OSV API v1 响应（/v1/vulns/{id}）的建模（仅消费所需字段）。
type OsvVuln struct {
	ID       string        `json:"id"`
	Affected []OsvAffected `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// OsvAffected OSV 的一个受影响包（只消费 ranges）。
type OsvAffected struct {
	Ranges []OsvRange `json:"ranges"`
}

// OsvRange OSV 版本区间。Type 取值 ECOSYSTEM / GIT / SEMVER。
type OsvRange struct {
	Type   string          `json:"type"`
	Events []OsvRangeEvent `json:"events"`
}

// OsvRangeEvent 区间事件：introduced / fixed / last_affected。
type OsvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// osvVersionUsable 报告版本串是否可作为可比较的版本号：去空白/前导 v 后，
// 每个点分段必须为纯数字（与 versioncmp.VersionIn 的 versionLike 口径一致）。
// commit hash / 分支名等不可比的值一律拒绝——宁可少报，也不能把
// ">=deadbeef" 交给版本比较器（C2-01）。
func osvVersionUsable(v string) bool {
	v = strings.TrimSpace(strings.ToLower(strings.TrimSpace(v)))
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return false
	}
	for _, seg := range strings.Split(v, ".") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			if seg[i] < '0' || seg[i] > '9' {
				return false
			}
		}
	}
	return true
}

// osvIntroducedZero 报告版本是否等价于 0（如 "0" / "0.0"），即"从最初版本起"。
func osvIntroducedZero(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(v)), "v")
	for _, seg := range strings.Split(v, ".") {
		for i := 0; i < len(seg); i++ {
			if seg[i] != '0' {
				return false
			}
		}
	}
	return true
}

// osvRangeConds 把一个 OSV 区间的 events 序列转换成区间条件组（每组是
// 一个 AND 条件列表，如 [">=1.0", "<1.5"]）。
//
// OSV 语义（https://ossf.github.io/osv-schema/#affectedranges-field）：
// fixed / last_affected 闭合最近一个 introduced；闭合后必须重新出现
// introduced 才开启下一段。旧实现从不重置 introduced、且完全忽略
// last_affected，导致多段区间被拍平成一个不可满足的长 AND（C2-01）。
func osvRangeConds(events []OsvRangeEvent) [][]string {
	var out [][]string
	introduced := ""
	closed := true // 当前没有打开的区间
	for _, ev := range events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
			closed = false
			continue
		}
		if closed || introduced == "" {
			continue
		}
		// 零版本下界（introduced:"0"）书写成 ">=0"：对 semver 全空间成立，
		// 显式保留可读性；非零下界必须能比较才输出。
		lower := ">=" + introduced
		if !osvVersionUsable(introduced) {
			// 下界不可比（例如 GIT 事件混进 ECOSYSTEM）：整段丢弃。
			introduced = ""
			closed = true
			continue
		}
		switch {
		case ev.Fixed != "":
			if osvVersionUsable(ev.Fixed) {
				out = append(out, []string{lower, "<" + ev.Fixed})
			}
		case ev.LastAffected != "":
			if osvVersionUsable(ev.LastAffected) {
				out = append(out, []string{lower, "<=" + ev.LastAffected})
			}
		}
		introduced = ""
		closed = true
	}
	// 收尾仍打开的区间：OSV 表示"至今无修复版本"→ 开区间 >=introduced，
	// 交给 versioncmp 判定（语义正确，且不会假阴性）。
	if introduced != "" && !closed && osvVersionUsable(introduced) {
		lower := ">=" + introduced
		if osvIntroducedZero(introduced) {
			lower = ">=0" // 与旧数据/canonical 形式保持一致，便于阅读
		}
		out = append(out, []string{lower})
	}
	return out
}

// OsvAffectedFromVuln 从 OSV 响应提取受影响版本区间串。
//
// 契约（C2-01 修复后）：
//   - 只消费 ECOSYSTEM 区间；GIT 区间的 commit hash **绝不进入**版本串；
//   - 多段区间按 **OR** 语义用 "|" 连接（消费方 intel.MatchWithNVD 按 "|"
//     拆 alternatives，逗号仍是 AND 条件）；
//   - 消费 last_affected，并把 introduced 在区间闭合后重置；
//   - 返回空串表示无可用的版本区间。
func OsvAffectedFromVuln(v OsvVuln) string {
	var groups []string
	seen := map[string]bool{}
	for _, aff := range v.Affected {
		for _, rg := range aff.Ranges {
			// GIT 区间的 fixed/introduced 是 commit hash，与"版本号"不可比；
			// 混入一个不可比条件会让整条 alternative 永远为假（历史数据 128
			// 条全部零命中的根因），故直接跳过。
			if !strings.EqualFold(strings.TrimSpace(rg.Type), "ECOSYSTEM") {
				continue
			}
			for _, conds := range osvRangeConds(rg.Events) {
				joined := strings.Join(conds, ",")
				if joined == "" || seen[joined] {
					continue
				}
				seen[joined] = true
				groups = append(groups, joined)
			}
		}
	}
	return strings.Join(groups, "|")
}

// OsvCVSSFromVuln 取 CVSS_V3 向量并本地算分；无向量返回零值。
func OsvCVSSFromVuln(v OsvVuln) (float64, string) {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, sev, err := CVSS3Score(s.Score); err == nil {
				return score, sev
			}
		}
	}
	return 0, ""
}

// Override 单条 CVE 覆盖（区间补全 + CVSS 评分）。
type Override struct {
	Affected  string  `json:"affected,omitempty"`
	CVSSScore float64 `json:"cvss_score,omitempty"`
	CVSSSev   string  `json:"cvss_sev,omitempty"`
}

// splitCondOp 把 "<op><version>" 拆成 (op, version)；op 只认 versioncmp
// 支持的形态，无法识别返回 ok=false。
func splitCondOp(cond string) (op, val string, ok bool) {
	cond = strings.TrimSpace(cond)
	for _, cand := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(cond, cand) {
			return cand, strings.TrimSpace(strings.TrimPrefix(cond, cand)), true
		}
	}
	return "", cond, false
}

// SanitizeAffected 规范化外部/历史遗留的区间串，供 ParseOverrides 在加载
// 期兜底（C2-01 的消费侧保护）：
//
//   - 按 "|" 拆分 OR 分支；分支内任何条件不可比较（commit hash、文本）→
//     **整分支丢弃**：历史数据把 GIT 区间与 ECOSYSTEM 区间拍平成一个逗号
//     串，只有整组丢弃才能保证不产生假「confirmed」（宁少报）；
//   - 分支内只保留可比较的 "<op><版本>" 条件，去重保序；
//   - 丢弃 ">=0" 这类等价于"全部版本"的空信息分支（它来自 GIT introduced
//     被拍平后的残渣，保留会让所有带版本的目标都判受影响）；
//   - 结果以 "|"（OR）连接，空串 = 该覆盖不携带可用版本区间。
func SanitizeAffected(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var alts []string
	seenAlt := map[string]bool{}
	for _, alt := range strings.Split(s, "|") {
		var cleaned []string
		usable := true
		for _, raw := range strings.Split(alt, ",") {
			cond := strings.TrimSpace(raw)
			if cond == "" {
				continue
			}
			op, val, ok := splitCondOp(cond)
			if !ok || !osvVersionUsable(val) {
				usable = false // 分支内出现不可比条件：整分支不可信
				break
			}
			cleaned = append(cleaned, op+strings.TrimPrefix(strings.ToLower(val), "v"))
		}
		if !usable || len(cleaned) == 0 {
			continue
		}
		// 只含 ">=0" 的分支 = 「全部版本」，属 GIT 区间拍平后的空信息，丢弃。
		if len(cleaned) == 1 {
			if op, val, ok := splitCondOp(cleaned[0]); ok && (op == ">=" || op == ">") && osvIntroducedZero(val) {
				continue
			}
		}
		joined := strings.Join(cleaned, ",")
		if !seenAlt[joined] {
			seenAlt[joined] = true
			alts = append(alts, joined)
		}
	}
	return strings.Join(alts, "|")
}

// ParseOverrides 解析 overrides 文件内容，并对 Affected 做规范化兜底：
// 旧版 update-osv 写出的区间串把 GIT commit hash 混进了版本条件（C2-01），
// 直接消费会让整条覆盖永远不可命中，甚至把原本 possible 的情报行推成
// excluded（漏报）。加载期统一清洗，并记录被清洗的条数便于排查。
func ParseOverrides(data []byte) (map[string]Override, error) {
	var m map[string]Override
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	sanitized := 0
	for cve, o := range m {
		if o.Affected == "" {
			continue
		}
		clean := SanitizeAffected(o.Affected)
		if clean != o.Affected {
			o.Affected = clean
			m[cve] = o
			sanitized++
		}
	}
	if sanitized > 0 {
		log.Printf("intel: overrides 区间规范化：%d/%d 条的 affected 含不可比较条件（commit hash 等）已剥离或丢弃", sanitized, len(m))
	}
	return m, nil
}

// MergeOverrides 把覆盖合并进 vuln_kb 条目：Affected 追加去重、
// CVSS 空位补齐。返回生效条数。
//
// 注意：只合并非空 Affected（空 = 覆盖不携带可用区间），因此不会把原本
// Affected 为空、结论为 possible 的情报行改写成不可判定的区间（C2-01）。
func MergeOverrides(vulns []Entry, ov map[string]Override) int {
	n := 0
	// CVE 索引：同 CVE 可能多条情报
	byCVE := map[string][]int{}
	for i := range vulns {
		c := strings.ToUpper(strings.TrimSpace(vulns[i].CVE))
		if c != "" {
			byCVE[c] = append(byCVE[c], i)
		}
	}
	for cve, o := range ov {
		idx, ok := byCVE[strings.ToUpper(strings.TrimSpace(cve))]
		if !ok {
			continue
		}
		for _, i := range idx {
			changed := false
			if o.Affected != "" && !strings.Contains(vulns[i].Affected, o.Affected) {
				if vulns[i].Affected == "" {
					vulns[i].Affected = o.Affected
				} else {
					vulns[i].Affected += "|" + o.Affected
				}
				changed = true
			}
			if vulns[i].CVSSScore == 0 && o.CVSSScore > 0 {
				vulns[i].CVSSScore = o.CVSSScore
				vulns[i].CVSSSev = o.CVSSSev
				changed = true
			}
			if changed {
				n++
			}
		}
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID }) // 稳定输出
	return n
}
