// 模板来源维度执行统计（CP-10）：把一轮 check/模板执行证据按「来源」聚合为
// runs / pass / fail / hits，供季度对标报告与模板治理使用。
//
// 语义（报告口径，勿混用）：
//   - Runs = 该来源本轮执行记录数（每条 CheckRun 一条）；
//   - Pass = 正常执行（status=executed，即请求成功、判定可下）——衡量「模板能用」；
//   - Fail = 未执行（not_executed：连接失败/超时/WAF 等执行侧原因）；
//   - PassRate = Pass / Runs（每来源通过率）；
//   - Hit  = executed 且命中（漏洞发现）；HitRate = Hit / Pass（命中率）。
//
// 「通过率」= 模板可用性，「命中率」= 有效产出；两者分开统计，避免把
// 「模板坏了」误读成「没检出漏洞」。
package checks

import (
	"sort"
	"strings"
)

// 执行状态常量（与 CheckRun.Status 的取值保持一致）。
const (
	RunStatusExecuted    = "executed"
	RunStatusNotExecuted = "not_executed"
)

// RunStat 单条执行结果 + 来源标签。来源由上层按 check id → 模板来源关联后
// 填入（nuclei 包提供 SourceResolver/SourcePassRates 适配器）；空来源归 unknown。
type RunStat struct {
	Source string // 来源类别（cves/network/afrog/legacy/native/unknown…）
	Status string // executed | not_executed
	Hit    bool   // 仅 executed 时有效
}

// SourcePassRate 单来源聚合结果（JSON 友好，可直接进报告）。
type SourcePassRate struct {
	Source   string  `json:"source"`
	Runs     int     `json:"runs"`
	Pass     int     `json:"pass"`
	Fail     int     `json:"fail"`
	PassRate float64 `json:"pass_rate"`
	Hits     int     `json:"hits"`
	HitRate  float64 `json:"hit_rate"`
}

// AggregateBySource 按来源聚合执行结果。
//   - 来源大小写/空白归一，空来源记 "unknown"；
//   - 非 executable 的状态一律记 fail（保守：不把未知状态当通过）；
//   - 输出按来源字典序稳定排序（报告可逐字节对比）；
//   - 入参为空返回 nil。
func AggregateBySource(stats []RunStat) []SourcePassRate {
	if len(stats) == 0 {
		return nil
	}
	idx := map[string]int{}
	var out []SourcePassRate
	for _, st := range stats {
		src := normalizeRunSource(st.Source)
		i, ok := idx[src]
		if !ok {
			i = len(out)
			idx[src] = i
			out = append(out, SourcePassRate{Source: src})
		}
		row := &out[i]
		row.Runs++
		if normalizeRunStatus(st.Status) == RunStatusExecuted {
			row.Pass++
			if st.Hit {
				row.Hits++
			}
		} else {
			row.Fail++
		}
	}
	for i := range out {
		row := &out[i]
		row.PassRate = divide(row.Pass, row.Runs)
		row.HitRate = divide(row.Hits, row.Pass)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// RunStatsFromCheckRuns 把 checks.CheckRun 转成带来源的 RunStat：
// resolve 为 nil 时全部记 unknown；resolve 返回空也记 unknown。
func RunStatsFromCheckRuns(runs []CheckRun, resolve func(checkID string) string) []RunStat {
	if len(runs) == 0 {
		return nil
	}
	out := make([]RunStat, 0, len(runs))
	for _, r := range runs {
		src := ""
		if resolve != nil {
			src = resolve(r.Check)
		}
		out = append(out, RunStat{Source: src, Status: r.Status, Hit: r.Hit})
	}
	return out
}

// AggregateCheckRuns = RunStatsFromCheckRuns + AggregateBySource 的组合入口，
// 供上层（engine 报告链路）一站式调用。
func AggregateCheckRuns(runs []CheckRun, resolve func(checkID string) string) []SourcePassRate {
	return AggregateBySource(RunStatsFromCheckRuns(runs, resolve))
}

func normalizeRunSource(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	return s
}

func normalizeRunStatus(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func divide(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
