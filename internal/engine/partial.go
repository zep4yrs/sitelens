// FE-12 零丢失：取消/中断扫描的部分结果标记与统计（引擎侧，纯函数）。
//
// 既有 engine.Scan 在 cancel 命中时仍返回已采集的 *Result（页面/技术/
// 发现/证据都在里面），但 server 当前在取消分支直接丢弃、只写 job.Status=
// cancelled。本文件不改变 Scan 的任何返回语义，只提供 additive 标记与统计，
// 供 server 侧落库函数（internal/server/partial.go 的 SavePartial）调用：
//
//	res := e.eng.Scan(...)
//	if cancelled { engine.MarkPartial(res, lastPhase); s.SavePartial(jobID, res, opts) }
package engine

import "cnb.cool/feng-qiao/sitelens/internal/model"

// MarkPartial 把 Result 标记为「部分结果」（additive 字段，正常完成时
// 不输出）。interruptedPhase 为中断时所在阶段（live 阶段名，可空），
// 供续扫规划优先重跑该阶段；completed 取诊断账本里已结束的阶段。
//
// 返回同一指针，便于链式调用；nil 安全。
func MarkPartial(res *Result, interruptedPhase string) *Result {
	if res == nil {
		return nil
	}
	res.Partial = true
	res.InterruptedPhase = interruptedPhase
	res.CompletedPhases = CompletedPhases(res)
	return res
}

// CompletedPhases 从诊断账本读取已结束阶段名（按出现顺序去重）。
// 无诊断（未启用效率账本/极早失败）时返回 nil。
func CompletedPhases(res *Result) []string {
	if res == nil || res.Diagnostics == nil {
		return nil
	}
	seen := make(map[string]bool, len(res.Diagnostics.Phases))
	out := make([]string, 0, len(res.Diagnostics.Phases))
	for _, p := range res.Diagnostics.Phases {
		if p.Phase == "" || seen[p.Phase] {
			continue
		}
		seen[p.Phase] = true
		out = append(out, p.Phase)
	}
	return out
}

// PartialCounts 部分结果规模：页面/技术/发现/证据。
// 证据 = verified 条目 + 结构化事实图中的 evidence 实体（有图时）。
func PartialCounts(res *Result) (pages, techs, findings, evidence int) {
	if res == nil {
		return 0, 0, 0, 0
	}
	pages = len(res.Pages)
	techs = len(res.Technologies)
	findings = len(res.Vulnerabilities)
	evidence = len(res.Verified)
	if res.Graph != nil {
		evidence += res.Graph.Counts()[model.KindEvidence]
	}
	return pages, techs, findings, evidence
}

// PartialSummaryText 生成 job 文案（如「已取消：已保存部分结果（3 页/2 技术/1 发现/4 证据）」），
// 供 server 落库后写 job.Message，避免各处重复拼串。
func PartialSummaryText(res *Result) string {
	pages, techs, findings, evidence := PartialCounts(res)
	return "已取消：已保存部分结果（" +
		itoa(pages) + " 页/" + itoa(techs) + " 技术/" +
		itoa(findings) + " 发现/" + itoa(evidence) + " 证据）"
}

// itoa 小整型转字符串（避免为几处统计引入 strconv 依赖噪音；strconv 亦可）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
