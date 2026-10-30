// 布尔差分盲注：真/假 payload 双向尺寸差分 + 双确认。
// 判定语义：真 payload 响应应与基线相似，假 payload 应显著偏离。
//
// 通道自适应（v5.0.1）：纯数字原值在字符串型注入上下文里（WHERE id='$id'）
// 会被 MySQL 弱转为数字，`1 AND 1=1` / `1 AND 1=2` 两轮响应完全一致——
// 老实现只试数字型通道，sqli-labs Less-1 这类靶场因此零命中。现在按
// 原值形态生成「数字型 / 字符串型 / 引号闭合型」三组候选，先试最可能的，
// 差分成立即命中（候选组总量有上限，不吃满预算）。
//
// 无害化：全部为恒真/恒假比较与定值乘法，不写库、不连表、不报错泄露。
// 每参数请求数受 boolChannelBudget 约束，有界。
package dast

import (
	"fmt"
	"net/url"
)

// BoolBlindSizePct 布尔差分的"相似"判定：尺寸差 ≤ 15% 视为相似。
// 原值 10% 对 sqli-labs Less-1 这类"真/假差 7%"的目标判不出差异——
// 字符串型注入的真/假响应尺寸差天然小于数字型（假分支只少一个字符），
// 而内容随机化站点的抖动通常 ≥ 20%（远超阈值），15% 仍安全。
const BoolBlindSizePct = 15

// BoolBlindDiffPct 真/假分支"可区分"的强制下限：两者相差不足该比例时
// 不算差分成立（防几字节的渲染抖动被当成注入证据）。5% 是实测出来的
// 下限：sqli-labs 字符串型注入的真/假差 7%，页面自身抖动通常 < 3%。
const BoolBlindDiffPct = 5

// boolChannelBudget 单参数布尔盲注的最多候选通道数（每个通道 2 次
// 请求：真/假；双确认再 ×2）。3 组候选覆盖绝大多数注入上下文。
const boolChannelBudget = 3

// boolChannel 一组真/假 payload 及其注入上下文描述。
type boolChannel struct {
	name string // 上下文标签（证据链展示）
	t    string // 真 payload
	f    string // 假 payload
}

// boolChannels 按原值形态返回候选通道（顺序即优先级）。
//
// 数字原值 "1" 可能落在三种拼接上下文里，各需不同 payload 形态：
//   - 数字型 `WHERE id=$id`：裸拼接即可；
//   - 字符串闭合型 `WHERE id='$id'`：裸拼接会被 MySQL 弱转成数字 1，
//     真假响应完全一致（sqli-labs Less-1 就是这么零命中的），必须补
//     前导单引号让表达式留在字符串上下文里；
//   - 乘法差分型：过滤了 AND/OR 关键字的场景下的备用通道。
//
// 非数字原值：单引号闭合 + 双引号闭合两条。
func boolChannels(orig string) []boolChannel {
	if orig == "" {
		orig = "1"
	}
	if isDigits(orig) {
		return []boolChannel{
			{name: "数字型", t: orig + " AND 1=1", f: orig + " AND 1=2"},
			{name: "引号闭合型", t: orig + "' AND '1'='1", f: orig + "' AND '1'='2"},
			{name: "乘法差分型", t: orig + "*1", f: orig + "*0"},
		}
	}
	// 字符串型：先单引号闭合（最常见），再双引号
	return []boolChannel{
		{name: "字符串闭合型", t: orig + "' AND '1'='1", f: orig + "' AND '1'='2"},
		{name: "双引号闭合型", t: orig + `" AND "1"="1`, f: orig + `" AND "1"="2`},
	}
}

// boolBlind 单参数布尔差分探测（多通道），命中返回 Finding。
func (r *Runner) boolBlind(tgt Target, done *int, total int) *Finding {
	label := shortLabel(tgt)
	orig := queryValue(tgt.URL, tgt.Param)
	channels := boolChannels(orig)
	if len(channels) > boolChannelBudget {
		channels = channels[:boolChannelBudget]
	}

	rb := func(u string) *Resp {
		resp := r.fetch.GetSmall(u)
		*done++
		if r.prog != nil {
			r.prog(*done, total, label)
		}
		return resp
	}
	// 基线 GET 属 benign 差分基准：同一 target 的其他通道（Run baseline 等）
	// 已取过则直接复用，不再重复发同一请求。
	rbBase := func() *Resp {
		resp := r.benignGET(tgt.URL)
		*done++
		if r.prog != nil {
			r.prog(*done, total, label)
		}
		return resp
	}
	// 基线只取一次：三通道共用（通道自身不改变原值语义）
	base := rbBase()
	if base == nil || r.stopped() {
		return nil
	}
	size0 := len(base.Body)

	for _, ch := range channels {
		if r.stopped() {
			return nil
		}
		uT := setParam(tgt.URL, tgt.Param, ch.t)
		uF := setParam(tgt.URL, tgt.Param, ch.f)
		if len(uT) > r.opts.MaxURLLen || len(uF) > r.opts.MaxURLLen {
			continue
		}
		tResp, fResp := rb(uT), rb(uF)
		if tResp == nil || fResp == nil {
			continue
		}
		if !boolDifferential(size0, len(tResp.Body), len(fResp.Body)) {
			continue
		}
		// 双确认：同一组 payload 再跑一轮，两轮都成立才报
		base2, t2, f2 := rbBase(), rb(uT), rb(uF)
		if base2 == nil || t2 == nil || f2 == nil {
			continue
		}
		if !boolDifferential(len(base2.Body), len(t2.Body), len(f2.Body)) {
			continue
		}
		sizeT, sizeF := len(tResp.Body), len(fResp.Body)
		f := &Finding{
			Check:    "bool-blind-sqli",
			Title:    "布尔盲注（SQL 差分确认）",
			Severity: "high",
			URL:      tgt.URL,
			Param:    tgt.Param,
			Payload:  ch.t,
			Evidence: fmt.Sprintf("注入上下文 %s：真 payload 尺寸 %dB 与基线 %dB 相似，假 payload %dB 显著偏离（双确认）",
				ch.name, sizeT, size0, sizeF),
			Advice: "参数值拼接入 SQL 语句已被差分证实，改用参数化查询/预编译语句",
		}
		chainEvidence(f, uT, tResp)
		f.Signals = []string{"真/假差分成立（" + ch.name + "）",
			fmt.Sprintf("基线 %dB / 真 %dB / 假 %dB", size0, sizeT, sizeF)}
		return f
	}
	return nil
}

// boolDifferential 差分成立判定：真分支与基线相似、且假分支显著偏离基线
// 且真/假彼此不相似。只满足"假不同"不报，防内容随机化站点误报。
func boolDifferential(base, sizeT, sizeF int) bool {
	// 条件一：真分支贴着基线（内容回显完整，说明探针没把页面打崩）
	if !sizeSimilar(base, sizeT) {
		return false
	}
	// 条件二：真/假分支可区分且差异不小于可测下限。这是判别力的全部来源——
	// 低差分尺寸（字符串型注入差 7%）天然落在"相似"区间，若反过来要求
	// "假分支远离基线"，真实差分会被当噪声吞掉（sqli-labs 零命中的第二层
	// 根因）；反过来要求"假分支贴近基线"，数字型注入（差 60%）又会被否掉。
	// 页面自身随机漂移之所以不会误报，靠的是"真分支贴基线"这条：随机站点
	// 连真分支都对不齐基线，第一轮就出局。
	return sizeDiffPct(sizeT, sizeF) >= BoolBlindDiffPct
}

// sizeSimilar 两尺寸相差 ≤ BoolBlindSizePct% 视为相似。
// 用乘法比较（先除后比会因整数截断把 10.75% 算成 10%）。
func sizeSimilar(a, b int) bool {
	return sizeDiffPct(a, b) <= BoolBlindSizePct
}

// sizeDiffPct 两尺寸的相对差（百分比，基准取两者较大值）。
func sizeDiffPct(a, b int) int {
	if a == b {
		return 0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	base := a
	if b > base {
		base = b
	}
	if base <= 0 {
		return 0
	}
	return diff * 100 / base
}

// boolPayloads 兼容旧签名的数字型/字符串型 payload 生成（单测与
// exploit 层复用）：返回首通道的真/假 payload 对。
func boolPayloads(orig string) (t, f string) {
	ch := boolChannels(orig)[0]
	return ch.t, ch.f
}

// isDigits 纯数字判定（数字型注入用恒真恒差拼接）。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// queryValue 取 URL query 中指定参数的当前值（构造 payload 的基底）。
func queryValue(rawURL, key string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}
