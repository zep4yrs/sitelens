// 表单字段布尔盲注：POST 提交的真/假 payload 尺寸差分 + 双确认。
// 与 URL 参数通道同判定语义（共用 boolDifferential / BoolBlindSizePct），
// 差异点：注入走表单字段，其余字段填惰性基线值。
//
// 为什么要独立通道：DVWA / pikachu 的 SQLi 模块把 id 参数放在 POST 表单里，
// 老实现只对表单做「单引号报错」探测，报错未回显时零产出——攻击面明明
// 存在却报不出来。时间盲注不进表单（PostForm 无计时契约，避免假阴/假阳）。
package dast

import (
	"fmt"
	"strings"
)

// formBoolBudget 单次扫描表单字段布尔盲注的最大字段数与通道数。
const (
	formBoolMaxFields   = 8
	formBoolChanPerArgs = 2 // 每字段最多试 2 个通道（请求量有界）
)

// runFormBoolBlind 对表单字段逐个做布尔差分盲注。
// 返回命中的发现，done/total 与调用方共享计数。
func (r *Runner) runFormBoolBlind(plan []FormTarget, done *int, total int) []Finding {
	if len(plan) == 0 {
		return nil
	}
	if len(plan) > formBoolMaxFields {
		plan = plan[:formBoolMaxFields]
	}
	var out []Finding
	for _, ft := range plan {
		if ft.Action == "" || r.stopped() {
			continue
		}
		for _, field := range ft.Fields {
			if field == "" || r.stopped() {
				continue
			}
			if f := r.formBoolBlindField(ft, field, done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				out = append(out, *f)
			}
		}
	}
	return out
}

// formBoolBlindField 单表单字段的布尔差分（多通道）。
func (r *Runner) formBoolBlindField(ft FormTarget, field string, done *int, total int) *Finding {
	label := field + "@" + ft.Action
	// 惰性基线：其余字段填占位值，避免触发业务副作用
	base := func(v string) map[string]string {
		data := make(map[string]string, len(ft.Fields))
		for _, f := range ft.Fields {
			if f != "" {
				data[f] = "sl-dast-base"
			}
		}
		if v != "" {
			data[field] = v
		}
		return data
	}
	post := func(v string) *Resp {
		resp := r.fetch.PostFormSmall(ft.Action, base(v))
		*done++
		if r.prog != nil {
			r.prog(*done, total, label)
		}
		return resp
	}

	// 表单字段无已知原值：数字型与引号闭合型各试一遍（原值为 "1"）
	channels := boolChannels("1")
	if len(channels) > formBoolChanPerArgs {
		channels = channels[:formBoolChanPerArgs]
	}
	baseResp := post("")
	if baseResp == nil || r.stopped() {
		return nil
	}
	size0 := len(baseResp.Body)

	for _, ch := range channels {
		if r.stopped() {
			return nil
		}
		tResp, fResp := post(ch.t), post(ch.f)
		if tResp == nil || fResp == nil {
			continue
		}
		if !boolDifferential(size0, len(tResp.Body), len(fResp.Body)) {
			continue
		}
		// 双确认
		b2, t2, f2 := post(""), post(ch.t), post(ch.f)
		if b2 == nil || t2 == nil || f2 == nil {
			continue
		}
		if !boolDifferential(len(b2.Body), len(t2.Body), len(f2.Body)) {
			continue
		}
		sizeT, sizeF := len(tResp.Body), len(fResp.Body)
		f := &Finding{
			Check:    "bool-blind-sqli",
			Title:    "布尔盲注（表单字段 SQL 差分确认）",
			Severity: "high",
			URL:      ft.Action,
			Param:    field,
			Payload:  ch.t,
			Evidence: fmt.Sprintf("表单字段 %s 注入上下文 %s：真 payload 尺寸 %dB 与基线 %dB 相似，假 payload %dB 显著偏离（双确认）",
				field, ch.name, sizeT, size0, sizeF),
			Replay: formReplay(ft.Action, field, ch.t),
			Request: "POST " + ft.Action + " HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
				field + "=" + ch.t,
			Response: &RespSnap{Status: tResp.Status, Size: sizeT, Snippet: snippetOf(tResp.Body)},
			Signals: []string{"表单真/假差分成立（" + ch.name + "）",
				fmt.Sprintf("基线 %dB / 真 %dB / 假 %dB", size0, sizeT, sizeF)},
			Advice: "该表单字段拼接入 SQL 语句已被差分证实，改用参数化查询/预编译语句",
		}
		return f
	}
	return nil
}

// formReplay 表单字段注入的复现命令（payload 内单引号按 shell 语义转义）。
func formReplay(action, field, payload string) string {
	return "curl -sk --path-as-is -d '" + field + "=" +
		strings.ReplaceAll(payload, "'", `'\''`) + "' '" + action + "'"
}
