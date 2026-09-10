// 布尔差分盲注：真/假 payload 双向尺寸差分 + 双确认。
// 判定语义：真 payload（AND 1=1）响应应与基线相似，假 payload（AND 1=2）
// 应显著偏离——只满足单向（假不同）不报，防内容随机化站点误报。
// 无害化：纯数值/字符串恒真恒假拼接，每参数固定 5 个请求，有界。
package dast

import (
	"fmt"
	"net/url"
)

// BoolBlindSizePct 布尔差分的"相似"判定：尺寸差 ≤ 10% 视为相似。
const BoolBlindSizePct = 10

// boolBlind 单参数布尔差分探测，命中返回 Finding。
func (r *Runner) boolBlind(tgt Target, done *int, total int) *Finding {
	label := shortLabel(tgt)
	orig := queryValue(tgt.URL, tgt.Param)
	tPayload, fPayload := boolPayloads(orig)
	uT := setParam(tgt.URL, tgt.Param, tPayload)
	uF := setParam(tgt.URL, tgt.Param, fPayload)
	if len(uT) > r.opts.MaxURLLen || len(uF) > r.opts.MaxURLLen {
		return nil
	}
	rb := func(u string) *Resp {
		resp := r.fetch.GetSmall(u)
		*done++
		if r.prog != nil {
			r.prog(*done, total, label)
		}
		return resp
	}

	base := rb(tgt.URL)
	if base == nil || r.stopped() {
		return nil
	}
	tResp := rb(uT)
	fResp := rb(uF)
	if tResp == nil || fResp == nil || r.stopped() {
		return nil
	}
	size0, sizeT, sizeF := len(base.Body), len(tResp.Body), len(fResp.Body)
	// 第一轮必须满足"真相似 + 假偏离"才有资格进入双确认
	if !sizeSimilar(size0, sizeT) || sizeSimilar(size0, sizeF) {
		return nil
	}

	base2 := rb(tgt.URL)
	t2 := rb(uT)
	f2 := rb(uF)
	if base2 == nil || t2 == nil || f2 == nil {
		return nil
	}
	if !sizeSimilar(len(base2.Body), len(t2.Body)) || sizeSimilar(len(base2.Body), len(f2.Body)) {
		return nil
	}

	return &Finding{
		Check:    "bool-blind-sqli",
		Title:    "布尔盲注（SQL 差分确认）",
		Severity: "high",
		URL:      tgt.URL,
		Param:    tgt.Param,
		Payload:  tPayload,
		Evidence: fmt.Sprintf("真payload 尺寸 %dB 与基线 %dB 相似，假payload %dB 显著偏离（双确认）",
			sizeT, size0, sizeF),
		Replay: curlReplay(uT),
		Advice: "参数值拼接入 SQL 语句已被差分证实，改用参数化查询/预编译语句",
	}
}

// sizeSimilar 两尺寸相差 ≤ BoolBlindSizePct% 视为相似。
// 用乘法比较（先除后比会因整数截断把 10.75% 算成 10%）。
func sizeSimilar(a, b int) bool {
	if a == b {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	base := a
	if b > base {
		base = b
	}
	return base > 0 && diff*100 <= base*BoolBlindSizePct
}

// boolPayloads 按原值形态构造真/假 payload（数字型 / 字符串型）。
func boolPayloads(orig string) (t, f string) {
	if orig == "" {
		orig = "1"
	}
	if isDigits(orig) {
		return orig + " AND 1=1", orig + " AND 1=2"
	}
	return orig + "' AND '1'='1", orig + "' AND '1'='2"
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
