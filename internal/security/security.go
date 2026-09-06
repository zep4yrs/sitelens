// Package security 安全响应头评估（对照 securityheaders.com 思路）。
// 检查 8 个安全响应头是否配置，按重要性加权打分并给出 A-F 等级与修复建议。
// 移植自 python 分支 scanner/security.py。
package security

import "strings"

type item struct {
	Header string
	Weight int
	Note   string
	Advice string
}

// checkItems (头名, 权重, 说明, 修复建议)，权重合计 100。
var checkItems = []item{
	{"strict-transport-security", 20, "强制 HTTPS（HSTS）",
		"添加 Strict-Transport-Security: max-age=31536000; includeSubDomains"},
	{"content-security-policy", 20, "内容安全策略（CSP）防 XSS",
		"添加 Content-Security-Policy，先 report-only 观察再强制"},
	{"x-frame-options", 10, "防点击劫持",
		"添加 X-Frame-Options: SAMEORIGIN 或用 CSP frame-ancestors"},
	{"x-content-type-options", 10, "禁止 MIME 嗅探",
		"添加 X-Content-Type-Options: nosniff"},
	{"referrer-policy", 10, "控制引用来源泄露",
		"添加 Referrer-Policy: strict-origin-when-cross-origin"},
	{"permissions-policy", 10, "限制摄像头/麦克风等能力",
		"添加 Permissions-Policy: camera=(), microphone=(), geolocation=()"},
	{"cross-origin-opener-policy", 10, "跨窗口隔离（COOP）",
		"添加 Cross-Origin-Opener-Policy: same-origin"},
	{"cross-origin-resource-policy", 10, "跨域资源隔离（CORP）",
		"添加 Cross-Origin-Resource-Policy: same-origin"},
}

// Item 单项评估结果（JSON 对齐 Python to_dict）。
type Item struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value"`
	Weight  int    `json:"weight"`
	Note    string `json:"note"`
	Advice  string `json:"advice"`
}

// Report 安全响应头评估报告。
type Report struct {
	Score int    `json:"score"`
	Grade string `json:"grade"`
	Items []Item `json:"items"`
}

var gradeSteps = []struct {
	floor int
	grade string
}{
	{90, "A+"}, {80, "A"}, {70, "B"}, {55, "C"}, {40, "D"}, {0, "F"},
}

// Assess 按检查清单逐项评估响应头（headers 为响应头映射）。
func Assess(headers map[string]string) *Report {
	get := func(name string) string {
		for k, v := range headers {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return ""
	}
	rep := &Report{Items: make([]Item, 0, len(checkItems))}
	earned := 0
	for _, ci := range checkItems {
		value := get(ci.Header)
		present := value != ""
		if present {
			earned += ci.Weight
		}
		v := value
		if len(v) > 120 {
			v = v[:120]
		}
		rep.Items = append(rep.Items, Item{
			Header: ci.Header, Present: present, Value: v,
			Weight: ci.Weight, Note: ci.Note, Advice: ci.Advice,
		})
	}
	rep.Score = earned // 权重合计 100，直接即百分制
	for _, s := range gradeSteps {
		if rep.Score >= s.floor {
			rep.Grade = s.grade
			break
		}
	}
	return rep
}
