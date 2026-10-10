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
	// Weaknesses 头存在但策略本身可绕过的弱点（CSP 指令级放宽等）。
	// 拓宽依据：只判「头在不在」会把 DVWA CSP Bypass 这类模块漏掉——
	// 它头是在的，但策略里允许 unsafe-inline/self 脚本注入即被绕过。
	Weaknesses []Weakness `json:"weaknesses,omitempty"`
}

// Weakness 一条安全头策略弱点。
type Weakness struct {
	Header    string `json:"header"`
	Directive string `json:"directive"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
	Advice    string `json:"advice"`
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
	rep.Weaknesses = assessCSP(get("content-security-policy"))
	return rep
}

// cspDirective 解析后的 CSP 指令（名小写 → 值列表）。
func parseCSP(v string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		vals := make([]string, 0, len(fields)-1)
		for _, f := range fields[1:] {
			vals = append(vals, strings.ToLower(f))
		}
		out[name] = vals
	}
	return out
}

// assessCSP 分析 CSP 指令级放宽（策略存在但可被绕过）。
//
// 判定面覆盖 DVWA CSP Bypass 的经典绕过链与常见弱配置：
//   - script-src 含 unsafe-inline / unsafe-eval → 内联注入可执行
//   - script-src 含 self / 通配 / 域名白名单 → 同源自托管脚本可执行
//     （DVWA 的解法正是上传含 JS 的图片到 self 再引入）
//   - script-src 含 data: / * → 数据 URI 或任意源脚本
//   - 缺 object-src / base-uri / frame-ancestors → 插件、base 劫持、点击劫持
//   - 缺 default-src 兜底 → 其他指令无约束
func assessCSP(v string) []Weakness {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	d := parseCSP(v)
	script := d["script-src"]
	if script == nil {
		script = d["default-src"]
	}
	var w []Weakness
	// CSP 关键字可能带单引号（'self' / 'unsafe-inline'），也可能裸写，
	// 比较前统一去引号，避免同一关键字两种写法判定不一致。
	has := func(vals []string, want string) bool {
		for _, x := range vals {
			if strings.Trim(x, "'") == strings.Trim(want, "'") {
				return true
			}
		}
		return false
	}

	if has(script, "unsafe-inline") {
		w = append(w, Weakness{"content-security-policy", "script-src", "high",
			"script-src 含 'unsafe-inline'：内联 <script>/事件处理器可执行，XSS 注入不受阻",
			"移除 'unsafe-inline'，用 nonce/hash 白名单替代"})
	}
	if has(script, "unsafe-eval") {
		w = append(w, Weakness{"content-security-policy", "script-src", "medium",
			"script-src 含 'unsafe-eval'：eval/Function 等动态求值可执行",
			"移除 'unsafe-eval'，改为不依赖字符串求值的写法"})
	}
	if has(script, "self") {
		w = append(w, Weakness{"content-security-policy", "script-src", "high",
			"script-src 含 'self'：同源自托管脚本可执行，上传含 JS 的文件即可绕过 CSP",
			"避免 'self'，用 nonce/hash 精确白名单；对上传目录单独收紧"})
	}
	if has(script, "*") || has(script, "data:") || has(script, "http:") || has(script, "https:") {
		w = append(w, Weakness{"content-security-policy", "script-src", "high",
			"script-src 含通配/任意协议源（* / data: / http: / https:）：脚本可从任意源加载",
			"收紧 script-src 到明确的可信源清单"})
	}
	if _, ok := d["object-src"]; !ok {
		w = append(w, Weakness{"content-security-policy", "object-src", "low",
			"未声明 object-src：<object>/<embed> 插件内容无约束",
			"添加 object-src 'none'"})
	}
	if _, ok := d["base-uri"]; !ok {
		w = append(w, Weakness{"content-security-policy", "base-uri", "medium",
			"未声明 base-uri：注入 <base href> 可劫持相对路径脚本/表单",
			"添加 base-uri 'none' 或 'self'"})
	}
	// frame-ancestors 不回落 default-src，缺了就是没防护
	if _, ok := d["frame-ancestors"]; !ok {
		w = append(w, Weakness{"content-security-policy", "frame-ancestors", "low",
			"未声明 frame-ancestors：页面可被任意站 iframe 嵌套（点击劫持）",
			"添加 frame-ancestors 'self'"})
	}
	if _, ok := d["default-src"]; !ok {
		w = append(w, Weakness{"content-security-policy", "default-src", "low",
			"缺少 default-src 兜底：未逐一列出的指令无约束",
			"添加 default-src 'self' 作为兜底"})
	}
	return w
}
