// Package passive 被动安全检测：基于已采集证据的纯只读检查，零额外请求。
//
// 两个模块（参考 Wapiti 被动模块思路）：
//   - Cookie 属性检查：HttpOnly / Secure / SameSite 缺失告警
//   - 表单 CSRF token 存在性检查：含密码框的表单缺 token 提示
//
// 全部为配置审查类发现，severity 均为 low/medium。
// Set-Cookie 逐条保真由 httpx.Response.SetCookies 保证，无需启发式切分。
package passive

import (
	"fmt"
	"net/url"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// Hit 一条被动检测发现（对齐 verified 条目形态）。
type Hit struct {
	Check    string `json:"check"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
	Src      string `json:"src"`
}

type cookieInfo struct {
	Name     string
	Value    string
	HTTPOnly bool
	Secure   bool
	SameSite string
}

// parseCookie 解析单条 Set-Cookie。
func parseCookie(raw string) cookieInfo {
	ci := cookieInfo{}
	seg := strings.SplitN(raw, ";", 2)
	head := strings.TrimSpace(seg[0])
	kv := strings.SplitN(head, "=", 2)
	ci.Name = kv[0]
	if len(kv) == 2 {
		ci.Value = strings.TrimSpace(kv[1])
	}
	attrs := ""
	if len(seg) == 2 {
		attrs = strings.ToLower(seg[1])
	}
	for _, a := range strings.Split(attrs, ";") {
		a = strings.TrimSpace(a)
		switch {
		case a == "httponly":
			ci.HTTPOnly = true
		case a == "secure":
			ci.Secure = true
		case strings.HasPrefix(a, "samesite="):
			ci.SameSite = strings.TrimPrefix(a, "samesite=")
		}
	}
	return ci
}

// checkCookieAttrs Cookie 属性检查：会话类 Cookie 缺安全属性则告警。
func checkCookieAttrs(resp *httpx.Response, pageURL string) []Hit {
	var hits []Hit
	for _, raw := range resp.SetCookies {
		ci := parseCookie(raw)
		if ci.Name == "" {
			continue
		}
		var missing []string
		if !ci.HTTPOnly {
			missing = append(missing, "HttpOnly")
		}
		if !ci.Secure {
			missing = append(missing, "Secure")
		}
		if ci.SameSite == "" {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		hits = append(hits, Hit{
			Check: "cookie-attrs", Title: "Cookie 缺少安全属性",
			Severity: "low", URL: pageURL,
			Evidence: fmt.Sprintf("Cookie %s 缺少 %s", ci.Name, strings.Join(missing, " / ")),
			Advice:   "为 Cookie 添加 HttpOnly、Secure、SameSite 属性",
			Src:      "passive",
		})
	}
	return hits
}

// sessionCookieNames 会话类 Cookie 名（弱会话 ID 只对会话标识有意义）。
var sessionCookieNames = map[string]bool{
	"phpsessid": true, "jsessionid": true, "asp.net_sessionid": true,
	"aspnetsessionid": true, "sessionid": true, "session": true, "sid": true,
	"sessid": true, "sess": true, "jsession": true, "connect.sid": true,
	"dvwasession": true, "session_id": true, "auth": true, "token": true,
}

// weakSessionID 判定会话 Cookie 值是否为可预测/低强度 ID。
//
// 判定口径（单样本可判定的形态，不含统计熵——单次观测测不出分布）：
//   - 纯短数字（≤8 位）：DVWA 弱会话 ID 模块即 `dvwaSession=1` 递增整数
//   - 时间戳形态（10/13 位数字）：生成可预测
//   - 近全数字的短十六进制：计数器直接转 hex 的低位派生
//
// 只报「形态本身就弱」的，不做熵估计——避免把正常随机 ID 误判。
func weakSessionID(name, value string) (string, bool) {
	if !sessionCookieNames[strings.ToLower(name)] {
		return "", false
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", false
	}
	// 纯数字
	if isAllDigits(v) {
		switch {
		case len(v) <= 8:
			return "会话 ID 为 " + v + "：短整型，可枚举预测", true
		case len(v) == 10 || len(v) == 13:
			return "会话 ID 为时间戳形态（" + v + "）：生成可预测", true
		}
		return "", false
	}
	// 十六进制形态只在「明显是计数器派生」时报：全数字或近全数字的短值。
	// 不报普通随机十六进制串（abc123def456 这类在各框架里正常），
	// 单样本测不出分布，泛报就是误报。
	if isHex(v) && len(v) >= 1 && len(v) <= 8 && mostlyDigits(v) {
		return "会话 ID 为短十六进制且近全数字（" + v + "）：疑似计数器派生，可预测", true
	}
	return "", false
}

// mostlyDigits 字符串是否以数字为主（允许末尾少数十六进制字母，
// 如计数器直接转 hex 的形态）。
func mostlyDigits(s string) bool {
	d := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d++
		}
	}
	return d*3 >= len(s)*2 // 数字占比 ≥ 2/3
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// checkSessionWeak session 类 Cookie 值形态弱点检查。
func checkSessionWeak(resp *httpx.Response, pageURL string) []Hit {
	var hits []Hit
	for _, raw := range resp.SetCookies {
		ci := parseCookie(raw)
		ev, ok := weakSessionID(ci.Name, ci.Value)
		if !ok {
			continue
		}
		hits = append(hits, Hit{
			Check: "weak-session-id", Title: "会话 ID 可预测",
			Severity: "high", URL: pageURL,
			Evidence: "Cookie " + ci.Name + " " + ev,
			Advice:   "会话 ID 改用密码学安全随机数生成器（≥128 位），禁用自增计数/时间戳派生",
			Src:      "passive",
		})
	}
	return hits
}

// csrfFieldNames 常见 CSRF token 字段名。
var csrfFieldNames = map[string]bool{
	"csrfmiddlewaretoken": true, "csrf_token": true, "csrftoken": true,
	"_csrf": true, "_token": true, "authenticity_token": true,
	"xsrf-token": true, "csrf": true, "token": true,
}

// strongStateChangeNames GET 表单的「强状态变更」字段名。
//
// 只用于 GET 表单判定：DVWA CSRF low 档的改密表单（password_new/password_conf）
// 必须命中；而搜索/查询表单里的 name/id/action 等通用字段、以及 submit 按钮
// 不能当成状态变更（标准靶场实测：DVWA SQLi/XSS 搜索表单被误报 csrf-form）。
var strongStateChangeNames = map[string]bool{
	"password_new": true, "password_conf": true, "password": true, "passwd": true,
	"new_password": true, "newpassword": true, "pass": true,
	"update": true, "save": true, "delete": true,
	"transfer": true, "amount": true,
}

// stateChangeActions 动作语义（URL/action 里出现即视为状态变更端点）。
var stateChangeActions = []string{
	"update", "delete", "remove", "create", "edit", "save", "transfer",
	"change", "reset", "admin", "manage", "modify", "send", "post",
}

// hasCSRFToken 表单内是否存在隐藏的 CSRF token 字段（名或值命中已知特征）。
func hasCSRFToken(f htmlx.Form) bool {
	for _, in := range f.Inputs {
		if in.Type != "hidden" {
			continue
		}
		name := strings.ToLower(in.Name)
		if csrfFieldNames[name] {
			return true
		}
		// 值域也认：不少框架把 token 藏在随机命名的隐藏域里
		v := strings.ToLower(in.Value)
		if len(v) >= 16 && (strings.Contains(name, "token") || strings.Contains(v, "csrf")) {
			return true
		}
	}
	return false
}

// isStateChanging 判断表单是否具备状态变更语义（拓宽后的 CSRF 触发面）。
func isStateChanging(f htmlx.Form) bool {
	if f.Method != "POST" {
		// GET 表单默认也可触发（DVWA CSRF low 档就是 GET），但纯搜索表单不算：
		// 有路径/动作语义或状态字段才算，避免把站内搜索刷成误报。
		if f.HasPassword || hasStateField(f) || actionSuggestsStateChange(f.Action) {
			return true
		}
		return false
	}
	return true
}

func hasStateField(f htmlx.Form) bool {
	for _, in := range f.Inputs {
		switch strings.ToLower(in.Type) {
		case "submit", "button", "reset", "image":
			continue // 按钮不是状态字段
		}
		if strongStateChangeNames[strings.ToLower(in.Name)] {
			return true
		}
	}
	return false
}

func actionSuggestsStateChange(action string) bool {
	a := strings.ToLower(action)
	for _, kw := range stateChangeActions {
		if strings.Contains(a, kw) {
			return true
		}
	}
	return false
}

// sameOriginFormAction 表单 action 是否与页面同源（空/相对路径视为同源）。
//
// 跨源表单（博客文章里嵌入的 jsfiddle/codepen 示例表单）不需要本站 CSRF
// token 校验，按本站 CSRF 报只会是误报（2026-11-01 真实站点实测）。
func sameOriginFormAction(pageURL, action string) bool {
	a := strings.TrimSpace(action)
	if a == "" {
		return true
	}
	au, err := url.Parse(a)
	if err != nil || au.Host == "" {
		return true // 解析失败/相对路径：保守按同源处理
	}
	pu, err := url.Parse(pageURL)
	if err != nil || pu.Host == "" {
		return true
	}
	if !strings.EqualFold(au.Host, pu.Host) {
		return false
	}
	if au.Scheme != "" && pu.Scheme != "" && !strings.EqualFold(au.Scheme, pu.Scheme) {
		return false
	}
	return true
}

// checkCSRF 状态变更表单是否缺少 CSRF token 字段。
// 拓宽：触发面从「登录表单」扩到「全部状态变更表单」，并按缺失程度分级——
// 无 token 为 high，token 存在但可预测（短/固定）为 medium。
func checkCSRF(doc *htmlx.Doc, pageURL string) []Hit {
	var hits []Hit
	for _, f := range doc.Forms {
		if !isStateChanging(f) {
			continue
		}
		if !sameOriginFormAction(pageURL, f.Action) {
			continue // 跨源表单不属于本站 CSRF 面
		}
		if hasCSRFToken(f) {
			continue
		}
		sev := "medium"
		title := "状态变更表单缺少 CSRF token"
		if f.Method == "POST" || hasStateField(f) {
			sev = "high"
		}
		if f.HasPassword {
			title = "登录表单缺少 CSRF token"
		}
		hits = append(hits, Hit{
			Check: "csrf-form", Title: title,
			Severity: sev, URL: pageURL,
			Evidence: "表单 " + f.Action + "（" + f.Method + "）含状态变更字段但未携带 CSRF token 字段",
			Advice:   "为状态变更表单加入一次性 CSRF token 校验（服务端强校验，不可仅前端）",
			Src:      "passive",
		})
	}
	return hits
}

// Deduper 跨页去重器：一次扫描内同一 cookie / 同一表单只报一次。
//
// 为什么需要：cookie-attrs 是站点级属性，每个爬到的页面都带着同一个
// Set-Cookie，逐页上报会在 24 页站点上产出 48 条重复（实测 DVWA 48 条、
// 靶场评测 59 条 cookie 重复）——不是误报，是脏数据：同一条结论被计数几十次，
// 拉低准确率口径、淹没真实发现。CSRF 同理：同一 action 的表单是同一个坑。
type Deduper struct {
	cookies map[string]bool // Cookie 名 + 缺失属性集合 → 已报
	forms   map[string]bool // 表单 action + 缺失事实 → 已报
}

// NewDeduper 创建去重器。
func NewDeduper() *Deduper {
	return &Deduper{cookies: map[string]bool{}, forms: map[string]bool{}}
}

// Run 对一页已采集响应执行全部被动检查（不去重；保留给单页调用方）。
func Run(resp *httpx.Response, doc *htmlx.Doc, pageURL string) []Hit {
	hits := checkCookieAttrs(resp, pageURL)
	hits = append(hits, checkSessionWeak(resp, pageURL)...)
	hits = append(hits, checkCSRF(doc, pageURL)...)
	return hits
}

// RunDedup 带跨页去重的被动检查：站内重复的 cookie 与表单只保留首条。
// d 为 nil 时退化为无去重（兼容旧调用）。
func RunDedup(resp *httpx.Response, doc *htmlx.Doc, pageURL string, d *Deduper) []Hit {
	all := Run(resp, doc, pageURL)
	if d == nil {
		return all
	}
	out := make([]Hit, 0, len(all))
	for _, h := range all {
		switch h.Check {
		case "cookie-attrs":
			if d.cookies[h.Evidence] {
				continue
			}
			d.cookies[h.Evidence] = true
		case "csrf-form", "weak-session-id":
			// 去重键只认同一表单（action + 缺失事实），不带所在页面——
			// 同一登录表单在多个页面回显是同一个坑，按页面去重会重复上报。
			// weak-session-id 同理：同一会话 ID 在每个响应里都出现。
			key := h.Evidence
			if d.forms[key] {
				continue
			}
			d.forms[key] = true
		}
		out = append(out, h)
	}
	return out
}

// Hygiene 标记该检查项是否属于「配置卫生」而非漏洞验证。
//
// 判定依据：这两类检查读的是响应头/表单结构这类配置事实（Cookie 缺
// HttpOnly、表单缺 CSRF token），它们在本机 PHP 内置服务器上确实存在，
// 但不在靶场官方埋的漏洞清单里——混进 verified 会同时拉低严格口径的
// 准确率（把配置项当误报）与召回口径（分母被稀释）。因此单独成列。
func Hygiene() map[string]bool {
	return map[string]bool{"cookie-attrs": true}
}
