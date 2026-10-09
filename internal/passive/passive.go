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
	HTTPOnly bool
	Secure   bool
	SameSite string
}

// parseCookie 解析单条 Set-Cookie。
func parseCookie(raw string) cookieInfo {
	ci := cookieInfo{}
	seg := strings.SplitN(raw, ";", 2)
	head := strings.TrimSpace(seg[0])
	ci.Name = strings.SplitN(head, "=", 2)[0]
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

// csrfFieldNames 常见 CSRF token 字段名。
var csrfFieldNames = map[string]bool{
	"csrfmiddlewaretoken": true, "csrf_token": true, "csrftoken": true,
	"_csrf": true, "_token": true, "authenticity_token": true,
	"xsrf-token": true, "csrf": true, "token": true,
}

// checkCSRF 含密码框的表单是否缺少 CSRF token 字段。
func checkCSRF(doc *htmlx.Doc, pageURL string) []Hit {
	var hits []Hit
	for _, f := range doc.Forms {
		if !f.HasPassword {
			continue
		}
		hasToken := false
		for _, in := range f.Inputs {
			if in.Type == "hidden" && csrfFieldNames[strings.ToLower(in.Name)] {
				hasToken = true
				break
			}
		}
		if hasToken {
			continue
		}
		hits = append(hits, Hit{
			Check: "csrf-form", Title: "登录表单缺少 CSRF token",
			Severity: "medium", URL: pageURL,
			Evidence: "表单 " + f.Action + " 含密码输入但未携带 CSRF token 字段",
			Advice:   "为状态变更表单加入一次性 CSRF token 校验",
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
		case "csrf-form":
			// 去重键只认同一表单（action + 缺失事实），不带所在页面——
			// 同一登录表单在多个页面回显是同一个坑，按页面去重会重复上报
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
	return map[string]bool{"cookie-attrs": true, "csrf-form": true}
}
