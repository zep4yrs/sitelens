package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

// 本文件：SPA / JS 路由发现（CP-01）。
//
// 从页面 HTML 的内联 <script> 与外链同域脚本中提取路由字符串
// （形如 path:"/x"、"/api/x"、router.push('/x')、href:'/y'），
// 生成同域候选 URL，交给 Crawl 按深度/页数预算入队。
//
// 约束：只做字符串提取，不执行 JS；外链脚本只取同域；单次爬取最多
// MaxJSRoutes 个候选（去重后）；外链脚本拉取有数量与体积上限，避免拖慢爬取。

const (
	// MaxJSRoutes 单次爬取最多收集的 JS 路由候选数（去重后，additive 上限）。
	MaxJSRoutes = 200
	// maxJSScriptFetches 单次爬取最多拉取的外链 JS 文件数（成本上限）。
	maxJSScriptFetches = 8
	// maxJSScriptBytes 单个外链 JS 的解析上限（超出部分截断，不整包读入）。
	maxJSScriptBytes = 512 << 10
)

var (
	// inlineScriptRe 内联脚本正文（非贪婪；未闭合脚本兜底到文末）。
	inlineScriptRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)(?:</script\s*>|$)`)
	// scriptSrcRe 外链脚本地址（双/单引号）。
	scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)
	// routeStringRe 引号包裹的绝对路径字符串：/x、/api/x、/user/{id}、/user/:id。
	routeStringRe = regexp.MustCompile("[\"'`](/[A-Za-z0-9._~!$&'()*+,;=:@%{}\\-]*(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}\\-]*)*)[\"'`]")
)

// extractInlineScripts 返回 HTML 中全部内联 <script> 正文。
func extractInlineScripts(html string) []string {
	if html == "" {
		return nil
	}
	ms := inlineScriptRe.FindAllStringSubmatch(html, -1)
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
			out = append(out, m[1])
		}
	}
	return out
}

// extractScriptSrcs 返回 HTML 中全部 <script src> 地址（htmlx 未覆盖时兜底用）。
func extractScriptSrcs(html string) []string {
	if html == "" {
		return nil
	}
	ms := scriptSrcRe.FindAllStringSubmatch(html, -1)
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if len(m) > 1 {
			if v := strings.TrimSpace(m[1]); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// extractJSRoutes 从 JS 文本中提取形如 "/x" 的路由字符串（按出现顺序去重）。
// 过滤明显非路由的字符串（协议相对 //、注释 /*、模板占位 ${}、静态资源后缀、
// 含空白/反斜杠/尖括号的片段），单次结果不超过 MaxJSRoutes。
func extractJSRoutes(js string) []string {
	if js == "" {
		return nil
	}
	ms := routeStringRe.FindAllStringSubmatch(js, -1)
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	seen := make(map[string]bool, len(ms))
	for _, m := range ms {
		if len(m) < 2 {
			continue
		}
		route := m[1]
		if !validJSRoute(route) || seen[route] {
			continue
		}
		seen[route] = true
		out = append(out, route)
		if len(out) >= MaxJSRoutes {
			break
		}
	}
	return out
}

// validJSRoute 路由字符串过滤（宁少报：只收看起来像站点路径的绝对路径）。
func validJSRoute(route string) bool {
	if len(route) < 2 || len(route) > 300 {
		return false
	}
	if !strings.HasPrefix(route, "/") || strings.HasPrefix(route, "//") {
		return false // 空路径、协议相对地址
	}
	if strings.HasPrefix(route, "/*") || strings.HasPrefix(route, "/<") {
		return false // 注释/标签噪音
	}
	if route == "/" {
		return false
	}
	if strings.ContainsAny(route, "\\ \t\r\n<>\"'`${}") {
		return false
	}
	if isStaticAssetPath(route) {
		return false // /logo.png 之类的静态资源不是路由页
	}
	return true
}

// resolveResource 解析「资源类」地址（外链脚本）：只做同域/协议/规范化校验，
// 不套用静态资源后缀过滤（.js 正是我们要拉的资源）。
func (c *Crawler) resolveResource(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || base == nil {
		return ""
	}
	if strings.ContainsAny(href, "\x00\r\n") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	scheme := strings.ToLower(abs.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	if abs.Host == "" || hostKey(abs) != c.homeHost {
		return ""
	}
	abs.Scheme = scheme
	canonicalizeURL(abs)
	return abs.String()
}

// fetchScriptRoutes 拉取同域外链脚本并提取路由（budget 为剩余拉取次数，
// 由调用方在整次爬取内共享；超出 budget 的脚本不再拉取）。
// 单脚本解析上限 maxJSScriptBytes；失败/超时静默跳过（不影响爬取主流程）。
func (c *Crawler) fetchScriptRoutes(srcs []string, base *url.URL, budget *int) []string {
	if len(srcs) == 0 || budget == nil || *budget <= 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool, len(srcs))
	for _, src := range srcs {
		if *budget <= 0 || c.timedOut() {
			break
		}
		abs := c.resolveResource(base, src)
		if abs == "" || seen[abs] {
			continue
		}
		seen[abs] = true
		*budget--
		resp, err := c.client.GetDirect(abs)
		if err != nil || resp == nil || resp.Status >= 400 {
			continue
		}
		body := resp.Body
		if len(body) > maxJSScriptBytes {
			body = body[:maxJSScriptBytes]
		}
		out = append(out, extractJSRoutes(body)...)
		if len(out) >= MaxJSRoutes {
			break
		}
	}
	return out
}
