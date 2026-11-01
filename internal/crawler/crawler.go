// Package crawler 同域浅爬取：从首页出发广度优先收集同源页面。
//
// 遵循 robots.txt（可配置关闭）；链接按「绝对地址去重」；
// 页数 / 每页链接数 / 阶段总时长三重上限，全部来自 config.CrawlerConfig。
// 产出 Page 供引擎逐页跑指纹，链接与表单供 DAST 选择探测点。
package crawler

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// crawlDebug 环境变量 SITLENS_CRAWL_DEBUG 非空时输出爬取决策日志
// （stderr）：诊断"认证站点只爬到 1 页"类覆盖问题。
var crawlDebug = os.Getenv("SITLENS_CRAWL_DEBUG") != ""

func crawlLog(format string, a ...any) {
	if crawlDebug {
		fmt.Fprintf(os.Stderr, "[crawl] "+format+"\n", a...)
	}
}

// Page 一页采集结果。
type Page struct {
	URL        string
	FinalURL   string
	Status     int
	Headers    map[string]string
	SetCookies []string
	Body       string
	Title      string
}

// Form 暴露给引擎的表单（与 htmlx.Form 解耦，避免引擎依赖解析细节）。
type Form struct {
	Names       []string `json:"names,omitempty"`       // 可注入字段名（DAST 表单探测用，截取前 16 个）
	FileFields  []string `json:"file_fields,omitempty"` // input[type=file] 字段名（上传面探测用）
	Action      string
	Method      string
	HasPwd      bool
	LoginFields []string `json:"login_fields,omitempty"` // 登录表单的用户名/口令字段名
	Fields      int
}

// DefaultMaxDepth 默认最大爬取深度（首页深度 0；首页直达链接为 1）。
// Crawler.MaxDepth 为 0 时使用该值（additive：保持既有默认覆盖范围）。
const DefaultMaxDepth = 2

// Result 爬取汇总。
type Result struct {
	Pages         []Page
	ParamLinks    []string // 带查询参数的链接（DAST 探测点）
	AllLinks      []string // 全部同域链接
	Forms         []Form
	RobotsHonored bool
	// RobotsAll 为 true 表示 robots.txt 封禁整站（Disallow: /），
	// 爬取已按策略塌缩到入口页——用于告警而非静默。
	RobotsAll bool

	// DepthHistogram 各深度实际抓取到的页面数（additive；key = 深度，首页为 0）。
	DepthHistogram map[int]int
	// Skipped 因过滤规则被丢弃的候选链接数（additive）：非 http(s) 协议 /
	// mailto·javascript·tel / 二进制或静态资源后缀 / 深度超限 / JS 路由超上限。
	// 外域链接与重复链接不计入（它们是预期内噪音，不是被过滤的攻击面）。
	Skipped int
}

// Crawler 爬取器。
type Crawler struct {
	client       *httpx.Client
	opts         config.CrawlerConfig
	homeHost     string       // 同域判定键（hostname:有效端口，见 hostKey）
	robots       *robotsGroup // 命中的 robots 规则组（nil = 无限制）
	robotsAll    bool         // robots 是否封禁整站（Disallow: /）
	start        time.Time
	renderer     Renderer // 可选：无头渲染器（SPA 支持）
	sitemapDecls []string // robots.txt 声明的 Sitemap 地址
	pageHook     func(*httpx.Response)

	// MaxDepth 最大爬取深度（additive）：首页深度 0，首页直达链接为 1；
	// 超过该深度的候选不再跟进（仍记录在 AllLinks/ParamLinks，供 DAST/目录探测）。
	// 0 = DefaultMaxDepth（2）。
	MaxDepth int
}

// New 创建爬取器；homeURL 用于确定同域边界。
func New(client *httpx.Client, opts config.CrawlerConfig, homeURL string) *Crawler {
	if opts.MaxPages <= 0 {
		opts.MaxPages = 4
	}
	if opts.MaxLinksPerPage <= 0 {
		opts.MaxLinksPerPage = 80
	}
	host := ""
	if u, err := url.Parse(homeURL); err == nil {
		host = hostKey(u)
	}
	return &Crawler{client: client, opts: opts, homeHost: host, start: time.Now()}
}

// Renderer 无头渲染接口（SPA 支持；chromedp 实现见 internal/headless）。
type Renderer interface {
	// Render 拉取并执行页面 JS，返回渲染后的 HTML；失败返回 ok=false。
	Render(rawURL string) (renderedHTML string, ok bool)
}

// SetRenderer 挂载无头渲染器（可选）：启用后首页会额外做一次
// JS 渲染并提取渲染后 DOM 的链接/路由（SPA 支持）。
func (c *Crawler) SetRenderer(r Renderer) { c.renderer = r }

// SetPageHook 挂载「每抓取到一页」的通知回调（可选，additive）。
//
// 语义约定（引擎流式分析用）：
//   - 只做通知，无返回值、不影响爬取：不改变抓取顺序/去重/页数上限/robots
//     语义；默认 nil 时行为与不挂载逐字节一致；
//   - 串行调用：Crawl 在当前实现里是单 goroutine 顺序抓取，回调按页面
//     入队完成顺序（= Result.Pages 顺序）串行触发，回调内无需加锁；
//   - 传的是爬取器持有的响应指针：回调必须把它当**只读**数据（不得修改
//     Body/Headers，也不得在回调返回后继续持有该指针——需要留存请自行复制）；
//   - 回调耗时会计入爬取阶段（同步调用）。需要并行处理请在回调内自行派发。
func (c *Crawler) SetPageHook(fn func(*httpx.Response)) { c.pageHook = fn }

// Crawl 从首页响应开始爬取（首页已由引擎采到，直接复用不重复请求）。
// extraSeeds 为外部提供的候选入口（jsmap API 端点 / sitemap / SPA 路由），
// 仅接受同域 http(s) 地址，且同样受 MaxPages 与 robots 约束。
func (c *Crawler) Crawl(home *httpx.Response, extraSeeds []string) *Result {
	res := &Result{DepthHistogram: map[int]int{}}
	if home == nil {
		return res
	}
	if c.opts.RespectRobots {
		res.RobotsHonored = true
		c.loadRobots(home.FinalURL)
		res.RobotsAll = c.robotsAll
	}
	maxDepth := c.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}

	visited := map[string]bool{}
	queue := []crawlItem{{resp: home, depth: 0}}
	queued := map[string]bool{normalize(home.FinalURL): true}
	// JS 路由候选上限与脚本拉取预算在整次爬取内共享。
	jsRouteBudget := MaxJSRoutes
	jsScriptBudget := maxJSScriptFetches

	// 种子独立预算：API 端点/sitemap 种子不挤占普通页面预算
	//（额外允许 16 个种子页；仍受 robots/同域/总时长约束）
	seedAllowance := 0
	if len(extraSeeds) > 0 {
		seedAllowance += 16
	}
	pageCap := c.opts.MaxPages + seedAllowance

	// 外部种子（jsmap 端点等）：同域过滤后最优先入队
	for _, seed := range extraSeeds {
		abs := c.resolveURL(home.FinalURL, seed)
		if abs == "" {
			continue
		}
		res.AllLinks = append(res.AllLinks, abs)
		k := normalize(abs)
		if queued[k] || visited[k] || !c.allowed(abs) {
			continue
		}
		if len(res.Pages)+len(queue) >= pageCap {
			break
		}
		queued[k] = true
		if c.timedOut() {
			break
		}
		if next, err := c.client.GetFollow(abs); err == nil && next != nil {
			queue = append(queue, crawlItem{resp: next, depth: 1})
		}
	}

	// sitemap 种子：/sitemap.xml 与 robots.txt 声明的 Sitemap 地址
	//（sitemapindex 递归一层取子 sitemap）
	for _, abs := range c.sitemapSeeds(home.FinalURL) {
		res.AllLinks = append(res.AllLinks, abs)
		k := normalize(abs)
		if queued[k] || visited[k] || !c.allowed(abs) {
			continue
		}
		if len(res.Pages)+len(queue) >= pageCap {
			break
		}
		queued[k] = true
		if c.timedOut() {
			break
		}
		if next, err := c.client.GetFollow(abs); err == nil && next != nil {
			queue = append(queue, crawlItem{resp: next, depth: 1})
		}
	}

	for len(queue) > 0 && len(res.Pages) < pageCap {
		item := queue[0]
		queue = queue[1:]
		resp, depth := item.resp, item.depth

		key := normalize(resp.FinalURL)
		if visited[key] {
			continue
		}
		visited[key] = true
		if resp.Status >= 400 {
			continue // 与 Python 版一致：非 2xx/3xx 页不入结果、不解析链接
		}

		doc := htmlx.Parse(resp.Body)

		// SPA 无头渲染：默认仅首页一次；crawler.headless_all_pages 开启后
		// 扩展到全部已爬页（JS 路由的二级页也能贡献链接/路由，代价是
		// 每页一次浏览器渲染，页面多时显著变慢）
		var renderedHTML string
		if c.renderer != nil && (resp == home || c.opts.HeadlessAllPages) {
			if rendered, ok := c.renderer.Render(resp.FinalURL); ok {
				renderedHTML = rendered
				rd := htmlx.Parse(rendered)
				doc.Links = append(doc.Links, rd.Links...)
				doc.NextRoutes = append(doc.NextRoutes, rd.NextRoutes...)
				// 渲染后 DOM 的外链脚本/内联脚本同样参与路由提取（SPA 路由
				// 常由 JS 动态挂载，静态 HTML 里看不到）。
				doc.ScriptSrcs = append(doc.ScriptSrcs, rd.ScriptSrcs...)
			}
		}

		crawlLog("page +%s (pages=%d queue=%d links=%d forms=%d status=%d depth=%d)", resp.FinalURL, len(res.Pages), len(queue), len(doc.Links), len(doc.Forms), resp.Status, depth)
		res.Pages = append(res.Pages, Page{
			URL:        resp.FinalURL,
			FinalURL:   resp.FinalURL,
			Status:     resp.Status,
			Headers:    resp.Headers,
			SetCookies: resp.SetCookies,
			Body:       resp.Body,
			Title:      doc.Title,
		})
		res.DepthHistogram[depth]++
		// 每页通知（additive，默认 nil 无行为变化）。放在 append 之后，
		// 回调看到的页面集合与 Result.Pages 前缀一致。
		if c.pageHook != nil {
			c.pageHook(resp)
		}

		// 收集表单与带参链接（任意已访问页都算攻击面）
		base, _ := url.Parse(resp.FinalURL)
		for _, f := range doc.Forms {
			act := f.Action
			if base != nil && act != "" {
				if ru, err := base.Parse(act); err == nil {
					act = ru.String()
				}
			}
			names := make([]string, 0, len(f.Inputs))
			var files, loginF []string
			var pwd, user string
			for _, in := range f.Inputs {
				if in.Name == "" {
					continue
				}
				if in.Type == "file" {
					if len(files) < 4 {
						files = append(files, in.Name)
					}
					continue
				}
				if len(names) < 16 {
					names = append(names, in.Name)
				}
				// 登录表单字段识别：口令框 + 用户名框（供 SQLi 认证绕过探测）
				low := strings.ToLower(in.Name)
				if in.Type == "password" {
					if pwd == "" {
						pwd = in.Name
					}
				} else if user == "" && (strings.Contains(low, "user") ||
					strings.Contains(low, "login") || strings.Contains(low, "email") ||
					strings.Contains(low, "account") || low == "uname") {
					user = in.Name
				}
			}
			if pwd != "" {
				loginF = []string{pwd}
				if user != "" {
					loginF = []string{user, pwd}
				}
			}
			res.Forms = append(res.Forms, Form{
				Action: act, Method: f.Method,
				HasPwd: f.HasPassword, Fields: len(f.Inputs),
				Names: names, FileFields: files, LoginFields: loginF,
			})
		}

		// SPA/JS 路由发现（CP-01）：内联脚本 + 同域外链脚本中的路由字符串
		// → 同域候选 URL。与数据岛路由一样进入候选队列，受 MaxDepth / MaxPages
		// 约束；候选总量 ≤ MaxJSRoutes（超上限计入 Skipped）。
		jsRoutes := extractJSRoutes(strings.Join(extractInlineScripts(resp.Body), "\n"))
		if renderedHTML != "" {
			jsRoutes = append(jsRoutes, extractJSRoutes(strings.Join(extractInlineScripts(renderedHTML), "\n"))...)
		}
		srcs := append([]string{}, doc.ScriptSrcs...)
		srcs = append(srcs, extractScriptSrcs(resp.Body)...)
		if renderedHTML != "" {
			srcs = append(srcs, extractScriptSrcs(renderedHTML)...)
		}
		jsRoutes = append(jsRoutes, c.fetchScriptRoutes(srcs, base, &jsScriptBudget)...)
		for _, route := range jsRoutes {
			if jsRouteBudget <= 0 {
				res.Skipped++
				continue
			}
			abs, filtered := c.resolve(base, route)
			if abs == "" {
				if filtered {
					res.Skipped++
				}
				continue
			}
			jsRouteBudget--
			res.AllLinks = append(res.AllLinks, abs)
			if strings.Contains(abs, "?") {
				res.ParamLinks = append(res.ParamLinks, abs)
			}
			k := normalize(abs)
			if queued[k] || visited[k] || !c.allowed(abs) {
				continue
			}
			childDepth := depth + 1
			if childDepth > maxDepth {
				res.Skipped++
				continue
			}
			if len(res.Pages)+len(queue) >= c.opts.MaxPages {
				continue
			}
			queued[k] = true
			if c.timedOut() {
				continue
			}
			if next, err := c.client.GetFollow(abs); err == nil && next != nil {
				queue = append(queue, crawlItem{resp: next, depth: childDepth})
			}
		}

		// SPA 数据岛路由：作为候选页入队（不受链接预算限制，受页数上限约束）
		for _, route := range doc.NextRoutes {
			abs, filtered := c.resolve(base, route)
			if abs == "" {
				if filtered {
					res.Skipped++
				}
				continue
			}
			res.AllLinks = append(res.AllLinks, abs)
			k := normalize(abs)
			if queued[k] || visited[k] || !c.allowed(abs) {
				continue
			}
			childDepth := depth + 1
			if childDepth > maxDepth {
				res.Skipped++
				continue
			}
			if len(res.Pages)+len(queue) >= c.opts.MaxPages {
				continue
			}
			queued[k] = true
			if c.timedOut() {
				continue
			}
			if next, err := c.client.GetFollow(abs); err == nil && next != nil {
				queue = append(queue, crawlItem{resp: next, depth: childDepth})
			}
		}

		// 链接解析：同域 + http(s) 才入队
		budget := c.opts.MaxLinksPerPage
		childDepth := depth + 1
		for _, href := range doc.Links {
			if budget <= 0 {
				break
			}
			abs, filtered := c.resolve(base, href)
			if abs == "" {
				if filtered {
					res.Skipped++
				}
				continue
			}
			res.AllLinks = append(res.AllLinks, abs)
			if strings.Contains(abs, "?") {
				res.ParamLinks = append(res.ParamLinks, abs)
			}
			budget--
			k := normalize(abs)
			if queued[k] || visited[k] || !c.allowed(abs) {
				crawlLog("link skip %s (queued=%v visited=%v allowed=%v)", abs, queued[k], visited[k], c.allowed(abs))
				continue
			}
			if childDepth > maxDepth {
				res.Skipped++
				continue
			}
			if len(res.Pages)+len(queue) >= c.opts.MaxPages {
				crawlLog("link cap-skip %s", abs)
				continue
			}
			queued[k] = true
			if c.timedOut() {
				continue // 阶段超时：不再抓新页，已抓到的照常处理
			}
			next, err := c.client.GetFollow(abs)
			if err != nil || next == nil {
				continue
			}
			queue = append(queue, crawlItem{resp: next, depth: childDepth})
		}
	}
	return res
}

// timedOut 阶段时长是否已用尽（TimeoutSec=0 表示不限）。
func (c *Crawler) timedOut() bool {
	return c.opts.TimeoutSec > 0 && time.Since(c.start) > time.Duration(c.opts.TimeoutSec)*time.Second
}

// crawlItem 候选页 + 其深度（首页 0；链接/路由每层 +1）。
type crawlItem struct {
	resp  *httpx.Response
	depth int
}

// resolve 以 base 解析相对链接，返回同域 http(s) 绝对地址（已规范化）。
//
// filtered 表示该 href 是「被规则过滤」的候选（非 http(s) 协议、mailto/
// javascript/tel、二进制/静态资源后缀、含控制字符等），供调用方计入
// Result.Skipped；外域链接与纯锚点返回 filtered=false（预期噪音，不计）。
func (c *Crawler) resolve(base *url.URL, href string) (abs string, filtered bool) {
	if base == nil {
		return "", false
	}
	raw := strings.TrimSpace(href)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", false // 空 href / 同页锚点
	}
	if strings.ContainsAny(raw, "\x00\r\n\t") {
		return "", true
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", true
	}
	// 无 scheme/host/path/query、只有 fragment 的相对锚点：不算被过滤。
	if ref.Scheme == "" && ref.Host == "" && ref.Path == "" && ref.RawQuery == "" {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	scheme := strings.ToLower(resolved.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", true // javascript:/mailto:/tel:/data: 等非页面协议
	}
	if resolved.Host == "" || hostKey(resolved) != c.homeHost {
		return "", false // 外域：与 Python 版一致，直接忽略且不告警
	}
	resolved.Scheme = scheme
	canonicalizeURL(resolved)
	if isStaticAssetPath(resolved.Path) {
		return "", true
	}
	return resolved.String(), false
}

// allowed robots.txt 放行判定：按命中的 UA 组做 Allow/Disallow
// 最长匹配。未开启遵循、无规则组、或解析失败均放行。
func (c *Crawler) allowed(raw string) bool {
	if !c.opts.RespectRobots || c.robots == nil {
		return true
	}
	return c.robots.allowedBy(pathOf(raw))
}

// loadRobotsAgent 拉取并解析 robots.txt：选中适用于 agent 的规则组，
// 同时收集 Sitemap 声明供种子提取。拉取失败视为无限制。
// agent 为空时用 "*"（不针对特定爬虫名做精确匹配）。
func (c *Crawler) loadRobotsAgent(homeURL, agent string) {
	u, err := url.Parse(homeURL)
	if err != nil {
		return
	}
	rb := u.Scheme + "://" + u.Host + "/robots.txt"
	resp, err := c.client.GetDirect(rb)
	if err != nil || resp == nil || resp.Status != 200 {
		return
	}
	f := parseRobots(resp.Body)
	c.sitemapDecls = append(c.sitemapDecls, f.sitemaps...)
	c.robots = f.selectGroup(agent)
	if c.robots == nil {
		return
	}
	// 全站封禁（Disallow: /）会让爬取塌缩到首页——这是常见且静默的
	// 覆盖缺口，明确记标记并告警，避免"扫了个空站却毫无提示"。
	if !c.robots.allowedBy("/") {
		c.robotsAll = true
		crawlLog("robots: User-agent group DISALLOWS '/' — crawling will collapse to the entry page (set crawler.respect_robots=false to override)")
	}
}

// loadRobots 兼容旧签名：以 "*" 组加载。
func (c *Crawler) loadRobots(homeURL string) { c.loadRobotsAgent(homeURL, "*") }

var locRe = regexp.MustCompile(`(?is)<loc>\s*([^<]+?)\s*</loc>`)

// sitemapSeeds 收集 sitemap 种子：robots Sitemap 声明（若有）+ 默认
// /sitemap.xml，解析其中 <loc> 条目，仅保留同域地址，条目数封顶。
func (c *Crawler) sitemapSeeds(homeURL string) []string {
	u, err := url.Parse(homeURL)
	if err != nil {
		return nil
	}
	root := u.Scheme + "://" + u.Host
	candidates := append([]string{}, c.sitemapDecls...)
	candidates = append(candidates, root+"/sitemap.xml")

	var out []string
	seen := map[string]bool{}
	budget := c.opts.MaxPages * 4 // 种子池上限：页数上限的 4 倍

	// fetchSitemap 拉取一个清单地址返回 URL 条目；
	// sitemapindex（嵌套 sitemap）递归一层展开子清单（depth 防循环）。
	var fetchSitemap func(sm string, depth int) []string
	fetchSitemap = func(sm string, depth int) []string {
		resp, err := c.client.GetDirect(sm)
		if err != nil || resp == nil || resp.Status != 200 {
			return nil
		}
		var locs []string
		for _, m := range locRe.FindAllStringSubmatch(resp.Body, -1) {
			abs := c.resolveRoot(m[1], root)
			if abs == "" || seen[abs] {
				continue
			}
			seen[abs] = true
			locs = append(locs, abs)
		}
		if strings.Contains(resp.Body, "<sitemapindex") && depth < 1 {
			var sub []string
			for _, loc := range locs {
				budget--
				if budget <= 0 {
					break
				}
				sub = append(sub, fetchSitemap(loc, depth+1)...)
			}
			return sub
		}
		return locs
	}

	for _, sm := range candidates {
		if budget <= 0 {
			break
		}
		for _, u := range fetchSitemap(sm, 0) {
			out = append(out, u)
			budget--
			if budget <= 0 {
				break
			}
		}
	}
	return out
}

// resolveRoot 以站点根解析 sitemap 中的地址（可能为绝对或相对路径），
// 仅保留同域 http(s) 地址。
func (c *Crawler) resolveRoot(p, root string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	ref, err := url.Parse(p)
	if err != nil {
		return ""
	}
	base, berr := url.Parse(root + "/")
	if berr != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	scheme := strings.ToLower(abs.Scheme)
	if scheme != "http" && scheme != "https" || strings.ToLower(abs.Host) == "" || hostKey(abs) != c.homeHost {
		return ""
	}
	abs.Scheme = scheme
	abs.Fragment = ""
	abs.RawQuery = "" // sitemap 条目通常无查询串；去掉以防重复种子
	if isStaticAssetPath(abs.Path) {
		return "" // sitemap 里的图片/静态资源不是页面
	}
	canonicalizeURL(abs)
	return abs.String()
}

// resolveURL 以 homeURL 为基解析外部种子地址，仅保留同域 http(s)。
func (c *Crawler) resolveURL(homeURL, seed string) string {
	base, err := url.Parse(homeURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(seed))
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	scheme := strings.ToLower(abs.Scheme)
	if scheme != "http" && scheme != "https" || abs.Host == "" || hostKey(abs) != c.homeHost {
		return ""
	}
	abs.Scheme = scheme
	canonicalizeURL(abs)
	if isStaticAssetPath(abs.Path) {
		return ""
	}
	return abs.String()
}
