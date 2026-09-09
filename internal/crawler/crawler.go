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
	Names  []string `json:"names,omitempty"` // 可注入字段名（DAST 表单探测用，截取前 16 个）
	Action string
	Method string
	HasPwd bool
	Fields int
}

// Result 爬取汇总。
type Result struct {
	Pages         []Page
	ParamLinks    []string // 带查询参数的链接（DAST 探测点）
	AllLinks      []string // 全部同域链接
	Forms         []Form
	RobotsHonored bool
}

// Crawler 爬取器。
type Crawler struct {
	client       *httpx.Client
	opts         config.CrawlerConfig
	homeHost     string
	disallow     []string // robots Disallow 前缀
	start        time.Time
	renderer     Renderer // 可选：无头渲染器（SPA 支持）
	sitemapDecls []string // robots.txt 声明的 Sitemap 地址
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
		host = strings.ToLower(u.Host)
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

// Crawl 从首页响应开始爬取（首页已由引擎采到，直接复用不重复请求）。
// extraSeeds 为外部提供的候选入口（jsmap API 端点 / sitemap / SPA 路由），
// 仅接受同域 http(s) 地址，且同样受 MaxPages 与 robots 约束。
func (c *Crawler) Crawl(home *httpx.Response, extraSeeds []string) *Result {
	res := &Result{}
	if home == nil {
		return res
	}
	if c.opts.RespectRobots {
		res.RobotsHonored = true
		c.loadRobots(home.FinalURL)
	}

	visited := map[string]bool{}
	queue := []*httpx.Response{home}
	queued := map[string]bool{normalize(home.FinalURL): true}

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
			queue = append(queue, next)
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
			queue = append(queue, next)
		}
	}

	for len(queue) > 0 && len(res.Pages) < pageCap {
		resp := queue[0]
		queue = queue[1:]

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
		if c.renderer != nil && (resp == home || c.opts.HeadlessAllPages) {
			if rendered, ok := c.renderer.Render(resp.FinalURL); ok {
				rd := htmlx.Parse(rendered)
				doc.Links = append(doc.Links, rd.Links...)
				doc.NextRoutes = append(doc.NextRoutes, rd.NextRoutes...)
			}
		}

		crawlLog("page +%s (pages=%d queue=%d links=%d forms=%d status=%d)", resp.FinalURL, len(res.Pages), len(queue), len(doc.Links), len(doc.Forms), resp.Status)
		res.Pages = append(res.Pages, Page{
			URL:        resp.FinalURL,
			FinalURL:   resp.FinalURL,
			Status:     resp.Status,
			Headers:    resp.Headers,
			SetCookies: resp.SetCookies,
			Body:       resp.Body,
			Title:      doc.Title,
		})

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
			for _, in := range f.Inputs {
				if in.Name != "" && len(names) < 16 {
					names = append(names, in.Name)
				}
			}
			res.Forms = append(res.Forms, Form{
				Action: act, Method: f.Method,
				HasPwd: f.HasPassword, Fields: len(f.Inputs),
				Names: names,
			})
		}

		// SPA 路由：数据岛提取的路径作为候选页入队（不受链接预算限制，受页数上限约束）
		for _, route := range doc.NextRoutes {
			abs := c.resolve(base, route)
			if abs == "" {
				continue
			}
			res.AllLinks = append(res.AllLinks, abs)
			k := normalize(abs)
			if queued[k] || visited[k] || !c.allowed(abs) {
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
				queue = append(queue, next)
			}
		}

		// 链接解析：同域 + http(s) 才入队
		budget := c.opts.MaxLinksPerPage
		for _, href := range doc.Links {
			if budget <= 0 {
				break
			}
			abs := c.resolve(base, href)
			if abs == "" {
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
			queue = append(queue, next)
		}
	}
	return res
}

// timedOut 阶段时长是否已用尽（TimeoutSec=0 表示不限）。
func (c *Crawler) timedOut() bool {
	return c.opts.TimeoutSec > 0 && time.Since(c.start) > time.Duration(c.opts.TimeoutSec)*time.Second
}

// resolve 以 base 解析相对链接，仅保留同域 http(s) 绝对地址。
func (c *Crawler) resolve(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if base == nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs.Host == "" || strings.ToLower(abs.Host) != c.homeHost {
		return ""
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

// normalize 去掉 fragment 与末尾斜杠差异，作为去重键。
func normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	s := u.String()
	if strings.HasSuffix(s, "/") && u.RequestURI() == "/" {
		return s
	}
	return strings.TrimSuffix(s, "/")
}

// allowed robots.txt Disallow 前缀检查。
func (c *Crawler) allowed(raw string) bool {
	if !c.opts.RespectRobots || len(c.disallow) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	for _, p := range c.disallow {
		if p == "" {
			continue
		}
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	return true
}

// loadRobots 拉取并解析 robots.txt 的 User-agent: * 段 Disallow 规则，
// 同时收集 Sitemap: 声明行供种子提取。拉取失败视为无限制。
func (c *Crawler) loadRobots(homeURL string) {
	u, err := url.Parse(homeURL)
	if err != nil {
		return
	}
	rb := u.Scheme + "://" + u.Host + "/robots.txt"
	resp, err := c.client.GetDirect(rb)
	if err != nil || resp == nil || resp.Status != 200 {
		return
	}
	inStar := false
	for _, line := range strings.Split(resp.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "user-agent":
			inStar = val == "*"
		case "disallow":
			if inStar {
				c.disallow = append(c.disallow, val)
			}
		case "sitemap":
			if strings.HasPrefix(val, "http") {
				c.sitemapDecls = append(c.sitemapDecls, val)
			}
		}
	}
}

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
	if strings.ToLower(abs.Host) != c.homeHost {
		return ""
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	abs.RawQuery = "" // sitemap 条目通常无查询串；去掉以防重复种子
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
	if strings.ToLower(abs.Host) != c.homeHost {
		return ""
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}
