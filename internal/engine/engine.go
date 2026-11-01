package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/authn"
	"cnb.cool/feng-qiao/sitelens/internal/chain"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/crawler"
	"cnb.cool/feng-qiao/sitelens/internal/cwe"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/headless"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/jsmap"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
	"cnb.cool/feng-qiao/sitelens/internal/passive"
	"cnb.cool/feng-qiao/sitelens/internal/resource"
	"cnb.cool/feng-qiao/sitelens/internal/security"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Options 每次扫描可单独指定的开关（对齐 /api/scan 平铺 payload）。
type Options struct {
	Deep          bool                    // 同域浅爬取
	ActiveFP      bool                    // FingerDir 主动路径指纹
	DirScan       bool                    // 目录探测
	DirBypass     bool                    // 403 绕过重试
	Subdomain     bool                    // 子域名枚举
	ServiceProbe  bool                    // 端口服务识别
	BrowserUA     bool                    // 浏览器 UA
	WeakAudit     bool                    // 敏感信息审计
	Webshell      bool                    // WebShell 探测
	Takeover      bool                    // 子域名接管探测（需先开 Subdomain 产出候选）
	Netsec        bool                    // TLS/DNS 安全检测
	DAST          bool                    // 参数级注入探测
	Exploit       bool                    // 利用级无害验证请求开关（总闸：exploit.enabled / 设置页）
	Passive       bool                    // 被动安全检测
	JSMap         bool                    // JS 攻击面提取（独立于 DAST 可开：bundle 端点/SourceMap，只读）
	NetProto      bool                    // 协议模板检测（不开端口服务识别时仅跑 dns 类模板）
	Checks        string                  // none | core | all
	NucleiCap     int                     // Nuclei 单次模板上限（0 = 用配置默认 nuclei_cap）
	DirMaxPaths   int                     // 目录探测字典上限（0 = 用配置默认）
	DirFullWords  bool                    // 目录探测用全量词表（3.2k+6k 并集；大词表档位置位）
	ShellMaxPaths int                     // WebShell 字典上限（0 = 用配置默认）
	SubMaxWords   int                     // 子域名字典词数上限（0 = 用配置默认）
	ProbePorts    []int                   // 端口探测端口集（nil = 用配置/默认常见端口集）
	AuthCookie    string                  // 授权扫描 Cookie
	Graph         bool                    // 收集结构化事实图（4.0 P2，默认关；关时与 3.0 行为一致）
	OnEvent       func(kind, text string) // 实时事件回调（阶段/命中/认证，nil = 不回调）
	OnLive        func(LiveStats)         // 实时统计回调（请求/页面/拦截/速率，节流 ~250ms，nil = 不回调）
	Preflight     *Preflight              // 可选：扫描前预检结果；命中且未过期时复用为首页响应（不重复请求）
}

// DefaultOptions 对齐 Python 默认：deep 开、checks 关、其余关。
func DefaultOptions() Options { return Options{Deep: true, Checks: "none"} }

// progress 阶段进度回调（percent 0-100）。
type progress func(percent int, msg string)

// Engine 一次完整扫描的编排器。
// matcher/kb 支持运行期热替换（SetMatcher/SetKB）：换枪为指针原子语义，
// 进行中的扫描持旧快照不受影响，新扫描取新数据。
type Engine struct {
	cfg         *config.Config
	dataMu      sync.Mutex
	matcher     *sitelens.Matcher
	kb          *intel.KB
	activeScans int              // 活跃扫描计数（>0 时 ReleaseIntel 跳过释放，避免与快照 Match 竞争）
	nucleiLRU   map[string]int64 // Nuclei 模板 LRU 调度表（持久化，重启不丢轮转进度）

	// 5.0 ML 资产惰性加载（首次预测才读 coef，cve-tech 94MB）。
	// 独立于 dataMu：模型资产不参与换枪一致性语义。
	mlMu     sync.Mutex
	mlAssets *ml.Assets
	mlDead   bool // 加载失败标记：本进程内静默禁用（防反复重读 94MB）

	// sev-prior ONNX 打分器（L3 阶段 B，§10.8）：一次尝试，失败（未启用/
	// 无 onnx 构建标签/资产或 DLL 缺失）后带原因降级 NVD 先验，不再重试。
	mlSev       *ml.SevScorer
	mlSevTried  bool
	mlSevReason string
}

// New 创建引擎。matcher / kb 可为 nil（对应能力降级跳过，不阻塞扫描）。
func New(cfg *config.Config, matcher *sitelens.Matcher, kb *intel.KB) *Engine {
	if cfg == nil {
		cfg = config.Default()
	}
	target.SetAllowPrivate(cfg.Target.AllowPrivate) // 本机靶场/授权内网开关（默认 false）
	e := &Engine{cfg: cfg}
	e.SetMatcher(matcher)
	e.SetKB(kb)
	e.loadNucleiLRU()
	return e
}

// SetMatcher 热替换指纹库（nil = 空 matcher，识别降级为无命中）。
func (e *Engine) SetMatcher(m *sitelens.Matcher) {
	e.dataMu.Lock()
	defer e.dataMu.Unlock()
	if m == nil {
		m = &sitelens.Matcher{}
	}
	e.matcher = m
}

// SetKB 热替换漏洞情报知识库（nil = 关闭情报关联）。
func (e *Engine) SetKB(kb *intel.KB) {
	e.dataMu.Lock()
	defer e.dataMu.Unlock()
	e.kb = kb
}

// snapshot 取本次扫描全程使用的数据快照（保证单次扫描内一致性）。
func (e *Engine) snapshot() (*sitelens.Matcher, *intel.KB) {
	e.dataMu.Lock()
	defer e.dataMu.Unlock()
	return e.matcher, e.kb
}

// Scan 执行扫描，异常统一进 Result.Error（消息可直接展示）。
// cancel 非空时在阶段边界与 check 循环内轮询，返回 true 即尽快终止（局部结果仍返回）。
func (e *Engine) Scan(rawURL string, opts Options, onProgress progress, cancel func() bool) *Result {
	// 活跃扫描计数：增减均持 dataMu，与 ReleaseIntel 的「检查+释放」互斥，
	// 杜绝计数为 0 判定后、释放完成前新扫描取到快照的窗口。
	e.dataMu.Lock()
	e.activeScans++
	e.dataMu.Unlock()
	defer func() {
		e.dataMu.Lock()
		e.activeScans--
		e.dataMu.Unlock()
	}()
	if onProgress == nil {
		onProgress = func(int, string) {}
	}
	cancelled := func() bool { return cancel != nil && cancel() }
	start := time.Now()
	res := &Result{
		ScannedAt:       time.Now().Format("2006-01-02 15:04:05"),
		Technologies:    []Tech{},
		Vulnerabilities: []intel.Finding{},
		Verified:        []map[string]any{},
		Pages:           []PageInfo{},
		Extras:          map[string]any{},
	}
	// 请求账本（client 建好后赋值；finish 时写入 result.Diagnostics）。
	var diag *diagRecorder
	var live *liveTracker
	finish := func() {
		// 毫秒精度（原 10ms 舍入会把 <5ms 的扫描记成 0.00）
		res.Duration = float64(int(time.Since(start).Seconds()*1000)) / 1000
		if live != nil {
			live.done()
		}
		if diag != nil {
			res.Diagnostics = diag.result(start)
		}
	}

	// 4.0 P2：结构化事实收集器（仅在 opts.Graph 时创建，默认不影响 3.0 行为）
	var col *collector
	if opts.Graph {
		col = newCollector(res.ScannedAt)
	}

	// 4.0 Track A / A7：内存预算器——超限逐级降档（爬取页数减半 → nuclei 减半 →
	// 跳过主动模块），全部降档动作记入 Extras["budget"] 并推事件流（明示降级）。
	maxMemMB := float64(e.cfg.Scan.MaxMemoryMB)
	var budgetDegrades []string
	overBudget := func() bool {
		return maxMemMB > 0 && resource.HeapAllocMB() > maxMemMB
	}
	noteBudget := func(what string) {
		budgetDegrades = append(budgetDegrades, what)
	}

	// 1) 校验（含 SSRF 防护）
	scheme, host, port, err := target.Validate(rawURL, e.cfg.Scan.Resolve)
	if err != nil {
		res.Error = err.Error()
		finish()
		return res
	}
	if !target.Allowed(host, e.cfg.Scan.AllowHosts) {
		res.Error = "目标不在 allow_hosts 授权白名单：" + host
		finish()
		return res
	}
	baseURL := scheme + "://" + host
	if port > 0 && !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		baseURL = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	// 种子 URL 的路径与查询串必须保留：靶场入口常是 /Less-1/?id=1 这类
	// 带参页面，丢弃路径/query 会退化成只扫站点根，参数级攻击面整块丢失。
	seedURL := baseURL
	seedHasQuery := false
	if pu, perr := url.Parse(strings.TrimSpace(rawURL)); perr == nil && pu.Path != "" && pu.Path != "/" {
		seedURL = baseURL + pu.Path
		if pu.RawQuery != "" {
			seedURL += "?" + pu.RawQuery
			seedHasQuery = true
		}
	} else if perr == nil && pu.RawQuery != "" {
		seedURL = baseURL + "?" + pu.RawQuery
		seedHasQuery = true
	}
	res.URL, res.Host = baseURL, host
	onProgress(5, "校验目标："+seedURL)

	client := e.newClient(opts)
	authDone := false
	// 效率轮 E2：请求账本 / 只读 GET 复用 / WAF 拦截隔离。
	// diag：阶段级请求数/耗时/去重命中/blocked（additive 诊断输出）。
	// roCache：单次扫描内复用的只读页面响应（首页/种子/爬取页；DAST payload
	// URL 不会命中，也不会写入）。blocked：拦截响应不进任何判定。
	blocked := newBlockedTracker()
	roCache := newReadOnlyCache()
	diag = newDiagRecorder(client, blocked, opts.Deep, e.cfg.Scan.RateMode, e.cfg.Scan.RateMaxRPS)
	// 实时统计：请求数/拦截数取自 client.Stats()，页面数由爬虫钩子累加；
	// 节流推送给服务端 job（前端实时面板消费），不参与任何判定。
	live = newLiveTracker(func() httpx.Stats { return client.Stats() }, opts.OnLive)
	if live != nil {
		live.setPhase("prepare", "准备")
	}
	// 实时事件流：阶段/命中/认证/绕过 统一经此推给 job 事件环
	emit := func(kind, text string) {
		if opts.OnEvent != nil {
			opts.OnEvent(kind, text)
		}
	}

	// 认证深化：配置了登录流则以凭证登录，捕获的会话 Cookie 供
	// 整次扫描（爬虫/DAST/目录探测）复用；用户显式给的 Cookie 优先
	if e.cfg.Auth.LoginURL != "" && opts.AuthCookie == "" {
		dt, ds := diag.begin()
		onProgress(8, "认证登录…")
		emit("auth", "登录中："+e.cfg.Auth.LoginURL)
		if cookie, ok, msg := authn.Login(client, e.cfg.Auth); ok {
			client.SetCookie(cookie)
			authDone = true
			onProgress(9, "认证成功："+msg)
			emit("auth", "登录成功（"+msg+"），后续扫描带认证态")
		} else {
			onProgress(9, "认证未确认："+msg)
			emit("auth", "登录未确认："+msg)
		}
		diag.end("auth", dt, ds, 0)
	}

	// 2) 采集首页（带种子路径/query 时采集该页面本身）
	dtHome, dsHome := diag.begin()
	live.setPhase("home", "首页采集")
	t0 := time.Now()
	var home *httpx.Response
	var ferr error
	reused := false
	if pf := opts.Preflight; pf.ValidFor(seedURL, opts.AuthCookie, time.Now()) {
		home = pf.Response()
		reused = true
		diag.preflightReused = true
	} else {
		home, ferr = client.GetFollow(seedURL)
	}
	live.touch()
	rtMS := time.Since(t0).Milliseconds()
	if reused && opts.Preflight != nil {
		rtMS = opts.Preflight.ResponseMS
	}
	if ferr != nil || home == nil {
		// 底层错误带出（refused/timeout/SSRF 拒绝原因一目了然）
		res.Error = "连接失败：" + seedURL
		if ferr != nil {
			res.Error += "（" + ferr.Error() + "）"
		}
		diag.end("home", dtHome, dsHome, 0)
		finish()
		return res
	}
	// 被 WAF/限流拦截的首页：不参与任何判定，直接终止并给出可读原因
	// （挑战页/429 的正文不是目标站真实内容，往下扫只会产生假阳性/假阴性）。
	if blocked.note(home) {
		res.Error = "目标被 WAF/限流拦截（" + home.BlockReason + "），响应不参与判定"
		diag.end("home", dtHome, dsHome, 0)
		finish()
		return res
	}
	if home.Status >= 400 {
		res.Error = fmt.Sprintf("目标返回 HTTP %d", home.Status)
		diag.end("home", dtHome, dsHome, 0)
		finish()
		return res
	}
	onProgress(25, fmt.Sprintf("已采集首页（%d）", home.Status))
	roCache.put(home) // 首页/种子页响应供后续只读复用（DAST benign 基线）
	diag.end("home", dtHome, dsHome, 0)

	res.IP = lookupIP(host)
	doc := htmlx.Parse(home.Body)
	res.Title = doc.Title
	res.Status = home.Status
	res.ResponseTimeMS = int(rtMS)
	res.Pages = append(res.Pages, PageInfo{URL: home.FinalURL, Status: home.Status})

	// 数据快照：本次扫描全程使用同一份 matcher/kb（热替换不影响进行中的扫描）
	matcher, kb := e.snapshot()

	// 效率轮 E2：逐页流式分析。每页一被抓到就启动该页指纹匹配/被动检查，
	// 与限速等待窗口重叠，不等全站爬完。favicon 指纹整站只取一次（提前到
	// 流水线启动前，保证 worker 拿到同一份 hash）。
	favHash := int64(0)
	if matcher != nil {
		favHash = sitelens.FaviconHashOf(client, baseURL)
	}
	stream := newPageStream(matcher, favHash, opts.Passive, e.cfg.Checks.Workers)
	stream.push(home, doc) // 首页先入流水线（不重复抓取）

	acc := newTechAcc()
	dastLinks := []string{}               // 爬取阶段收集的带参链接（DAST 探测点）
	allLinks := []string{}                // 爬取阶段收集的全部同域链接（目录探测端点扩展用）
	pageURLs := []string{}                // 实际采集到的页面 URL（端点发现的来源回链用）
	apiCandidates := []string{}           // API 风格页面 URL（未授权/IDOR 探测点）
	var dastFormTargets []dast.FormTarget // 爬取阶段收集的表单（DAST 表单探测点）
	var loginForms []loginFormEntry       // 含密码框的表单页（弱口令审计入口）

	// 首页表单/链接即刻采集（任何档位都做）：首页就是 DVWA 登录页与
	// SQLi/XSS 模块入口，deep=false 时不采集则整站攻击面不可见。
	collectHomeFormTargets(doc, home.FinalURL, &dastLinks, &dastFormTargets, &loginForms)
	// 种子带参页面本身即 DAST 探测点：单入口深扫（如 /item?id=1）时
	// 该参数必须进入探测队列，否则 URL 参数注入整块测不到。
	if seedHasQuery {
		dastLinks = append(dastLinks, seedURL)
	}

	// 3) 同域浅爬取（DAST 或 JS 端点开启时 jsmap 前置：API 端点回灌爬虫种子）
	var jsEndpoints []jsmap.Endpoint
	if opts.DAST || opts.JSMap {
		dtJS, dsJS := diag.begin()
		onProgress(38, "JS 攻击面提取…")
		live.setPhase("jsmap", "JS 攻击面")
		var jsFind []jsmap.Finding
		// jsmap 走拦截隔离 fetcher：WAF 挑战页正文不参与 SourceMap/API 端点提取。
		jsFind, jsEndpoints = jsmap.Run(blockedAwareFetcher{c: client, blocked: blocked, live: live}, baseURL, doc, 4)
		for _, f := range jsFind {
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "js",
			}))
			if col != nil {
				col.addJSFinding(f)
			}
		}
		if len(jsEndpoints) > 0 {
			res.Extras["js"] = jsEndpoints
		}
		if col != nil {
			col.captureEntryPoints(nil, nil, jsEndpoints)
		}
		diag.end("jsmap", dtJS, dsJS, 0)
	}
	if opts.Deep {
		dtCrawl, dsCrawl := diag.begin()
		onProgress(40, "同域浅爬取…")
		live.setPhase("crawl", "同域爬取")
		cc := e.cfg.Crawler
		if overBudget() {
			cc.MaxPages /= 2
			noteBudget("爬取页数减半（" + fmt.Sprint(cc.MaxPages) + "）")
		}
		c := crawler.New(client, cc, baseURL)
		c.MaxDepth = e.cfg.Crawler.MaxDepth
		if e.cfg.Crawler.Headless {
			c.SetRenderer(chromeRenderer{headless.NewChrome(time.Duration(e.cfg.Crawler.HeadlessTimeoutSec)*time.Second, e.cfg.Crawler.HeadlessExecPath)})
		}
		var seeds []string
		for _, ep := range jsEndpoints {
			if ep.Kind == "api" {
				seeds = append(seeds, ep.Endpoint)
			}
		}
		// 逐页流式：爬取过程中每拿到一页立即启动该页指纹/被动分析；被 WAF/
		// 限流拦截的页面不进分析集（不参与任何判定），只登记以便命中过滤。
		c.SetPageHook(func(p *httpx.Response) {
			if p == nil || p == home { // 首页已在爬取前入流水线
				return
			}
			if normalizeKey(p.FinalURL) == normalizeKey(home.FinalURL) {
				return // 重定向回首页等重复页
			}
			if blocked.note(p) {
				return
			}
			roCache.put(p)
			stream.push(p, nil)
			live.notePage()
			live.touch()
		})
		cr := c.Crawl(home, seeds)
		if cr.RobotsAll {
			// robots 封禁整站（Disallow: /）：爬取已塌缩到入口页。显式提示，
			// 避免「扫出个空站却毫无线索」。需要覆盖时设 crawler.respect_robots=false。
			onProgress(41, "robots.txt 封禁整站（Disallow: /），爬取仅入口页；如需完整爬取请将 crawler.respect_robots 设为 false")
		}
		// 爬取期带参链接并入（不覆盖）首页/种子已采集的探测点：
		// cr.ParamLinks 只含被反解析为 <a href> 的链接，而「首页 GET 表单
		// 合成的带参 URL」与「带参种子」不在其中——直接赋值会把它们丢掉，
		// 导致 Search.asp?tfSearch 这类「参数藏在 GET 表单里」的入口整块
		// 测不到（Acunetix testasp 的 Search.asp 就是这么漏的）。
		dastLinks = append(dastLinks, cr.ParamLinks...)
		allLinks = append(allLinks, cr.AllLinks...)
		// 认证深化：未配置 login_url 时，从爬到的表单里自动发现登录表单
		// （含 password 输入框）并以凭证登录——DAST/目录探测随后带认证态
		if e.cfg.Auth.LoginURL == "" && opts.AuthCookie == "" &&
			e.cfg.Auth.Username != "" && e.cfg.Auth.Password != "" && !authDone {
			sigs := make([]authn.FormSig, 0, len(cr.Forms))
			for _, f := range cr.Forms {
				if !f.HasPwd {
					continue
				}
				sg := authn.FormSig{Action: f.Action, HasPassword: true}
				for _, n := range f.Names {
					sg.Inputs = append(sg.Inputs, authn.InputSig{Name: n})
				}
				sigs = append(sigs, sg)
			}
			if cookie, ok, msg := authn.AutoDetect(client, sigs, baseURL, e.cfg.Auth); ok {
				client.SetCookie(cookie)
				authDone = true
				onProgress(45, "自动发现登录表单并登录："+msg)
			}
		}
		collectForms(cr.Forms, &dastLinks, &dastFormTargets, &loginForms)
		// 爬取面入图：带参链接与表单是无证据的攻击面事实，不喂 collector
		// 则图内 entry_points 少报（命中时才补建），与设计意图不符
		if col != nil {
			col.captureEntryPoints(dastLinks, dastFormTargets, nil)
		}
		diag.end("crawl", dtCrawl, dsCrawl, 0)
	}

	// 逐页流水线收尾：等待页内指纹匹配全部完成，按页序重建页面清单
	// （与串行实现顺序一致；被 WAF/限流拦截的页不进清单、不参与判定）。
	stream.wait()
	pages := stream.pages
	if opts.Deep {
		for _, p := range pages[1:] {
			res.Pages = append(res.Pages, PageInfo{URL: p.resp.FinalURL, Status: p.resp.Status})
			pageURLs = append(pageURLs, p.resp.FinalURL)
		}
		pageURLs = append(pageURLs, home.FinalURL)
		// API 探测点：API 端点通常不带查询串（/api/v2/user/1），拿不到就整块
		// 测不到——只从带参链接收集会让 API 通道永远空跑。这里把爬到的
		// 页面 URL 一并登记，由 RunAPI 自行筛出 API 风格路径。
		for _, pg := range res.Pages {
			if pg.URL != "" {
				apiCandidates = append(apiCandidates, pg.URL)
			}
		}
	}

	// 4.0 Track A / A8：页面清单驻留上限（超出省略并计数，削扫描期内存）
	if capN := e.cfg.Scan.PagesRetained; capN > 0 && len(res.Pages) > capN {
		res.Extras["pages_omitted"] = len(res.Pages) - capN
		res.Pages = res.Pages[:capN]
	}

	// 4) 多页指纹识别：匹配已在逐页流水线里完成，这里只按页序合并结果
	// （合并顺序 = 页序 = 串行实现的累加顺序，Technologies 输出稳定）。
	dtFP, dsFP := diag.begin()
	if matcher != nil {
		onProgress(55, fmt.Sprintf("指纹识别（%d 页）…", len(pages)))
		live.setPhase("fingerprint", "指纹识别")
		for _, hits := range stream.fpHits {
			for _, h := range hits {
				acc.add(h.Name, h.Website, h.Version, h.Evidence, h.Conf, h.Cats)
			}
		}
	}
	res.Technologies = acc.list()
	if col != nil {
		col.captureTechs(res.Technologies)
	}
	diag.end("fingerprint", dtFP, dsFP, 0)

	// 5) 安全响应头评分（逐页 CSP 候选已在流水线 push 时记录）
	dtSec, dsSec := diag.begin()
	onProgress(70, "评估安全响应头…")
	live.setPhase("security", "安全响应头")
	res.Security = security.Assess(home.Headers)
	// CSP 是**逐路径**策略：DVWA 只在 `vulnerabilities/csp/` 上设 CSP 头，
	// 首页没有。只评首页会让「有策略但策略可绕过」整块漏掉——实测漏报。
	// 取页序首个带 CSP 的响应做指令级弱点分析（首页没有时用流水线记录的候选）。
	cspHeaders, cspURL := home.Headers, baseURL
	if !hasCSPHeader(cspHeaders) && stream.cspURL != "" {
		cspHeaders, cspURL = stream.cspHeaders, stream.cspURL
	}
	if strings.TrimSpace(cspURL) != strings.TrimSpace(baseURL) {
		sc := security.Assess(cspHeaders)
		res.Security.Weaknesses = append(res.Security.Weaknesses, sc.Weaknesses...)
	}
	// 安全头策略弱点（CSP 指令级放宽等）进 verified：
	// 「头在但策略可绕过」是实打实的漏洞（DVWA CSP Bypass 即此类），
	// 只挂在 security 评分里不会被覆盖率口径看见。
	// 同一指令去重：Assess 会多次追加（首页 + 子路径），不去重会刷出
	// 多条同 URL 同指令的记录。
	seenWeak := map[string]bool{}
	for _, w := range res.Security.Weaknesses {
		key := cspURL + "\x00" + w.Directive
		if seenWeak[key] {
			continue
		}
		seenWeak[key] = true
		m := verifiedMap(map[string]any{
			"check": "csp-weak-directive", "title": "CSP 策略可绕过（" + w.Directive + "）",
			"severity": w.Severity, "url": cspURL,
			"evidence": w.Evidence, "advice": w.Advice, "src": "security",
		})
		res.Verified = append(res.Verified, m)
	}
	diag.end("security", dtSec, dsSec, 0)

	// 5.5) 敏感页缓存卫生：会话/账户类页面缺 no-store 时，内容可被
	// 共享缓存或浏览器回退键命中——会话数据外泄的常见路径。
	// 归 verified（映射 CWE-525），不是 hygiene：它是对「可见敏感页」的
	// 实际暴露判定，不是通用配置建议。
	if opts.Passive || opts.DAST {
		for _, p := range pages {
			u := p.resp.FinalURL
			if u == "" || !pageLooksSensitive(u) {
				continue
			}
			if ok, cc := pageCacheable(p.resp.Headers); ok {
				res.Verified = append(res.Verified, verifiedMap(map[string]any{
					"check": "cacheable-sensitive", "title": "敏感页面可被缓存",
					"severity": "medium", "url": u,
					"evidence": "敏感页 " + u + " 的 Cache-Control 为 " + cc +
						"（未禁止存储），会话内容可能被共享缓存或浏览器回退键读取",
					"advice": "对会话/账户类响应设置 Cache-Control: no-store; private",
					"src":    "passive",
				}))
				break // 同站同类只报一次，防逐页刷屏
			}
		}
	}

	// 6) 验证型 check
	if opts.Checks != "" && opts.Checks != "none" {
		dtChk, dsChk := diag.begin()
		cmsIDs := []string{}
		for _, t := range res.Technologies {
			cmsIDs = append(cmsIDs, checks.CMSTechChecks(t.Name)...)
		}
		if len(cmsIDs) > 0 {
			onProgress(75, "CMS 联动专项 check…")
			live.setPhase("checks", "专项检测")
		}
		// 5.0 深度融合·前置：cve-tech 产品先验 → 相关 check 提权排序 +
		// 核心档位扩展集增量纳入（只增不删）；中段家族联动在 runner 内由
		// 命中触发；收尾富化见步骤 12。任一环节失败静默跳过。
		var prior *checks.Prior
		if e.cfg.ML.Predict && !cancelled() {
			if p, promoted, info := e.mlPrior(res, home, opts.Checks, cmsIDs); p != nil {
				prior = p
				cmsIDs = append(cmsIDs, promoted...)
				res.Extras["ml_prior"] = info
				if prods := info["products"].([]map[string]any); len(prods) > 0 {
					emit("ml", fmt.Sprintf("产品先验 %s（%.2f）：提权 %d 项、增量纳入 %d 项",
						prods[0]["product"], prods[0]["prob"], info["boosted"], len(promoted)))
				}
			}
		}
		hits, checkRuns := checks.RunChecksWithPrior(client, baseURL, opts.Checks, cmsIDs, prior, e.cfg.Checks.Workers, cancelled,
			func(done, total int, msg string) {
				if total > 0 {
					onProgress(75+done*10/total, "check："+msg)
				}
			}, func(h checks.Hit) {
				emit("hit", h.Severity+" · "+h.Title+" — "+h.URL)
			})
		res.CheckRuns = append(res.CheckRuns, checkRuns...)
		for _, h := range hits {
			// 被 WAF/限流拦截的响应不参与判定：命中 URL 曾返回拦截页则丢弃
			// （否则挑战页正文/头会被当成漏洞证据）。
			if blocked.isBlockedURL(h.URL) {
				continue
			}
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check": h.Check, "title": h.Title, "severity": h.Severity,
				"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
				"request": h.Request, "replay": h.Replay,
				"response": h.Response, "signals": h.Signals,
				"confirmed": h.Confirmed,
			}))
			if col != nil {
				col.addCheckHit(h, "check")
			}
			// 版本抽取回填：wp-readme 等命中可为技术补版本，
			// 让情报关联从 possible 升级为 confirmed
			if h.Version != "" {
				if _, techName, ok := checks.ExtractFor(h.Check); ok {
					acc.refineVersion(techName, h.Version)
				}
			}
		}
		res.Technologies = acc.list()
		diag.end("checks", dtChk, dsChk, 0)
	}

	// 6.5) Nuclei 社区模板子集（all 级别 + 模板库存在时）
	if opts.Checks == "all" && !cancelled() && e.cfg.Checks.NucleiCap > 0 && e.cfg.Checks.NucleiDir != "" {
		dtNuc, dsNuc := diag.begin()
		onProgress(84, "运行 Nuclei 社区模板子集…")
		live.setPhase("nuclei", "模板检测")
		if overBudget() {
			// 先解析有效值：未显式指定（0）时降档须作用于配置默认上限，
			// 否则 0/2=0 会被 nucleiSubset 重置回全量配置上限（降档空操作）
			if opts.NucleiCap <= 0 {
				opts.NucleiCap = e.cfg.Checks.NucleiCap
			}
			if opts.NucleiCap > 1 {
				opts.NucleiCap /= 2
			}
			noteBudget("Nuclei 模板上限减半（" + fmt.Sprint(opts.NucleiCap) + "）")
		}
		if nl, stat := e.nucleiSubset(res.Technologies, res.Title, opts.NucleiCap); stat != nil {
			// 模板通道可见性：不记录的话，报告里只有"跑了 N 条"，
			// 看不出预算是被 tag 命中吃掉的还是被 LRU 轮转吃掉的——
			// 而这两者的命中概率差一个量级（EXP-1003：info 暴露面类
			// lift 12 倍 vs 带 CVE 的复现类长期 0 命中）。
			res.Extras["nuclei"] = stat
			nHits, nRuns := checks.RunListWithLog(client, baseURL, nl, e.cfg.Checks.Workers, cancelled,
				func(done, total int, msg string) {
					if total > 0 {
						onProgress(84, fmt.Sprintf("nuclei %d/%d", done, total))
					}
				}, func(h checks.Hit) {
					emit("hit", h.Severity+" · "+h.Title+" — "+h.URL)
				})
			res.CheckRuns = append(res.CheckRuns, nRuns...)
			for _, h := range nHits {
				// 被 WAF/限流拦截的响应不参与判定（同 checks 通道）。
				if blocked.isBlockedURL(h.URL) {
					continue
				}
				res.Verified = append(res.Verified, verifiedMap(map[string]any{
					"check": h.Check, "title": h.Title, "severity": h.Severity,
					"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
					"src":     "nuclei",
					"request": h.Request, "replay": h.Replay,
					"response": h.Response, "signals": h.Signals,
					"confirmed": h.Confirmed,
				}))
				if col != nil {
					col.addCheckHit(h, "nuclei")
				}
			}
		}
		diag.end("nuclei", dtNuc, dsNuc, 0)
	}

	// 7) 被动安全检测（零额外请求）：结果已在逐页流水线 push 时按页序算好，
	// 这里只按页序做跨页去重后的最终归并（顺序与串行实现一致）。
	if opts.Passive {
		dtPas, dsPas := diag.begin()
		onProgress(80, "被动安全检测…")
		live.setPhase("passive", "被动检测")
		hygieneChecks := passive.Hygiene()
		var hygiene []map[string]any
		for idx := range pages {
			for _, h := range stream.passiveHits[idx] {
				m := verifiedMap(map[string]any{
					"check": h.Check, "title": h.Title, "severity": h.Severity,
					"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
					"src": "passive",
				})
				if hygieneChecks[h.Check] {
					// 配置卫生项单独成列（Extras["hygiene"]）：不混进
					// verified 漏洞列表，避免拉低严格口径准确率
					m["kind"] = "hygiene"
					hygiene = append(hygiene, m)
				} else {
					res.Verified = append(res.Verified, m)
				}
				if col != nil {
					col.addPassiveHit(h)
				}
			}
		}
		if len(hygiene) > 0 {
			res.Extras["hygiene"] = hygiene
		}
		diag.end("passive", dtPas, dsPas, 0)
	}

	// 8) DAST：参数级探测（JS 攻击面已在爬取前提取，端点回灌了爬虫种子）
	if opts.DAST {
		dtDAST, dsDAST := diag.begin()
		dedupBefore := roCache.Hits()
		onProgress(85, "参数级 DAST 探测…")
		live.setPhase("dast", "参数级 DAST")
		var dastAll []dast.Finding
		var dastMaps []map[string]any
		// SSRF 出带：配置启用且扫描器 beacon 可被目标触达时才生效。
		// B4：不再 Reset 全局表——token 自 scoped（各自只认自己发出的），
		// 并发扫描互不干扰；过期条目由 maxEntries LRU 自然淘汰
		beaconBase := ""
		if e.cfg.Ssrf.BeaconEnabled && e.cfg.Ssrf.BeaconBase != "" {
			beaconBase = strings.TrimRight(e.cfg.Ssrf.BeaconBase, "/")
		}
		deepOn := e.cfg.DAST.DeepProbes
		errStatusOn := e.cfg.DAST.ErrorStatus
		// 只读页面复用：cache 里只有首页/种子/爬取页（DAST payload URL 不会命中）；
		// 被 WAF/限流拦截的响应在 fetcher 层直接按「无响应」处理。
		df := dastFetcher{c: client, cache: roCache, blocked: blocked, live: live}
		r := dast.New(df, dast.Options{
			MaxParams:         e.cfg.DAST.MaxParams,
			TimeBlind:         e.cfg.DAST.TimeBlind,
			BoolBlind:         e.cfg.DAST.BoolBlind,
			BlindThresholdMS:  e.cfg.DAST.BlindThresholdMS,
			SleepSeconds:      e.cfg.DAST.SleepSeconds,
			MaxURLLen:         e.cfg.DAST.MaxURLLen,
			BeaconBase:        beaconBase,
			MaxProbes:         e.cfg.Ssrf.MaxProbes,
			DeepProbes:        &deepOn,
			CmdInject:         e.cfg.DAST.CmdInject && deepOn,
			CRLF:              e.cfg.DAST.CRLF && deepOn,
			ErrorStatus:       &errStatusOn,
			RandomDiff:        e.cfg.DAST.RandomDiff && deepOn,
			StoredXSS:         e.cfg.DAST.StoredXSS && deepOn,
			WeakCookie:        e.cfg.DAST.WeakCookie && deepOn,
			CaptchaReplay:     e.cfg.LoginBrute.CaptchaReplay && deepOn,
			AuthzBypass:       e.cfg.DAST.AuthzBypass && deepOn,
			APIAudit:          e.cfg.DAST.APIAudit && deepOn,
			CryptoProbe:       e.cfg.DAST.CryptoProbe && deepOn,
			UploadBypass:      e.cfg.DAST.UploadBypass && deepOn,
			MaxProbesPerClass: e.cfg.DAST.MaxProbesPerClass,
			OnHit: func(f dast.Finding) {
				emit("hit", f.Severity+" · "+f.Title+" — "+f.Param)
			},
		})
		// 出带回调（OOB）：目标外发到外部接收端即确认。与 beacon 互补——
		// beacon 要求目标能连回扫描器（公网靶场不成立），OOB 用可公网访问的
		// 接收端/本地 CSV，覆盖 SSRF / 盲 XSS / XXE 外发 / JNDI 出带。
		// 默认关；开启后对候选参数各发一次探针（有界）。
		oobCfg := dast.OobConfig{
			Enabled:   e.cfg.Oob.Enabled,
			Mode:      e.cfg.Oob.Mode,
			Callback:  e.cfg.Oob.Callback,
			CSVPath:   e.cfg.Oob.CSVPath,
			TokenHost: e.cfg.Oob.TokenHost,
			MaxProbes: e.cfg.Oob.MaxProbes,
		}
		for _, f := range r.RunForms(dastFormTargets) {
			dastAll = append(dastAll, f)
			m := verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "dast", "param": f.Param,
				"payload": f.Payload, "replay": f.Replay, // 重放与证据链输入
			})
			res.Verified = append(res.Verified, m)
			dastMaps = append(dastMaps, m)
		}
		for _, f := range r.RunAPI(append(append([]string{}, dastLinks...), apiCandidates...)) {
			dastAll = append(dastAll, f)
			m := verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "dast", "param": f.Param,
				"payload": f.Payload, "replay": f.Replay,
			})
			res.Verified = append(res.Verified, m)
			dastMaps = append(dastMaps, m)
		}
		for _, f := range r.RunAuthz(dastLinks) {
			dastAll = append(dastAll, f)
			m := verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "dast", "param": f.Param,
				"payload": f.Payload, "replay": f.Replay,
			})
			res.Verified = append(res.Verified, m)
			dastMaps = append(dastMaps, m)
		}
		for _, f := range r.Run(dastLinks) {
			dastAll = append(dastAll, f)
			m := verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "dast", "param": f.Param,
				"payload": f.Payload, "replay": f.Replay,
			})
			res.Verified = append(res.Verified, m)
			dastMaps = append(dastMaps, m)
		}
		// 出带回调探测（默认关）：对已采集的带参目标逐参数注入回调地址。
		if oobCfg.Enabled {
			var oobTargets []dast.Target
			for _, t := range r.URLTargets(dastLinks) {
				oobTargets = append(oobTargets, t)
			}
			for _, f := range r.OobProbe(oobTargets, oobCfg) {
				dastAll = append(dastAll, f)
				m := verifiedMap(map[string]any{
					"check": f.Check, "title": f.Title, "severity": f.Severity,
					"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
					"src": "dast", "param": f.Param,
					"payload": f.Payload,
				})
				res.Verified = append(res.Verified, m)
				dastMaps = append(dastMaps, m)
			}
		}
		// 3.0 利用级无害验证：双开关（请求开关 × config exploit.enabled，
		// 设置页「利用级验证」控制总闸）；目标合规责任在使用者
		if opts.Exploit && e.cfg.Exploit.Enabled && len(dastAll) > 0 {
			onProgress(86, "利用级无害验证…")
			live.setPhase("exploit", "利用级验证")
			// exploit 层不复用只读缓存（proven 证据必须来自本次新鲜请求），
			// 但仍做拦截隔离（WAF 回显 payload 不能算 proven）。
			proven, observed := e.runExploit(host, dastAll, dastMaps,
				dastFetcher{c: client, blocked: blocked, live: live}, emit)
			res.Extras["exploit"] = map[string]any{
				"proven": proven, "observed": observed, "gate": "enabled",
			}
		}
		// 结构化收集放在 exploit 之后：impact/impact_evidence 已被回填进 dastMaps。
		if col != nil {
			for i := range dastAll {
				var m map[string]any
				if i < len(dastMaps) {
					m = dastMaps[i]
				}
				col.addDASTFinding(dastAll[i], m)
			}
		}
		// 去重命中 = 引擎只读页复用 + DAST benign 基线跨通道复用（payload 不复用）。
		diag.end("dast", dtDAST, dsDAST, (roCache.Hits()-dedupBefore)+r.BaseCacheHits())
	}

	// 9) 主动模块（默认关）
	var dirHits []modules.PageHit
	if overBudget() {
		noteBudget("跳过主动模块（目录/子域/WebShell/指纹/端口）")
		emit("budget", "内存超预算，跳过主动模块段")
	} else if opts.DirScan || opts.Subdomain || opts.Webshell || opts.WeakAudit || opts.ActiveFP || opts.ServiceProbe || opts.NetProto {
		dtMod, dsMod := diag.begin()
		ac := e.cfg.Active
		if opts.DirBypass {
			ac.DirBypass403 = true // 每次扫描可覆盖配置（对齐 Python options.dir_bypass）
		}
		// 强度档位的字典缩放（每扫描覆盖配置；0 = 沿用配置默认）
		if opts.DirMaxPaths > 0 {
			ac.DirMaxPaths = opts.DirMaxPaths
		}
		if opts.ShellMaxPaths > 0 {
			ac.ShellMaxPaths = opts.ShellMaxPaths
		}
		if opts.SubMaxWords > 0 {
			ac.SubMaxWords = opts.SubMaxWords
		}
		if opts.Subdomain {
			onProgress(86, "子域名枚举…")
			live.setPhase("active", "主动模块")
			subs := modules.SubdomainEnum(res.Host, ac, nil, cancelled)
			res.Extras["subdomain"] = subs
			if opts.Takeover && len(subs) > 0 {
				onProgress(86, "子域名接管探测…")
				res.Extras["takeover"] = modules.TakeoverProbe(client, subs, ac, nil, cancelled)
			}
		}
		if opts.DirScan {
			onProgress(87, "目录探测…")
			// 词表升级：全量档位（3.2k+ / 6k+）带全量档位标签时，把
			// active 词表并集拉进来——默认 300 条保守词表在实测里
			// 只覆盖全量 9633 条的 55/9633，upload 端点一个都不在。
			// 升级只在显式大词表档位发生，不改默认档位的请求预算。
			if opts.DirFullWords && ac.DirMaxPaths < len(fullWordlistUnion(e.cfg.Active.WordlistDir)) {
				ac.DirMaxPaths = len(fullWordlistUnion(e.cfg.Active.WordlistDir))
			}
			// 爬取链接扩展：端点存在性核查（词表猜不到的端点在链接里）。
			viaOf := func(link string) string { return pageOfLink(link, pageURLs) }
			dirHits = modules.DirScanExtra(client, baseURL, ac, allLinks, viaOf, nil, cancelled)
			res.Extras["dir"] = dirHits
			// 403 绕过命中的路径单列成块（可被绕过的访问控制 = 独立发现）
			var bypassed []modules.PageHit
			for _, h := range dirHits {
				if h.Bypass != "" {
					bypassed = append(bypassed, h)
					emit("bypass", "403 可绕过："+h.Path+"（"+h.Bypass+"）")
					if col != nil {
						col.addDirBypass(h)
					}
				}
			}
			if len(bypassed) > 0 {
				res.Extras["bypass"] = bypassed
			}
			// 目录探测命中进 verified：此前只落 Extras["dir"]，报告主体里
			// 看不见——「报出来了但不在发现列表」等于没报。分类：
			// 目录列表开启 / 403 可绕过 / 路径存在且可直读（源码/配置/备份
			// 的后缀判定由后缀白名单给出，不臆断「是漏洞」）。
			for _, h := range dirHits {
				check, title := dirFindingOf(h)
				if check == "" {
					continue // 无缺陷语义的路径存在（普通入口页）不进发现
				}
				m := verifiedMap(map[string]any{
					"check": check, "title": title, "severity": dirSeverityOf(h),
					"url": h.URL, "advice": dirAdviceOf(h), "src": "dir",
					"evidence": dirEvidenceOf(h),
				})
				res.Verified = append(res.Verified, m)
				emit("hit", m["severity"].(string)+" · "+title+" — "+h.URL)
			}
		}
		if opts.Webshell {
			onProgress(88, "WebShell 探测…")
			res.Extras["webshell"] = modules.WebshellProbe(client, baseURL, ac, nil, cancelled)
		}
		if opts.ActiveFP && kb != nil && len(kb.FingerDir()) > 0 {
			onProgress(89, "FingerDir 主动指纹…")
			res.Extras["active_fp"] = modules.ActiveFP(client, baseURL,
				kb.FingerDir(), nil, cancelled, e.cfg.Active.FPMaxRequests)
		}
		var services []modules.ServiceHit
		if opts.ServiceProbe && kb != nil && len(kb.ServiceFP()) > 0 {
			onProgress(89, "端口服务识别…")
			ports := e.cfg.Active.ProbePorts
			if len(opts.ProbePorts) > 0 {
				ports = opts.ProbePorts // 强度档位的端口集覆盖（每扫描）
			}
			services = modules.ServiceProbe(host, kb.ServiceFP(),
				ports, e.cfg.Active.ProbeTimeoutMS,
				e.cfg.Active.ProbeWorkers, nil, cancelled)
			res.Extras["service"] = services
		}
		// 3.0 协议模板检测（非 HTTP）：与端口服务识别解耦——独立选择时
		// 仅跑 dns 类模板（查询目标域名自身）；开端口识别则 tcp 模板
		// 跑探测到的服务端口；同闸授权语义
		if opts.ServiceProbe || opts.NetProto {
			onProgress(90, "协议模板检测（tcp/dns/ssl）…")
			if hits := e.netprotoScan(host, services, emit, cancelled); len(hits) > 0 {
				res.Extras["netproto"] = hits
			}
		}
		if opts.WeakAudit {
			users := loginbrute.LoadList(
				wordlistPath(e.cfg, "weak_users.txt"), e.cfg.LoginBrute.MaxUsers)
			pwds := loginbrute.LoadList(
				wordlistPath(e.cfg, "weak_passwords.txt"), e.cfg.LoginBrute.MaxPasswords)
			// 表单弱口令：爬取阶段发现的登录表单（DVWA/pikachu 这类弱口令
			// 靶场的入口就在表单里）。此前只做 HTTP Basic 401 审计，
			// 表单口令完全没覆盖——这是「登录爆破未识别 DVWA 表单」的根因。
			if len(loginForms) > 0 {
				onProgress(89, "登录表单弱口令审计…")
				for _, lf := range loginForms {
					if cancelled() {
						break
					}
					// 验证码接线：配了 ddddocr sidecar 地址才启用识别；
					// 每次尝试前重取验证码图（旧码提交后即失效）。
					capType, ocrURL := "none", ""
					fetchImg := func(string) ([]byte, error) { return nil, errNoImageChannel }
					if e.cfg.LoginBrute.CaptchaOCRURL != "" {
						capType = e.cfg.LoginBrute.CaptchaType
						if capType == "" {
							capType = "digits"
						}
						ocrURL = e.cfg.LoginBrute.CaptchaOCRURL
						fetchImg = imageFetcher(client)
					}
					hits, lerr := loginbrute.Brute(postFormPoster{client}, loginbrute.Options{
						PageURL:     lf.URL,
						Users:       users,
						Passwords:   pwds,
						MaxTries:    e.cfg.LoginBrute.MaxTries,
						IntervalMS:  e.cfg.LoginBrute.IntervalMS,
						CaptchaType: capType,
						OCRURL:      ocrURL,
						FetchImage:  fetchImg,
						AllowHosts:  e.cfg.Scan.AllowHosts,
					}, nil)
					if lerr != nil {
						continue // 无表单 / 验证码页：跳过，不中断其余审计
					}
					for _, h := range hits {
						res.Verified = append(res.Verified, verifiedMap(map[string]any{
							"check": "weak-login-form", "title": "登录表单弱口令",
							"severity": "high", "url": h.URL,
							"evidence": "用户 " + h.User + " / 口令 " + strings.Repeat("*", len(h.Password)) + " 登录成功",
							"advice":   "改用强口令并启用登录失败限制 / 多因素认证",
							"src":      "weak", "type": "login-form",
						}))
						if col != nil {
							col.addWeakCredential(loginbrute.Hit{Type: "login-form",
								User: h.User, Password: h.Password, URL: h.URL})
						}
					}
				}
			}
			// 基础认证弱口令：目录探测发现的 401 路径
			var urls401 []string
			for _, h := range dirHits {
				if h.Status == 401 {
					urls401 = append(urls401, h.URL)
					if len(urls401) >= 3 {
						break
					}
				}
			}
			if len(urls401) > 0 {
				onProgress(89, "基础认证弱口令审计…")
				for _, h := range loginbrute.BasicAuthBrute(client, urls401, users, pwds,
					e.cfg.LoginBrute.MaxTries, e.cfg.LoginBrute.IntervalMS, nil) {
					res.Verified = append(res.Verified, verifiedMap(map[string]any{
						"check": "weak-basic-auth", "title": "基础认证弱口令",
						"severity": "high", "url": h.URL,
						"evidence": "用户 " + h.User + " 弱口令命中",
						"advice":   "改用强口令并禁用 HTTP Basic；启用登录失败限制",
						"src":      "weak", "type": h.Type,
					}))
					// P7：弱口令命中 → priv_change（mechanism=credential）。
					if col != nil {
						col.addWeakCredential(h)
					}
				}
			}
		}
		diag.end("modules", dtMod, dsMod, 0)
	}

	// 10) 网络层安全
	if opts.Netsec {
		dtNs, dsNs := diag.begin()
		onProgress(89, "TLS / DNS 安全检测…")
		tlsPort := port
		if tlsPort == 0 || tlsPort == 80 {
			tlsPort = 443
		}
		findings := netsec.CheckTLS(host, tlsPort)
		if e.cfg.Netsec.MailCheck {
			findings = append(findings, netsec.CheckDNSMail(host)...)
		}
		// HSTS / HTTP→HTTPS 跳转：一次只读 GET（≤5s、丢弃正文）。
		findings = append(findings, netsec.CheckHTTP(seedURL)...)
		// 端口探测默认关（额外 TCP 连接）：netsec.port_scan 显式开启。
		if e.cfg.Netsec.PortScan {
			findings = append(findings, netsec.CheckPorts(host, nil, 1500*time.Millisecond)...)
		}
		res.Extras["netsec"] = map[string]any{"findings": findings}
		diag.end("netsec", dtNs, dsNs, 0)
	}

	// 11) 漏洞情报关联
	if !cancelled() && kb != nil {
		dtInt, dsInt := diag.begin()
		onProgress(92, "关联漏洞情报…")
		techs := acc.techHits()
		res.Vulnerabilities = append(res.Vulnerabilities, kb.Match(techs)...)
		res.Vulnerabilities = append(res.Vulnerabilities, cveMsFindings(kb.MatchCVEMs(techs, 20))...)
		attachTemplates(e, res.Vulnerabilities)
		if col != nil {
			for _, f := range res.Vulnerabilities {
				col.addIntelFinding(f)
			}
		}
		diag.end("intel", dtInt, dsInt, 0)
	}

	if len(budgetDegrades) > 0 {
		res.Extras["budget"] = budgetDegrades
	}

	// 4.0 P2：结构化事实图挂到结果（失败不阻塞扫描——图是附加产物）
	if col != nil {
		res.Graph = col.graph()
		// 4.0 P5：CVE → CWE 关联（NVD weaknesses 通道；未挂 NVD 时跳过）
		if kb != nil && kb.HasNVD() { // A3：只判断是否配置，不拉起索引
			cwe.Relate(res.Graph, nvdLookup{kb})
		}
		// 4.0 P7/P10：为 impact 补 KEV/CVSS 先验标注（**仅解释，不参与建链**）。
		if kb != nil {
			col.annotatePriorsFromKB(kb)
		}
		// 4.0 P6：证据驱动建链（无证据的候选边不建；见 internal/chain）。
		chain.Build(res.Graph, chain.Options{})
		if err := res.Graph.Validate(); err != nil {
			emit("graph", "结构化事实图校验异常："+err.Error())
		}
	}

	// 12) 5.0 ML 推理富化（L3 阶段 A，cfg.ML.Predict 默认开）：对发现中的
	// CVE 做受影响产品 Top-5 + CWE 弱点类型先验预测，附加 predictions
	// 字段。模型只提供先验参考，不改变任何判定；资产缺失/加载失败/
	// 推理异常一律静默跳过（字段缺席，主流程零影响）。
	if !cancelled() && e.cfg.ML.Predict && len(res.Vulnerabilities) > 0 {
		dtML, dsML := diag.begin()
		e.mlEnrich(res, kb)
		diag.end("ml", dtML, dsML, 0)
	}

	onProgress(100, fmt.Sprintf("完成，识别 %d 项技术，%d 条已验证发现",
		len(res.Technologies), len(res.Verified)))
	finish()
	return res
}

// ClientFor 导出客户端装配（登录爆破等模块复用同一套限速/UA/Cookie 配置）。
func (e *Engine) ClientFor(opts Options) *httpx.Client { return e.newClient(opts) }

// ReleaseIntel 释放情报知识库常驻内存（A10 自适应版）：表清空、惰性路径保留，
// 下一次扫描/检索自动重载。供 serve 管理端点在长空闲时调用。
// 并发安全：全程持 dataMu，消除对 e.kb 的无锁读（与 SetKB 热替换的指针竞争）；
// 活跃扫描计数 >0 时跳过释放——进行中的扫描全程共用快照 *KB（契约见上），
// KB.Release 的清表会与其 Match 读构成数据竞争。
func (e *Engine) ReleaseIntel() {
	e.dataMu.Lock()
	defer e.dataMu.Unlock()
	if e.activeScans > 0 {
		return
	}
	e.kb.Release()
}

// ---- 内部辅助 ----

type crawlPage struct {
	resp *httpx.Response
	doc  *htmlx.Doc
}

// newClient 按配置与本次选项装配客户端。
//
// 限速档位（scan.rate_mode）：balanced = WAF-aware 自适应（400ms 起步，连续
// 干净成功后加速到 200ms 硬下限；命中 429/503/WAF/挑战页后退避）；其余
// （polite / 未知值，config 已归一到 polite）= 固定间隔、逐字节保持旧语义。
func (e *Engine) newClient(opts Options) *httpx.Client {
	sc := e.cfg.Scan
	return httpx.NewWithOptions(httpx.ClientOptions{
		Interval:     time.Duration(sc.RateIntervalMS) * time.Millisecond,
		Timeout:      time.Duration(sc.TimeoutSec) * time.Second,
		MaxHops:      sc.MaxHops,
		MaxBodyBytes: sc.MaxBodyMB * 1024 * 1024,
		UserAgent:    uaFor(sc.UserAgent, opts.BrowserUA),
		AuthCookie:   opts.AuthCookie,
		Resolve:      sc.Resolve,
		Adaptive:     sc.RateMode == "balanced",
		MaxRPS:       sc.RateMaxRPS,
	})
}

// uaFor 选择 UA：配置优先，其次浏览器 UA 选项，最后默认自报。
func uaFor(cfgUA string, browserUA bool) string {
	if cfgUA != "" {
		return cfgUA
	}
	if browserUA {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	}
	return ""
}

func lookupIP(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func normalizeKey(u string) string { return strings.TrimSuffix(u, "/") }

// wordlistPath 字典文件路径（wordlist_dir 下）。
func wordlistPath(cfg *config.Config, name string) string {
	return filepath.Join(cfg.Active.WordlistDir, name)
}

// chromeRenderer 把 headless.Chrome 适配为 crawler.Renderer。
type chromeRenderer struct{ c *headless.Chrome }

func (a chromeRenderer) Render(rawURL string) (string, bool) {
	html, err := a.c.Render(rawURL)
	if err != nil {
		return "", false
	}
	return html, true
}

// nucleiLRU 持久化 LRU 调度表：模板路径 → 最近运行时间。
// 落盘 data/state/nuclei_schedule.json，跨进程重启保持轮转公平——
// 数学保证：可运行全集 C、单次上限 N，⌈C/N⌉ 次扫描后全部模板各跑一遍。
var nucleiLRUMu sync.Mutex

// attachTemplates 模板情报层：CVE → 可运行模板路径。
// 只读缓存（IndexCached），缓存未就绪时静默跳过——绝不 mid-scan 重建。
// 单 CVE 最多挂 6 条避免报告膨胀。
func attachTemplates(e *Engine, findings []intel.Finding) {
	if len(findings) == 0 || e.cfg.Checks.NucleiDir == "" {
		return
	}
	entries := nuclei.IndexCached(filepath.Join(e.cfg.Store.DataDir, "nuclei_index.json"))
	if len(entries) == 0 {
		return
	}
	byCVE := map[string][]string{}
	for i := range entries {
		for _, c := range entries[i].CVEs {
			if len(byCVE[c]) < 6 {
				byCVE[c] = append(byCVE[c], entries[i].Path)
			}
		}
	}
	for i := range findings {
		cve := strings.ToUpper(findings[i].CVE)
		if cve != "" {
			findings[i].Templates = byCVE[cve]
		}
	}
}

// dirFindingOf 目录探测命中 → (check, title)。返回空 check 表示该命中
// 只有「路径存在」语义（普通入口页/目录），不构成缺陷，不进发现列表。
//
// 判定只依据可观测事实，不做"猜漏洞类型"：
//   - 目录列表开启（响应本身是索引页）→ dir-listing，可直读文件
//   - 403 被绕过 → dir-bypass-403，访问控制失效
//   - 路径后缀是可执行/配置/备份形态且正文非空 → exposed-endpoint，
//     服务端直接把非常规资源吐出来了（upload-labs 这类"关卡页"面）
func dirFindingOf(h modules.PageHit) (check, title string) {
	switch {
	case h.DirIndex:
		return "dir-listing", "目录列表开启（可直读目录内容）"
	case h.Bypass != "":
		return "dir-bypass-403", "访问控制可绕过（403 变体命中）"
	}
	if !sensitiveSuffix(h.Path) {
		return "", ""
	}
	return "exposed-endpoint", "端点为可直读的源/配置/备份形态：" + h.Path
}

// sensitiveSuffix 路径后缀是否为"本不该被直接读取"的形态。
// 只按后缀判定，不看内容——内容判定交给 check 层的词匹配。
func sensitiveSuffix(p string) bool {
	low := strings.ToLower(p)
	dot := strings.LastIndex(low, ".")
	if dot < 0 {
		return false
	}
	switch low[dot:] {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phps",
		".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".do", ".action",
		".cgi", ".pl", ".py", ".rb", ".sh", ".cgi-bin":
		return false // 脚本端点：正常可达，是否存在缺陷要靠内容判定
	case ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
		".sql", ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".gz",
		".conf", ".config", ".ini", ".yml", ".yaml", ".env", ".log",
		".key", ".pem", ".crt", ".p12", ".jks":
		return true
	}
	return false
}

// dirSeverityOf 目录发现的严重度：直读备份/配置(key/pem/env)最重。
func dirSeverityOf(h modules.PageHit) string {
	if h.DirIndex || h.Bypass != "" {
		return "medium"
	}
	low := strings.ToLower(h.Path)
	for _, s := range []string{".env", ".key", ".pem", ".p12", ".jks", ".sql", ".conf", ".config", ".ini", ".yml", ".yaml"} {
		if strings.HasSuffix(low, s) {
			return "high"
		}
	}
	return "medium"
}

func dirAdviceOf(h modules.PageHit) string {
	switch {
	case h.DirIndex:
		return "关闭目录索引（autoindex off / Directory Listing 禁用）"
	case h.Bypass != "":
		return "修正访问控制策略（403 不应可被路径变异/伪造头绕过）"
	}
	return "移除 Web 根下的备份/配置文件，或加访问控制"
}

// dirEvidenceOf 目录发现的证据文本：状态码 + 尺寸 + 命中来源回链。
func dirEvidenceOf(h modules.PageHit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d · %dB", h.Status, h.Size)
	if h.DirIndex {
		b.WriteString(" · 目录索引标记命中")
	}
	if h.Bypass != "" {
		b.WriteString(" · 403 绕过（" + h.Bypass + "）")
	}
	if h.Via != "" {
		b.WriteString(" · 来源 " + h.Via)
	}
	return b.String()
}

// pageOfLink 端点扩展的证据回链：给出「谁把这个链接带出来的」。
//
// 爬取结果只保留了链接集合，没有逐条保留「来源页」映射（Result.AllLinks
// 是扁平的）。这里的近似是诚实的：若链接的路径自身就出现在某页 URL 里，
// 说明该页与该端点同源；否则回落到站点根——绝不编造来源。
func pageOfLink(link string, pages []string) string {
	lu, err := url.Parse(link)
	if err != nil {
		return ""
	}
	target := strings.Trim(lu.Path, "/")
	if target == "" {
		return ""
	}
	for _, p := range pages {
		pu, perr := url.Parse(p)
		if perr != nil {
			continue
		}
		pp := strings.Trim(pu.Path, "/")
		if pp == "" || pp == target {
			continue // 自指不是溯源：链接自身不能当自己的来源
		}
		if strings.HasPrefix(target, pp+"/") || strings.HasPrefix(pp, target+"/") {
			return p
		}
	}
	return ""
}

// fullWordlistUnion 全量目录词表并集（去重）。用于大词表档位把
// active 词表从保守 300 条扩到全量：实测默认词表 1887 条里
// upload 端点一个都没有，而 full/dir-9.6k.txt 里有整组 upload.* 路径。
// 文件缺失时返回空（调用方沿用原上限）。
func fullWordlistUnion(dir string) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range []string{"dir-9.6k.txt", "php-3.2k.txt", "jsp-4.2k.txt"} {
		data, err := os.ReadFile(filepath.Join(dir, "full", name))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || seen[l] {
				continue
			}
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// affectedCVEs 目标指纹 → 受影响 CVE 集合（intel KB 关联）。
// 只读、失败静默（KB 未挂载 / 匹配异常 → 空集，调度退回纯 tag+LRU）。
// 上限防爆：单技术最多取 maxPerTech 条情报行的 CVE，且集合整体封顶。
func (e *Engine) affectedCVEs(techs []Tech) map[string]bool {
	_, kb := e.snapshot()
	if kb == nil || len(techs) == 0 {
		return nil
	}
	hits := make([]intel.TechHit, 0, len(techs))
	for _, t := range techs {
		hits = append(hits, intel.TechHit{Name: t.Name, Version: t.Version})
	}
	out := map[string]bool{}
	for _, f := range kb.Match(hits) {
		cve := strings.ToUpper(strings.TrimSpace(f.CVE))
		if cve == "" {
			continue
		}
		out[cve] = true
		if len(out) >= maxAffectedCVEs {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// maxAffectedCVEs 单次扫描纳入 CVE 通道的 CVE 数上限。
// 情报关联对一台指纹繁多的目标可能产出成百条 CVE，全量反查模板会把
// 命中集撑到预算之外——封顶保证 CVE 通道是「精准提权」而非「换一种
// 方式吃光预算」。
const maxAffectedCVEs = 64

// nucleiSubset 按已识别技术挑选 Nuclei 模板并转换为 check。
func (e *Engine) nucleiSubset(techs []Tech, pageTitle string, cap int) ([]checks.Check, map[string]any) {
	entries, err := nuclei.Index(e.cfg.Checks.NucleiDir,
		filepath.Join(e.cfg.Store.DataDir, "nuclei_index.json"))
	if err != nil || len(entries) == 0 {
		return nil, nil
	}
	var names []string
	for _, t := range techs {
		names = append(names, t.Name)
	}
	// 技术名 → 模板 tag 归一（显示名 `Microsoft IIS` vs 模板 tag `iis`）：
	// 精确比对下 tag 这一路对多数技术空转，预算全落 LRU 轮转。
	tags := nuclei.TechTagSet(names)
	// CVE 通道（准入收口）：指纹技术名 → 受影响 CVE（intel 关联）→ 声明
	// 该 CVE 的模板置顶。对应「情报关联命中 CVE 时把该 CVE 影响的模板
	// 直接提权，而不是等 LRU 轮到那一条」——这是把「库存」变成「这次
	// 就可能打中」的那一步。intel 未挂载时 cveSet 为空，行为零回归。
	cveSet := e.affectedCVEs(techs)
	// 相关度查询文本：技术名 + 页面标题（模板名/tag 词面重合排序）
	query := strings.Join(names, " ") + " " + pageTitle

	nucleiLRUMu.Lock()
	defer nucleiLRUMu.Unlock()
	if cap <= 0 {
		cap = e.cfg.Checks.NucleiCap
	}
	selected := nuclei.SelectWithCVE(entries, tags, cveSet, query, cap, e.nucleiLRU)
	stat := map[string]any{
		"index_total": len(entries),
		"tag_hits":    nuclei.CountTagHits(entries, tags),
		"cve_hits":    nuclei.CountCVEHits(entries, cveSet),
		"cve_total":   len(cveSet),
		"selected":    len(selected),
		"budget":      cap,
		"sources":     nuclei.SourceCounts(selected),
	}
	if len(selected) > 0 {
		now := time.Now().UnixNano()
		for _, ent := range selected {
			e.nucleiLRU[ent.Path] = now
		}
		e.saveNucleiLRU()
	}

	var out []checks.Check
	for _, ent := range selected {
		// A6：走编译缓存（mtime 键控，模板更新自然失效）
		cs, err := nuclei.LoadFileCached(filepath.Join(e.cfg.Checks.NucleiDir, filepath.FromSlash(ent.Path)))
		if err != nil {
			continue
		}
		out = append(out, cs...)
	}
	return out, stat
}

// loadNucleiLRU 从磁盘恢复调度表（文件缺失/内容损坏 = 全新开始）。
//
// 兜底语义（BUG-012）：JSON `null` 会把目标 map 置为 nil 且 err==nil
// （解出空指针合法），解析失败同理不可留旧 nil。调度表必须是可写空表——
// 否则 nucleiSubset 里 `e.nucleiLRU[ent.Path] = now` 直接 panic:
// assignment to entry in nil map。
func (e *Engine) loadNucleiLRU() {
	m := map[string]int64{}
	if data, err := os.ReadFile(filepath.Join(e.cfg.Store.DataDir, "nuclei_schedule.json")); err == nil {
		if derr := json.Unmarshal(data, &m); derr != nil || m == nil {
			m = map[string]int64{}
		}
	}
	e.nucleiLRU = m
}

// saveNucleiLRU 调度表落盘（tmp+rename 原子写，防中途崩溃损坏调度表）。
func (e *Engine) saveNucleiLRU() {
	dst := filepath.Join(e.cfg.Store.DataDir, "nuclei_schedule.json")
	data, err := json.Marshal(e.nucleiLRU)
	if err != nil {
		return
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, dst)
}

// dastFetcher 把 httpx 客户端适配为 dast.Fetcher。
// dastFetcher 把 httpx 客户端适配为 dast.Fetcher。
//
// cache：引擎只读 GET 复用（只含爬取阶段抓过的页面/种子/首页；DAST payload URL
// 不会命中，也不会被写入——payload 请求绝不复用）。blocked：被 WAF/限流拦截
// 的响应一律按「无响应」返回，避免 WAF 挑战页回显 payload 造成假阳性。
type dastFetcher struct {
	c       *httpx.Client
	cache   *readOnlyCache
	blocked *blockedTracker
	live    *liveTracker
}

// wrap 拦截隔离 + 适配：Blocked 响应登记后返回 nil（不参与任何判定）。
func (d dastFetcher) wrap(r *httpx.Response) *dast.Resp {
	if r == nil {
		return nil
	}
	if d.live != nil {
		d.live.touch()
	}
	if d.blocked != nil && d.blocked.note(r) {
		return nil
	}
	return &dast.Resp{Status: r.Status, Headers: r.Headers, SetCookies: r.SetCookies, Body: r.Body}
}

func (d dastFetcher) PostFormSmall(rawURL string, data map[string]string) *dast.Resp {
	r, err := d.c.PostForm(rawURL, data)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// PostFormRawSmall 原始表单体 POST（dast 侧可选接口 rawFormPoster，预编码
// 载荷通道用）。
//
// body 由 dast 侧按表单编码纪律显式构造：其余字段照常表单编码，仅需注入
// 原始字节/控制符的目标字段值原样保留（%0d%0a 等）。这里必须原样发出，
// **不能再经 url.Values.Encode**——否则 "%" 被二次编码成 "%25"，服务端
// 单次解码只拿到字面文本，表单侧 CRLF 注入实际不生效（BUG-017 表单残留）。
func (d dastFetcher) PostFormRawSmall(rawURL, body string) *dast.Resp {
	r, err := d.c.PostRaw(rawURL, "application/x-www-form-urlencoded", body)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

func (d dastFetcher) GetSmall(rawURL string) *dast.Resp {
	// 只读页面复用：仅当该 URL 是爬取阶段已抓过的页面/种子时命中；
	// DAST payload URL 不在缓存里，语义不变。
	if d.cache != nil {
		if r, ok := d.cache.get(rawURL); ok {
			return d.wrap(r)
		}
	}
	r, err := d.c.GetDirect(rawURL)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// GetWithHeaders 带自定义请求头的 GET（Cookie/头注入通道）。
func (d dastFetcher) GetWithHeaders(rawURL string, headers map[string]string) *dast.Resp {
	r, err := d.c.GetWithHeaders(rawURL, headers)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// PostRawSmall 原始体 POST（XXE 的 XML 探测用）。
func (d dastFetcher) PostRawSmall(rawURL, contentType, body string) *dast.Resp {
	r, err := d.c.PostRaw(rawURL, contentType, body)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// PostMultipartSmall 多段上传（上传受理面探测用）。
func (d dastFetcher) PostMultipartSmall(rawURL, fileField, fileName, content string, extra map[string]string) *dast.Resp {
	r, err := d.c.PostMultipart(rawURL, fileField, fileName, content, extra)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// PostMultipartSmallCT 多段上传（可指定 Content-Type，上传绕过验证用）。
func (d dastFetcher) PostMultipartSmallCT(rawURL, fileField, fileName, content, contentType string, extra map[string]string) *dast.Resp {
	r, err := d.c.PostMultipartCT(rawURL, fileField, fileName, content, contentType, extra)
	if err != nil {
		return nil
	}
	return d.wrap(r)
}

// cveMsFindings 把微软公告关联转为统一 Finding 形态。
func cveMsFindings(ms []intel.CVEMsFinding) []intel.Finding {
	out := make([]intel.Finding, 0, len(ms))
	for _, m := range ms {
		out = append(out, intel.Finding{
			Tech: m.Tech, CVE: m.CVE, Title: m.Title,
			Severity: m.Severity, Verdict: "possible", Src: "cve_ms",
		})
	}
	return out
}

// errNoImageChannel 未配 OCR 通道时的图片拉取占位错误（爆破侧据此明确报错）。
var errNoImageChannel = errors.New("未配置验证码图片拉取通道")

// imageFetcher 验证码图片字节拉取（走同一限速客户端，单请求不跟重定向）。
func imageFetcher(client *httpx.Client) func(string) ([]byte, error) {
	return func(rawURL string) ([]byte, error) {
		r, err := client.GetDirect(rawURL)
		if err != nil || r == nil {
			return nil, err
		}
		return []byte(r.Body), nil
	}
}

// postFormPoster 表单弱口令审计的 loginbrute.Poster 适配（引擎侧）。
// 与 server 侧 httpPoster 同语义：单请求不跟重定向，让 302 成功信号可见。
type postFormPoster struct{ c *httpx.Client }

func (p postFormPoster) GetSmall(rawURL string) (int, string, error) {
	r, err := p.c.GetDirect(rawURL)
	if err != nil || r == nil {
		return 0, "", err
	}
	return r.Status, r.Body, nil
}

func (p postFormPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	r, err := p.c.PostForm(rawURL, fields)
	if err != nil || r == nil {
		return 0, "", err
	}
	return r.Status, r.Body, nil
}

func (p postFormPoster) PostJSON(rawURL, body string) (int, string, error) {
	r, err := p.c.PostJSON(rawURL, body)
	if err != nil || r == nil {
		return 0, "", err
	}
	return r.Status, r.Body, nil
}

// PostFormResponse / PostJSONResponse：实现 loginbrute 可选 ResponsePoster /
// JSONResponsePoster，让命中证据可带 Set-Cookie / Location（成功证据四件套）。
func (p postFormPoster) PostFormResponse(rawURL string, fields map[string]string) (int, string, http.Header, error) {
	r, err := p.c.PostForm(rawURL, fields)
	if err != nil || r == nil {
		return 0, "", nil, err
	}
	return r.Status, r.Body, responseHeader(r), nil
}

func (p postFormPoster) PostJSONResponse(rawURL, body string) (int, string, http.Header, error) {
	r, err := p.c.PostJSON(rawURL, body)
	if err != nil || r == nil {
		return 0, "", nil, err
	}
	return r.Status, r.Body, responseHeader(r), nil
}

// responseHeader 把 httpx.Response 的响应头/Set-Cookie 转成 http.Header（证据用）。
func responseHeader(r *httpx.Response) http.Header {
	if r == nil {
		return nil
	}
	h := make(http.Header, len(r.Headers)+1)
	for k, v := range r.Headers {
		h.Set(k, v)
	}
	for _, sc := range r.SetCookies {
		h.Add("Set-Cookie", sc)
	}
	return h
}

// collectHomeFormTargets 采集首页表单/带参链接（任何档位都执行）。
// 与爬取期的 collectForms 同语义，只差数据源是首页解析结果。
func collectHomeFormTargets(doc *htmlx.Doc, pageURL string,
	links *[]string, forms *[]dast.FormTarget, loginForms *[]loginFormEntry) {
	collectFormSignals(doc, pageURL, links, forms, loginForms)
}

// loginFormEntry 含密码框的表单页（弱口令审计入口）。
type loginFormEntry struct{ URL string }

// collectForms 采集爬取页的表单/带参链接。
func collectForms(crForms []crawler.Form,
	links *[]string, forms *[]dast.FormTarget, loginForms *[]loginFormEntry) {
	for _, f := range crForms {
		// 含密码框的表单页：登记为弱口令审计入口（表单弱口令此前零覆盖）
		if f.HasPwd && f.Action != "" {
			*loginForms = append(*loginForms, loginFormEntry{URL: f.Action})
		}
		// 文件型表单与「无字段状态变更表单」都要登记：
		// 前者是上传面入口；后者（DVWA Weak Session IDs 的
		// <form method=post><input type=submit></form>）提交后不发会
		// 弱会话 Cookie，是弱会话 ID 模块唯一可见点。
		if f.Action == "" || (len(f.Names) == 0 && len(f.FileFields) == 0 &&
			!strings.EqualFold(f.Method, "post")) {
			continue
		}
		addFormTarget(f.Action, f.Names, f.Method, f.FileFields, f.LoginFields, links, forms)
	}
}

// collectFormSignals 从 htmlx 文档采集表单信号（首页路径）。
func collectFormSignals(doc *htmlx.Doc, pageURL string,
	links *[]string, forms *[]dast.FormTarget, loginForms *[]loginFormEntry) {
	for _, f := range doc.Forms {
		action := resolveAction(pageURL, f.Action)
		if f.HasPassword && action != "" {
			*loginForms = append(*loginForms, loginFormEntry{URL: action})
		}
		names := make([]string, 0, len(f.Inputs))
		var files []string
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
		}
		// 无字段的 POST 表单也要登记（状态变更表单：DVWA Weak Session IDs
		// 就是「只有 submit 按钮」的 POST 表单，提交后下发弱会话 Cookie）。
		if action == "" || (len(names) == 0 && len(files) == 0 &&
			!strings.EqualFold(f.Method, "post")) {
			continue
		}
		addFormTarget(action, names, f.Method, files, loginFieldsOf(f.Inputs), links, forms)
	}
}

// addFormTarget 登记一个表单探测目标；GET 表单额外合成带参 URL——
// DVWA 类靶场的 SQLi/XSS 模块菜单链接不带参数、参数在 GET 表单里，
// 不合成则 URL 参数探测永远探不到。
func addFormTarget(action string, names []string, method string, files []string,
	loginFields []string, links *[]string, forms *[]dast.FormTarget) {
	if strings.EqualFold(method, "get") {
		if u, err := url.Parse(action); err == nil {
			q := u.Query()
			for _, n := range names {
				if n != "" {
					q.Set(n, "1")
				}
			}
			u.RawQuery = q.Encode()
			*links = append(*links, u.String())
		}
	}
	*forms = append(*forms, dast.FormTarget{
		Action: action, Fields: names, FileFields: files, LoginFields: loginFields,
		Method: strings.ToLower(method),
	})
}

// loginFieldsOf 从表单输入里挑出登录表单的用户名/口令字段名。
// 口令字段优先级最高（password 类型）；用户名按 type/name 语义推断。
// 找不到口令字段返回 nil（非登录表单，不做认证绕过探测）。
func loginFieldsOf(inputs []htmlx.Input) []string {
	var pwd, user string
	for _, in := range inputs {
		if in.Name == "" {
			continue
		}
		low := strings.ToLower(in.Name)
		switch {
		case in.Type == "password":
			if pwd == "" {
				pwd = in.Name
			}
		case user == "" && (strings.Contains(low, "user") || strings.Contains(low, "login") ||
			strings.Contains(low, "email") || strings.Contains(low, "account") || low == "uname"):
			user = in.Name
		}
	}
	if pwd == "" {
		return nil
	}
	if user == "" {
		return []string{pwd} // 只有口令也做（部分表单用户名固定）
	}
	return []string{user, pwd}
}

// resolveAction 解析表单相对 action（空 action 按页面自身）。
func resolveAction(pageURL, action string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return action
	}
	if action == "" {
		return pageURL
	}
	ref, err := url.Parse(action)
	if err != nil {
		return action
	}
	return base.ResolveReference(ref).String()
}

// pageLooksSensitive 判定 URL 是否属于会话/账户类页面（缓存卫生的适用面）。
func pageLooksSensitive(u string) bool {
	l := strings.ToLower(u)
	for _, h := range []string{"account", "profile", "user", "admin", "dashboard",
		"session", "login", "bank", "order", "cart", "checkout", "settings", "password"} {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// pageCacheable 判定响应是否允许被缓存（无 no-store/private/no-cache 即可缓存）。
func pageCacheable(headers map[string]string) (bool, string) {
	cc := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Cache-Control") {
			cc = strings.ToLower(v)
			break
		}
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache") {
		return false, cc
	}
	if cc == "" {
		return true, "(未设置)"
	}
	return true, cc
}

// hasCSPHeader 响应头里是否有非空的 Content-Security-Policy。
func hasCSPHeader(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Security-Policy") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
