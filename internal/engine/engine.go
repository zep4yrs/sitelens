package engine

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/crawler"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/jsmap"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
	"cnb.cool/feng-qiao/sitelens/internal/passive"
	"cnb.cool/feng-qiao/sitelens/internal/security"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Options 每次扫描可单独指定的开关（对齐 /api/scan 平铺 payload）。
type Options struct {
	Deep         bool   // 同域浅爬取
	ActiveFP     bool   // FingerDir 主动路径指纹
	DirScan      bool   // 目录探测
	DirBypass    bool   // 403 绕过重试
	Subdomain    bool   // 子域名枚举
	ServiceProbe bool   // 端口服务识别
	BrowserUA    bool   // 浏览器 UA
	WeakAudit    bool   // 敏感信息审计
	Webshell     bool   // WebShell 探测
	Netsec       bool   // TLS/DNS 安全检测
	DAST         bool   // 参数级注入探测
	Passive      bool   // 被动安全检测
	Checks       string // none | core | all
	AuthCookie   string // 授权扫描 Cookie
}

// DefaultOptions 对齐 Python 默认：deep 开、checks 关、其余关。
func DefaultOptions() Options { return Options{Deep: true, Checks: "none"} }

// progress 阶段进度回调（percent 0-100）。
type progress func(percent int, msg string)

// Engine 一次完整扫描的编排器。
type Engine struct {
	cfg       *config.Config
	matcher   *sitelens.Matcher
	kb        *intel.KB
	dastLinks []string // 爬取阶段收集的带参链接
}

// New 创建引擎。matcher / kb 可为 nil（对应能力降级跳过，不阻塞扫描）。
func New(cfg *config.Config, matcher *sitelens.Matcher, kb *intel.KB) *Engine {
	if cfg == nil {
		cfg = config.Default()
	}
	return &Engine{cfg: cfg, matcher: matcher, kb: kb}
}

// Scan 执行扫描，异常统一进 Result.Error（消息可直接展示）。
// cancel 非空时在阶段边界与 check 循环内轮询，返回 true 即尽快终止（局部结果仍返回）。
func (e *Engine) Scan(rawURL string, opts Options, onProgress progress, cancel func() bool) *Result {
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
	finish := func() {
		// 毫秒精度（原 10ms 舍入会把 <5ms 的扫描记成 0.00）
		res.Duration = float64(int(time.Since(start).Seconds()*1000)) / 1000
	}

	// 1) 校验（含 SSRF 防护）
	scheme, host, port, err := target.Validate(rawURL, e.cfg.Scan.Resolve)
	if err != nil {
		res.Error = err.Error()
		finish()
		return res
	}
	baseURL := scheme + "://" + host
	if port > 0 && !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		baseURL = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	res.URL, res.Host = baseURL, host
	onProgress(5, "校验目标："+baseURL)

	client := e.newClient(opts)

	// 2) 采集首页
	t0 := time.Now()
	home, ferr := client.GetFollow(baseURL)
	rtMS := time.Since(t0).Milliseconds()
	if ferr != nil || home == nil {
		res.Error = "连接失败：" + baseURL
		finish()
		return res
	}
	if home.Status >= 400 {
		res.Error = fmt.Sprintf("目标返回 HTTP %d", home.Status)
		finish()
		return res
	}
	onProgress(25, fmt.Sprintf("已采集首页（%d）", home.Status))

	res.IP = lookupIP(host)
	doc := htmlx.Parse(home.Body)
	res.Title = doc.Title
	res.Status = home.Status
	res.ResponseTimeMS = int(rtMS)
	res.Pages = append(res.Pages, PageInfo{URL: home.FinalURL, Status: home.Status})

	acc := newTechAcc()
	pages := []crawlPage{{resp: home, doc: doc}}

	// 3) 同域浅爬取
	if opts.Deep {
		onProgress(40, "同域浅爬取…")
		c := crawler.New(client, e.cfg.Crawler, baseURL)
		cr := c.Crawl(home)
		for i := range cr.Pages {
			p := &cr.Pages[i]
			if normalizeKey(p.FinalURL) == normalizeKey(home.FinalURL) {
				continue // 首页已收录
			}
			res.Pages = append(res.Pages, PageInfo{URL: p.FinalURL, Status: p.Status})
			pages = append(pages, crawlPage{
				resp: &httpx.Response{
					Status:     p.Status,
					Headers:    p.Headers,
					SetCookies: p.SetCookies,
					Body:       p.Body,
					FinalURL:   p.FinalURL,
				},
				doc: htmlx.Parse(p.Body),
			})
		}
		e.dastLinks = cr.ParamLinks
	}

	// 4) 多页指纹识别
	if e.matcher != nil {
		onProgress(55, fmt.Sprintf("指纹识别（%d 页）…", len(pages)))
		for _, p := range pages {
			for _, h := range e.matcher.Match(sitelens.Extract(p.resp)) {
				acc.add(h.Name, h.Website, h.Version, h.Evidence, h.Conf, h.Cats)
			}
		}
	}
	res.Technologies = acc.list()

	// 5) 安全响应头评分
	onProgress(70, "评估安全响应头…")
	res.Security = security.Assess(home.Headers)

	// 6) 验证型 check
	if opts.Checks != "" && opts.Checks != "none" {
		cmsIDs := []string{}
		for _, t := range res.Technologies {
			cmsIDs = append(cmsIDs, checks.CMSTechChecks(t.Name)...)
		}
		if len(cmsIDs) > 0 {
			onProgress(75, "CMS 联动专项 check…")
		}
		hits := checks.RunChecks(client, baseURL, opts.Checks, cmsIDs, cancelled,
			func(done, total int, msg string) {
				if total > 0 {
					onProgress(75+done*10/total, "check："+msg)
				}
			})
		for _, h := range hits {
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check": h.Check, "title": h.Title, "severity": h.Severity,
				"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
			}))
		}
	}

	// 6.5) Nuclei 社区模板子集（all 级别 + 模板库存在时）
	if opts.Checks == "all" && !cancelled() && e.cfg.Checks.NucleiCap > 0 && e.cfg.Checks.NucleiDir != "" {
		onProgress(84, "运行 Nuclei 社区模板子集…")
		if nl := e.nucleiSubset(res.Technologies, res.Title); len(nl) > 0 {
			for _, h := range checks.RunList(client, baseURL, nl, cancelled,
				func(done, total int, msg string) {
					if total > 0 {
						onProgress(84, fmt.Sprintf("nuclei %d/%d", done, total))
					}
				}) {
				res.Verified = append(res.Verified, verifiedMap(map[string]any{
					"check": h.Check, "title": h.Title, "severity": h.Severity,
					"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
					"src": "nuclei",
				}))
			}
		}
	}

	// 7) 被动安全检测（零额外请求）
	if opts.Passive {
		onProgress(80, "被动安全检测…")
		for _, p := range pages {
			for _, h := range passive.Run(p.resp, p.doc, p.resp.FinalURL) {
				res.Verified = append(res.Verified, verifiedMap(map[string]any{
					"check": h.Check, "title": h.Title, "severity": h.Severity,
					"url": h.URL, "evidence": h.Evidence, "advice": h.Advice,
					"src": "passive",
				}))
			}
		}
	}

	// 8) DAST：JS 攻击面提取 + 参数级探测
	if opts.DAST {
		onProgress(83, "JS 攻击面提取…")
		jsFind, jsEps := jsmap.Run(jsmap.NewFetcher(client), baseURL, doc, 4)
		for _, f := range jsFind {
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "js",
			}))
		}
		if len(jsEps) > 0 {
			res.Extras["js"] = jsEps
		}

		onProgress(85, "参数级 DAST 探测…")
		r := dast.New(dastFetcher{client}, dast.Options{
			MaxParams:        e.cfg.DAST.MaxParams,
			TimeBlind:        e.cfg.DAST.TimeBlind,
			BlindThresholdMS: e.cfg.DAST.BlindThresholdMS,
			SleepSeconds:     e.cfg.DAST.SleepSeconds,
			MaxURLLen:        e.cfg.DAST.MaxURLLen,
		})
		for _, f := range r.Run(e.dastLinks) {
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check": f.Check, "title": f.Title, "severity": f.Severity,
				"url": f.URL, "evidence": f.Evidence, "advice": f.Advice,
				"src": "dast", "param": f.Param,
			}))
		}
	}

	// 9) 主动模块（默认关，仅限授权目标）
	var dirHits []modules.PageHit
	if opts.DirScan || opts.Subdomain || opts.Webshell || opts.WeakAudit || opts.ActiveFP || opts.ServiceProbe {
		ac := e.cfg.Active
		if opts.Subdomain {
			onProgress(86, "子域名枚举…")
			subs := modules.SubdomainEnum(res.Host, ac, nil, cancelled)
			res.Extras["subdomain"] = subs
		}
		if opts.DirScan {
			onProgress(87, "目录探测…")
			dirHits = modules.DirScan(client, baseURL, ac, nil, cancelled)
			res.Extras["dir"] = dirHits
		}
		if opts.Webshell {
			onProgress(88, "WebShell 探测…")
			res.Extras["webshell"] = modules.WebshellProbe(client, baseURL, ac, nil, cancelled)
		}
		if opts.ActiveFP && e.kb != nil && len(e.kb.FingerDir()) > 0 {
			onProgress(89, "FingerDir 主动指纹…")
			res.Extras["active_fp"] = modules.ActiveFP(client, baseURL,
				e.kb.FingerDir(), nil, cancelled, e.cfg.Active.FPMaxRequests)
		}
		if opts.ServiceProbe && e.kb != nil && len(e.kb.ServiceFP()) > 0 {
			onProgress(89, "端口服务识别…")
			res.Extras["service"] = modules.ServiceProbe(host, e.kb.ServiceFP(),
				e.cfg.Active.ProbePorts, e.cfg.Active.ProbeTimeoutMS,
				e.cfg.Active.ProbeWorkers, nil, cancelled)
		}
		if opts.WeakAudit {
			// 基础认证弱口令：目录探测发现的 401 路径（表单弱口令走登录爆破端点）
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
				users := loginbrute.LoadList(
					wordlistPath(e.cfg, "weak_users.txt"), e.cfg.LoginBrute.MaxUsers)
				pwds := loginbrute.LoadList(
					wordlistPath(e.cfg, "weak_passwords.txt"), e.cfg.LoginBrute.MaxPasswords)
				for _, h := range loginbrute.BasicAuthBrute(client, urls401, users, pwds,
					e.cfg.LoginBrute.MaxTries, e.cfg.LoginBrute.IntervalMS, nil) {
					res.Verified = append(res.Verified, verifiedMap(map[string]any{
						"check": "weak-basic-auth", "title": "基础认证弱口令",
						"severity": "high", "url": h.URL,
						"evidence": "用户 " + h.User + " 弱口令命中",
						"advice":   "改用强口令并禁用 HTTP Basic；启用登录失败限制",
						"src":      "weak", "type": h.Type,
					}))
				}
			}
		}
	}

	// 10) 网络层安全
	if opts.Netsec {
		onProgress(89, "TLS / DNS 安全检测…")
		tlsPort := port
		if tlsPort == 0 || tlsPort == 80 {
			tlsPort = 443
		}
		findings := netsec.CheckTLS(host, tlsPort)
		if e.cfg.Netsec.MailCheck {
			findings = append(findings, netsec.CheckDNSMail(host)...)
		}
		res.Extras["netsec"] = map[string]any{"findings": findings}
	}

	// 11) 漏洞情报关联
	if !cancelled() && e.kb != nil {
		onProgress(92, "关联漏洞情报…")
		techs := acc.techHits()
		res.Vulnerabilities = append(res.Vulnerabilities, e.kb.Match(techs)...)
		res.Vulnerabilities = append(res.Vulnerabilities, cveMsFindings(e.kb.MatchCVEMs(techs, 20))...)
	}

	onProgress(100, fmt.Sprintf("完成，识别 %d 项技术，%d 条已验证发现",
		len(res.Technologies), len(res.Verified)))
	finish()
	return res
}

// ClientFor 导出客户端装配（登录爆破等模块复用同一套限速/UA/Cookie 配置）。
func (e *Engine) ClientFor(opts Options) *httpx.Client { return e.newClient(opts) }

// ---- 内部辅助 ----

type crawlPage struct {
	resp *httpx.Response
	doc  *htmlx.Doc
}

// newClient 按配置与本次选项装配客户端。
func (e *Engine) newClient(opts Options) *httpx.Client {
	sc := e.cfg.Scan
	return httpx.NewWithOptions(httpx.ClientOptions{
		Interval:     time.Duration(sc.RateIntervalMS) * time.Millisecond,
		Timeout:      time.Duration(sc.TimeoutSec) * time.Second,
		MaxHops:      sc.MaxHops,
		MaxBodyBytes: sc.MaxBodyMB * 1024 * 1024,
		UserAgent:    uaFor(sc.UserAgent, opts.BrowserUA),
		AuthCookie:   opts.AuthCookie,
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

// nucleiCursor 跨扫描轮转游标（进程级：保证无 tag 信号的模板长期全覆盖）。
var nucleiCursor int
var nucleiMu sync.Mutex

// nucleiSubset 按已识别技术挑选 Nuclei 模板并转换为 check。
func (e *Engine) nucleiSubset(techs []Tech, pageTitle string) []checks.Check {
	entries, err := nuclei.Index(e.cfg.Checks.NucleiDir,
		filepath.Join(e.cfg.Store.DataDir, "nuclei_index.json"))
	if err != nil || len(entries) == 0 {
		return nil
	}
	tags := map[string]bool{}
	var names []string
	for _, t := range techs {
		tags[strings.ToLower(t.Name)] = true
		names = append(names, t.Name)
	}
	// 相关度查询文本：技术名 + 页面标题（模板名/tag 词面重合排序）
	query := strings.Join(names, " ") + " " + pageTitle
	nucleiMu.Lock()
	selected := nuclei.Select(entries, tags, query, e.cfg.Checks.NucleiCap, &nucleiCursor)
	nucleiMu.Unlock()

	var out []checks.Check
	for _, ent := range selected {
		cs, err := nuclei.LoadFile(filepath.Join(e.cfg.Checks.NucleiDir, filepath.FromSlash(ent.Path)))
		if err != nil {
			continue
		}
		out = append(out, cs...)
	}
	return out
}

// dastFetcher 把 httpx 客户端适配为 dast.Fetcher。
type dastFetcher struct{ c *httpx.Client }

func (d dastFetcher) GetSmall(rawURL string) *dast.Resp {
	r, err := d.c.GetDirect(rawURL)
	if err != nil || r == nil {
		return nil
	}
	return &dast.Resp{Status: r.Status, Headers: r.Headers, Body: r.Body}
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
