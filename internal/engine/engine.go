package engine

import (
	"fmt"
	"net"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/crawler"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
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
		res.Duration = float64(int(time.Since(start).Seconds()*100)) / 100
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

	// 8) DAST 参数级探测
	if opts.DAST {
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
	if opts.DirScan || opts.Subdomain || opts.Webshell {
		ac := e.cfg.Active
		if opts.Subdomain {
			onProgress(86, "子域名枚举…")
			subs := modules.SubdomainEnum(res.Host, ac, nil, cancelled)
			res.Extras["subdomain"] = subs
		}
		if opts.DirScan {
			onProgress(87, "目录探测…")
			res.Extras["dir"] = modules.DirScan(client, baseURL, ac, nil, cancelled)
		}
		if opts.Webshell {
			onProgress(88, "WebShell 探测…")
			res.Extras["webshell"] = modules.WebshellProbe(client, baseURL, ac, nil, cancelled)
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
