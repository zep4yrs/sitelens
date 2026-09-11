// Package dast 参数级无害注入检测（主动验证模块）。
//
// 检测类型：反射 XSS / 报错 SQLi / 时间盲注 / 开放重定向 / 目录遍历。
// 原理：对爬取到的带参数链接逐参数注入安全标记/探测值，按响应特征判定。
// 全部为只读探测（不破坏数据、不执行远程命令），请求总量有上限。
// 误报防护：报错特征与遍历特征先取目标基线剔除（页面本来就有的不算），
// 时间盲注命中后复测一次双确认（防网络抖动）。
package dast

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 探测标记与判定特征。标记含随机段，正常页面不可能天然含有。
const (
	xssMark   = "slq9z7\"><svg/onload=slq9z7>"
	xssRaw    = "slq9z7\"><svg"
	traversal = "../../../../../../../../etc/passwd"
	travHit   = "root:x:0:0:"
	redirMark = "//sitelens-dt.example.com"
)

// sqlErrors 报错型 SQLi 特征（与基线求差后判定）。
var sqlErrors = []string{
	"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
	"unclosed quotation", "jdbc", "pg_query", "odbc", "sqlstate",
	"sqlite3.", "sqlcmd", "syntax error at or near",
	"unterminated quoted string", "mysql_num_rows",
}

// Options 探测阈值（.sitelens.yml [dast] 节可覆盖）。
type Options struct {
	MaxParams        int    // 最多探测的参数个数
	TimeBlind        bool   // 是否做时间盲注（每参数多 2 个请求）
	BoolBlind        bool   // 是否做布尔差分盲注（每参数 5 个请求）
	BlindThresholdMS int64  // 时间盲注延迟判定阈值（毫秒）
	SleepSeconds     int    // 注入的 SLEEP 秒数
	MaxURLLen        int    // 探测 URL 长度上限，超过则跳过
	BeaconBase       string // SSRF 出带回调基地址（空 = 禁用）
	MaxProbes        int    // 出带探测参数上限
}

// DefaultOptions 最佳实践默认值。
func DefaultOptions() Options {
	return Options{
		MaxParams:        24,
		TimeBlind:        true,
		BoolBlind:        true,
		BlindThresholdMS: 3500,
		SleepSeconds:     4,
		MaxURLLen:        2048,
	}
}

// Resp 最小响应（由引擎把 httpx.Response 适配过来）。
type Resp struct {
	Status  int
	Headers map[string]string
	Body    string
}

// Header 大小写不敏感取响应头。
func (r *Resp) Header(name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// Fetcher HTTP 请求接口：单请求、不跟随重定向（开放重定向需要看原始 30x）。
type Fetcher interface {
	GetSmall(rawURL string) *Resp
	// PostFormSmall 表单 POST（表单探测用；同不跟随重定向）。
	PostFormSmall(rawURL string, data map[string]string) *Resp
}

// Target 带参数的探测目标。
type Target struct {
	URL   string // 完整 URL（含 query）
	Param string // 参数名
}

// Runner DAST 探测执行器。
type Runner struct {
	fetch  Fetcher
	opts   Options
	cancel func() bool
	prog   func(done, total int, msg string)
}

// New 创建 DAST 探测器。
func New(f Fetcher, opts Options) *Runner {
	if opts.MaxParams <= 0 {
		opts.MaxParams = 24
	}
	if opts.MaxURLLen <= 0 {
		opts.MaxURLLen = 2048
	}
	return &Runner{fetch: f, opts: opts}
}

// SetCancel 设置取消钩子（阶段边界检查）。
func (r *Runner) SetCancel(fn func() bool) { r.cancel = fn }

// SetProgress 设置进度回调（done/total 为探测请求数）。
func (r *Runner) SetProgress(fn func(done, total int, msg string)) { r.prog = fn }

func (r *Runner) stopped() bool { return r.cancel != nil && r.cancel() }

// Run 对全部探测目标执行注入检测，返回命中的发现。
func (r *Runner) Run(links []string) []Finding {
	targets := collectParams(links, r.opts.MaxParams)
	if len(targets) == 0 {
		return nil
	}
	perTarget := 5 // 基线 + xss / sqli / redirect / traversal
	if r.opts.TimeBlind {
		perTarget += 3 // 基线 + 注入 + 复测
	}
	total := len(targets) * perTarget
	done := 0
	tick := func(msg string) {
		done++
		if r.prog != nil {
			r.prog(done, total, msg)
		}
	}

	var hits []Finding
	for _, tgt := range targets {
		if r.stopped() {
			break
		}
		// 基线：原 URL 响应。页面天然含有的报错/系统特征不算命中。
		baseBody := ""
		if base := r.fetch.GetSmall(tgt.URL); base != nil {
			baseBody = strings.ToLower(base.Body)
		}
		tick(shortLabel(tgt))

		for _, probe := range []struct {
			kind  string
			value string
		}{
			{"xss", xssMark},
			{"sqli", "'"},
			{"redirect", redirMark},
			{"traversal", traversal},
		} {
			if r.stopped() {
				return hits
			}
			probeURL := setParam(tgt.URL, tgt.Param, probe.value)
			if len(probeURL) > r.opts.MaxURLLen {
				tick(shortLabel(tgt))
				continue
			}
			resp := r.fetch.GetSmall(probeURL)
			tick(shortLabel(tgt))
			if resp == nil {
				continue
			}
			if hit := judge(probe.kind, resp, baseBody, tgt); hit != nil {
				hit.Payload = probe.value
				hit.Replay = curlReplay(probeURL)
				hit.Signals = []string{probe.kind + " 探针命中"}
				chainEvidence(hit, probeURL, resp)
				hits = append(hits, *hit)
			}
		}

		if r.opts.TimeBlind && !r.stopped() {
			if f := r.timeBlind(tgt, &done, total); f != nil {
				hits = append(hits, *f)
			}
		}
		if r.opts.BoolBlind && !r.stopped() {
			if f := r.boolBlind(tgt, &done, total); f != nil {
				hits = append(hits, *f)
			}
		}
		if r.opts.BoolBlind && !r.stopped() {
			if f := r.deserProbe(tgt, &done, total); f != nil {
				hits = append(hits, *f)
			}
		}
	}
	// SSRF 出带回调：目标侧回连本服务 beacon 即确认可达
	if r.opts.BeaconBase != "" && !r.stopped() {
		hits = append(hits, r.ssrfProbe(targets)...)
	}
	return hits
}

// FormTarget POST 表单探测目标（来自爬虫的表单采集）。
type FormTarget struct {
	Action string   // 绝对 URL
	Fields []string // 可注入字段名
}

// RunForms 对表单字段执行与 URL 参数相同的四类无害探测。
// 与 Run 的差异：注入走表单字段（其余字段填基线值），判定复用
// judge；时间盲注暂不覆盖表单（Fetcher 无计时报文，避免假阴/假阳）。
// 字段总预算并入 opts.MaxParams。
func (r *Runner) RunForms(targets []FormTarget) []Finding {
	// 字段预算：全局 MaxParams 与链接参数共享，表单侧先到先得
	budget := r.opts.MaxParams
	type planItem struct {
		ft    FormTarget
		field string
	}
	var plan []planItem
	seen := map[string]bool{}
	for _, ft := range targets {
		if ft.Action == "" || r.stopped() {
			continue
		}
		for _, f := range ft.Fields {
			if f == "" || budget <= 0 {
				continue
			}
			key := ft.Action + "\x00" + f
			if seen[key] {
				continue
			}
			seen[key] = true
			budget--
			plan = append(plan, planItem{ft, f})
		}
	}
	if len(plan) == 0 {
		return nil
	}

	total := len(plan) * 5 // 基线 + xss / sqli / redirect / traversal
	done := 0
	tick := func(label string) {
		done++
		if r.prog != nil {
			r.prog(done, total, label)
		}
	}

	var hits []Finding
	for _, p := range plan {
		if r.stopped() {
			break
		}
		label := p.field + "@" + p.ft.Action
		// 基线：全部字段填惰性值（页面天然含有的报错/系统特征不算命中）
		baseData := map[string]string{}
		for _, f := range p.ft.Fields {
			if f != "" {
				baseData[f] = "sl-dast-base"
			}
		}
		baseBody := ""
		if base := r.fetch.PostFormSmall(p.ft.Action, baseData); base != nil {
			baseBody = strings.ToLower(base.Body)
		}
		tick(label)

		for _, probe := range []struct {
			kind  string
			value string
		}{
			{"xss", xssMark},
			{"sqli", "'"},
			{"redirect", redirMark},
			{"traversal", traversal},
		} {
			if r.stopped() {
				return hits
			}
			data := map[string]string{}
			for f := range baseData {
				data[f] = "sl-dast-base"
			}
			data[p.field] = probe.value
			resp := r.fetch.PostFormSmall(p.ft.Action, data)
			tick(label)
			if resp == nil {
				continue
			}
			if hit := judge(probe.kind, resp, baseBody, Target{URL: p.ft.Action, Param: p.field}); hit != nil {
				hits = append(hits, *hit)
			}
		}
	}
	return hits
}

// timeBlind 时间盲注：基线计时 → 注入 SLEEP → 超阈值再复测一次双确认。
func (r *Runner) timeBlind(tgt Target, done *int, total int) *Finding {
	label := shortLabel(tgt)
	sleep := r.opts.SleepSeconds
	if sleep <= 0 {
		sleep = 4
	}
	if len(setParam(tgt.URL, tgt.Param, sleepPayload(sleep))) > r.opts.MaxURLLen {
		return nil
	}

	start := time.Now()
	r.fetch.GetSmall(setParam(tgt.URL, tgt.Param, "1"))
	baseMS := time.Since(start).Milliseconds()
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	if r.stopped() {
		return nil
	}

	start = time.Now()
	inj := r.fetch.GetSmall(setParam(tgt.URL, tgt.Param, sleepPayload(sleep)))
	injMS := time.Since(start).Milliseconds()
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	if inj == nil || injMS < r.opts.BlindThresholdMS || baseMS >= r.opts.BlindThresholdMS {
		return nil // 首测未超阈值，或基线本身就慢
	}
	if r.stopped() {
		return nil
	}

	// 双确认：注入再测一次仍超阈值才报（防网络抖动）
	if r.stopped() {
		return nil
	}
	start = time.Now()
	again := r.fetch.GetSmall(setParam(tgt.URL, tgt.Param, sleepPayload(sleep)))
	againMS := time.Since(start).Milliseconds()
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	if again == nil || againMS < r.opts.BlindThresholdMS {
		return nil
	}
	return &Finding{
		Check:    "sqli-blind-time",
		Title:    "时间盲注 SQL 注入（响应延迟异常）",
		Severity: "high",
		URL:      tgt.URL,
		Param:    tgt.Param,
		Evidence: "注入 SLEEP 后响应耗时两次为 " +
			formatMS(injMS) + " / " + formatMS(againMS) +
			"，基线 " + formatMS(baseMS),
		Advice: "使用参数化查询；限制查询执行时间",
	}
}

func sleepPayload(seconds int) string {
	return "1 AND SLEEP(" + strconv.Itoa(seconds) + ")"
}

func formatMS(ms int64) string {
	return strconv.FormatInt(ms, 10) + "ms"
}

func shortLabel(tgt Target) string {
	u, err := url.Parse(tgt.URL)
	if err != nil {
		return tgt.Param
	}
	name := u.Path
	if name == "" {
		name = "/"
	}
	return name + "?" + tgt.Param
}

// Finding 一条 DAST 检测发现。
// RespSnap 证据链响应快照。
type RespSnap struct {
	Status  int    `json:"status"`
	Size    int    `json:"size"`
	Snippet string `json:"snippet"`
}

type Finding struct {
	Check      string    `json:"check"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	URL        string    `json:"url"`
	Param      string    `json:"param"`
	Evidence   string    `json:"evidence"`
	Advice     string    `json:"advice"`
	Payload    string    `json:"payload,omitempty"`    // 注入的探针值（证据链）
	Replay     string    `json:"replay,omitempty"`     // curl 一键复现命令（证据链）
	Request    string    `json:"request,omitempty"`    // 重放请求文本（证据链）
	Response   *RespSnap `json:"response,omitempty"`   // 命中响应快照（证据链）
	Signals    []string  `json:"signals,omitempty"`    // 通道命中信号明细（证据链）
	Hypothesis string    `json:"hypothesis,omitempty"` // 验证假设（2.0 证据链扩展位）
	Impact     string    `json:"impact,omitempty"`     // 影响面说明（2.0 证据链扩展位）
}

// curlReplay DAST 探针的复现命令（GET 语义，与探测行为一致）。
func curlReplay(u string) string {
	return "curl -sk --path-as-is '" + strings.ReplaceAll(u, "'", `'\''`) + "'"
}

// reqText 重放请求文本（GET 探针语义）。
func reqText(u string) string {
	path, host := "/", ""
	if p, err := url.Parse(u); err == nil {
		if p.Path != "" {
			path = p.Path
		}
		if p.RawQuery != "" {
			path += "?" + p.RawQuery
		}
		host = p.Host
	}
	return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
}

// snippetOf 命中正文摘要（压缩空白取头部，全量以复现命令为准）。
func snippetOf(body string) string {
	c := strings.Join(strings.Fields(body), " ")
	r := []rune(c)
	if len(r) > 240 {
		return string(r[:240]) + "…"
	}
	return c
}

// chainEvidence 为命中发现填充统一证据链（请求/响应/信号）。
func chainEvidence(f *Finding, probeURL string, resp *Resp) {
	if f == nil {
		return
	}
	f.Request = reqText(probeURL)
	f.Replay = curlReplay(probeURL)
	if resp != nil {
		f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
	}
}

// collectParams 从爬取到的链接收集待探测参数：按「主机+路径+参数名」去重，上限 cap。
func collectParams(links []string, cap int) []Target {
	seen := map[string]bool{}
	var out []Target
	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil || u.Host == "" || u.RawQuery == "" {
			continue
		}
		for name := range u.Query() {
			key := u.Host + u.Path + "|" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Target{URL: link, Param: name})
			if len(out) >= cap {
				return out
			}
		}
	}
	return out
}

// setParam 替换（或追加）query 参数值，保留其余参数。
func setParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// judge 根据探测类型和响应判定是否命中；baseline 为原页面小写正文（误报剔除）。
func judge(kind string, resp *Resp, baseline string, tgt Target) *Finding {
	body := strings.ToLower(resp.Body)

	switch kind {
	case "xss":
		if strings.Contains(body, xssRaw) {
			return &Finding{
				Check: "xss-reflect", Title: "反射型 XSS（标记未转义回显）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 回显未转义标记",
				Advice:   "对该参数输出做 HTML 转义或上下文编码",
			}
		}
	case "sqli":
		for _, e := range sqlErrors {
			if strings.Contains(body, e) && !strings.Contains(baseline, e) {
				return &Finding{
					Check: "sqli-error", Title: "报错型 SQL 注入特征",
					Severity: "high", URL: tgt.URL, Param: tgt.Param,
					Evidence: "注入单引号触发数据库报错特征：" + e,
					Advice:   "使用参数化查询；关闭详细报错回显",
				}
			}
		}
	case "redirect":
		loc := strings.ToLower(resp.Header("Location"))
		if redirectStatus(resp.Status) && strings.Contains(loc, redirMark) {
			return &Finding{
				Check: "open-redirect", Title: "开放重定向",
				Severity: "medium", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 可控制跳转目标（Location: " +
					resp.Header("Location") + "）",
				Advice: "重定向目标使用白名单校验",
			}
		}
	case "traversal":
		if strings.Contains(body, travHit) && !strings.Contains(baseline, travHit) {
			return &Finding{
				Check: "lfi-passwd", Title: "目录遍历读取 /etc/passwd",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 注入 ../ 序列读到系统文件",
				Advice:   "路径白名单校验，禁止 .. 序列",
			}
		}
	}
	return nil
}

func redirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}
