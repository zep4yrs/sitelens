// Package dast 参数级无害注入检测（主动验证模块）。
//
// 检测类型：反射 XSS / 报错 SQLi / 时间盲注 / 开放重定向 / 目录遍历。
// 原理：对爬取到的带参数链接逐参数注入安全标记/探测值，按响应特征判定。
// 全部为只读探测（不破坏数据、不执行远程命令），请求总量有上限。
// 误报防护：报错特征与遍历特征先取目标基线剔除（页面本来就有的不算），
// 时间盲注命中后复测一次双确认（防网络抖动）。
package dast

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 探测标记与判定特征。标记含随机段，正常页面不可能天然含有。
const (
	xssMark = "slq9z7\"><svg/onload=slq9z7>"
	xssRaw  = "slq9z7\"><svg"
	// redirHost 开放重定向的标记域名（Location 含它即说明参数可控跳转目标）
	redirHost = "sitelens-dt.example.com"
)

// sqlErrors 报错型 SQLi 特征（与基线求差后判定）。
// 覆盖 MySQL / MariaDB / PostgreSQL / Oracle / SQLite / MSSQL / PHP 警告
// 七族：sqli-labs 这类靶场只回显 PHP 警告或 SQL 片段，特征表窄了就是漏报。
var sqlErrors = []string{
	"sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
	"mysql_result", "ora-", "postgresql", "sqlite",
	"unclosed quotation", "jdbc", "pg_query", "odbc", "sqlstate",
	"sqlite3.", "sqlcmd", "syntax error at or near",
	"unterminated quoted string", "you have an error in your sql",
	"warning: mysqli", "warning: mysql", "supplied argument is not a valid mysql",
	"quoted string not properly terminated", "microsoft ole db provider for sql server",
	"odbc sql server driver", "unclosed quotation mark after the character string",
	"java.sql.sqlsyntaxerrorexception", "pg::syntaxerror", "invalid query",
	"error based", "check the manual that corresponds to your",
}

// traversalMarks 目录遍历命中内容特征（多文件多形态）。
// 只认 /etc/passwd 会漏 Windows 目标与 CVE 根路径变体；
// 全部与基线求差后判定（页面本来就有的不算）。
var traversalMarks = []string{
	"root:x:0:0:", "root:x:0:0", "daemon:x:1:1:", // Linux /etc/passwd
	"[boot loader]", "[operating systems]", // Windows boot.ini
	"[fonts]", "[extensions]", "for 16-bit app support", // Windows win.ini
	"127.0.0.1\tlocalhost", "127.0.0.1 localhost", // /etc/hosts
}

// traversalProbes 目录遍历探针序列（按优先级）。
// 文件面：passwd（Linux）→ win.ini / boot.ini（Windows，多形态）。
// 编码面 6 形态：原生 ../ / 双写 ....// / URL 编码 %2e%2e%2f / 绝对路径 /
// 混编 ..%2f / 双重编码 %252e%252e%252f——覆盖常见过滤器绕过。
// 顺序即优先级：文件外层、编码内层，最可能命中的组合排最前。
var traversalFiles = []string{
	"/etc/passwd", "/windows/win.ini", "/etc/hosts", "/boot.ini",
}

var traversalEncodings = []string{
	"../../../../../../../../{f}",                      // 原生
	"....//....//....//....//....//....//{f}",          // 双写斜杠绕过
	"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{f}", // URL 编码
	"{f}",                               // 绝对路径
	"..%2f..%2f..%2f..%2f..%2f..%2f{f}", // 混编编码
	"%252e%252e%252f%252e%252e%252f%252e%252e%252f{f}", // 双重编码
}

var traversalProbes = func() []string {
	var ps []string
	for _, f := range traversalFiles {
		for _, enc := range traversalEncodings {
			ps = append(ps, strings.ReplaceAll(enc, "{f}", f))
		}
	}
	return ps
}()

// redirProbes 开放重定向探针序列：协议相对 / 绝对 / 反斜杠变体。
var redirProbes = []string{
	"//sitelens-dt.example.com",
	"https://sitelens-dt.example.com/",
	`\/\/sitelens-dt.example.com`,
}

// sqliErrorProbes 报错型 SQLi 探针序列：单引号 / 双引号 / 括号闭合 /
// 数字型尾随——不同上下文触发报错的位置不同。
var sqliErrorProbes = []string{"'", "\"", "')", "1'"}

// xssProbes 反射型 XSS 探针序列：标签突破 + 属性突破 + 纯文本标记。
// 判定统一看未转义标记是否原样回显（与基线求差）。
var xssProbes = []string{
	xssMark,
	"\"><script>slq9z7</script>",
	"javascript:slq9z7",
}

// Options 探测阈值（.sitelens.yml [dast] 节可覆盖）。
type Options struct {
	MaxParams         int           // 最多探测的参数个数
	TimeBlind         bool          // 是否做时间盲注（每参数多 2 个请求）
	BoolBlind         bool          // 是否做布尔差分盲注（每参数 5 个请求）
	BlindThresholdMS  int64         // 时间盲注延迟判定阈值（毫秒）
	SleepSeconds      int           // 注入的 SLEEP 秒数
	MaxURLLen         int           // 探测 URL 长度上限，超过则跳过
	BeaconBase        string        // SSRF 出带回调基地址（空 = 禁用）
	MaxProbes         int           // 出带探测参数上限
	DeepProbes        *bool         // 深度探测面总闸（nil = 默认开）
	CmdInject         bool          // 命令注入时间差分（重类，默认开）
	CRLF              bool          // CRLF 响应头注入
	MaxProbesPerClass int           // 单类探针上限（防重类吃满预算，默认 12）
	ErrorStatus       *bool         // 报错状态差分通道（nil = 默认开）
	RandomDiff        bool          // 会话载体随机差分（两次取样比标识值，默认开）
	StoredXSS         bool          // 存储型 XSS 探测（写无害标记，跨请求读回）
	CacheHygiene      bool          // 敏感页缓存卫生（缺 no-store 判定）
	WeakCookie        bool          // 状态变更表单下发弱会话 Cookie（值形态判定）
	CaptchaReplay     bool          // 验证码重放/校验缺失（侧信道，不需 OCR）
	AuthzBypass       bool          // 越权（授权绕过）探测：身份标识可控 + 无访问控制
	APIAudit          bool          // 开放 API 通道（未授权读取 / IDOR）
	CryptoProbe       bool          // 加密实现弱点（确定性加密 / 弱算法）
	UploadBypass      bool          // 上传绕过验证（危险扩展名/类型/双扩展名）
	OnHit             func(Finding) // 命中即时回调（实时事件流，nil = 不回调）
}

// DefaultOptions 最佳实践默认值。
func DefaultOptions() Options {
	return Options{
		MaxParams:         24,
		TimeBlind:         true,
		BoolBlind:         true,
		BlindThresholdMS:  3500,
		SleepSeconds:      4,
		MaxURLLen:         2048,
		CmdInject:         true,
		CRLF:              true,
		RandomDiff:        true,
		StoredXSS:         true,
		CacheHygiene:      true,
		WeakCookie:        true,
		CaptchaReplay:     true,
		AuthzBypass:       true,
		APIAudit:          true,
		CryptoProbe:       true,
		UploadBypass:      true,
		MaxProbesPerClass: 12,
	}
}

// Resp 最小响应（由引擎把 httpx.Response 适配过来）。
type Resp struct {
	Status  int
	Headers map[string]string
	// SetCookies 单条保真的 Set-Cookie（httpx 有意不并入 Headers：
	// Go http.Header 本就逐条分离，弱会话判定需要看值形态）。
	SetCookies []string
	Body       string
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
	// PostRawSmall 原始体 POST（XXE 的 XML 体探测用；同不跟随重定向）。
	// 可选实现：返回 nil 表示不支持，XXE 通道自动跳过（不误报）。
	PostRawSmall(rawURL, contentType, body string) *Resp
	// PostMultipartSmall 多段上传（上传面探测用；同不跟随重定向）。
	// 可选实现：返回 nil 表示不支持，上传通道自动跳过（不误报）。
	PostMultipartSmall(rawURL, fileField, fileName, content string, extra map[string]string) *Resp
}

// HeaderFetcher 可选扩展：支持带自定义请求头的单请求（Cookie/头注入通道）。
type HeaderFetcher interface {
	GetWithHeaders(rawURL string, headers map[string]string) *Resp
}

// MultipartCTFetcher 可选扩展：支持指定 Content-Type 的多段上传
// （上传绕过验证需要「危险扩展名 + 伪造 MIME」组合）。
// 可选实现：返回 nil 表示不支持，上传绕过通道自动跳过（不误报）。
type MultipartCTFetcher interface {
	PostMultipartSmallCT(rawURL, fileField, fileName, content, contentType string, extra map[string]string) *Resp
}

// Target 带参数的探测目标。
type Target struct {
	URL         string // 完整 URL（含 query）
	Param       string // 参数名
	Status      int    // 基线 HTTP 状态码（报错状态差分通道用；0 = 未知）
	ErrorStatus bool   // 报错状态差分开关（Run 里按 Options 回填）
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
	if opts.MaxProbesPerClass <= 0 {
		opts.MaxProbesPerClass = 12
	}
	return &Runner{fetch: f, opts: opts}
}

// SetCancel 设置取消钩子（阶段边界检查）。
func (r *Runner) SetCancel(fn func() bool) { r.cancel = fn }

// SetProgress 设置进度回调（done/total 为探测请求数）。
func (r *Runner) SetProgress(fn func(done, total int, msg string)) { r.prog = fn }

func (r *Runner) stopped() bool { return r.cancel != nil && r.cancel() }

// Run 对全部探测目标执行注入检测，返回命中的发现。
//
// 每参数探测预算：基线 1 + XSS/报错SQLi/重定向/遍历 各自的探针序列 +
// 时间盲注 3 + 布尔通道 2N + 反序列化 1。探针序列按优先级短路
// （首个命中即停），未命中才继续下一个探针。
func (r *Runner) Run(links []string) []Finding {
	targets := collectParams(links, r.opts.MaxParams)
	if len(targets) == 0 {
		return nil
	}
	// 进度条总长：与测试上界共用同一口径（maxURLRequestsPerParam），避免两处漂移。
	perTarget := maxURLRequestsPerParam(r.opts)
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
		// 同时记基线状态码：报错状态差分通道要拿它判断"注入把页面打崩了"。
		baseBody := ""
		if base := r.fetch.GetSmall(tgt.URL); base != nil {
			baseBody = strings.ToLower(base.Body)
			tgt.Status = base.Status
		}
		tgt.ErrorStatus = r.errorStatusEnabled()
		tick(shortLabel(tgt))

		hits = append(hits, r.probeSequences(tgt, baseBody, &done, total)...)

		// 深度面里两件 probeSequences 放不下的：命令注入（时间差分 + 双确认，
		// 不是单发探针）与 CRLF（要拿响应头基线比对）。其余深度家族已由
		// probeSequences 的类表覆盖，不重复发请求。
		if r.deepEnabled() && !r.stopped() {
			var baseHeaders map[string]bool
			if base := r.fetch.GetSmall(tgt.URL); base != nil {
				baseHeaders = headerNameSet(base)
			}
			done++
			if r.prog != nil {
				r.prog(done, total, shortLabel(tgt))
			}
			hits = append(hits, r.deepResidual(tgt, baseHeaders, &done, total)...)
		}

		// Cookie / 头注入通道（sqli-labs Less-24/42~45 类入口；需扩展接口）
		if r.deepEnabled() && !r.stopped() {
			hits = append(hits, r.cookieHeaderProbe(tgt, baseBody, &done, total)...)
		}

		if r.opts.TimeBlind && !r.stopped() {
			if f := r.timeBlind(tgt, &done, total); f != nil {
				hits = append(hits, *f)
			}
		}
		if r.opts.BoolBlind && !r.stopped() {
			if f := r.boolBlind(tgt, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
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

// probeSequences 对单个目标跑四类探针序列（XSS / 报错 SQLi /
// 开放重定向 / 目录遍历），每类按优先级短路，命中即停该类。
func (r *Runner) probeSequences(tgt Target, baseBody string, done *int, total int) []Finding {
	label := shortLabel(tgt)
	var hits []Finding
	type probeCase struct {
		kind   string
		values []string
	}
	cases := []probeCase{
		{"xss", xssProbes},
		{"sqli", sqliErrorAll()},
		{"redirect", redirProbes},
		{"traversal", traversalProbes},
	}
	if r.deepEnabled() {
		for _, dc := range probeSequenceDeepClasses() {
			cases = append(cases, probeCase{dc.Kind, dc.Values})
		}
	}
	for _, pc := range cases {
		for i, value := range pc.values {
			if r.stopped() || (r.opts.MaxProbesPerClass > 0 && i >= r.opts.MaxProbesPerClass) {
				break
			}
			probeURL := setParam(tgt.URL, tgt.Param, value)
			if len(probeURL) > r.opts.MaxURLLen {
				*done++
				if r.prog != nil {
					r.prog(*done, total, label)
				}
				continue
			}
			resp := r.fetch.GetSmall(probeURL)
			*done++
			if r.prog != nil {
				r.prog(*done, total, label)
			}
			if resp == nil {
				continue
			}
			hit := probeJudge(pc.kind, resp, baseBody, tgt)
			if hit == nil {
				continue
			}
			hit.Payload = value
			chainEvidence(hit, probeURL, resp)
			hit.Signals = []string{pc.kind + " 探针命中"}
			if r.opts.OnHit != nil {
				r.opts.OnHit(*hit)
			}
			hits = append(hits, *hit)
			break // 该类命中即停，省预算给其余类别
		}
	}
	return hits
}

// FormTarget POST 表单探测目标（来自爬虫的表单采集）。
type FormTarget struct {
	Action     string   // 绝对 URL
	Fields     []string // 可注入字段名
	FileFields []string // 文件型字段名（上传面探测用）
	// LoginFields 登录表单的用户名/口令字段（非空 = 该表单是登录表单）。
	// 用于 SQLi 认证绕过探测：SQLi 登录绕过（admin'--）与表单盲注是不同的
	// 判定通道——成功登录返回 302/跳转，尺寸差分判不出。
	LoginFields []string
	// Method 表单方法（小写）。状态变更探测只对 POST 表单做——
	// DVWA Weak Session IDs 是「无字段 + POST 提交按钮」这种形态。
	Method string
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
	total := len(plan) * 5 // 基线 + xss / sqli / redirect / traversal
	done := 0
	tick := func(label string) {
		done++
		if r.prog != nil {
			r.prog(done, total, label)
		}
	}

	var hits []Finding
	xxeDone := map[string]bool{}
	uploadDone := map[string]bool{}

	// SQLi 认证绕过：登录表单专用通道（302 型成功在尺寸差分下不可见）。
	// 独立于字段注入 plan——登录表单的成功/失败不以响应尺寸区分。
	hits = append(hits, r.runAuthBypass(targets, &done, total)...)

	// 上传受理面探测：对含 input[type=file] 的表单提交一次无害文本文件。
	// 与字段注入 plan 分开——上传表单（upload-labs 类）往往没有可注入的
	// 文本字段、不进 plan，此行在其之前，plan 为空也照样探。
	if r.deepEnabled() {
		for _, ft := range targets {
			if r.stopped() {
				break
			}
			if ft.Action == "" || len(ft.FileFields) == 0 || uploadDone[ft.Action] {
				continue
			}
			uploadDone[ft.Action] = true
			for _, ff := range ft.FileFields {
				if r.stopped() || ff == "" {
					break
				}
				extra := map[string]string{}
				for _, f := range ft.Fields {
					if f != "" {
						extra[f] = "sl-upload-probe"
					}
				}
				if f := r.uploadProbe(ft.Action, ff, extra, &done, total); f != nil {
					if r.opts.OnHit != nil {
						r.opts.OnHit(*f)
					}
					hits = append(hits, *f)
				}
				// 上传绕过验证：受理面之上再判「危险扩展名/类型是否被放行」。
				// 只在受理面成立时才有意义（uploadProbe 内部会重复建基线，
				// 这里独立判定，拒绝一切的表单不会误报）。
				if r.opts.UploadBypass {
					hits = append(hits, r.uploadBypassProbe(ft, ff, extra)...)
				}
				break // 每表单只探第一个文件字段
			}
		}
	}

	// 存储型 XSS：写无害标记 → 跨请求读回。与字段注入 plan 分开——
	// 反射通道看的是「同一响应回显」，存储通道看的是「持久化后别处读到」。
	if r.opts.StoredXSS {
		storedDone := map[string]bool{}
		for _, ft := range targets {
			if r.stopped() {
				break
			}
			if ft.Action == "" || len(ft.Fields) == 0 || storedDone[ft.Action] {
				continue
			}
			storedDone[ft.Action] = true
			if f := r.storedXSSSubmit(ft, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
		}
	}

	// 状态变更表单（无字段 + POST 提交按钮）：提交一次观测是否下发
	// 弱形态会话 Cookie。DVWA Weak Session IDs 模块唯一可见点。
	if r.opts.WeakCookie {
		scDone := map[string]bool{}
		for _, ft := range targets {
			if r.stopped() {
				break
			}
			if ft.Action == "" || len(ft.Fields) > 0 || scDone[ft.Action] ||
				len(ft.LoginFields) > 0 {
				continue
			}
			scDone[ft.Action] = true
			if f := r.stateChangeSubmit(ft, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
		}
	}

	// 加密实现弱点（确定性加密 / 弱算法）：提交定值看密文形态。
	if r.opts.CryptoProbe {
		cryptoDone := map[string]bool{}
		for _, ft := range targets {
			if r.stopped() {
				break
			}
			if ft.Action == "" || len(ft.Fields) == 0 || cryptoDone[ft.Action] {
				continue
			}
			cryptoDone[ft.Action] = true
			if f := r.cryptoDeterminismProbe(ft, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
			if r.stopped() {
				break
			}
			if f := r.cryptoWeakAlgoProbe(ft, "", &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
		}
	}

	// 验证码重放/校验缺失（侧信道）：含验证码字段的表单专有通道。
	// 与字段注入 plan 分开——验证码缺陷看的是「校验被绕过」，不是参数注入。
	if r.opts.CaptchaReplay {
		capDone := map[string]bool{}
		for _, ft := range targets {
			if r.stopped() {
				break
			}
			if ft.Action == "" || capDone[ft.Action] {
				continue
			}
			capDone[ft.Action] = true
			if f := r.captchaReplayProbe(ft, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
		}
	}

	// 无文本可注入字段时，上传探测已跑完，无需再做字段注入循环。
	if len(plan) == 0 {
		return hits
	}

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

		formCases := []struct {
			kind   string
			values []string
		}{
			{"xss", xssProbes},
			{"sqli", sqliErrorAll()},
			{"redirect", redirProbes},
			{"traversal", traversalProbes},
		}
		if r.deepEnabled() {
			for _, dc := range formDeepProbeClasses() {
				formCases = append(formCases, struct {
					kind   string
					values []string
				}{dc.Kind, dc.Values})
			}
		}
		for _, pc := range formCases {
			for i, value := range pc.values {
				if r.stopped() || (r.opts.MaxProbesPerClass > 0 && i >= r.opts.MaxProbesPerClass) {
					break
				}
				data := map[string]string{}
				for f := range baseData {
					data[f] = "sl-dast-base"
				}
				data[p.field] = value
				resp := r.fetch.PostFormSmall(p.ft.Action, data)
				tick(label)
				if resp == nil {
					continue
				}
				hit := probeJudge(pc.kind, resp, baseBody, Target{URL: p.ft.Action, Param: p.field})
				if hit == nil {
					continue
				}
				probeURL := p.ft.Action + "?" + p.field + "=" + value
				hit.Payload = value
				hit.Replay = formReplay(p.ft.Action, p.field, value)
				hit.Request = formReqText(p.ft.Action, p.field, value)
				chainEvidence(hit, probeURL, resp)
				hit.Signals = []string{pc.kind + " 表单探针命中"}
				hits = append(hits, *hit)
				break // 该类命中即停
			}
		}
		// 命令注入回显通道：表单字段专有路径。DVWA Command Injection 模块是
		// POST 表单（ip 字段）+ 命令输出回显，而 cmdEchoInject 此前只在
		// deepResidual 里对 URL 参数跑——POST 表单型目标整块漏掉。
		if r.deepEnabled() && r.opts.CmdInject && !r.stopped() {
			if f := r.cmdEchoForm(p.ft, p.field, baseBody, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
			}
		}
		// 布尔差分盲注：表单字段专有通道（报错不回显时的唯一出路）
		if r.opts.BoolBlind && !r.stopped() {
			plan := []FormTarget{{Action: p.ft.Action, Fields: []string{p.field}}}
			hits = append(hits, r.runFormBoolBlind(plan, &done, total)...)
		}
		// XXE：XML 体探测（POST 端点，每端点一次；解析器禁用实体则无回显）
		if r.deepEnabled() && !r.stopped() && !xxeDone[p.ft.Action] {
			xxeDone[p.ft.Action] = true
			if f := r.xxeProbe(p.ft.Action, &done, total); f != nil {
				if r.opts.OnHit != nil {
					r.opts.OnHit(*f)
				}
				hits = append(hits, *f)
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
	injURL := setParam(tgt.URL, tgt.Param, sleepPayload(sleep))
	if len(injURL) > r.opts.MaxURLLen {
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
	inj := r.fetch.GetSmall(injURL)
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
	again := r.fetch.GetSmall(injURL)
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
		Payload:  sleepPayload(sleep),
		Replay:   curlReplay(injURL),
		Request:  reqText(injURL),
		Signals: []string{"基线 " + formatMS(baseMS) + " / 注入 " + formatMS(injMS) +
			" / 复测 " + formatMS(againMS)},
		Response: &RespSnap{Status: inj.Status, Size: len(inj.Body), Snippet: snippetOf(inj.Body)},
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

// SetParam 导出的参数替换（3.0 exploit 层构造利用级探针 URL 用）。
func SetParam(rawURL, param, value string) string { return setParam(rawURL, param, value) }

// RandToken 导出的 128 位随机令牌（exploit 出带通道生成 beacon 注入串用）。
func RandToken() string { return randToken() }

// shellQuote 用单引号包裹并转义内部单引号（POSIX shell 安全）。
//
// 复现命令会被使用者**直接复制粘贴到 shell 执行**，其中的内容可能直接来自
// 被扫站点（表单 action 属性、控件 name 属性、注入载荷）——不转义等于把
// 命令执行权交给目标站点（BUG-002）。
// 与 internal/checks 的 shellQuote 同语义；两处各持一份，避免跨包耦合。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// curlReplay DAST 探针的复现命令（GET 语义，与探测行为一致）。
func curlReplay(u string) string {
	return "curl -sk --path-as-is " + shellQuote(u)
}

// formBody 表单请求体（application/x-www-form-urlencoded）：字段名与值都按
// 表单编码规则转义，与引擎实际发出的 POST 字节一致。
func formBody(field, payload string) string {
	if field == "" {
		return url.QueryEscape(payload)
	}
	v := url.Values{}
	v.Set(field, payload)
	return v.Encode()
}

// formReqText 表单通道的重放请求文本（POST 语义），单字段。
//
// 与真实发出的请求一致：表单通道发的是 POST 表单，若证据链里写成 GET，
// 使用者复制后复现出来的就不是同一个请求（BUG-018）。
func formReqText(action, field, payload string) string {
	return formReqTextRaw(action, formBody(field, payload))
}

// formReqTextRaw 表单通道的重放请求文本（POST 语义），body 由调用方给定。
func formReqTextRaw(action, body string) string {
	return "POST " + action + " HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
		body
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
//
// Request / Replay **只在缺失时填充**：表单通道已按 POST 语义构造好复现命令，
// 若这里无条件覆盖，就会把 POST 的复现命令换成 GET 的——复现命令必须与真实
// 发出的请求一致，否则「证据链可复核」这条产品红线就破了（BUG-018）。
func chainEvidence(f *Finding, probeURL string, resp *Resp) {
	if f == nil {
		return
	}
	if f.Request == "" {
		f.Request = reqText(probeURL)
	}
	if f.Replay == "" {
		f.Replay = curlReplay(probeURL)
	}
	if resp != nil {
		f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
	}
}

// RunAuthz 越权（授权绕过）探测：对带身份标识的 URL 参数做横向/纵向试探。
// 独立于 Run 的参数注入通道——越权判定看的是「标识可控 + 无访问控制」。
func (r *Runner) RunAuthz(links []string) []Finding {
	if !r.authzEnabled() {
		return nil
	}
	done := 0
	total := len(links) * 4
	return r.runAuthzBypass(links, &done, total)
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
		// 报错状态差分：参数正常时页面 2xx/3xx，注入引号后翻成 5xx。
		// 这类目标（Acunetix testasp 的 Search.asp）只回一个通用 500 页，
		// 正文里没有任何 sqlErrors 特征——特征表再宽也命不中，靠状态码
		// 翻转才是唯一通道。基线必须是健康态，否则站点本身 5xx 时会漫天误报。
		if tgt.ErrorStatus && tgt.Status > 0 && tgt.Status < 400 &&
			resp.Status >= 500 {
			return &Finding{
				Check: "sqli-error", Title: "报错型 SQL 注入（状态差分确认）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 注入引号后响应由 " +
					fmt.Sprint(tgt.Status) + " 翻为 " + fmt.Sprint(resp.Status) +
					"（注入触发服务端异常）",
				Advice: "使用参数化查询；关闭详细报错回显",
			}
		}
	case "redirect":
		loc := strings.ToLower(resp.Header("Location"))
		if redirectStatus(resp.Status) && strings.Contains(loc, "sitelens-dt.example.com") {
			return &Finding{
				Check: "open-redirect", Title: "开放重定向",
				Severity: "medium", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 可控制跳转目标（Location: " +
					resp.Header("Location") + "）",
				Advice: "重定向目标使用白名单校验",
			}
		}
	case "traversal":
		for _, mark := range traversalMarks {
			if strings.Contains(body, mark) && !strings.Contains(baseline, mark) {
				return &Finding{
					Check: "lfi-passwd", Title: "目录遍历读取系统文件",
					Severity: "high", URL: tgt.URL, Param: tgt.Param,
					Evidence: "参数 " + tgt.Param + " 注入 ../ 序列读到系统文件（命中特征 " + mark + "）",
					Advice:   "路径白名单校验，禁止 .. 序列与绝对路径",
				}
			}
		}
	}
	return nil
}

func redirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// authzEnabled 越权通道总闸：跟随深度探测面总闸（默认开）。
func (r *Runner) authzEnabled() bool {
	return r.opts.AuthzBypass
}
