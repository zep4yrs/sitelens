// 深度探测面（v5.1）：在核心四类（反射 XSS / 报错 SQLi / 开放重定向 /
// 目录遍历）之外补齐的主动注入家族。
//
// 设计沿用核心探针同一套语义：探针序列按优先级、类内首个命中即短路、
// 判定与基线求差剔除固有回显、命中即填证据链（请求/响应/信号/复现）。
// 全部为无害探针——只触发可观测的解析/执行信号（回显、报错、延迟、
// 响应头新增），不写入、不破坏、不外发真实数据。
//
// 家族清单：
//
//	SSTI        模板注入（四族语法 × 唯一算术乘积回显）
//	SQLi 报错扩展 堆叠/ORDER BY/注释闭合等上下文变体
//	命令注入     分号/管道 sleep 时间差分 + 双确认
//	CRLF 头注入  参数值中 \r\n 注入 → 响应头集合新增
//	NoSQL 注入   操作符注入触发数据层报错回显
//	XPath 注入   引号闭合触发 XPath 解析报错回显
//	LDAP 注入    通配/括号注入触发 LDAP 解析报错回显
//	SSTI/表达式  SpEL / OGNL / EL 报错特征
//	XXE          XML 外部实体解析信号（POST XML 通道）
//	SSRF 内网    指向回环/元数据地址的回显或状态变化（无出带依赖）
//	Log4Shell    ${jndi:} 注入触发的解析特征
package dast

import (
	"strings"
	"time"
)

// sstiProbes SSTI 探针：四族模板语法 + 唯一算术乘积。
// 乘积 7393*8453=62500029 是 8 位唯一随机值，正常页面不可能天然出现；
// 回显该乘积即说明参数进入了模板求值链（与单纯回显 7393*8453 区分）。
const sstiExpr = "7393*8453"
const sstiResult = "62500029"

var sstiProbes = []string{
	"{{" + sstiExpr + "}}",    // Jinja2 / Twig / Nunjucks / Django
	"${" + sstiExpr + "}",     // JSP EL / FreeMarker / Spring
	"#{" + sstiExpr + "}",     // Thymeleaf / Seam
	"<%= " + sstiExpr + " %>", // ERB / EJS / Rails
	"@(" + sstiExpr + ")",     // Razor / Thymeleaf 部分方言
	"{" + sstiExpr + "}",      // Python format / 部分方言
	"*{" + sstiExpr + "}",     // 部分表达式引擎
}

// cmdProbes 命令注入探针：命令分隔符 + sleep（时间差分确认执行）。
// 只做 sleep，不执行任何破坏性/读取性命令。
var cmdProbes = []string{
	";sleep %ds", "|sleep %ds", "||sleep %ds", "&sleep %ds", "&&sleep %ds",
	"`sleep %ds`", "$(sleep %ds)", "%%0asleep %ds", "\nsleep %ds",
}

// crlfHeaders CRLF 注入时观测的注入头名（参数值注入 \r\n 后响应头应新增）。
const crlfHeaderName = "X-Sitelens-Crlf"
const crlfInject = "%0d%0a" + crlfHeaderName + ":%20sl9z7"

// nosqlMarkers NoSQL 操作符注入触发数据层报错的回显特征。
// 不列 "$ne"/"$gt"/"$where" 等操作符字面量——它们在探针自身里，
// 反射回显会被误判；只认数据层报错文本。
var nosqlMarkers = []string{
	"mongoerror", "mongodb", "bson", "unknown operator",
	"objectid", "cast to objectid", "cannot canonicalize",
	"redis error", "wrong number of arguments for",
}

// xpathMarkers XPath 注入触发解析报错的回显特征。
var xpathMarkers = []string{
	"xpathexception", "invalid xpath", "xpath syntax", "unterminated literal",
	"system.xml.xpath", "xpathselect", "xml.xpath", "invalid expression",
}

// ldapMarkers LDAP 注入触发解析报错的回显特征。
var ldapMarkers = []string{
	"ldapexception", "ldap_search", "invalid dn syntax", "javax.naming",
	"ldap error", "bad search filter", "protocol error", "namingexception",
}

// spelMarkers 表达式注入（SpEL / OGNL / EL）触发的解析报错特征。
var spelMarkers = []string{
	"spelparseexception", "el1007e", "el exception", "ognlexception",
	"methodnotfoundexception", "expression evaluation", "propertynotfoundexception",
	"javax.el.", "el.expressionfactory", "templateinputexception",
}

// log4jMarkers Log4Shell 注入触发的解析特征（回显型误用；出带依赖另计）。
// 只认异常类名/堆栈特征，不认 "jndi"/"ldap://" 这类出现在探针自身或正常
// 文档里的字符串——反射回显型靶场会把探针原样吐出，弱标记必误报。
var log4jMarkers = []string{
	"javax.naming.communicationexception", "javax.naming.namingexception",
	"javax.naming.ldapexception", "lookup failed for", "javax.naming.name",
}

// expressionProbes 表达式注入探针（SpEL / OGNL / EL 常见定界符）。
var expressionProbes = []string{"${7393*8453}", "*{7393*8453}", "%{7393*8453}", "#{7393*8453}"}

// nosqlProbes NoSQL 操作符注入探针（对象形态 + 数组形态 + 逻辑恒真）。
var nosqlProbes = []string{
	`{"$ne":""}`, `[$ne]=1`, `' || '1'=='1`,
	`{"$gt":""}`, `[$gt]=`, `{"$where":"1"}`,
}

// xpathProbes XPath 注入探针（引号闭合 / 谓词恒真）。
var xpathProbes = []string{"'", `"`, "']", "1' or '1'='1", `x' or 'x'='x`}

// ldapProbes LDAP 注入探针（通配符 / 括号闭合）。
var ldapProbes = []string{"*", "*)(", "*))%00", ")(cn=*", `\*`}

// log4jProbes Log4Shell 探针（JNDI lookup 三形态）。
var log4jProbes = []string{
	"${jndi:ldap://127.0.0.1/sl}",
	"${jndi:rmi://127.0.0.1/sl}",
	"${${lower:j}ndi:ldap://127.0.0.1/a}",
}

// sqliErrorExtra 报错 SQLi 的上下文变体探针（堆叠/排序/注释闭合）。
// 与核心 sqliErrorProbes 合并使用，覆盖不同 DBMS 与拼接上下文。
var sqliErrorExtra = []string{
	"' AND 1=CONVERT(int,(SELECT @@version))--",
	"1 ORDER BY 100--",
	"';--",
	"1')--",
	"\");--",
	"' UNION SELECT 1,2,3--",
}

// deepResidual 深度面里探针序列循环覆盖不到的两件（每目标一次）：
//   - CRLF 头注入：判定要看响应头集合与基线求差，不是单纯回显匹配；
//   - 命令注入：时间差分 + 双确认，一次判定要发多个请求。
//
// 其余深度家族（SSTI / 表达式 / NoSQL / XPath / LDAP / Log4j）都是标准
// 「单发探针 + 类内短路」形态，统一由 probeSequences 的类表跑，
// 这里不再重复发请求。
func (r *Runner) deepResidual(tgt Target, baseHeaders map[string]bool, done *int, total int) []Finding {
	if !r.deepEnabled() {
		return nil
	}
	label := shortLabel(tgt)
	var hits []Finding
	emit := func(f Finding) {
		if r.opts.OnHit != nil {
			r.opts.OnHit(f)
		}
		hits = append(hits, f)
	}

	// 1) CRLF 头注入：注入 \r\n 后响应头集合新增
	if r.opts.CRLF {
		u := setParam(tgt.URL, tgt.Param, crlfInject)
		if len(u) <= r.opts.MaxURLLen {
			resp := probeGet(r, u, label, done, total)
			if resp != nil {
				if f := judgeDeep("crlf", resp, "", Target{URL: tgt.URL, Param: tgt.Param}); f != nil {
					f.Payload = crlfInject
					chainEvidence(f, u, resp)
					f.Signals = []string{"响应头新增 " + crlfHeaderName}
					emit(*f)
				}
			}
		}
	}

	// 2) 命令注入：分隔符 + sleep 时间差分 + 双确认
	if r.opts.CmdInject {
		if f := r.cmdInject(tgt, label, done, total); f != nil {
			emit(*f)
		}
	}
	return hits
}

// cmdInject 命令注入时间差分探测：注入 sleep 后响应延迟超阈值 + 复测确认。
func (r *Runner) cmdInject(tgt Target, label string, done *int, total int) *Finding {
	sleep := r.opts.SleepSeconds
	if sleep <= 0 {
		sleep = 4
	}
	// 基线计时
	start := time.Now()
	if r.stopped() {
		return nil
	}
	probeGet(r, tgt.URL, label, done, total)
	baseMS := time.Since(start).Milliseconds()
	if baseMS >= r.opts.BlindThresholdMS {
		return nil // 基线慢，判不准
	}
	budget := r.opts.MaxProbesPerClass
	if budget <= 0 {
		budget = 12
	}
	probes := cmdProbes
	if len(probes) > budget {
		probes = probes[:budget]
	}
	for _, tmpl := range probes {
		if r.stopped() {
			return nil
		}
		payload := strings.ReplaceAll(tmpl, "%d", itoa(sleep))
		u := setParam(tgt.URL, tgt.Param, payload)
		if len(u) > r.opts.MaxURLLen {
			continue
		}
		start = time.Now()
		resp := probeGet(r, u, label, done, total)
		injMS := time.Since(start).Milliseconds()
		if resp == nil || injMS < r.opts.BlindThresholdMS {
			continue
		}
		// 双确认
		if r.stopped() {
			return nil
		}
		start = time.Now()
		again := probeGet(r, u, label, done, total)
		againMS := time.Since(start).Milliseconds()
		if again == nil || againMS < r.opts.BlindThresholdMS {
			continue
		}
		f := &Finding{
			Check: "cmd-inject", Title: "命令注入（时间差分确认）",
			Severity: "critical", URL: tgt.URL, Param: tgt.Param, Payload: payload,
			Evidence: "参数注入 sleep 命令后响应耗时两次为 " +
				formatMS(injMS) + " / " + formatMS(againMS) + "，基线 " + formatMS(baseMS),
			Advice: "禁止将用户输入拼接进系统命令；使用参数化 API 与白名单",
		}
		chainEvidence(f, u, resp)
		f.Signals = []string{"命令分隔符触发延迟（双确认）",
			"基线 " + formatMS(baseMS) + " / 注入 " + formatMS(injMS) + " / 复测 " + formatMS(againMS)}
		return f
	}
	return nil
}

// probeGet 单次探测请求 + 进度/取消处理（deep.go 内复用）。
func probeGet(r *Runner, u, label string, done *int, total int) *Resp {
	resp := r.fetch.GetSmall(u)
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	return resp
}

// matchMarker 在响应正文中找标记且基线中没有（区分固有回显）。
//
// 关键误报防线：标记若本就是注入 payload 的字面量（如把 "%s" 塞进
// LDAP 通配探针，页面原样回显探针），回显匹配会把「参数被回显」误判成
// 「解析报错」。这里额外传入 payload，若标记出现在 payload 字面量里
// 则跳过——真正触发解析异常时，报错文本不是探针自己的字符。
func matchMarker(body, baseBody string, markers []string) string {
	return matchMarkerNotIn(body, baseBody, "", markers)
}

// matchMarkerNotIn 在 matchMarker 基础上排除「标记来自 payload 回显」。
func matchMarkerNotIn(body, baseBody, payload string, markers []string) string {
	low := strings.ToLower(body)
	base := strings.ToLower(baseBody)
	pl := strings.ToLower(payload)
	for _, m := range markers {
		if strings.Contains(pl, m) {
			continue // 标记是探针自身字面量 → 回显不算命中
		}
		if strings.Contains(low, m) && !strings.Contains(base, m) {
			return m
		}
	}
	return ""
}

// captureHeaders 记录响应头名集合（CRLF 基线用）。
func headerNameSet(resp *Resp) map[string]bool {
	out := map[string]bool{}
	if resp == nil {
		return out
	}
	for k := range resp.Headers {
		out[strings.ToLower(k)] = true
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// deepEnabled 深度探测面总闸（nil = 默认开，兼容旧调用方）。
func (r *Runner) deepEnabled() bool {
	return r.opts.DeepProbes == nil || *r.opts.DeepProbes
}

// errorStatusEnabled 报错状态差分通道（nil = 默认开）。
func (r *Runner) errorStatusEnabled() bool {
	return r.opts.ErrorStatus == nil || *r.opts.ErrorStatus
}

// sqliErrorAll 核心报错 SQLi 探针 + 上下文变体扩展（堆叠/排序/注释闭合）。
func sqliErrorAll() []string {
	out := make([]string, 0, len(sqliErrorProbes)+len(sqliErrorExtra))
	out = append(out, sqliErrorProbes...)
	out = append(out, sqliErrorExtra...)
	return out
}

// xxeBody XXE 探测的 XML 体：外部实体引用本地文件。无害——只引用
// 目标自身文件系统的常见文件，不写库、不外发数据。
func xxeBody(marker string) string {
	return `<?xml version="1.0"?><!DOCTYPE sltest [<!ENTITY slx SYSTEM "file:///etc/passwd">]>` +
		`<root><sl>` + marker + `</sl><x>&slx;</x></root>`
}

// xxeMarkers XXE 解析成功时正文可能出现的特征（实体展开的文件内容）。
var xxeMarkers = []string{"root:x:0:0:", "[extensions]", "for 16-bit app support"}

// xxeProbe 对表单/端点做 XML 外部实体探测（POST XML 通道）。
// 若响应正文出现实体展开的文件特征，即确认 XML 解析器未禁用外部实体。
func (r *Runner) xxeProbe(action string, done *int, total int) *Finding {
	label := action + " (XXE)"
	body := xxeBody("sl-xxe-7393")
	resp := r.fetch.PostRawSmall(action, "application/xml", body)
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	if resp == nil {
		return nil
	}
	low := strings.ToLower(resp.Body)
	for _, m := range xxeMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			f := &Finding{
				Check: "xxe", Title: "XML 外部实体注入（XXE）",
				Severity: "high", URL: action, Param: "(XML body)",
				Payload:  xxeBody("sl-xxe"),
				Evidence: "POST XML 体引用外部实体后正文出现文件内容特征：" + m,
				Advice:   "禁用 DTD/外部实体（禁用外部实体解析与网络访问）",
			}
			f.Request = "POST " + action + " HTTP/1.1\r\nContent-Type: application/xml\r\n\r\n" + body
			f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
			f.Signals = []string{"外部实体展开特征：" + m}
			return f
		}
	}
	return nil
}

// ---- 上传面探测（非破坏性） ----------------------------------------------
//
// 语义：向检测到的上传表单提交一个**无害文本文件**（唯一标记，不是
// webshell、不含可执行内容），依据响应判定服务端是否「接受」该上传：
//   - 出现拒绝特征（扩展名/类型/MIME 黑名单提示）→ 未命中；
//   - 出现成功特征（上传成功/文件路径/唯一标记回显）→ 命中上传受理面。
//
// 这是「探测面存在性」判定，不是「上传绕过可利用」确认——报告里以
// medium + 明确措辞给出，绕过验证属后续 exploit 层职责，杜绝夸大成利用。

// uploadRejectMarkers 上传被拒绝时的响应特征（命中即不算受理）。
var uploadRejectMarkers = []string{
	"not allowed", "不允许", "禁止上传", "invalid file", "invalid extension",
	"file type not", "unsupported", "拒绝", "黑名单", "not permitted",
	"extension is not", "类型不允许", "上传失败", "upload failed", "error",
}

// uploadAcceptMarkers 上传被受理时的响应特征。
var uploadAcceptMarkers = []string{
	"upload success", "uploaded", "上传成功", "successfully uploaded",
	"file saved", "文件已", "上传完成", "image uploaded", "upload ok",
}

// uploadProbeMarker 无害上传文件的唯一标记（用于确认文件被服务端接收）。
const uploadProbeMarker = "sitelens-upload-probe-not-malicious"

// uploadProbe 对单个表单目标做上传受理面探测。
// 只提交一次无害文本文件；拒绝/受理都据实记录，不重复刷请求。
func (r *Runner) uploadProbe(action string, fileField string, extra map[string]string, done *int, total int) *Finding {
	label := action + " (upload)"
	fname := "sitelens_probe.txt"
	content := uploadProbeMarker
	resp := r.fetch.PostMultipartSmall(action, fileField, fname, content, extra)
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	if resp == nil {
		return nil
	}
	low := strings.ToLower(resp.Body)
	// 拒绝优先：出现拒绝特征即判定未受理（避免把错误页当受理）。
	for _, m := range uploadRejectMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return nil
		}
	}
	accepted := false
	why := ""
	for _, m := range uploadAcceptMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			accepted = true
			why = m
			break
		}
	}
	// 无条件成功信号：正文回显了上传文件的唯一标记（说明读到了文件内容）
	if !accepted && strings.Contains(resp.Body, uploadProbeMarker) {
		accepted = true
		why = "响应回显上传文件内容标记"
	}
	if !accepted {
		return nil
	}
	f := &Finding{
		Check: "upload-surface", Title: "文件上传受理面（未做绕过验证）",
		Severity: "medium", URL: action, Param: fileField, Payload: fname,
		Evidence: "上传无害文本文件被服务端受理（信号：" + why +
			"）；仅证明存在上传受理面，未验证扩展名/内容绕过",
		Advice: "上传做白名单扩展名 + 内容类型校验 + 落盘目录禁止执行",
	}
	f.Request = "POST " + action + " HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n" +
		"(文件字段 " + fileField + " = " + fname + "，内容为无害探针标记)"
	f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
	f.Signals = []string{"上传受理信号：" + why}
	return f
}

// ---- Cookie / Header 注入通道 --------------------------------------------
//
// sqli-labs Less-24/42~45 与大量真实系统的注入点不在 query/表单，而在
// Cookie 或 User-Agent/Referer/X-Forwarded-For 等头。此前 DAST 只看
// query 参数，这类入口整块进不了探测面。
//
// 语义：对目标 URL 注入改造后的 Cookie/头值，判定复用报错 SQLi 与
// 反射 XSS 的特征。Cookie 保留原有键值、只对值追加探测串（不破坏
// 会话语义）；头注入为附加（不覆盖原请求头）。

// cookieProbeSuffixes Cookie 值注入的探针后缀（报错/盲注形态）。
var cookieProbeSuffixes = []string{
	"'", `"`, "' AND '1'='1", "' ORDER BY 100--", "1')--",
}

// headerInjectTargets 常用注入头（值追加探针）。
var headerInjectTargets = []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"}

// cookieHeaderProbe 对目标做 Cookie / Header 注入探测（报错 SQLi / 反射 XSS）。
// 需要 Fetcher 支持带自定义头的请求（扩展接口 HeaderFetcher）。
func (r *Runner) cookieHeaderProbe(tgt Target, baseBody string, done *int, total int) []Finding {
	hf, ok := r.fetch.(HeaderFetcher)
	if !ok {
		return nil
	}
	label := shortLabel(tgt)
	var hits []Finding
	emit := func(f Finding) {
		if r.opts.OnHit != nil {
			r.opts.OnHit(f)
		}
		hits = append(hits, f)
	}

	// 1) Cookie 注入（保留键、只改值）
	for _, suf := range cookieProbeSuffixes {
		if r.stopped() {
			return hits
		}
		cookie := "sl=" + suf
		resp := probeGetH(r, hf, tgt.URL, map[string]string{"Cookie": cookie}, label, done, total)
		if resp == nil {
			continue
		}
		if f := judgeHeaderInject("cookie", "Cookie", suf, resp, baseBody, tgt); f != nil {
			emit(*f)
			break
		}
	}

	// 2) 头注入（User-Agent / Referer / XFF）
	for _, hn := range headerInjectTargets {
		if r.stopped() {
			return hits
		}
		hit := false
		for _, suf := range []string{"'", "' AND '1'='1", `"`} {
			resp := probeGetH(r, hf, tgt.URL, map[string]string{hn: "sl-probe" + suf}, label, done, total)
			if resp == nil {
				continue
			}
			if f := judgeHeaderInject("header", hn, suf, resp, baseBody, tgt); f != nil {
				emit(*f)
				hit = true
				break
			}
		}
		if hit {
			continue
		}
	}
	return hits
}

// judgeHeaderInject 头/Cookie 注入判定：报错 SQLi 特征或反射 XSS 标记。
func judgeHeaderInject(channel, name, payload string, resp *Resp, baseBody string, tgt Target) *Finding {
	body := strings.ToLower(resp.Body)
	base := strings.ToLower(baseBody)
	for _, e := range sqlErrors {
		if strings.Contains(body, e) && !strings.Contains(base, e) {
			f := &Finding{
				Check: "sqli-error-" + channel, Title: "报错型 SQL 注入（" + name + " 通道）",
				Severity: "high", URL: tgt.URL, Param: name, Payload: payload,
				Evidence: name + " 注入探针后响应出现数据库报错特征：" + e,
				Advice:   "对 Cookie/头做参数化处理；不要在查询中拼接这些来源",
			}
			f.Signals = []string{name + " 通道报错特征：" + e}
			return f
		}
	}
	if strings.Contains(body, xssRaw) && !strings.Contains(base, xssRaw) {
		f := &Finding{
			Check: "xss-reflect-" + channel, Title: "反射型 XSS（" + name + " 通道）",
			Severity: "high", URL: tgt.URL, Param: name, Payload: payload,
			Evidence: name + " 值未转义回显到页面（标记原样出现）",
			Advice:   "对该头的回显做 HTML 转义",
		}
		f.Signals = []string{name + " 通道反射回显"}
		return f
	}
	return nil
}

// probeGetH 带自定义头单请求 + 进度/取消（HeaderFetcher 通道）。
func probeGetH(r *Runner, hf HeaderFetcher, rawURL string, headers map[string]string,
	label string, done *int, total int) *Resp {
	resp := hf.GetWithHeaders(rawURL, headers)
	*done++
	if r.prog != nil {
		r.prog(*done, total, label)
	}
	return resp
}

// ---- 表单侧深度面插件（PR #29 增量层） -----------------------------------
//
// 与 URL 侧的 deepSequences 分开：表单通道没有响应头基线（CRLF 语义弱），
// 命令注入在 POST 上没有携带 sleep 的形态，故表单侧只接可判定的子集。

// formDeepProbeClasses 表单侧深度面探针类（类名 → 探针序列）。
// 与 deepProbeClasses 同源：SSTI / CRLF 在 POST 体里同样成立；
// NoSQL / XPath 的表单判定与 URL 判定共用 judgeDeep，一并接入。
func formDeepProbeClasses() []struct {
	Kind   string
	Values []string
} {
	return []struct {
		Kind   string
		Values []string
	}{
		{"ssti", sstiProbes},
		{"crlf", []string{crlfInject}},
		{"nosql", nosqlFormProbes},
		{"xpath", xpathFormProbes},
	}
}

// nosqlFormProbes 表单侧 NoSQL 探针（POST 体不做操作符数组形态）。
var nosqlFormProbes = []string{`{"$ne":""}`, `' || '1'=='1`, `{"$where":"1"}`}

// xpathFormProbes 表单侧 XPath 探针（引号闭合形态）。
var xpathFormProbes = []string{"'", `"`, "1' or '1'='1"}

// judgeDeep 深度面判定（SSTI / CRLF / NoSQL / XPath）。
// 与 judge 分开维护：核心四类走 judge，新增面走这里，文件边界清晰。
func judgeDeep(kind string, resp *Resp, baseline string, tgt Target) *Finding {
	if resp == nil {
		return nil
	}
	switch kind {
	case "ssti":
		if strings.Contains(resp.Body, sstiResult) && !strings.Contains(baseline, sstiResult) {
			return &Finding{
				Check: "ssti", Title: "服务端模板注入（表达式求值回显）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 注入模板表达式后回显算术乘积 " + sstiResult,
				Advice:   "模板表达式与用户输入隔离；禁止用户输入直接进模板引擎求值",
			}
		}
	case "crlf":
		for k := range resp.Headers {
			if strings.EqualFold(k, crlfHeaderName) {
				return &Finding{
					Check: "crlf-inject", Title: "CRLF 响应头注入",
					Severity: "medium", URL: tgt.URL, Param: tgt.Param,
					Evidence: "参数 " + tgt.Param + " 注入 CRLF 序列后响应头新增 " + crlfHeaderName,
					Advice:   "过滤输入中的 CR/LF；响应头输出做编码",
				}
			}
		}
	case "expression":
		// 表达式求值回显优先，其次解析报错特征。
		if strings.Contains(resp.Body, sstiResult) && !strings.Contains(baseline, sstiResult) {
			return &Finding{
				Check: "expression-inject", Title: "表达式注入（EL/SpEL/OGNL 求值回显）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数 " + tgt.Param + " 注入表达式后回显求值结果 " + sstiResult,
				Advice:   "禁止对用户输入做表达式求值",
			}
		}
		if m := matchMarkerNotIn(resp.Body, baseline, "", spelMarkers); m != "" {
			return &Finding{
				Check: "expression-inject", Title: "表达式注入（解析报错特征）",
				Severity: "medium", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数注入表达式触发解析异常：" + m,
				Advice:   "禁止对用户输入做表达式求值",
			}
		}
	case "nosql":
		if m := matchMarkerNotIn(resp.Body, baseline, "", nosqlMarkers); m != "" {
			return &Finding{
				Check: "nosql-inject", Title: "NoSQL 注入（数据层报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数注入 NoSQL 操作符触发数据层报错：" + m,
				Advice:   "对 NoSQL 查询输入做强类型校验，拒绝对象/操作符形态输入",
			}
		}
	case "xpath":
		if m := matchMarkerNotIn(resp.Body, baseline, "", xpathMarkers); m != "" {
			return &Finding{
				Check: "xpath-inject", Title: "XPath 注入（解析报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数注入引号触发 XPath 解析异常：" + m,
				Advice:   "参数化 XPath 查询；过滤引号与谓词字符",
			}
		}
	case "ldap":
		if m := matchMarkerNotIn(resp.Body, baseline, "", ldapMarkers); m != "" {
			return &Finding{
				Check: "ldap-inject", Title: "LDAP 注入（解析报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数注入 LDAP 通配/括号触发解析异常：" + m,
				Advice:   "使用参数化 LDAP 查询；转义 * ( ) \\ 等元字符",
			}
		}
	case "log4j":
		if m := matchMarkerNotIn(resp.Body, baseline, "", log4jMarkers); m != "" {
			return &Finding{
				Check: "log4j-inject", Title: "疑似 Log4Shell / JNDI 注入特征",
				Severity: "critical", URL: tgt.URL, Param: tgt.Param,
				Evidence: "参数注入 ${jndi:} 后响应出现 JNDI 解析特征：" + m,
				Advice:   "升级 log4j 至安全版本；过滤 ${jndi:} 等 lookup 语法",
			}
		}
	}
	return nil
}

// probeJudge 探针判定分发。
//
// 深度面的家族名各自有专属判定（expression / nosql / xpath / ldap / log4j），
// 直接走 judgeDeep，不要落回核心 judge——否则类名语义被折叠，
// 比如 expression 会被当成 ssti 判、ldap/log4j 干脆判不出来。
func probeJudge(kind string, resp *Resp, baseline string, tgt Target) *Finding {
	if hit := judgeDeep(kind, resp, baseline, tgt); hit != nil {
		return hit
	}
	return judge(kind, resp, baseline, tgt)
}

// ---- 请求预算口径（生产与测试共用，单一来源） ---------------------------
//
// 历史上进度条估算与测试上界各写一份，改探针数就得两处同改、极易漂移。
// 这里统一成 maxURLRequestsPerParam / maxFormRequestsPerField 两个口径函数，
// 进度条与测试都调它们。

// maxURLRequestsPerParam URL 参数单参数请求数上界。
//
// 口径与 Runner.Run 的实际请求序列严格对齐，共四段：
//
//  1. 基线响应 1
//  2. probeSequences：四类核心 4.0 + 深度面各家族（都走同一个探针序列循环，
//     逐类受 MaxProbesPerClass 约束）
//  3. 深度面专属：CRLF 响应头基线 1 + 命令注入（基线 + 探针 + 复测）
//  4. 时间盲注 3 + 布尔盲注 5 + 反序列化 1
//
// 这个函数是生产（进度条总长）与测试（上界断言）的单一来源——探针表一变，
// 两边同时跟着变，不会再出现「改了探针数、预算没跟」的漂移。
func maxURLRequestsPerParam(o Options) int {
	n := 1 // 基线响应
	n += probeSequenceBudget(o)
	if deepEnabled(o) {
		n += 1 // CRLF 响应头基线
		if o.CmdInject {
			n += 1 + capOpt(len(cmdProbes), o) + 1 // 基线 + 注入 + 复测
		}
	}
	if o.TimeBlind {
		n += 3
	}
	if o.BoolBlind {
		n += 5
	}
	n += 1 // 反序列化探针
	return n
}

// probeSequenceBudget probeSequences 的请求数上界：四类核心 + 深度面各家族，
// 每类按 MaxProbesPerClass 截断。
func probeSequenceBudget(o Options) int {
	n := capOpt(len(xssProbes), o) + capOpt(len(sqliErrorAll()), o) +
		capOpt(len(redirProbes), o) + capOpt(len(traversalProbes), o)
	if deepEnabled(o) {
		for _, dc := range probeSequenceDeepClasses() {
			n += capOpt(len(dc.Values), o)
		}
	}
	return n
}

// maxFormRequestsPerField 表单字段单字段请求数上界：
// 基线 1 + 四类核心探针序列 + 表单侧深度面 + 布尔盲注 5。
func maxFormRequestsPerField(o Options) int {
	n := 1 + capOpt(len(xssProbes), o) + capOpt(len(sqliErrorAll()), o) +
		capOpt(len(redirProbes), o) + capOpt(len(traversalProbes), o)
	if deepEnabled(o) {
		for _, dc := range formDeepProbeClasses() {
			n += capOpt(len(dc.Values), o)
		}
	}
	if o.BoolBlind {
		n += 5
	}
	return n
}

// deepEnabled Options 口径的深度面总闸（nil = 默认开）。
func deepEnabled(o Options) bool { return o.DeepProbes == nil || *o.DeepProbes }

// errorStatusEnabled 报错状态差分通道总闸（nil = 默认开）。
func errorStatusEnabled(o Options) bool { return o.ErrorStatus == nil || *o.ErrorStatus }

// boolP 取 bool 地址（Options 里三态开关用 nil 表示"未设置=默认开"）。
func boolP(v bool) *bool { return &v }

// capOpt 单类上限口径（0 = 不限）。
func capOpt(n int, o Options) int {
	if o.MaxProbesPerClass > 0 && n > o.MaxProbesPerClass {
		return o.MaxProbesPerClass
	}
	return n
}

// probeSequenceDeepClasses 能走「单发探针 + 类内短路」的深度面家族。
// 排除 crlf：它要响应头基线与集合求差，归 deepResidual。
func probeSequenceDeepClasses() []struct {
	Kind   string
	Values []string
} {
	out := []struct {
		Kind   string
		Values []string
	}{}
	for _, dc := range deepProbeClasses() {
		if dc.Kind == "crlf" {
			continue
		}
		out = append(out, dc)
	}
	return out
}

// deepProbeClasses 深度面探针类（类名 → 探针序列）。
// 必须与 deepSequences 实际跑的家族一一对应——预算口径从这里累计，
// 漏一类（如表达式/LDAP/Log4j）就会让进度条总长与测试上界同时算少。
func deepProbeClasses() []struct {
	Kind   string
	Values []string
} {
	return []struct {
		Kind   string
		Values []string
	}{
		{"ssti", sstiProbes},
		{"expression", expressionProbes},
		{"crlf", []string{crlfInject}},
		{"nosql", nosqlProbes},
		{"xpath", xpathProbes},
		{"ldap", ldapProbes},
		{"log4j", log4jProbes},
	}
}
