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

// deepSequences 对单个目标跑深度探测面各家族（类内首个命中即短路）。
func (r *Runner) deepSequences(tgt Target, baseBody string, baseHeaders map[string]bool, done *int, total int) []Finding {
	if r.opts.DeepProbes != nil && !*r.opts.DeepProbes {
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
	budget := r.opts.MaxProbesPerClass
	if budget <= 0 {
		budget = 12
	}
	// 单类探针上限：防遍历/命令这类重类吃满预算
	capProbes := func(list []string) []string {
		if len(list) > budget {
			return list[:budget]
		}
		return list
	}

	// 1) SSTI：唯一算术乘积回显
	for _, v := range capProbes(sstiProbes) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		if len(u) > r.opts.MaxURLLen {
			continue
		}
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if strings.Contains(resp.Body, sstiResult) && !strings.Contains(baseBody, sstiResult) {
			f := Finding{
				Check: "ssti", Title: "服务端模板注入（SSTI）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数 " + tgt.Param + " 注入模板表达式后回显求值结果 " + sstiResult +
					"（" + sstiExpr + "）",
				Advice: "不要将用户输入拼接进模板；使用沙箱/白名单上下文变量",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"模板表达式求值回显", "乘积 " + sstiExpr + " → " + sstiResult}
			emit(f)
			break
		}
	}

	// 2) 表达式注入（SpEL/OGNL/EL）：报错特征
	for _, v := range capProbes([]string{"${7393*8453}", "*{7393*8453}", "%{7393*8453}", "#{7393*8453}"}) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if strings.Contains(resp.Body, sstiResult) && !strings.Contains(baseBody, sstiResult) {
			f := Finding{
				Check: "expression-inject", Title: "表达式注入（EL/SpEL/OGNL）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入表达式后回显求值结果 " + sstiResult,
				Advice:   "禁止对用户输入做表达式求值",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"表达式求值回显"}
			emit(f)
			break
		}
		if m := matchMarkerNotIn(resp.Body, baseBody, v, spelMarkers); m != "" {
			f := Finding{
				Check: "expression-inject", Title: "表达式注入（解析报错特征）",
				Severity: "medium", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入表达式触发解析异常：" + m,
				Advice:   "禁止对用户输入做表达式求值",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"表达式解析报错：" + m}
			emit(f)
			break
		}
	}

	// 3) 命令注入：分隔符 + sleep 时间差分 + 双确认
	if r.opts.CmdInject {
		if f := r.cmdInject(tgt, label, done, total); f != nil {
			emit(*f)
		}
	}

	// 4) CRLF 头注入：注入 \r\n 后响应头集合新增
	if r.opts.CRLF {
		u := setParam(tgt.URL, tgt.Param, crlfInject)
		if len(u) <= r.opts.MaxURLLen {
			resp := probeGet(r, u, label, done, total)
			if resp != nil {
				if resp.Header(crlfHeaderName) != "" && !baseHeaders[strings.ToLower(crlfHeaderName)] {
					f := Finding{
						Check: "crlf-inject", Title: "CRLF 响应头注入",
						Severity: "medium", URL: tgt.URL, Param: tgt.Param, Payload: crlfInject,
						Evidence: "参数注入 %0d%0a 后响应出现注入头 " + crlfHeaderName + "（头注入可控）",
						Advice:   "对进入响应头/重定向头的用户输入做 CR/LF 过滤",
					}
					chainEvidence(&f, u, resp)
					f.Signals = []string{"响应头新增 " + crlfHeaderName}
					emit(f)
				}
			}
		}
	}

	// 5) NoSQL 注入：操作符注入触发数据层报错
	for _, v := range capProbes([]string{`{"$ne":""}`, `[$ne]=1`, `' || '1'=='1`, `{"$gt":""}`, `[$gt]=`, `{"$where":"1"}`}) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if m := matchMarkerNotIn(resp.Body, baseBody, v, nosqlMarkers); m != "" {
			f := Finding{
				Check: "nosql-inject", Title: "NoSQL 注入（数据层报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入 NoSQL 操作符触发数据层报错：" + m,
				Advice:   "对查询参数做类型校验；拒绝以对象/数组形态传入的操作符",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"数据层报错：" + m}
			emit(f)
			break
		}
	}

	// 6) XPath 注入：引号闭合触发解析报错
	for _, v := range capProbes([]string{"'", `"`, "']", "1' or '1'='1", `x' or 'x'='x`}) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if m := matchMarkerNotIn(resp.Body, baseBody, v, xpathMarkers); m != "" {
			f := Finding{
				Check: "xpath-inject", Title: "XPath 注入（解析报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入引号触发 XPath 解析异常：" + m,
				Advice:   "参数化 XPath 查询；过滤引号与谓词字符",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"XPath 解析报错：" + m}
			emit(f)
			break
		}
	}

	// 7) LDAP 注入：通配/括号注入触发解析报错
	for _, v := range capProbes([]string{"*", "*)(", "*))%00", ")(cn=*", `\*`}) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if m := matchMarkerNotIn(resp.Body, baseBody, v, ldapMarkers); m != "" {
			f := Finding{
				Check: "ldap-inject", Title: "LDAP 注入（解析报错特征）",
				Severity: "high", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入 LDAP 通配/括号触发解析异常：" + m,
				Advice:   "使用参数化 LDAP 查询；转义 * ( ) \\ 等元字符",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"LDAP 解析报错：" + m}
			emit(f)
			break
		}
	}

	// 8) Log4Shell：JNDI 注入触发的解析特征（回显型误用）
	for _, v := range capProbes([]string{"${jndi:ldap://127.0.0.1/sl}", "${jndi:rmi://127.0.0.1/sl}", "${${lower:j}ndi:ldap://127.0.0.1/a}"}) {
		if r.stopped() {
			return hits
		}
		u := setParam(tgt.URL, tgt.Param, v)
		resp := probeGet(r, u, label, done, total)
		if resp == nil {
			continue
		}
		if m := matchMarkerNotIn(resp.Body, baseBody, v, log4jMarkers); m != "" {
			f := Finding{
				Check: "log4j-inject", Title: "疑似 Log4Shell / JNDI 注入特征",
				Severity: "critical", URL: tgt.URL, Param: tgt.Param, Payload: v,
				Evidence: "参数注入 ${jndi:} 后响应出现 JNDI 解析特征：" + m,
				Advice:   "升级 log4j 至安全版本；过滤 ${jndi:} 等 lookup 语法",
			}
			chainEvidence(&f, u, resp)
			f.Signals = []string{"JNDI 解析特征：" + m}
			emit(f)
			break
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

// deepBudget 单目标深度探测面的请求数上界（进度条总长估算用）。
// 各家族探针数均受 MaxProbesPerClass 约束，此处按其上界累计。
func (r *Runner) deepBudget() int {
	if !r.deepEnabled() {
		return 0
	}
	c := r.opts.MaxProbesPerClass
	if c <= 0 {
		c = 12
	}
	n := 1 // CRLF 基线响应
	n += min(len(sstiProbes), c)
	n += min(4, c)                   // 表达式
	n += min(len(sqliErrorExtra), c) // 报错 SQLi 扩展（在核心序列里用）
	n += min(6, c)                   // NoSQL
	n += min(5, c)                   // XPath
	n += min(5, c)                   // LDAP
	n += min(3, c)                   // Log4j
	if r.opts.CmdInject {
		n += 1 + min(len(cmdProbes), c) + 1 // 基线 + 注入 + 复测
	}
	n += 1 // CRLF 探针
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
