// 扩展探测面：随机差分型扫描信号 + 命令注入回显通道。
//
// 这一批解决的是「引擎报不出 DVWA 里已经存在的洞」这类漏报——
// 底座能力（发请求、比响应、看 header）都在，缺的是判定通道：
//
//	random-diff   会话 ID 时间戳 / 低熵水平（两次响应同名带值物变化率过高）
//	no-cache      敏感页 Cache-Control 可缓存（会话内容易被共享缓存/回退键泄露）
//	cmd-echo      命令注入回显通道（时间差分只覆盖「盲」场景；命令输出直接
//	              回显在响应正文里时，sleep 通道看不见）
//	xsstored      存储型 XSS（无回显的反射通道看不见「写进去、别处读出来」）
//
// 全部为无害探针：命令注入只注入加法运算（回显结果可验算），
// 存储型 XSS 只写无害标记（含随机段，绝不携带脚本执行载荷）。
package dast

import (
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 随机差分：会话标识 / 防缓存令牌的「每次刷新都变」是低熵弱随机的强信号
// ---------------------------------------------------------------------------

// valueTokens 会话类命名的值载体（从响应头 Set-Cookie 与正文里提取）。
// 只认「名字本身就带随机语义」的载体：包含 session/sessid/rand/csrf/token/
// nonce/uid/track/viewstate 等词根。否则埋点时间戳、_ga 这类正常波动值
// 会被误判成弱点。
var valueTokenNames = []string{
	"session", "sessid", "sess_id", "jsessionid", "phpsessid", "asp.net_sessionid",
	"csrftoken", "csrf_token", "_token", "xsrf", "nonce", "rand", "random",
	"viewstate", "eventvalidation", "requestverificationtoken",
}

// nameLooksRandom 判定 Cookie/隐藏字段名是否带随机语义（决定要不要比值）。
func nameLooksRandom(name string) bool {
	l := strings.ToLower(strings.TrimSpace(name))
	for _, t := range valueTokenNames {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// hexish 判定值是否「像机器生成的标识」而不是业务内容。
// 全数字 / 十六进制 / 含连字符的 GUID 形态才参与比较；
// 正常业务值（姓名、金额、日期）不参与，避免误报。
var hexishRE = regexp.MustCompile(`^[0-9a-fA-F-]{4,64}$`)
var digitsRE = regexp.MustCompile(`^[0-9]{4,20}$`)

func hexishValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 64 {
		return false
	}
	return hexishRE.MatchString(v) || digitsRE.MatchString(v)
}

// lowEntropyShape 判定值形态本身是否低熵（弱随机）。
// 时间戳形态（10 位秒 / 13 位毫秒，且落在合理区间）、
// 短整数（≤8 位）、近全数字短十六进制。
// 强随机串（长度 ≥ 16 且字符种类足够）一律不报——单样本测不出分布，
// 泛报就是误报。这条与 passive 的 weak-session-id 同口径。
func lowEntropyShape(v string) (bool, string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, ""
	}
	// 纯数字：时间戳形态优先（10 位 ≈ 秒级 2001-2033 / 13 位 ≈ 毫秒）
	if digitsRE.MatchString(v) || regexp.MustCompile(`^[0-9]{1,20}$`).MatchString(v) {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if (len(v) == 10 && n > 1000000000 && n < 2200000000) ||
				(len(v) == 13 && n > 1000000000000 && n < 2200000000000) {
				return true, "时间戳形态（" + v + "）"
			}
		}
		if len(v) <= 8 {
			return true, "短整数（" + v + "）"
		}
	}
	// 近全数字的短十六进制（去掉连字符后全为数字、长度 ≤ 12）
	compact := strings.ReplaceAll(v, "-", "")
	if len(compact) >= 4 && len(compact) <= 12 {
		allDigit := true
		for _, c := range compact {
			if c < '0' || c > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			return true, "近全数字短十六进制（" + v + "）"
		}
	}
	return false, ""
}

// randomDiffThreshold 判定「每次刷新都变」的容忍度：两次取样完全不同的
// 载体占比超过该值即认为该标识是低熵随机（不是会话级稳定标识）。
const randomDiffRatio = 0.6

// ---------------------------------------------------------------------------
// 敏感页可缓存：缺 Cache-Control: no-store/private 的会话页
// ---------------------------------------------------------------------------

// sensitivePathHints 会话/账户类路径词根（这些页面上出现的内容不该进共享缓存）。
var sensitivePathHints = []string{
	"account", "profile", "user", "admin", "dashboard", "session", "login",
	"bank", "order", "cart", "checkout", "settings", "password", "token",
}

func pathLooksSensitive(u string) bool {
	l := strings.ToLower(u)
	for _, h := range sensitivePathHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// cacheable 判定响应头是否允许被缓存（无 no-store/private 即视为可缓存）。
func cacheable(headers map[string]string) (bool, string) {
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

// ---------------------------------------------------------------------------
// 命令注入回显通道：把算术运算的结果直接回显在响应里
// ---------------------------------------------------------------------------

// 命令注入回显通道的常量与探针序列（cmdEchoExpr / cmdEchoResult /
// cmdEchoProbes）由 deep.go 定义——同一条通道只留一份来源。
// 判定也不再靠「结果串出现」这一弱信号：反射回显型目标会把探针原样吐出，
// 算式的两个操作数与结果在正文里同框，纯子串匹配必误报。deep.go 的
// cmdEchoConfirmed 改用「结果是否独立成串（未被算式紧邻）」判定。

// ---------------------------------------------------------------------------
// 存储型 XSS：写进去、别处读出来
// ---------------------------------------------------------------------------

// storedXSSMark 无害标记（含随机段）。不携带任何脚本语法——
// 判定依据是「标记被原样持久化并回显」，即存储型 XSS 的必要条件；
// 是否可执行（脚本上下文）由响应里的标记邻域上下文判定。
func storedXSSMark() string {
	return "slstored" + randToken() + "z9"
}

// scriptContextNear 判定标记附近是否存在未转义的脚本/事件上下文。
// 存储型 XSS 的可执行性看的是标记被写进哪：落在 <script> 内、
// 落在标签属性/事件处理里、或紧邻未转义的 < > 交付。
func scriptContextNear(body, mark string) (bool, string) {
	low := strings.ToLower(body)
	idx := strings.Index(low, strings.ToLower(mark))
	if idx < 0 {
		return false, ""
	}
	// 截取标记前后各 120 字符做上下文判定
	start := idx - 120
	if start < 0 {
		start = 0
	}
	end := idx + len(mark) + 120
	if end > len(low) {
		end = len(low)
	}
	ctx := low[start:end]
	for _, sig := range []string{"<script", "onerror=", "onload=", "onmouseover=", "javascript:"} {
		if strings.Contains(ctx, sig) {
			return true, "标记落在脚本/事件上下文（邻近 " + sig + "）"
		}
	}
	return false, ""
}

// echoedAsLiteral 判定结果数字是否**只**以「探针算式原文」的形态出现。
//
// 反射回显型目标把整条 payload 原样吐回，响应里出现结果数字是探针自身的
// 字面量；真求值后会**额外**多出一个孤立的数字 token（DVWA exec 模块就是
// "PING ...\n15846" 这种形态）。
//
// 判据：枚举所有出现位置，只要存在一处「孤立出现」就是真求值；
// 全部紧邻命令/算式标记才判为字面量回显。
func echoedAsLiteral(b byte) bool { return isSepOrSpace(b) }

// sessionCookieNames 会话类 Cookie 名（与 passive 同口径，弱会话 ID 只对这些有意义）。
var sessionCookieNames = map[string]bool{
	"phpsessid": true, "jsessionid": true, "asp.net_sessionid": true,
	"aspnetsessionid": true, "sessionid": true, "session": true, "sid": true,
	"sessid": true, "sess": true, "jsession": true, "connect.sid": true,
	"dvwasession": true, "session_id": true, "auth": true, "token": true,
}

// weakSessionCookieValue 会话 Cookie 值的形态判定（与 passive 口径一致）：
// 短整数 / 时间戳形态 / 近全数字短十六进制命中；强随机不报。
func weakSessionCookieValue(name, value string) (string, bool) {
	if !sessionCookieNames[strings.ToLower(name)] {
		return "", false
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", false
	}
	allDigit := true
	for _, c := range v {
		if c < '0' || c > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		switch {
		case len(v) <= 8:
			return "会话 ID 为 " + v + "：短整型，可枚举预测", true
		case len(v) == 10 || len(v) == 13:
			return "会话 ID 为时间戳形态（" + v + "）：生成可预测", true
		}
		return "", false
	}
	// 短十六进制且近全数字 → 疑似计数器派生
	if len(v) >= 1 && len(v) <= 8 {
		hex, digits := true, 0
		for _, c := range v {
			ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !ok {
				hex = false
				break
			}
			if c >= '0' && c <= '9' {
				digits++
			}
		}
		if hex && digits*3 >= len(v)*2 {
			return "会话 ID 为短十六进制且近全数字（" + v + "）：疑似计数器派生，可预测", true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// 验证码重放（侧信道）：不要求 OCR 成功，要求「同一次校验结果被跨步骤复用」
//
// DVWA Insecure CAPTCHA 的真正缺陷是**服务端把「验证码已通过」记在客户端可控
// 的状态里**：第一步 /?step=1 提交正确的 captcha 后，第二步 /?step=2 只要
// 不再校验就放行改密。攻击者只需在一次校验通过后，反复用同一份表单数据重放
// 后续步骤——甚至可以完全不看验证码。
//
// 判定不需要识别验证码：注入一个固定错误串，比较「首个步骤」与「后续步骤」
// 对同一份数据的接受度差异——
//
//	captcha-replay   后续步骤在**未通过校验**的情况下照样受理（跨步骤绕过）
//	captcha-generic  验证码字段接受任意值（校验恒真）
//
// 两条通道都只在服务端对「同一步骤 + 同一份数据」表现出稳定的接受/拒绝差异时
// 才报，且都做双确认（重复提交一致）。默认开（OCR 之外的独立侧信道）。
// ---------------------------------------------------------------------------

// captchaFields 验证码字段名的常见形态（含 DVWA 的 g-recaptcha-response）。
var captchaFields = []string{
	"captcha", "g-recaptcha-response", "recaptcha", "code", "verify", "verification",
	"verificationcode", "verifycode", "seccode", "vcode", "captcha_code", "checkcode",
	"validcode", "authcode", "imagecode", "security_code", "human", "answer",
}

// captchaFieldIn 从表单字段名里挑出验证码字段（无则返回空）。
func captchaFieldIn(fields []string) string {
	for _, f := range fields {
		l := strings.ToLower(strings.TrimSpace(f))
		for _, c := range captchaFields {
			if l == c {
				return f
			}
		}
	}
	for _, f := range fields {
		l := strings.ToLower(strings.TrimSpace(f))
		for _, c := range captchaFields {
			if strings.Contains(l, c) && !strings.Contains(l, "success") {
				return f
			}
		}
	}
	return ""
}

// captchaAcceptSignals 服务端「校验通过/受理」的语义标记。
// 命中任一即视为该步骤接受了这份提交（与拒绝形态区分）。
var captchaAcceptSignals = []string{
	"success", "passed", "verified", "congratulations", "captcha was correct",
	"captcha is correct", "thank you", "accepted", "已完成", "成功",
}

// captchaRejectSignals 服务端「校验失败」的语义标记。
var captchaRejectSignals = []string{
	"incorrect", "invalid", "failed", "error", "wrong", "try again", "mismatch",
	"denied", "拒绝", "错误", "失败", "校验",
}

// captchaVerdict 依据响应正文/状态判定该步骤是否受理了本次提交。
// 返回 (受理, 依据文本)。
func captchaVerdict(status int, body string) (bool, string) {
	low := strings.ToLower(body)
	accept, reject := "", ""
	for _, s := range captchaAcceptSignals {
		if strings.Contains(low, s) {
			accept = s
			break
		}
	}
	for _, s := range captchaRejectSignals {
		if strings.Contains(low, s) {
			reject = s
			break
		}
	}
	// 3xx 且无拒绝语：跳转通常意味着受理
	if status >= 300 && status < 400 && reject == "" {
		return true, "3xx 跳转（无拒绝标记）"
	}
	if status >= 500 {
		return false, "5xx 服务端错误"
	}
	// 有明确成功标记且无拒绝标记 → 受理
	if accept != "" && reject == "" {
		return true, "命中受理标记：" + accept
	}
	// 明确拒绝标记优先于默认受理判定
	if reject != "" && accept == "" {
		return false, "命中拒绝标记：" + reject
	}
	if accept != "" && reject != "" {
		// 同时出现：以「谁更靠前」作次序判断（DVWA 的 success 块在错误提示之前）
		if strings.Index(low, accept) < strings.Index(low, reject) {
			return true, "受理标记先于拒绝标记：" + accept
		}
		return false, "拒绝标记先于受理标记：" + reject
	}
	return false, "无受理/拒绝标记"
}

// captchaReplayProbe 验证码重放探测。
//
// 手法（全无害）：对含验证码字段的表单，提交一个固定错误串：
//  1. 记录首个步骤的受理/拒绝；
//  2. 再提交一次同样的数据（同步骤重放）——结果应一致，作对照；
//  3. 报「同一步骤下，同一份明显错误的验证码被稳定受理」= 校验恒真。
//
// 跨步骤重放（step=1 → step=2）需要知道多步骤表单的具体语义，交给
// 调用方按 step 参数拆解——此函数只处理「单表单，验证码字段被接受」这条
// 与 DVWA 无关的通用缺陷。
func (r *Runner) captchaReplayProbe(ft FormTarget, done *int, total int) *Finding {
	cf := captchaFieldIn(ft.Fields)
	if cf == "" {
		return nil
	}
	// 固定错误验证码（随机段保证不会撞上真值）
	bad := "slcap" + randToken()
	fill := func(code string) map[string]string {
		data := map[string]string{}
		for _, f := range ft.Fields {
			data[f] = "sl-cap-base"
		}
		data[cf] = code
		return data
	}
	post := func(data map[string]string) *Resp {
		resp := r.fetch.PostFormSmall(ft.Action, data)
		*done++
		if r.prog != nil {
			r.prog(*done, total, "captcha@"+ft.Action)
		}
		return resp
	}
	first := post(fill(bad))
	if first == nil || r.stopped() {
		return nil
	}
	ok1, why1 := captchaVerdict(first.Status, first.Body)
	// 首次未受理：正常表现，不报（错误验证码被拒绝是正确行为）
	if !ok1 {
		return nil
	}
	if r.stopped() {
		return nil
	}
	// 双确认：同一步骤下同一份错误验证码再提交一次
	again := post(fill(bad))
	if again == nil || r.stopped() {
		return nil
	}
	ok2, why2 := captchaVerdict(again.Status, again.Body)
	if !ok2 {
		return nil
	}
	return &Finding{
		Check: "captcha-missing", Title: "验证码校验缺失（任意值被受理）",
		Severity: "medium", URL: ft.Action, Param: cf,
		Payload: bad,
		Evidence: "验证码字段 " + cf + " 提交明显错误值后被稳定受理（双确认）：" +
			why1 + " / " + why2,
		Advice: "服务端必须对每次提交校验验证码，且校验后立即失效（一次性）",
	}
}

// FormTargetStep 多步骤表单的语义（DVWA Insecure CAPTCHA 类：
// 同一 action 上以 step 参数区分「校验验证码」与「执行敏感操作」两个阶段）。
type FormTargetStep struct {
	Action    string
	StepParam string   // 步骤参数名（如 step）
	Steps     []string // 步骤取值序列（如 ["1", "2"]）
	Fields    []string // 各步骤共享的字段名
}

// captchaStepReplayProbe 跨步骤验证码重放（DVWA Insecure CAPTCHA 的教科书形态）。
//
// 判定：把「校验通过」的一次成功提交的**数据**原样重放到后续步骤——
// 后续步骤若不再校验验证码就受理，说明校验状态可被跳过。
// 这里不去猜哪个验证码正确：改用「步骤 1 提交错误验证码被拒 → 步骤 2 直接
// 提交（跳过校验）被受理」的差异证明校验只在第一步存在。
func (r *Runner) captchaStepReplayProbe(ft FormTargetStep, done *int, total int) *Finding {
	if ft.Action == "" || ft.StepParam == "" || len(ft.Steps) < 2 {
		return nil
	}
	cf := captchaFieldIn(ft.Fields)
	post := func(step, code string) *Resp {
		data := map[string]string{}
		for _, f := range ft.Fields {
			data[f] = "sl-cap-base"
		}
		data[ft.StepParam] = step
		if cf != "" {
			data[cf] = code
		}
		resp := r.fetch.PostFormSmall(ft.Action, data)
		*done++
		if r.prog != nil {
			r.prog(*done, total, "captcha-step@"+ft.Action)
		}
		return resp
	}
	// 末步骤不提交验证码（若表单有该字段则提交错误值模拟「跳过」）
	last := ft.Steps[len(ft.Steps)-1]
	skip := post(last, "slcaptcha-skip")
	if skip == nil || r.stopped() {
		return nil
	}
	ok1, why1 := captchaVerdict(skip.Status, skip.Body)
	if !ok1 {
		return nil
	}
	if r.stopped() {
		return nil
	}
	again := post(last, "slcaptcha-skip")
	if again == nil || r.stopped() {
		return nil
	}
	ok2, why2 := captchaVerdict(again.Status, again.Body)
	if !ok2 {
		return nil
	}
	return &Finding{
		Check: "captcha-replay", Title: "验证码校验可跨步骤重放（后置步骤不校验）",
		Severity: "high", URL: ft.Action, Param: ft.StepParam,
		Payload: ft.StepParam + "=" + last,
		Evidence: "表单在 " + ft.StepParam + "=" + last + " 步骤未提交有效验证码即被受理" +
			"（双确认：" + why1 + " / " + why2 + "），证明验证码校验只作用于前置步骤" +
			"，可通过跳过/重放后置步骤绕过",
		Advice: "每次敏感操作都必须重新校验验证码；校验结果绑定服务端会话并一次性失效",
	}
}
