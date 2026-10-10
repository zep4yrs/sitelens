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

// cmdEchoMarkers 命令输出回显的特征：探针里的算式结果。
// 用 7393+8453=15846 这类唯一值：参数原样回显时是算式文本，不是结果；
// 只有真被 shell 求值了才会出现结果数字。
const cmdEchoA = "7393"
const cmdEchoB = "8453"
const cmdEchoSum = "15846" // 7393 + 8453
const cmdEchoSub = "1061"  // 8453 - 7393

// cmdEchoProbes 回显型命令注入探针（分隔符 + echo 算式）。
// 只做 echo 运算，不读取文件、不外发、不破坏。
var cmdEchoProbes = []string{
	";echo " + cmdEchoSum,
	"|echo " + cmdEchoSum,
	"&&echo " + cmdEchoSum,
	"&echo " + cmdEchoSum,
	"$(echo " + cmdEchoSum + ")",
	"`echo " + cmdEchoSum + "`",
	"$((" + cmdEchoA + "+" + cmdEchoB + "))",
	";expr " + cmdEchoA + " + " + cmdEchoB,
	"|expr " + cmdEchoA + " + " + cmdEchoB,
	"%0aecho " + cmdEchoSum,
}

// cmdEchoVariant 第二种算式（防止单值撞上页面里本来就有 15846）。
var cmdEchoProbes2 = []string{
	";echo " + cmdEchoSub,
	"|echo " + cmdEchoSub,
	"$(expr " + cmdEchoB + " - " + cmdEchoA + ")",
}

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
func echoedAsLiteral(body, result, expr string) bool {
	low := strings.ToLower(body)
	needle := strings.ToLower(result)
	exprLow := strings.ToLower(expr)
	idx := 0
	found := false
	for {
		i := strings.Index(low[idx:], needle)
		if i < 0 {
			break
		}
		i += idx
		found = true
		start := i - 40
		if start < 0 {
			start = 0
		}
		ctx := low[start:i]
		literal := strings.Contains(ctx, exprLow)
		if !literal {
			before := strings.TrimRight(ctx, " \t\r\n")
			// 覆盖 URL 编码形态：反射型回显常把 payload 以 %3Becho+ 形式吐出
			for _, mark := range []string{"echo", "expr", "$(", "`", "|", ";", "&&", "&",
				"%3b%20", "%3b+", "%7c", "%26%26", "%24%28", "+echo", "echo+"} {
				if strings.HasSuffix(before, mark) || strings.HasSuffix(before, mark+" ") {
					literal = true
					break
				}
			}
			after := low[i+len(result):]
			if strings.HasPrefix(strings.TrimLeft(after, " \t"), "=") {
				literal = true
			}
		}
		if !literal {
			return false
		}
		idx = i + len(needle)
		if idx >= len(low) {
			break
		}
	}
	return found
}

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
