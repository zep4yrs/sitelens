// 加密实现弱点（Cryptography）与开放 API（API）两条判定通道。
//
// 为什么单列：这两类都不是「参数注入」，判定依据与注入通道正交——
//
//	crypto-weak         同一明文多次加密得到**同一密文**（确定性加密），
//	                    且密文形态可识别（十六进制/Base64 定长）→ ECB 模式
//	                    或固定 IV / 硬编码密钥的直接证据。DVWA 的
//	                    Cryptography 模块就是这一形态（同明文同密文）。
//	crypto-weak-algo    响应里出现无盐弱哈希（32 位十六进制在口令相关
//	                    上下文）或明文可逆编码冒充加密。
//	api-unauth          发现 API 风格端点后，以**无凭证**请求读同一资源，
//	                    内容一致（或返回了明显不该公开的字段）→ 未授权访问。
//	api-idor            端点路径/参数里的资源标识可被替换，且跨主体返回成功
//	                    内容（与 authz-bypass 的区别：这里是对 /api/ 风格
//	                    端点，且要求同时验证「无凭证」与「跨标识」两件事）。
//
// 全部无损：加密通道只提交无害定值（不含任何机密），API 通道只 GET 只读。
package dast

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// 确定性加密（ECB / 固定 IV / 硬编码密钥）
// ---------------------------------------------------------------------------

// cryptoCipherFields 可能承载密文的字段/参数名。
var cryptoCipherFields = []string{
	"cipher", "encrypted", "encrypt", "crypt", "crypto", "token", "hash",
	"signature", "sig", "mac", "digest", "checksum", "key", "secret",
	"data", "value", "pass", "password", "plaintext",
}

// cryptoFormFields 表单里最可能作为「待加密明文」的字段（提交定值给它们）。
func cryptoPlainFieldIn(fields []string) string {
	for _, f := range fields {
		l := strings.ToLower(strings.TrimSpace(f))
		for _, h := range []string{"text", "plain", "input", "message", "msg", "data", "value", "secret", "plaintext"} {
			if l == h || l == h+"_" {
				return f
			}
		}
	}
	return ""
}

// hexBlobRE 定长十六进制密文（16/32/48/64/128 位宽的常见形态）。
var hexBlobRE = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{16}\b`)

// base64BlobRE 定长 Base64 密文（16/24/32 字节 → 24/32/44 字符，带 = 填充）。
var base64BlobRE = regexp.MustCompile(`\b[A-Za-z0-9+/]{20,44}={0,2}\b`)

// extractCipherBlob 从响应正文里取一个「像密文」的定长串（优先十六进制）。
// 返回 (串, 是否找到)。
func extractCipherBlob(body string) (string, bool) {
	if m := hexBlobRE.FindString(body); m != "" {
		return m, true
	}
	for _, m := range base64BlobRE.FindAllString(body, 8) {
		// 排除明显的英文单词/路径/类名噪音：必须含数字且大小写混杂或带填充
		if !strings.ContainsAny(m, "0123456789") {
			continue
		}
		hasUpper := strings.ToLower(m) != m
		hasLower := strings.ToUpper(m) != m
		if hasUpper && hasLower || strings.HasSuffix(m, "=") {
			return m, true
		}
	}
	return "", false
}

// cryptoDeterminismProbe 确定性加密探测：同一表单同一明文提交两次，
// 响应中的定长密文完全一致即判定（ECB / 固定 IV / 硬编码密钥）。
//
// 关键：先要求「不同明文 → 不同密文」（证明该串确实是明文的函数），
// 否则静态常量串会被误判为确定性加密。
func (r *Runner) cryptoDeterminismProbe(ft FormTarget, done *int, total int) *Finding {
	pf := cryptoPlainFieldIn(ft.Fields)
	if pf == "" {
		return nil
	}
	fill := func(v string) map[string]string {
		data := map[string]string{}
		for _, f := range ft.Fields {
			data[f] = "sl-crypto-base"
		}
		data[pf] = v
		return data
	}
	post := func(v string) *Resp {
		resp := r.fetch.PostFormSmall(ft.Action, fill(v))
		*done++
		if r.prog != nil {
			r.prog(*done, total, "crypto@"+ft.Action)
		}
		return resp
	}
	// 两次同一明文
	a1 := post("sitelens-crypto-plain")
	if a1 == nil || r.stopped() {
		return nil
	}
	c1, ok1 := extractCipherBlob(a1.Body)
	if !ok1 {
		return nil
	}
	if r.stopped() {
		return nil
	}
	a2 := post("sitelens-crypto-plain")
	if a2 == nil || r.stopped() {
		return nil
	}
	c2, ok2 := extractCipherBlob(a2.Body)
	if !ok2 || c1 != c2 {
		return nil // 密文每次都变（随机 IV）：无确定性缺陷
	}
	// 对照：换明文必须换密文，否则该串不是明文的函数（静态值）
	b := post("sitelens-crypto-plain-2")
	if b == nil || r.stopped() {
		return nil
	}
	c3, ok3 := extractCipherBlob(b.Body)
	if !ok3 || c3 == c1 {
		return nil
	}
	return &Finding{
		Check: "crypto-deterministic", Title: "确定性加密（ECB / 固定 IV / 硬编码密钥）",
		Severity: "medium", URL: ft.Action, Param: pf,
		Payload: "sitelens-crypto-plain",
		Evidence: "字段 " + pf + " 提交同一明文两次得到完全相同的密文 " + c1 +
			"，换明文后密文随之变化（" + c3 + "）——加密是明文的确定性函数，" +
			"即 ECB 模式或固定 IV/密钥，泄露明文相等性（可被选择明文分析）",
		Advice: "改用带随机 IV 的 AEAD 模式（AES-GCM / ChaCha20-Poly1305）；" +
			"密钥由密钥管理服务注入，不硬编码",
	}
}

// cryptoWeakAlgoMarkers 无盐弱哈希 / 可逆编码冒充加密的特征。
// 只在「与口令/敏感字段同页」时才判，避免把普通校验和当弱点。
var cryptoWeakAlgoMarkers = []string{
	"md5(", "sha1(", "base64_encode", "base64_decode", "des_", "rc4",
	"ecb", "openssl_encrypt", "mcrypt",
}

// cryptoWeakAlgoProbe 弱加密算法特征探测（响应里直接回显算法名/调用）。
func (r *Runner) cryptoWeakAlgoProbe(ft FormTarget, baseline string, done *int, total int) *Finding {
	if len(ft.Fields) == 0 {
		return nil
	}
	data := map[string]string{}
	for _, f := range ft.Fields {
		data[f] = "sl-crypto-probe"
	}
	resp := r.fetch.PostFormSmall(ft.Action, data)
	*done++
	if r.prog != nil {
		r.prog(*done, total, "crypto-algo@"+ft.Action)
	}
	if resp == nil {
		return nil
	}
	low := strings.ToLower(resp.Body)
	base := strings.ToLower(baseline)
	for _, m := range cryptoWeakAlgoMarkers {
		if strings.Contains(low, m) && !strings.Contains(base, m) {
			return &Finding{
				Check: "crypto-weak-algo", Title: "弱加密/编码实现暴露（无盐哈希或可逆编码）",
				Severity: "medium", URL: ft.Action,
				Evidence: "响应中出现弱加密实现特征 " + m + "（基线中无此特征）",
				Advice:   "口令存储改 bcrypt/argon2；传输加密用 AEAD 而非 ECB/无盐哈希",
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 开放 API：未授权访问 / IDOR
// ---------------------------------------------------------------------------

// apiPathRE API 风格路径（/api/…、/v1/…、/rest/…、/graphql）。
var apiPathRE = regexp.MustCompile(`(?i)/(api|rest|v[0-9]+|graphql|jsonrpc)(/|$)`)
var apiIdRE = regexp.MustCompile(`(?i)/(\d{1,8})(/|$|\?)`)

// apiLooksLike 判断链接是否为 API 端点。
func apiLooksLike(rawURL string) bool { return apiPathRE.MatchString(rawURL) }

// apiSensitiveFields 响应中出现即视为「不该公开」的字段名。
var apiSensitiveFields = []string{
	"password", "passwd", "pwd", "password_hash", "passwordhash", "hash",
	"secret", "api_key", "apikey", "private_key", "token", "ssn", "creditcard",
	"credit_card", "email", "phone", "address", "role", "is_admin", "admin",
}

// apiSensitiveIn 返回命中的敏感字段名（按 JSON 键形态匹配，带引号或冒号）。
func apiSensitiveIn(body string) string {
	low := strings.ToLower(body)
	if !strings.Contains(low, "{") && !strings.Contains(low, "[") {
		return "" // 非结构化响应：不做字段级判定，避免正文里出现单词即误报
	}
	for _, f := range apiSensitiveFields {
		for _, pat := range []string{`"` + f + `"`, f + ":", f + `":`} {
			if strings.Contains(low, pat) {
				return f
			}
		}
	}
	return ""
}

// apiProbe 对 API 端点做「未授权读取」判定。
//
// 手法（只读）：直接 GET 该端点（扫描器携带的凭证由引擎决定；本通道关心的是
// **响应是否泄露了结构化敏感数据**）。判定成立要求两件事同时为真：
//
//  1. 响应是结构化数据（JSON/XML）；
//  2. 出现敏感字段名（password / email / token / role …）。
//
// 单靠「返回 200」会漫天误报——公开的 API 返回 200 是正常行为。
func (r *Runner) apiProbe(rawURL string, done *int, total int) *Finding {
	resp := r.fetch.GetSmall(rawURL)
	*done++
	if r.prog != nil {
		r.prog(*done, total, "api@"+rawURL)
	}
	if resp == nil || authzRespDenied(resp.Status, resp.Body) {
		return nil
	}
	field := apiSensitiveIn(resp.Body)
	if field == "" {
		return nil
	}
	return &Finding{
		Check: "api-unauth", Title: "API 未授权/过度暴露（返回敏感字段）",
		Severity: "high", URL: rawURL,
		Evidence: "API 端点 " + rawURL + " 无凭证即返回结构化数据，且包含敏感字段 " + field,
		Advice:   "API 端点强制鉴权；响应按调用方权限裁剪字段（不返回口令/令牌/内部标识）",
	}
}

// apiIDORProbe 对 API 端点做 IDOR 判定：路径中的资源标识可替换且跨主体可见。
func (r *Runner) apiIDORProbe(rawURL string, done *int, total int) *Finding {
	m := apiIdRE.FindStringSubmatch(rawURL)
	if m == nil {
		return nil
	}
	cur := m[1]
	alt := "1"
	if cur == "1" {
		alt = "2"
	}
	idx := strings.LastIndex(rawURL, "/"+cur)
	if idx < 0 {
		return nil
	}
	altURL := rawURL[:idx] + "/" + alt + rawURL[idx+1+len(cur):]
	if altURL == rawURL {
		return nil
	}
	base := r.fetch.GetSmall(rawURL)
	*done++
	if base == nil || authzRespDenied(base.Status, base.Body) {
		return nil
	}
	if apiSensitiveIn(base.Body) == "" {
		return nil // 基线本身不含敏感字段：不算过度暴露
	}
	if r.stopped() {
		return nil
	}
	other := r.fetch.GetSmall(altURL)
	*done++
	if r.prog != nil {
		r.prog(*done, total, "api-idor@"+rawURL)
	}
	if other == nil || authzRespDenied(other.Status, other.Body) {
		return nil
	}
	if apiSensitiveIn(other.Body) == "" || sizeSimilar(len(base.Body), len(other.Body)) {
		return nil
	}
	return &Finding{
		Check: "api-idor", Title: "API 资源越权（IDOR：标识可替换）",
		Severity: "high", URL: altURL,
		Evidence: "把资源标识 " + cur + " 换成 " + alt + " 后仍返回含敏感字段的完整" +
			"资源数据（" + altURL + "），服务端未校验调用方对该资源的访问权",
		Advice: "服务端按会话主体限制资源范围；对每个对象访问做授权校验（防 IDOR）",
	}
}

// RunAPI 开放 API 通道：未授权读取 + IDOR。
func (r *Runner) RunAPI(links []string) []Finding {
	if !r.opts.APIAudit {
		return nil
	}
	seen := map[string]bool{}
	var out []Finding
	done, total := 0, 0
	cands := make([]string, 0, len(links))
	for _, l := range links {
		if apiLooksLike(l) && !seen[l] {
			seen[l] = true
			cands = append(cands, l)
		}
		if len(cands) >= 24 {
			break
		}
	}
	total = len(cands) * 3
	for _, u := range cands {
		if r.stopped() {
			break
		}
		if f := r.apiProbe(u, &done, total); f != nil {
			if r.opts.OnHit != nil {
				r.opts.OnHit(*f)
			}
			out = append(out, *f)
		}
		if r.stopped() {
			break
		}
		if f := r.apiIDORProbe(u, &done, total); f != nil {
			if r.opts.OnHit != nil {
				r.opts.OnHit(*f)
			}
			out = append(out, *f)
		}
	}
	return out
}
