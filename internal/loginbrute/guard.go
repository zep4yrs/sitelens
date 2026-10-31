// guard.go LB-01 登录爆破安全护栏（5.2）：
//
//   - 锁号保护：失败响应出现锁号/限流特征（锁定、冻结、locked、too many
//     attempts…）或 429/403 → 立即停止该目标并返回明确原因；
//   - 连续失败阈值（默认 5）：达到后默认停止；配置 FailBackoffMS 后改为
//     指数退避再继续（总尝试数仍受 MaxTries 硬上限约束）；
//   - 每账号尝试上限（默认 3）：同一用户名不超限，避免把真实账号锁死；
//   - 成功证据：响应差异摘要 + Set-Cookie + 跳转 URL + 可复制 curl
//     （Hit 新增字段，命中判定逻辑不变）。
//
// 授权确认由调用方（UI/文档）承载；本文件不改变既有判定语义。
package loginbrute

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// defaultMaxPerUser 每用户名默认最多尝试次数（LB-01）。
	defaultMaxPerUser = 3
	// defaultMaxConsecutiveFails 连续失败默认阈值（达到即停止）。
	defaultMaxConsecutiveFails = 5
	// maxBackoff 指数退避上限，避免退避本身把扫描挂住。
	maxBackoff = 30 * time.Second
	// maxEvidenceCookies 证据里最多保留的 Set-Cookie 条数。
	maxEvidenceCookies = 8
)

// lockoutKeywords 失败响应中的锁号/限流特征（小写比较）。
// 只在登录 POST 的失败响应上判定，不扫初始登录页——避免把登录页上的
// 「连续失败将锁定账号」提示语当作已锁号（宁可继续一次，也不误停真目标；
// 但一旦失败响应命中就立即停止，不锁号优先）。
var lockoutKeywords = []string{
	"锁定", "冻结", "locked", "too many attempts", "too many failed",
	"too many requests", "rate limit", "尝试次数过多", "账号已被锁定", "账户已被锁定",
}

// lockoutSignal 判断失败响应是否触发锁号/限流信号，返回非空原因。
func lockoutSignal(status int, body string) string {
	switch status {
	case http.StatusTooManyRequests:
		return "HTTP 429（尝试次数过多/限流）"
	case http.StatusForbidden:
		return "HTTP 403（拒绝访问，疑似封禁/锁号）"
	}
	low := strings.ToLower(body)
	for _, kw := range lockoutKeywords {
		if strings.Contains(low, kw) {
			return "响应含锁号/限流特征「" + kw + "」"
		}
	}
	return ""
}

// combo 一组待尝试凭据。
type combo struct{ u, pw string }

// buildCombos 生成尝试组合：总量受 budget 约束，同一用户名最多 maxPerUser
// 次（maxPerUser <= 0 = 不限制）。返回顺序保持「用户字典序 × 口令字典序」。
func buildCombos(users, passwords []string, budget, maxPerUser int) []combo {
	if budget <= 0 {
		budget = 1
	}
	out := make([]combo, 0, budget)
	perUser := map[string]int{}
	for _, u := range users {
		for _, pw := range passwords {
			if len(out) >= budget {
				return out
			}
			if maxPerUser > 0 && perUser[u] >= maxPerUser {
				break
			}
			out = append(out, combo{u: u, pw: pw})
			perUser[u]++
		}
	}
	return out
}

// resolveGuard 解析护栏默认值：0 → 默认；负值 → 关闭/不限制（显式退出）。
func resolveGuard(o *Options) (maxPerUser, maxFails int) {
	maxPerUser = o.MaxPerUser
	if maxPerUser == 0 {
		maxPerUser = defaultMaxPerUser
	}
	maxFails = o.MaxConsecutiveFails
	if maxFails == 0 {
		maxFails = defaultMaxConsecutiveFails
	}
	return maxPerUser, maxFails
}

// backoffDelay 指数退避：base << level，封顶 maxBackoff。
func backoffDelay(baseMS, level int) time.Duration {
	if baseMS <= 0 {
		return 0
	}
	d := time.Duration(baseMS) * time.Millisecond
	for i := 0; i < level; i++ {
		if d >= maxBackoff {
			return maxBackoff
		}
		d *= 2
	}
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// sleepMS 毫秒休眠（<= 0 不睡）。
func sleepMS(ms int) {
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

// ResponsePoster 表单模式可选扩展：适配器实现本接口后，成功证据可带
// Set-Cookie / Location 响应头。Poster 接口本身保持不变（API 向后兼容，
// 旧适配器无需改动）；未实现时证据里的 Set-Cookie 为空，其余证据仍由
// 正文与状态推导。
type ResponsePoster interface {
	PostFormResponse(rawURL string, fields map[string]string) (status int, body string, header http.Header, err error)
}

// JSONResponsePoster JSON 模式可选扩展（语义同 ResponsePoster）。
type JSONResponsePoster interface {
	PostJSONResponse(rawURL, body string) (status int, respBody string, header http.Header, err error)
}

// postFormFull 提交表单：实现 ResponsePoster 时取响应头，否则回退三方法 Poster。
func postFormFull(p Poster, rawURL string, fields map[string]string) (int, string, http.Header, error) {
	if rp, ok := p.(ResponsePoster); ok {
		return rp.PostFormResponse(rawURL, fields)
	}
	st, body, err := p.PostForm(rawURL, fields)
	return st, body, nil, err
}

// postJSONFull 提交 JSON：实现 JSONResponsePoster 时取响应头，否则回退。
func postJSONFull(p Poster, rawURL, body string) (int, string, http.Header, error) {
	if rp, ok := p.(JSONResponsePoster); ok {
		return rp.PostJSONResponse(rawURL, body)
	}
	st, respBody, err := p.PostJSON(rawURL, body)
	return st, respBody, nil, err
}

// hitEvidence 命中证据（映射到 Hit 的 additive 字段）。
type hitEvidence struct {
	Summary   string   // 响应差异摘要
	Redirect  string   // 成功跳转目标
	SetCookie []string // Set-Cookie 响应头（可能为空：适配器未实现可选接口）
	Curl      string   // 可复制复现命令
}

// buildEvidence 组装命中证据：状态/正文尺寸与失败基线对比 + 跳转 + Cookie。
func buildEvidence(status int, body string, header http.Header, baseStatus, baseSize int) hitEvidence {
	var ev hitEvidence
	ev.Summary = fmt.Sprintf("HTTP %d（失败基线 %d）；正文 %d 字节（基线 %d，%+d）",
		status, baseStatus, len(body), baseSize, len(body)-baseSize)
	if header != nil {
		ev.Redirect = strings.TrimSpace(header.Get("Location"))
		if vals := header.Values("Set-Cookie"); len(vals) > 0 {
			if len(vals) > maxEvidenceCookies {
				vals = vals[:maxEvidenceCookies]
			}
			ev.SetCookie = append([]string{}, vals...)
		}
	}
	if ev.Redirect == "" {
		ev.Redirect = redirectTarget(body)
	}
	if ev.Redirect != "" {
		ev.Summary += "；跳转 " + ev.Redirect
	}
	if len(ev.SetCookie) > 0 {
		ev.Summary += fmt.Sprintf("；Set-Cookie %d 条", len(ev.SetCookie))
	}
	return ev
}

// formEvidence 表单命中证据（含 curl）。
func formEvidence(action string, fields map[string]string, status int, body string,
	header http.Header, baseStatus, baseSize int) hitEvidence {
	ev := buildEvidence(status, body, header, baseStatus, baseSize)
	ev.Curl = formCurl(action, fields)
	return ev
}

// jsonEvidence JSON 命中证据（含 curl）。
func jsonEvidence(endpoint, reqBody string, status int, respBody string,
	header http.Header, baseStatus, baseSize int) hitEvidence {
	ev := buildEvidence(status, respBody, header, baseStatus, baseSize)
	ev.Curl = jsonCurl(endpoint, reqBody)
	return ev
}

// formCurl 生成可复制 curl：字段按名称排序保证输出稳定。
func formCurl(action string, fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("curl -i -sS -X POST ")
	b.WriteString(shellQuote(action))
	for _, k := range keys {
		b.WriteString(" --data-urlencode ")
		b.WriteString(shellQuote(k + "=" + fields[k]))
	}
	return b.String()
}

// jsonCurl 生成 JSON 登录的可复制 curl。
func jsonCurl(endpoint, body string) string {
	return "curl -i -sS -X POST " + shellQuote(endpoint) +
		" -H 'Content-Type: application/json' --data " + shellQuote(body)
}

// shellQuote POSIX shell 单引号转义（curl 命令可复制粘贴）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
