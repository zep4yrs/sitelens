// 失败原因分类（LB-02，additive）。
//
// 只做「可观测」：不改变任何命中判定（isSuccess）、也不改变既有停止条件
// （lockoutSignal 的锁号/限流关键词集合保持 LB-01 原样）。分类结果通过
// 两个 additive 出口暴露：
//
//   - onProgress 文案追加 " [失败: <分类>]"（既有 "user / ***" 前缀不变）；
//   - Options.OnFailure 回调（nil = 静默；事件不含口令）。
//
// 分类枚举：locked / rate_limited / captcha_required / invalid_user /
// invalid_password / mfa_required / unknown。
package loginbrute

import (
	"net/http"
	"strings"
)

// 失败原因枚举（ClassifyFailure 返回值）。
const (
	FailureLocked          = "locked"           // 账号锁定/封禁
	FailureRateLimited     = "rate_limited"     // 限流（429/频率限制）
	FailureCaptchaRequired = "captcha_required" // 需要验证码（图形/人机校验）
	FailureInvalidUser     = "invalid_user"     // 用户名不存在/无效
	FailureInvalidPassword = "invalid_password" // 口令错误（凭据不匹配）
	FailureMFARequired     = "mfa_required"     // 需要二次验证（OTP/短信/2FA）
	FailureUnknown         = "unknown"          // 无法归类
)

// FailureEvent 一次失败尝试的分类结果（LB-02，additive）。
// 刻意不含口令：回调方可能是日志/UI，凭证不得外流。
type FailureEvent struct {
	Category string // ClassifyFailure 枚举值
	Status   int    // HTTP 状态码（0 = 网络错误/无响应）
	User     string // 本次尝试的用户名
}

// 分类关键词（小写比较）。与 LB-01 的 lockoutKeywords 分开维护：
// 后者是**停止条件**（语义不得变），这里是**归类**（可更细/更宽）。
var (
	classifyLockedKeywords = []string{
		"锁定", "冻结", "locked", "账号已被锁定", "账户已被锁定",
		"account is locked", "account locked", "account suspended",
		"账号已冻结", "封禁", "封号",
	}
	classifyRateLimitKeywords = []string{
		"too many attempts", "too many failed", "too many requests",
		"rate limit", "rate-limit", "ratelimit", "尝试次数过多",
		"请求过于频繁", "操作过于频繁", "请稍后再试", "请稍后重试",
	}
	classifyMFAKeywords = []string{
		"mfa", "2fa", "two-factor", "two factor", "two-step verification",
		"one-time password", "one-time code", "one time code", "otp",
		"authenticator", "totp", "动态口令", "动态密码", "短信验证码",
		"手机验证码", "邮箱验证码", "两步验证", "双因素", "二次验证",
		"身份验证器", "验证身份",
	}
	classifyCaptchaKeywords = []string{
		"captcha", "recaptcha", "hcaptcha", "turnstile",
		"图形验证码", "验证码", "人机验证", "not a robot",
		"verify you are human", "滑动验证", "拖动滑块", "点击验证", "请完成验证",
	}
	classifyInvalidUserKeywords = []string{
		"user not found", "no such user", "unknown user", "invalid user",
		"user does not exist", "invalid username", "username not found",
		"用户名不存在", "用户不存在", "账号不存在", "账户不存在",
		"用户名错误", "账号错误", "无效的用户",
	}
	classifyInvalidPasswordKeywords = []string{
		"incorrect password", "invalid password", "wrong password", "bad password",
		"incorrect credentials", "invalid credentials", "bad credentials",
		"incorrect username or password", "invalid login", "login failed",
		"authentication failed", "auth failed", "密码错误", "密码不正确",
		"密码有误", "用户名或密码错误", "账号或密码错误", "认证失败",
		"登录失败", "凭据无效",
	}
)

// ClassifyFailure 按状态码与响应正文归类登录失败原因（LB-02）。
//
// 判定优先级（先命中先返回）：锁号 → 限流 → 二次验证 → 验证码 →
// 用户名无效 → 口令错误 → unknown。状态码兜底：429=限流、403=锁号
// （与 LB-01 把 403 视为封禁/锁号的口径一致）、401=口令错误。
// 该函数只用于「可观测」，不参与命中/停止判定。
func ClassifyFailure(status int, body string) string {
	low := strings.ToLower(body)
	switch {
	case hasAny(low, classifyLockedKeywords) || status == http.StatusForbidden:
		return FailureLocked
	case status == http.StatusTooManyRequests || hasAny(low, classifyRateLimitKeywords):
		return FailureRateLimited
	case hasAny(low, classifyMFAKeywords):
		return FailureMFARequired
	case hasAny(low, classifyCaptchaKeywords):
		return FailureCaptchaRequired
	case hasAny(low, classifyInvalidUserKeywords):
		return FailureInvalidUser
	case hasAny(low, classifyInvalidPasswordKeywords) || status == http.StatusUnauthorized:
		return FailureInvalidPassword
	default:
		return FailureUnknown
	}
}

// notifyFailure 归类并触发 OnFailure 回调（LB-02 additive），返回分类值。
func notifyFailure(opts *Options, user string, status int, body string) string {
	cat := ClassifyFailure(status, body)
	if opts.OnFailure != nil {
		opts.OnFailure(FailureEvent{Category: cat, Status: status, User: user})
	}
	return cat
}

// maskPassword 进度文案里的口令掩码（只露长度，不露内容）。
func maskPassword(pw string) string { return strings.Repeat("*", len(pw)) }

// attemptProgress 进度文案前缀（既有格式 "user / ***" 保持不变）。
func attemptProgress(user, pass string) string {
	return user + " / " + maskPassword(pass)
}
