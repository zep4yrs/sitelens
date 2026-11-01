// CP-02 认证矩阵（additive）：Header / Bearer / Basic / Cookie 四种只读注入。
//
// 与既有表单登录流（Login / AutoDetect / LoginForm，见 authn.go）并列：
// 表单登录负责「用凭证换会话」，本文件负责「把已有会话/令牌注入后续请求」。
//
// 安全口径（红线）：
//   - 凭据只从配置或 SLENS_AUTH_* 环境变量读取；
//   - 不写日志、不返回：错误信息只说明缺哪个字段，绝不回显凭据值；
//     Config/Session 的 String() 全部脱敏（防 %v/%s 误打日志）；
//   - 请求头名按 RFC 7230 token 校验、头值拒绝 CR/LF（防头注入）；
//     Cookie 必须是 k=v; k2=v2 形态。
//
// 接线说明（为什么注入目标是接口）：httpx.Client 目前只暴露 SetCookie /
// SetTimeout，没有持久化请求头注入点。本包不改其它包，因此用 Client 接口
// 表达「注入需要什么能力」；给 httpx.Client 补一个 SetHeader 即可直接传入，
// 或改用 Config.Headers() 经 httpx.GetWithHeaders/MethodFollowWith 按请求注入。
package authn

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

// Mode 认证方式（矩阵）。
type Mode string

const (
	ModeNone   Mode = "none"   // 不注入（零值默认）
	ModeHeader Mode = "header" // 自定义请求头（如 X-API-Key / Authorization）
	ModeBearer Mode = "bearer" // Authorization: Bearer <token>
	ModeBasic  Mode = "basic"  // Authorization: Basic base64(user:pass)
	ModeCookie Mode = "cookie" // Cookie: k=v; k2=v2
)

// EnvPrefix 认证相关环境变量前缀（SLENS_AUTH_*，清单见 ConfigFromEnv）。
const EnvPrefix = "SLENS_AUTH_"

// Client 认证注入目标（最小能力集）。
//
// 为什么是接口而不是 *httpx.Client：httpx.Client 目前只暴露 SetCookie /
// SetTimeout，没有持久化请求头注入点（请求头只能按请求经
// GetWithHeaders/MethodFollowWith 传入）。本包不改其它包，因此用接口表达
// 注入所需能力；接线方给 httpx.Client 补一个 SetHeader(name,value) 即可直接
// 传入，或改用 Config.Headers() 按请求注入。
type Client interface {
	SetHeader(name, value string) // 注入/覆盖一个持久请求头
	SetCookie(cookie string)      // 注入/覆盖 Cookie 头（"k=v; k2=v2"）
	SetTimeout(d time.Duration)   // 调整单请求超时
}

// Config 认证矩阵配置（只读注入）。零值 = 不注入。
type Config struct {
	Mode     Mode          // 认证方式；"" 等同 none
	Header   string        // ModeHeader：请求头名（如 X-API-Key）
	Value    string        // ModeHeader：请求头值
	Token    string        // ModeBearer：令牌（"Bearer " 前缀会自动去掉）
	Username string        // ModeBasic：用户名
	Password string        // ModeBasic：口令
	Cookie   string        // ModeCookie：Cookie 字符串（"k=v; k2=v2"）
	Timeout  time.Duration // >0：Apply 同时设置客户端单请求超时；<0 非法
}

// mode 归一：空值 → none，大小写/空白不敏感。
func (c Config) mode() Mode {
	return Mode(strings.ToLower(strings.TrimSpace(string(c.Mode))))
}

// Validate 校验配置：空凭据 / 非法头名 / 头值含 CR/LF / 非法 Cookie /
// 未知认证方式 / 负超时 → 明确错误。错误信息只含字段名，不含凭据值。
func (c Config) Validate() error {
	if c.Timeout < 0 {
		return fmt.Errorf("authn: timeout 不能为负")
	}
	switch c.mode() {
	case ModeNone, "":
		return nil
	case ModeHeader:
		if err := validateHeaderName(c.Header); err != nil {
			return err
		}
		if strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("authn: header 模式的头值不能为空（空凭据不注入）")
		}
		return validateHeaderValue(c.Value)
	case ModeBearer:
		if bearerToken(c.Token) == "" {
			return fmt.Errorf("authn: bearer 模式的令牌不能为空（空凭据不注入）")
		}
		return validateHeaderValue(c.Token)
	case ModeBasic:
		if strings.TrimSpace(c.Username) == "" || c.Password == "" {
			return fmt.Errorf("authn: basic 模式的用户名/口令不能为空（空凭据不注入）")
		}
		return nil
	case ModeCookie:
		return validateCookie(c.Cookie)
	default:
		return fmt.Errorf("authn: 未知认证方式 %q（可选 header/bearer/basic/cookie/none）",
			string(c.Mode))
	}
}

// Apply 把认证方式注入 client（统一入口；只读，失败不修改 client）。
// Timeout>0 时同时调整客户端单请求超时。
func (c Config) Apply(client Client) error {
	if client == nil {
		return fmt.Errorf("authn: 注入目标客户端为空")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Timeout > 0 {
		client.SetTimeout(c.Timeout)
	}
	switch c.mode() {
	case ModeHeader:
		client.SetHeader(c.Header, c.Value)
	case ModeBearer:
		client.SetHeader("Authorization", "Bearer "+bearerToken(c.Token))
	case ModeBasic:
		client.SetHeader("Authorization", "Basic "+basicCredential(c.Username, c.Password))
	case ModeCookie:
		client.SetCookie(strings.TrimSpace(c.Cookie))
	}
	return nil
}

// Headers 返回该认证方式需要附加的请求头（供 httpx.GetWithHeaders /
// MethodFollowWith 按请求注入；不注入时返回 nil）。
// 返回值含凭据：调用方不得写日志/落证据。
func (c Config) Headers() (map[string]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch c.mode() {
	case ModeHeader:
		return map[string]string{c.Header: c.Value}, nil
	case ModeBearer:
		return map[string]string{"Authorization": "Bearer " + bearerToken(c.Token)}, nil
	case ModeBasic:
		return map[string]string{"Authorization": "Basic " + basicCredential(c.Username, c.Password)}, nil
	case ModeCookie:
		return map[string]string{"Cookie": strings.TrimSpace(c.Cookie)}, nil
	default:
		return nil, nil
	}
}

// String 脱敏表示（实现 fmt.Stringer）：只暴露方式/头名/字段是否已配置，
// 绝不输出凭据值——防 %v/%s/%+v 把口令/令牌/Cookie 误打进日志。
func (c Config) String() string {
	return fmt.Sprintf("authn.Config{mode=%s, header=%q, value=%s, token=%s, username=%s, password=%s, cookie=%s, timeout=%s}",
		c.mode(), c.Header, configuredMark(c.Value), configuredMark(c.Token),
		configuredMark(c.Username), configuredMark(c.Password),
		configuredMark(c.Cookie), c.Timeout)
}

// configuredMark 脱敏标记：只区分「空 / 已配置」，不泄露长度或内容。
func configuredMark(v string) string {
	if strings.TrimSpace(v) == "" {
		return "<空>"
	}
	return "<已配置>"
}

// 环境变量清单（前缀 SLENS_AUTH_；空值视为未设置）：
//
//	SLENS_AUTH_MODE      header|bearer|basic|cookie|none
//	SLENS_AUTH_HEADER    header 模式的请求头名
//	SLENS_AUTH_VALUE     header 模式的请求头值
//	SLENS_AUTH_TOKEN     bearer 模式的令牌
//	SLENS_AUTH_USERNAME  basic 模式的用户名
//	SLENS_AUTH_PASSWORD  basic 模式的口令
//	SLENS_AUTH_COOKIE    cookie 模式的 Cookie 字符串
//	SLENS_AUTH_TIMEOUT   可选，Go duration（如 20s / 1500ms）
const envMode = EnvPrefix + "MODE"

// ConfigFromEnv 从 SLENS_AUTH_* 环境变量构造认证配置并校验。
// 未设置任何变量 → 零值 Config（不注入）；变量不完整/取值非法 → 明确错误
// （不静默降级为「无认证」）。错误信息不含凭据值。
func ConfigFromEnv() (Config, error) {
	var c Config
	if err := c.FillFromEnv(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// FillFromEnv 用环境变量补齐空字段（显式配置优先：非空字段不被覆盖）。
// 仅填充与校验 duration；字段完整性由 Validate 判定。
func (c *Config) FillFromEnv() error {
	if strings.TrimSpace(string(c.Mode)) == "" {
		if v := strings.TrimSpace(os.Getenv(envMode)); v != "" {
			c.Mode = Mode(strings.ToLower(v))
		}
	}
	fill := func(dst *string, key string) {
		if strings.TrimSpace(*dst) != "" {
			return
		}
		if v := strings.TrimSpace(os.Getenv(EnvPrefix + key)); v != "" {
			*dst = v
		}
	}
	fill(&c.Header, "HEADER")
	fill(&c.Value, "VALUE")
	fill(&c.Token, "TOKEN")
	fill(&c.Username, "USERNAME")
	fill(&c.Password, "PASSWORD")
	fill(&c.Cookie, "COOKIE")
	if c.Timeout == 0 {
		if v := strings.TrimSpace(os.Getenv(EnvPrefix + "TIMEOUT")); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("authn: %sTIMEOUT 不是合法时长（如 20s）：%v", EnvPrefix, err)
			}
			if d < 0 {
				return fmt.Errorf("authn: %sTIMEOUT 不能为负", EnvPrefix)
			}
			c.Timeout = d
		}
	}
	return nil
}

// bearerToken 归一 Bearer 令牌：去空白，容忍调用方带 "Bearer " 前缀。
func bearerToken(tok string) string {
	t := strings.TrimSpace(tok)
	if len(t) >= 7 && strings.EqualFold(t[:7], "Bearer ") {
		t = strings.TrimSpace(t[7:])
	}
	return t
}

// basicCredential 生成 Basic 认证头值（user:pass 的 base64）。
func basicCredential(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// validateHeaderName 校验请求头名：RFC 7230 token 字符集，非空。
func validateHeaderName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("authn: 请求头名不能为空")
	}
	for _, r := range name {
		if !isTokenRune(r) {
			return fmt.Errorf("authn: 请求头名含非法字符（仅允许 RFC 7230 token 字符）")
		}
	}
	return nil
}

// isTokenRune RFC 7230 token 字符：ALPHA / DIGIT / "!#$%&'*+-.^_`|~"。
func isTokenRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", r)
}

// validateHeaderValue 校验请求头值：拒绝 CR/LF（防头注入）。
func validateHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("authn: 请求头值不得包含 CR/LF（防头注入）")
	}
	return nil
}

// validateCookie 校验 Cookie 字符串：非空、无 CR/LF、每段必须是 k=v（k 非空）。
func validateCookie(raw string) error {
	c := strings.TrimSpace(raw)
	if c == "" {
		return fmt.Errorf("authn: cookie 模式的 Cookie 不能为空（空凭据不注入）")
	}
	if strings.ContainsAny(c, "\r\n") {
		return fmt.Errorf("authn: Cookie 不得包含 CR/LF（防头注入）")
	}
	for _, part := range strings.Split(c, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, _, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("authn: Cookie 必须是 k=v; k2=v2 形态（存在缺 = 或名称为空的分段）")
		}
	}
	return nil
}
