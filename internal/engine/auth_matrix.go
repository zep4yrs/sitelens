// CP-02 认证矩阵接线（additive）：把 SLENS_AUTH_* 声明的 Header/Bearer/Basic/
// Cookie 认证注入扫描 HTTP 客户端。
//
// 背景：CP-02 已在 internal/authn/matrix.go 提供 authn.Config（校验/Apply/
// 环境变量解析）与最小注入接口 Client{SetHeader,SetCookie,SetTimeout}；
// httpx.Client 本轮补上 SetHeader 后即可直接作为注入目标。
//
// 接线口径（零行为变化优先）：
//   - 未设置任何 SLENS_AUTH_* → 不注入（isEnvConfigured=false 直接返回）；
//   - 配置非法（缺凭据/非法头名/CR-LF/非法超时）→ 返回错误，扫描显式失败
//     （不静默降级成「无认证」，也不回显凭据值）；
//   - 既有表单登录流（config.auth.login_url → authn.Login）保持原路径不变；
//     config.AuthConfig 目前只有表单登录字段、没有矩阵字段，故矩阵只从
//     环境变量读取（config 包不在本任务改动范围，后续若加字段可在此映射）。
package engine

import (
	"os"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/authn"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// envAuthValue 读取 SLENS_AUTH_<key> 环境变量（与 authn.ConfigFromEnv 同源）。
func envAuthValue(key string) string { return os.Getenv(authn.EnvPrefix + key) }

// authEnvConfigured 是否设置了任一 SLENS_AUTH_* 环境变量。
// 单独列出而非依赖 authn.Config 零值判断：MODE=none 也是显式配置。
func authEnvConfigured() bool {
	for _, key := range []string{
		"MODE", "HEADER", "VALUE", "TOKEN", "USERNAME", "PASSWORD", "COOKIE", "TIMEOUT",
	} {
		if strings.TrimSpace(envAuthValue(key)) != "" {
			return true
		}
	}
	return false
}

// applyAuthMatrix 把环境变量声明的认证矩阵注入 client（CP-02）。
// 返回生效的认证方式（"" / "none" 表示未注入）；错误不含凭据值。
//
// client 为 nil 时返回 ("",nil)：既有调用方不受影响。
func applyAuthMatrix(client *httpx.Client) (string, error) {
	if client == nil || !authEnvConfigured() {
		return "", nil // 无配置 = 零行为变化
	}
	cfg, err := authn.ConfigFromEnv()
	if err != nil {
		return "", err
	}
	mode := strings.ToLower(strings.TrimSpace(string(cfg.Mode)))
	if mode == "" || mode == "none" {
		return "", nil
	}
	if err := cfg.Apply(client); err != nil {
		return "", err
	}
	return mode, nil
}
