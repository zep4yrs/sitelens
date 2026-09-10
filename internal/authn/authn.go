// Package authn 登录流认证：用配置的凭证对登录端点做一次表单提交，
// 捕获会话 Cookie 供整次扫描复用（认证态爬虫/DAST/目录探测共用）。
// 凭证只从配置读取，不写日志、不落证据。
package authn

import (
	"fmt"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// Login 执行一次登录流：POST user_field/pass_field → 校验成功标记 →
// 提取会话 Cookie。返回 (cookie, 是否成功, 说明)。
// 判定优先级：HTTP 客户端已带会话（Set-Cookie 捕获成功）或响应含成功标记。
func Login(client *httpx.Client, cfg config.AuthConfig) (string, bool, string) {
	if cfg.LoginURL == "" {
		return "", false, "未配置 login_url"
	}
	if cfg.UserField == "" {
		cfg.UserField = "username"
	}
	if cfg.PassField == "" {
		cfg.PassField = "password"
	}
	client.SetTimeout(15 * time.Second)
	resp, err := client.PostForm(cfg.LoginURL, map[string]string{
		cfg.UserField: cfg.Username,
		cfg.PassField: cfg.Password,
	})
	if err != nil {
		return "", false, "登录请求失败: " + err.Error()
	}
	if resp == nil {
		return "", false, "登录响应为空"
	}
	cookie := captureSetCookie(resp)
	marker := strings.TrimSpace(cfg.SuccessMarker)
	if marker != "" && strings.Contains(resp.Body, marker) {
		return cookie, true, "成功标记命中"
	}
	if cookie != "" {
		return cookie, true, "Set-Cookie 捕获"
	}
	return "", false, fmt.Sprintf("未确认登录成功（HTTP %d，无 Cookie 且成功标记未命中）", resp.Status)
}

// captureSetCookie 从响应头提取会话 Cookie（k=v 对，去掉属性位）。
func captureSetCookie(resp *httpx.Response) string {
	raw := resp.Header("Set-Cookie")
	if raw == "" {
		return ""
	}
	var pairs []string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(kv[0]))
		if k == "PATH" || k == "MAX-AGE" || k == "EXPIRES" || k == "SECURE" ||
			k == "HTTPONLY" || k == "SAMESITE" || k == "DOMAIN" {
			continue
		}
		pairs = append(pairs, strings.TrimSpace(kv[0])+"="+strings.TrimSpace(kv[1]))
	}
	return strings.Join(pairs, "; ")
}
