// Package authn 登录流认证：用配置的凭证对登录端点做一次表单提交，
// 捕获会话 Cookie 供整次扫描复用（认证态爬虫/DAST/目录探测共用）。
// 凭证只从配置读取，不写日志、不落证据。
package authn

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// FormSig 登录表单签名（调用方从各自 HTML 解析类型映射，authn 不耦合解析器）。
type FormSig struct {
	Action      string
	HasPassword bool
	Inputs      []InputSig
}

// InputSig 表单输入字段签名。
type InputSig struct{ Name, Type, Value string }

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

// AutoDetect 自动发现登录表单并登录：在已爬取页面解析出的表单里找
// 含 password 输入框的表单，按字段名语义填入凭证后提交。
// 会话失败判定与 Login 一致（Set-Cookie 捕获或成功标记）。
func AutoDetect(client *httpx.Client, forms []FormSig, pageURL string,
	cfg config.AuthConfig) (string, bool, string) {
	if cfg.Username == "" || cfg.Password == "" {
		return "", false, "未配置凭证（auth.username/password）"
	}
	for _, f := range forms {
		if !f.HasPassword {
			continue
		}
		return LoginForm(client, f.Action, pageURL, f.Inputs, cfg)
	}
	return "", false, "页面中未发现登录表单"
}

// LoginForm 对单个表单提交凭证：字段按名/类型语义分配
// （password 型或含 pass → 密码；含 user/email/login/account → 用户名；
// hidden 保留原值）。字段名无法辨认的非关键输入留空。
func LoginForm(client *httpx.Client, action, pageURL string, inputs []InputSig,
	cfg config.AuthConfig) (string, bool, string) {
	postURL := pageURL
	if action != "" {
		base, err := url.Parse(pageURL)
		ref, rerr := url.Parse(action)
		if err != nil || rerr != nil {
			return "", false, "表单 action 解析失败"
		}
		postURL = base.ResolveReference(ref).String()
	}
	data := map[string]string{}
	userSet, passSet := false, false
	for _, in := range inputs {
		if in.Name == "" || in.Type == "submit" || in.Type == "button" || in.Type == "image" {
			continue
		}
		low := strings.ToLower(in.Name)
		switch {
		case in.Type == "password" || strings.Contains(low, "pass"):
			data[in.Name] = cfg.Password
			passSet = true
		case strings.Contains(low, "user") || strings.Contains(low, "email") ||
			strings.Contains(low, "login") || strings.Contains(low, "account") ||
			(cfg.UserField != "" && in.Name == cfg.UserField):
			data[in.Name] = cfg.Username
			userSet = true
		case in.Type == "hidden":
			data[in.Name] = in.Value
		default:
			data[in.Name] = in.Value
		}
	}
	if !passSet || !userSet {
		return "", false, "表单字段无法辨认用户名/密码输入"
	}
	client.SetTimeout(15 * time.Second)
	resp, err := client.PostForm(postURL, data)
	if err != nil || resp == nil {
		return "", false, "登录提交失败"
	}
	cookie := captureSetCookie(resp)
	marker := strings.TrimSpace(cfg.SuccessMarker)
	if marker != "" && strings.Contains(resp.Body, marker) {
		return cookie, true, "成功标记命中"
	}
	if cookie != "" {
		return cookie, true, "Set-Cookie 捕获"
	}
	return "", false, fmt.Sprintf("未确认登录成功（HTTP %d）", resp.Status)
}
