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
	"net/url"
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
				Request: formReqTextRaw(ft.Action,
					formBody(userField, payload)+"&"+formBody(passField, "x")),
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

// ---------------------------------------------------------------------------
// 越权（授权绕过）判定：AuthZ 缺陷要求「身份/资源标识由客户端指定」
//
// DVWA Authorisation Bypass 与 Altoro 的账号枚举属同一类：请求里带一个
// **客户端可控的身份/资源标识**（user_id / account / uid / id …），服务端
// 不校验「当前会话是否有权访问该标识指向的资源」。判定不依赖特定靶场，
// 只依赖两个可观测事实：
//
//	1. 同一标识取不同值时，响应**内容确实不同**（说明服务端按标识取数，
//	   不是静态页也不是恒定拒绝）——这是「标识有效」的先决条件；
//	2. 该标识的取值**不受当前会话约束**——换一个明显不属于当前用户的高权
//	   标识，仍然返回成功内容（而非 403/404/登录页）。
//
// 误报防护（三道）：
//   - 标识无效（不同值响应相同）→ 不报，避免把静态页当成越权；
//   - 目标本就返回 401/403/登录页 → 不报（访问控制生效）；
//   - 双确认：越权响应形态重复一次仍成立才报。
// ---------------------------------------------------------------------------

// authzIdParamHints 身份/资源标识类参数名（客户端指定 = 越权候选）。
// 只收「指向资源主体」的名字，不收 page/id 这类通用分页名。
var authzIdParamHints = []string{
	"user_id", "userid", "user", "uid", "account", "account_id", "accountid",
	"customer_id", "customerid", "member_id", "memberid", "profile_id",
	"owner", "owner_id", "ownerid", "tenant", "tenant_id", "org_id", "emp_id",
}

// authzHighValueTargets 明显超出普通用户权限的标识取值（横向/纵向越权）。
var authzHighValueTargets = []string{"1", "2", "admin", "administrator", "root"}

// authzDeniedSignals 访问控制生效的响应特征。
var authzDeniedSignals = []string{
	"403", "forbidden", "access denied", "not authorized", "unauthorized",
	"permission denied", "no permission", "无权", "禁止访问", "权限不足",
	"login", "sign in", "signin", "authenticate", "请先登录",
}

// authzParamIn 从参数集中挑出身份/资源标识参数。
func authzParamIn(params []string) string {
	for _, p := range params {
		l := strings.ToLower(strings.TrimSpace(p))
		for _, h := range authzIdParamHints {
			if l == h {
				return p
			}
		}
	}
	for _, p := range params {
		l := strings.ToLower(strings.TrimSpace(p))
		if strings.HasSuffix(l, "_id") || strings.HasSuffix(l, "id") {
			for _, h := range authzIdParamHints {
				if strings.Contains(l, strings.TrimSuffix(h, "_id")) {
					return p
				}
			}
		}
	}
	return ""
}

// authzRespDenied 响应是否表现出「访问控制拒绝」。
func authzRespDenied(status int, body string) bool {
	if status == 401 || status == 403 {
		return true
	}
	low := strings.ToLower(body)
	// 登录页形态（含口令框）视为拒绝
	if strings.Contains(low, `type="password"`) || strings.Contains(low, "type='password'") {
		return true
	}
	for _, s := range authzDeniedSignals {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// runAuthzBypass 对带身份标识的 URL 参数做越权（横向/纵向）探测。
// 与参数注入通道分开：越权看的不是注入回显，是「标识可控 + 无访问控制」。
func (r *Runner) runAuthzBypass(links []string, done *int, total int) []Finding {
	type tgt struct {
		url   string
		param string
	}
	seen := map[string]bool{}
	var targets []tgt
	for _, link := range links {
		if r.stopped() {
			break
		}
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(u.Query()))
		for n := range u.Query() {
			names = append(names, n)
		}
		p := authzParamIn(names)
		if p == "" {
			continue
		}
		key := u.Host + u.Path + "|" + p
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, tgt{link, p})
	}
	var out []Finding
	for _, t := range targets {
		if r.stopped() {
			break
		}
		if f := r.authzProbe(t.url, t.param, done, total); f != nil {
			if r.opts.OnHit != nil {
				r.opts.OnHit(*f)
			}
			out = append(out, *f)
		}
	}
	return out
}

// authzProbe 单目标的越权探测。
func (r *Runner) authzProbe(rawURL, param string, done *int, total int) *Finding {
	get := func(v string) *Resp {
		resp := r.fetch.GetSmall(setParam(rawURL, param, v))
		*done++
		if r.prog != nil {
			r.prog(*done, total, "authz@"+shortLabel(Target{URL: rawURL, Param: param}))
		}
		return resp
	}
	// 先探两个不同取值，要求响应内容确实随标识变化（否则标识无效）
	a := get("1")
	if a == nil || r.stopped() {
		return nil
	}
	if authzRespDenied(a.Status, a.Body) {
		return nil // 访问控制生效（基线就被拒）
	}
	if r.stopped() {
		return nil
	}
	b := get("999999")
	if b == nil || r.stopped() {
		return nil
	}
	// 两种取值响应几乎一致 → 参数未真正决定资源（静态页/忽略入参）：不报
	if sizeSimilar(len(a.Body), len(b.Body)) {
		return nil
	}
	// 越权确认：换一个明显高权/他人的标识仍返回成功内容
	for _, hid := range authzHighValueTargets {
		if r.stopped() {
			return nil
		}
		if hid == "1" {
			continue // 已作基线
		}
		resp := get(hid)
		if resp == nil || r.stopped() {
			continue
		}
		if authzRespDenied(resp.Status, resp.Body) {
			continue // 拒绝：访问控制在此取值上生效
		}
		if sizeSimilar(len(resp.Body), len(a.Body)) || sizeSimilar(len(resp.Body), len(b.Body)) {
			continue // 与已知取值同形：无新信息
		}
		// 双确认
		again := get(hid)
		if again == nil || r.stopped() || authzRespDenied(again.Status, again.Body) {
			continue
		}
		if !sizeSimilar(len(again.Body), len(resp.Body)) {
			continue
		}
		return &Finding{
			Check: "authz-bypass", Title: "越权访问（资源标识由客户端指定且未鉴权）",
			Severity: "high", URL: rawURL, Param: param,
			Payload: param + "=" + hid,
			Evidence: "参数 " + param + " 取值 " + hid + "（非当前会话主体）仍返回成功内容" +
				"（状态 " + fmt.Sprint(resp.Status) + "，双确认一致），" +
				"服务端仅凭客户端标识取数、未校验会话对该资源的访问权",
			Advice: "服务端按会话主体限制资源范围；资源标识不得作为唯一授权依据（防 IDOR）",
		}
	}
	return nil
}
