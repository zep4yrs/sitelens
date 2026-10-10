// 存储型 XSS 探测：写无害标记 → 从「列表/回显页」读回。
//
// 为什么必须与反射通道分开：反射型 XSS 的判定是「同一个请求的响应里
// 回显原样标记」；存储型 XSS 的标记落在**另一个**请求的响应里（留言板
// 写进去、列表页读出来）。DVWA 的 XSS (Stored) 模块（guestbook）就是这类：
// 反射通道对它必然零命中——不是探测面窄，是判定通道不对。
//
// 安全约束：只写无害文本标记（随机段，不含任何脚本语法），
// 只在同一表单的提交→读取路径内验证，不做批量污染。
package dast

import "strings"

// storedXSSSubmit 对一个含文本字段的表单写入无害标记，并从提交响应
// 与表单所在页两个读取点查标记是否被持久化回显。
//
// 返回命中 Finding（未命中返回 nil）。命中判定：
//  1. 提交响应或页面回读里出现该标记（说明写入了、且服务端没过滤掉）；
//  2. 标记处于脚本/事件上下文（可执行性）。
//
// 只满足 1 不满足 2 时按「内容未过滤存储」报 low——它是存储型 XSS 的
// 前置条件，但不是可执行 XSS，不能说成全的。
func (r *Runner) storedXSSSubmit(ft FormTarget, done *int, total int) *Finding {
	if !r.opts.StoredXSS || ft.Action == "" || len(ft.Fields) == 0 {
		return nil
	}
	mark := storedXSSMark()
	field := ft.Fields[0]
	data := make(map[string]string, len(ft.Fields))
	for _, f := range ft.Fields {
		data[f] = mark
	}
	resp := r.fetch.PostFormSmall(ft.Action, data)
	*done++
	if r.prog != nil {
		r.prog(*done, total, "stored-xss@"+ft.Action)
	}
	if resp == nil {
		return nil
	}
	// 读回点 1：提交响应本身（DVWA guestbook 提交后同页列出留言）
	if ok, ctx := scriptContextNear(resp.Body, mark); ok {
		f := &Finding{
			Check: "xss-stored", Title: "存储型 XSS（标记持久化回显于脚本上下文）",
			Severity: "high", URL: ft.Action, Param: field,
			Payload: mark,
			Evidence: "表单字段 " + field + " 写入标记后，提交响应中原样回显且 " + ctx +
				"（标记含随机段，非页面固有内容）",
			Advice: "输出编码 + 输入过滤；存储内容按所在上下文转义",
		}
		chainEvidence(f, ft.Action, resp)
		f.Signals = []string{"标记跨请求持久化回显", ctx}
		return f
	}
	if strings.Contains(resp.Body, mark) {
		f := &Finding{
			Check: "xss-stored-raw", Title: "存储型 XSS 前置：存储内容未过滤",
			Severity: "medium", URL: ft.Action, Param: field,
			Payload: mark,
			Evidence: "表单字段 " + field + " 写入的标记被原样持久化回显（未过滤），" +
				"但当前回显上下文未见可执行脚本位置",
			Advice: "输出编码 + 输入过滤；确认存储内容的所有渲染点均转义",
		}
		chainEvidence(f, ft.Action, resp)
		f.Signals = []string{"标记跨请求持久化回显（未过滤）"}
		return f
	}
	return nil
}

// stateChangeSubmit 对「无字段只带提交按钮」的状态变更表单发一次 POST，
// 观测响应是否下发**弱形态**的会话 Cookie。
//
// 覆盖的场景极窄但真实：DVWA 的 Weak Session IDs 模块就是一个
// <form method="post"><input type="submit" value="Generate"></form>——
// 没有可注入字段，既不进字段注入 plan，也不含密码框，此前整块不可见。
// 它每次 POST 都下发 `dvwaSession=<递增整数>`，是教科书级的弱会话 ID。
//
// 只判 Cookie 值形态（复用 passive 的同一口径），不做请求重放。
func (r *Runner) stateChangeSubmit(ft FormTarget, done *int, total int) *Finding {
	if !r.opts.WeakCookie {
		return nil
	}
	if ft.Action == "" || len(ft.Fields) > 0 || ft.Method == "get" {
		return nil
	}
	resp := r.fetch.PostFormSmall(ft.Action, map[string]string{"submit": "1"})
	*done++
	if r.prog != nil {
		r.prog(*done, total, "state-change@"+ft.Action)
	}
	if resp == nil {
		return nil
	}
	for _, raw := range resp.SetCookies {
		name, val := cookieNameValue(raw)
		if name == "" {
			continue
		}
		ev, ok := weakSessionCookieValue(name, val)
		if !ok {
			continue
		}
		f := &Finding{
			Check: "weak-session-id", Title: "弱会话标识（可预测形态）",
			Severity: "medium", URL: ft.Action, Param: name,
			Evidence: "状态变更请求下发的会话 Cookie " + name + " 形态可预测：" + ev,
			Advice:   "改用密码学安全的随机源（≥128 位）生成会话标识",
		}
		chainEvidence(f, ft.Action, resp)
		f.Signals = []string{"状态变更响应下发低熵会话 Cookie"}
		return f
	}
	return nil
}

// cookieNameValue 拆分单条 Set-Cookie 的名与值。
func cookieNameValue(raw string) (string, string) {
	head := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
	kv := strings.SplitN(head, "=", 2)
	if len(kv) != 2 {
		return "", ""
	}
	return strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
}
