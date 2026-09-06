// Package loginbrute 登录页弱口令爆破（独立模块，仅限授权目标）。
//
// 流程：GET 登录页 → 解析含密码框的表单（字段名缺失按 id/placeholder 推断）
// → 字典组合 POST 提交 → 按「失败基线 + 响应差异」判定命中。
// 安全护栏：请求总量硬上限（config LoginBrute.MaxTries）、复用全局限速、
// 授权确认由调用方（UI/文档）承载。
// 验证码识别（ddddocr）未迁移至 Go 版：要求验证码的表单会明确报错拒绝。
// 移植自 python 分支 scanner/loginbrute.py。
package loginbrute

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

var userHints = []string{"username", "user", "email", "account", "login", "loginname", "uname"}
var userHintZh = []string{"用户", "账号", "帐号", "邮箱"}

// Form 解析出的登录表单。
type Form struct {
	Action       string
	Method       string
	UserField    string
	PassField    string
	CaptchaField string
	HasCaptcha   bool
	Hidden       map[string]string
}

// analyze 从页面文档挑选最像登录表单的候选（无 form 标签时全文兜底）。
func analyze(doc *htmlx.Doc, baseURL string) *Form {
	type cand struct {
		f     *Form
		score int
	}
	var cands []cand
	scan := func(inputs []htmlx.Input, action, method string) {
		f := &Form{Action: action, Method: method, Hidden: map[string]string{}}
		userFound := false
		for _, in := range inputs {
			switch in.Type {
			case "submit", "button", "image", "reset":
				continue
			case "hidden":
				if in.Name != "" {
					f.Hidden[in.Name] = in.Value
				}
				continue
			}
			key := strings.ToLower(in.Name + " " + in.ID + " " + in.Placeholder)
			if in.Type == "password" {
				f.PassField = firstNonEmpty(in.Name, in.ID, in.Placeholder, "password")
				continue
			}
			if in.Type == "text" || in.Type == "email" || in.Type == "tel" {
				if !userFound && (hasAny(key, userHints) || hasAny(strings.ToLower(in.Placeholder), toLower(userHintZh))) {
					f.UserField = firstNonEmpty(in.Name, in.ID, "username")
					userFound = true
				}
			}
			if !f.HasCaptcha && containsAnyLetter(key, "captcha", "verif", "code", "valid") {
				f.HasCaptcha = true
				f.CaptchaField = firstNonEmpty(in.Name, in.ID, "captcha")
			}
		}
		if f.PassField == "" {
			return
		}
		if f.UserField == "" {
			f.UserField = "username"
		}
		if f.Method == "" {
			f.Method = "POST"
		}
		score := 0
		if userFound {
			score += 2
		}
		cands = append(cands, cand{f, score})
	}
	for _, form := range doc.Forms {
		scan(form.Inputs, resolveRef(baseURL, form.Action), form.Method)
	}
	if len(cands) == 0 {
		// JS 渲染站兜底：文档范围找密码框
		scan(allInputs(doc), baseURL, "POST")
	}
	if len(cands) == 0 {
		return nil
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.score > best.score {
			best = c
		}
	}
	return best.f
}

// Diag 表单解析诊断计数（报错提示用）。
type Diag struct {
	Forms     int
	Inputs    int
	Passwords int
}

// AnalyzeWithDiag 带诊断的解析。
func AnalyzeWithDiag(doc *htmlx.Doc, baseURL string) (*Form, Diag) {
	d := Diag{Forms: len(doc.Forms)}
	for _, f := range doc.Forms {
		d.Inputs += len(f.Inputs)
		if f.HasPassword {
			d.Passwords++
		}
	}
	f := analyze(doc, baseURL)
	return f, d
}

// LoadList 字典加载：去空行，截取前 limit 条。
func LoadList(path string, limit int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Hit 一组命中凭据。
type Hit struct {
	User     string `json:"user"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// Poster 表单提交接口（由 httpx 适配）。
type Poster interface {
	PostForm(rawURL string, fields map[string]string) (status int, body string, err error)
	GetSmall(rawURL string) (status int, body string, err error)
}

// Brute 执行爆破：返回命中列表（命中一组即停，控制请求量）。
// maxTries 为总尝试硬上限；captchaType 非空非 none 直接报错（Go 版未含 OCR）。
func Brute(p Poster, pageURL string, users, passwords []string, maxTries int,
	captchaType string, onProgress func(done, total int, msg string)) ([]Hit, error) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	if captchaType != "" && !strings.EqualFold(captchaType, "none") {
		return nil, fmt.Errorf("该登录页需要验证码识别，Go 版暂未包含该能力；请改用无验证码的表单页或使用 Python 分支")
	}
	if maxTries <= 0 {
		maxTries = 300
	}

	_, body, err := p.GetSmall(pageURL)
	if err != nil {
		return nil, fmt.Errorf("登录页请求失败：%v", err)
	}
	doc := htmlx.Parse(body)
	form, diag := AnalyzeWithDiag(doc, pageURL)
	if form == nil {
		return nil, fmt.Errorf("未解析到含密码框的登录表单（表单 %d 个，输入框 %d 个，密码框 %d 个）。"+
			"若页面由 JS 动态渲染登录框，请改用传统表单登录页测试",
			diag.Forms, diag.Inputs, diag.Passwords)
	}

	combos := []struct{ u, pw string }{}
	for _, u := range users {
		for _, pw := range passwords {
			if len(combos) >= maxTries-1 {
				break
			}
			combos = append(combos, struct{ u, pw string }{u, pw})
		}
	}
	total := len(combos) + 1

	// 失败基线：一组必然错误的提交
	bStatus, bBody, berr := p.PostForm(form.Action, map[string]string{
		form.UserField: "__nl_probe__", form.PassField: "__nl_probe__"})
	baseSize := len(bBody)
	if berr != nil {
		bStatus = 0
	}

	var hits []Hit
	for i, c := range combos {
		fields := map[string]string{}
		for k, v := range form.Hidden {
			fields[k] = v
		}
		fields[form.UserField] = c.u
		fields[form.PassField] = c.pw
		rStatus, rBody, rerr := p.PostForm(form.Action, fields)
		onProgress(i+2, total, c.u+" / "+strings.Repeat("*", len(c.pw)))
		if rerr != nil {
			continue
		}
		if isSuccess(rStatus, rBody, bStatus, baseSize) {
			hits = append(hits, Hit{User: c.u, Password: c.pw, URL: form.Action})
			break
		}
	}
	return hits, nil
}

// isSuccess 命中判定：不在登录页（无密码框回显）且状态/内容偏离失败基线。
func isSuccess(status int, body string, baseStatus, baseSize int) bool {
	if status == 0 || status >= 400 {
		return false
	}
	if strings.Contains(strings.ToLower(body), `type="password"`) ||
		strings.Contains(strings.ToLower(body), "type='password'") {
		return false // 仍在登录页
	}
	if baseStatus != 0 {
		thresh := baseSize * 15 / 100
		if thresh < 16 {
			thresh = 16
		}
		diff := len(body) - baseSize
		if diff < 0 {
			diff = -diff
		}
		if status == baseStatus && diff < thresh {
			return false
		}
	}
	return true
}

// ---- helpers ----

func allInputs(doc *htmlx.Doc) []htmlx.Input {
	var out []htmlx.Input
	for _, f := range doc.Forms {
		out = append(out, f.Inputs...)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func hasAny(s string, keys []string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func toLower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

func containsAnyLetter(s string, keys ...string) bool {
	return hasAny(s, keys)
}

// resolveRef 解析相对 action。
func resolveRef(base, ref string) string {
	if ref == "" {
		return base
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return bu.ResolveReference(ru).String()
}
