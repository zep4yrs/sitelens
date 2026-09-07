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
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/captcha"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
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
	Type     string `json:"type"` // basic-auth | login-form
	User     string `json:"user"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Note     string `json:"note,omitempty"` // 人工复核提示（如提交目标为登录页自身）
}

// BasicAuthBrute 对一组 401 路径做 HTTP Basic 弱口令尝试（命中即停/路径）。
// 凭据来自外部字典文件（调用方 LoadList），代码不内嵌任何可用凭据组合。
// intervalMS 为相邻尝试的间隔（对目标限速，0 = 不间隔）。
func BasicAuthBrute(client *httpx.Client, urls []string, users, passwords []string,
	maxTries int, intervalMS int, onProgress func(done, total int, msg string)) []Hit {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	if maxTries <= 0 {
		maxTries = 120
	}
	combos := []struct{ u, pw string }{}
	for _, u := range users {
		for _, pw := range passwords {
			if len(combos) >= maxTries {
				break
			}
			combos = append(combos, struct{ u, pw string }{u, pw})
		}
	}
	if len(combos) == 0 || len(urls) == 0 {
		return nil
	}
	if len(urls) > 3 {
		urls = urls[:3]
	}
	total := len(combos) * len(urls)
	done := 0
	var hits []Hit
	for _, u := range urls {
		for ci, c := range combos {
			sleepInterval(intervalMS, ci)
			token := base64.StdEncoding.EncodeToString([]byte(c.u + ":" + c.pw))
			r, err := client.GetFollowWith(u, map[string]string{"Authorization": "Basic " + token})
			done++
			if err == nil && r != nil && r.Status == 200 {
				hits = append(hits, Hit{Type: "basic-auth", User: c.u, Password: c.pw, URL: u})
				break // 该路径命中即换下一路径
			}
			onProgress(done, total, "Basic "+c.u+" / "+strings.Repeat("*", len(c.pw)))
		}
	}
	return hits
}

// sleepInterval 相邻尝试间隔（首个尝试前不休眠；0 = 不间隔）。
func sleepInterval(intervalMS, attemptIndex int) {
	if intervalMS > 0 && attemptIndex > 0 {
		time.Sleep(time.Duration(intervalMS) * time.Millisecond)
	}
}

// solveCaptcha 刷新登录页取新验证码图，拉取字节后经 ddddocr sidecar 识别。
// digits：仅保留字母数字；calc：从识别文本解析两步算术并计算。
func solveCaptcha(p Poster, opts Options, pageURL string, fallbackImgs []string) (string, error) {
	_, body, err := p.GetSmall(pageURL)
	if err != nil {
		return "", err
	}
	imgs := htmlx.Parse(body).CaptchaImgs
	if len(imgs) == 0 {
		imgs = fallbackImgs
	}
	if len(imgs) == 0 {
		return "", fmt.Errorf("页面未找到验证码图片")
	}
	imgURL := resolveRef(pageURL, imgs[0])
	if opts.FetchImage == nil {
		return "", fmt.Errorf("未配置图片拉取通道")
	}
	raw, err := opts.FetchImage(imgURL)
	if err != nil {
		return "", err
	}
	cli := captcha.NewClient(opts.OCRURL, 10*time.Second)
	code, err := cli.SolveImage(raw)
	if err != nil {
		return "", err
	}
	code = strings.TrimSpace(code)
	if strings.EqualFold(opts.CaptchaType, "calc") {
		v, ok := calcEval(code)
		if !ok {
			return "", fmt.Errorf("算术验证码解析失败：%q", code)
		}
		return strconv.Itoa(v), nil
	}
	// digits：仅保留字母数字（OCR 常带噪声）
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, code), nil
}

var calcRe = regexp.MustCompile(`(\d{1,4})\s*([+\-x×*÷/])\s*(\d{1,4})`)

// calcEval 从识别文本解析「a op b」并计算；手工实现，不用 eval。
func calcEval(text string) (int, bool) {
	m := calcRe.FindStringSubmatch(strings.NewReplacer("×", "*", "÷", "/").Replace(text))
	if m == nil {
		return 0, false
	}
	a, e1 := strconv.Atoi(m[1])
	b, e2 := strconv.Atoi(m[3])
	if e1 != nil || e2 != nil {
		return 0, false
	}
	switch m[2] {
	case "+":
		return a + b, true
	case "-":
		return a - b, true
	case "*", "x":
		return a * b, true
	case "/":
		if b != 0 {
			return a / b, true
		}
		return 0, false
	}
	return 0, false
}

// Poster 表单提交接口（由 httpx 适配）。
type Poster interface {
	PostForm(rawURL string, fields map[string]string) (status int, body string, err error)
	GetSmall(rawURL string) (status int, body string, err error)
	PostJSON(rawURL, body string) (status int, respBody string, err error)
}

// Options 爆破参数。
type Options struct {
	PageURL         string                              // 登录页地址
	Users           []string                            // 用户名字典
	Passwords       []string                            // 密码字典
	MaxTries        int                                 // 总尝试硬上限
	IntervalMS      int                                 // 相邻尝试间隔（毫秒，0 = 不间隔）
	CaptchaType     string                              // 验证码类型（none/digits/calc；digits|calc 需配 OCRURL）
	OCRURL          string                              // ddddocr sidecar 地址（空 = 无 OCR 能力）
	CaptchaImgs     []string                            // 登录页中的验证码图片地址（相对/绝对均可）
	FetchImage      func(rawURL string) ([]byte, error) // 验证码图片字节拉取
	RenderedBody    string                              // SPA 支持：无头渲染后的页面 HTML；非空时表单解析优先使用它
	LoginMode       string                              // form（默认）| json
	JSONEndpoint    string                              // json 模式登录接口（空 = PageURL）
	JSONTemplate    string                              // 含 {user}/{pass} 占位符的 JSON 模板
	SuccessContains string                              // json 模式可选成功特征
}

// Brute 执行爆破：返回命中列表（命中一组即停，控制请求量）。
// 表单解析优先使用 RenderedBody（SPA 登录页由 chromedp 渲染后传入），
// 为空时抓取 PageURL 的静态 HTML——纯 JS 渲染且未开无头渲染的页面
// 会解析不到表单并明确报错。
// CaptchaType=digits/calc 时需配 OCRURL（ddddocr sidecar）：
// 每次尝试前刷新登录页取新验证码图，OCR 识别后自动填入验证码字段。
func Brute(p Poster, opts Options, onProgress func(done, total int, msg string)) ([]Hit, error) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	if opts.CaptchaType != "" && !strings.EqualFold(opts.CaptchaType, "none") && opts.OCRURL == "" {
		return nil, fmt.Errorf("该登录页需要验证码识别：请先启动 ddddocr sidecar" +
			"（python tools/ocr_server.py）并在配置 loginbrute.captcha_ocr_url 指向它")
	}
	if opts.MaxTries <= 0 {
		opts.MaxTries = 300
	}
	pageURL := opts.PageURL

	pageBody := opts.RenderedBody
	formSrc := "渲染页"
	if pageBody == "" {
		_, body, err := p.GetSmall(pageURL)
		if err != nil {
			return nil, fmt.Errorf("登录页请求失败：%v", err)
		}
		pageBody = body
		formSrc = "静态页"
	}
	doc := htmlx.Parse(pageBody)
	form, diag := AnalyzeWithDiag(doc, pageURL)
	if form == nil {
		return nil, fmt.Errorf("未解析到含密码框的登录表单（%s：表单 %d 个，输入框 %d 个，密码框 %d 个）。"+
			"若页面由 JS 动态渲染登录框，请在 crawler.headless 开启无头渲染后重试",
			formSrc, diag.Forms, diag.Inputs, diag.Passwords)
	}
	if form.CaptchaField != "" && opts.OCRURL == "" {
		return nil, fmt.Errorf("登录表单含验证码字段（%s）但未配置识别服务；"+
			"请在配置 loginbrute.captcha_ocr_url 指向 ddddocr sidecar 后重试", form.CaptchaField)
	}

	combos := []struct{ u, pw string }{}
	for _, u := range opts.Users {
		for _, pw := range opts.Passwords {
			if len(combos) >= opts.MaxTries-1 {
				break
			}
			combos = append(combos, struct{ u, pw string }{u, pw})
		}
	}
	total := len(combos) + 1

	// 提交目标诚实标注：表单无 action 时按惯例 POST 到登录页自身，
	// 命中证据里注明，提醒人工复核该结果的提交语义
	submitTargetNote := ""
	if form.Action == pageURL {
		submitTargetNote = "；表单未声明 action，提交目标为登录页自身，建议人工复核"
	}

	// 失败基线：一组必然错误的提交
	bStatus, bBody, berr := p.PostForm(form.Action, map[string]string{
		form.UserField: "__nl_probe__", form.PassField: "__nl_probe__"})
	baseSize := len(bBody)
	if berr != nil {
		bStatus = 0
	}

	var hits []Hit
	for i, c := range combos {
		sleepInterval(opts.IntervalMS, i)
		fields := map[string]string{}
		for k, v := range form.Hidden {
			fields[k] = v
		}
		fields[form.UserField] = c.u
		fields[form.PassField] = c.pw
		if form.CaptchaField != "" {
			// 每次尝试前刷新登录页取新验证码图（旧码通常已失效）
			code, cerr := solveCaptcha(p, opts, pageURL, doc.CaptchaImgs)
			if cerr != nil {
				onProgress(i+2, total, "验证码识别失败，跳过 "+c.u+"："+cerr.Error())
				continue
			}
			fields[form.CaptchaField] = code
		}
		rStatus, rBody, rerr := p.PostForm(form.Action, fields)
		onProgress(i+2, total, c.u+" / "+strings.Repeat("*", len(c.pw)))
		if rerr != nil {
			continue
		}
		if isSuccess(rStatus, rBody, bStatus, baseSize) {
			hits = append(hits, Hit{
				User: c.u, Password: c.pw, URL: form.Action,
				Note: submitTargetNote,
			})
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
