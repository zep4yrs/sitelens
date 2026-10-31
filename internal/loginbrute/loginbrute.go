// Package loginbrute 登录页弱口令爆破（独立模块；目标合规责任在使用者）。
//
// 流程：GET 登录页 → 解析含密码框的表单（字段名缺失按 id/placeholder 推断）
// → 字典组合 POST 提交 → 按「失败基线 + 响应差异」判定命中。
// 安全护栏（LB-01，5.2）：请求总量硬上限（config LoginBrute.MaxTries）、
// 复用全局限速；锁号/限流信号（锁定/冻结/locked/too many attempts、429/403）
// 立即停止；连续失败阈值（默认 5）停止或指数退避；每账号尝试上限（默认 3）；
// 每次 POST 前重取登录页刷新 hidden/CSRF token；命中附响应差异摘要 +
// Set-Cookie + 跳转 + 可复制 curl 证据（命中判定逻辑不变）。
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
	// 成功证据（LB-01，additive）：命中判定逻辑不变，仅补充可复核证据。
	Evidence  string   `json:"evidence,omitempty"`   // 响应差异摘要（状态/正文尺寸对比失败基线）
	Redirect  string   `json:"redirect,omitempty"`   // 成功跳转目标（Location 或正文跳转提示）
	SetCookie []string `json:"set_cookie,omitempty"` // 成功响应 Set-Cookie（需 Poster 实现 ResponsePoster，否则为空）
	Curl      string   `json:"curl,omitempty"`       // 可复制复现命令
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

// solveCaptcha 取登录页中的验证码图，拉取字节后经 ddddocr sidecar 识别。
// pageBody 非空时复用调用方刚刷新的页面正文（LB-01 的 CSRF 刷新与验证码
// 刷新共用一次 GET，避免每次尝试两个 GET）；为空时自行拉取登录页。
// digits：仅保留字母数字；calc：从识别文本解析两步算术并计算。
func solveCaptcha(p Poster, opts Options, pageURL, pageBody string, fallbackImgs []string) (string, error) {
	if pageBody == "" {
		_, body, err := p.GetSmall(pageURL)
		if err != nil {
			return "", err
		}
		pageBody = body
	}
	imgs := htmlx.Parse(pageBody).CaptchaImgs
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
	CaptchaField    string                              // 验证码字段名（空 = 表单自动识别；非空覆盖解析结果）
	OCRURL          string                              // ddddocr sidecar 地址（空 = 无 OCR 能力）
	CaptchaImgs     []string                            // 登录页中的验证码图片地址（相对/绝对均可）
	FetchImage      func(rawURL string) ([]byte, error) // 验证码图片字节拉取
	RenderedBody    string                              // SPA 支持：无头渲染后的页面 HTML；非空时表单解析优先使用它
	LoginMode       string                              // form（默认）| json
	JSONEndpoint    string                              // json 模式登录接口（空 = PageURL）
	JSONTemplate    string                              // 含 {user}/{pass} 占位符的 JSON 模板
	SuccessContains string                              // json 模式可选成功特征
	Cancel          func() bool                         // 取消轮询：返回 true 时爆破提前终止（由调用方注入，nil = 不可取消）

	// ---- LB-01 安全护栏（additive；零值 = 默认护栏，显式负值 = 关闭/不限） ----

	// MaxPerUser 同一用户名最多尝试次数（0 = 默认 3；<0 = 不限制）。
	// 目的：避免把真实账号连续打满触发锁定。
	MaxPerUser int
	// MaxConsecutiveFails 连续失败阈值（0 = 默认 5；<0 = 关闭该保护）。
	// 达到阈值后：FailBackoffMS <= 0 → 立即停止并返回原因；
	// FailBackoffMS > 0 → 指数退避后继续（总尝试仍受 MaxTries 约束）。
	MaxConsecutiveFails int
	// FailBackoffMS 连续失败达阈值后的指数退避基数（毫秒；0 = 直接停止）。
	// 实际等待 = base << level（level 从 0 递增），封顶 30s。
	FailBackoffMS int
	// DisableTokenRefresh 关闭「每次 POST 前重取登录页刷新 hidden/CSRF
	// token」的额外 GET（默认 false = 启用）。启用时含隐藏字段/验证码的
	// 表单每次尝试额外 1 个 GET；POST 尝试数仍受 MaxTries 硬上限约束。
	DisableTokenRefresh bool
}

// refreshLoginForm 重取登录页，刷新 hidden/CSRF 字段与验证码图（LB-01）。
// 一次性 token 站点（每次 GET 换 token）靠它避免「用旧 token 提交」的
// 误判；GET 失败/解析不到表单时返回 ok=false，调用方沿用旧表单继续
// （不因刷新失败中断爆破）。
func refreshLoginForm(p Poster, pageURL string) (hidden map[string]string, captchaImgs []string, body string, ok bool) {
	st, body, err := p.GetSmall(pageURL)
	if err != nil || st == 0 || st >= 400 {
		return nil, nil, "", false
	}
	doc := htmlx.Parse(body)
	f, _ := AnalyzeWithDiag(doc, pageURL)
	if f == nil {
		return nil, nil, "", false
	}
	return f.Hidden, doc.CaptchaImgs, body, true
}

// Brute 执行爆破：返回命中列表（命中一组即停，控制请求量）。
// 表单解析优先使用 RenderedBody（SPA 登录页由 chromedp 渲染后传入），
// 为空时抓取 PageURL 的静态 HTML——纯 JS 渲染且未开无头渲染的页面
// 会解析不到表单并明确报错。
// CaptchaType=digits/calc 时需配 OCRURL（ddddocr sidecar）：
// 每次尝试前刷新登录页取新验证码图，OCR 识别后自动填入验证码字段。
//
// LB-01 护栏：每次 POST 前重取登录页刷新 hidden/CSRF token（可用
// Options.DisableTokenRefresh 关闭）；失败响应命中锁号/限流信号立即停止；
// 连续失败达阈值停止（或指数退避）；每账号尝试数受限。命中判定逻辑
// （isSuccess）不变，Hit 只追加证据字段。
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
	maxPerUser, maxFails := resolveGuard(&opts)
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
	// 用户显式指定的验证码字段名覆盖自动识别（自动解析可能选错输入框）
	if opts.CaptchaField != "" {
		form.CaptchaField = opts.CaptchaField
		form.HasCaptcha = true
	}

	// 组合生成（LB-01）：MaxTries-1 为基线预留 1 次；每账号最多
	// maxPerUser 次（避免连续打同一真实账号触发锁定）。
	budget := opts.MaxTries - 1
	if budget <= 0 {
		budget = 1
	}
	combos := buildCombos(opts.Users, opts.Passwords, budget, maxPerUser)
	total := len(combos) + 1 // +1 = 失败基线

	// 提交目标诚实标注：表单无 action 时按惯例 POST 到登录页自身，
	// 命中证据里注明，提醒人工复核该结果的提交语义
	submitTargetNote := ""
	if form.Action == pageURL {
		submitTargetNote = "；表单未声明 action，提交目标为登录页自身，建议人工复核"
	}

	// 需要刷新 token 的表单：含隐藏字段（CSRF/一次性 token）或验证码
	// （验证码图每次 GET 更新）。无 token 的表单不做额外 GET，避免请求量翻倍。
	needRefresh := len(form.Hidden) > 0 || form.CaptchaField != ""
	// refreshPage 重取登录页：返回刷新后的 hidden 字段、验证码图与正文。
	// 刷新失败、或刷新到的静态页没有可用 token/验证码（SPA 静态壳场景）
	// 时回退初始表单数据，不中断爆破。
	refreshPage := func() (map[string]string, []string, string) {
		if needRefresh && !opts.DisableTokenRefresh {
			if h, imgs, body, ok := refreshLoginForm(p, pageURL); ok && (len(h) > 0 || len(imgs) > 0) {
				return h, imgs, body
			}
		}
		return form.Hidden, doc.CaptchaImgs, ""
	}

	// 失败基线：一组必然错误的提交（带刷新后的 hidden/CSRF，使基线差异
	// 来自「错误口令」而不是「无效 token」）。验证码表单尽量解出验证码后
	// 再取基线；OCR 失败时不把 403/429 当锁号（可能是验证码无效造成）。
	baseHidden, baseImgs, baseBody := refreshPage()
	baselineFields := make(map[string]string, len(baseHidden)+2)
	for k, v := range baseHidden {
		baselineFields[k] = v
	}
	baselineFields[form.UserField] = "__nl_probe__"
	baselineFields[form.PassField] = "__nl_probe__"
	baselineCaptchaOK := true
	if form.CaptchaField != "" {
		code, cerr := solveCaptcha(p, opts, pageURL, baseBody, baseImgs)
		if cerr != nil {
			baselineCaptchaOK = false
			onProgress(1, total, "基线验证码识别失败，继续（基线差异仅供参考）："+cerr.Error())
		} else {
			baselineFields[form.CaptchaField] = code
		}
	}
	bStatus, bBody, _, berr := postFormFull(p, form.Action, baselineFields)
	baseSize := len(bBody)
	if berr != nil {
		bStatus = 0
	}
	if berr == nil {
		if sig := lockoutSignal(bStatus, bBody); sig != "" {
			selfInflicted := form.CaptchaField != "" && !baselineCaptchaOK &&
				(bStatus == 403 || bStatus == 429)
			if !selfInflicted {
				return nil, fmt.Errorf("失败基线即触发锁号/限流信号（%s）：已停止对 %s 的爆破，避免误锁真实账号", sig, pageURL)
			}
		}
	}

	var hits []Hit
	fails, backoffLevel := 0, 0
	for i, c := range combos {
		if opts.Cancel != nil && opts.Cancel() {
			break // 已取消：停止后续登录尝试，命中结果照常返回
		}
		sleepInterval(opts.IntervalMS, i)
		hidden, captchaImgs, refreshBody := refreshPage()
		fields := make(map[string]string, len(hidden)+3)
		for k, v := range hidden {
			fields[k] = v
		}
		fields[form.UserField] = c.u
		fields[form.PassField] = c.pw
		if form.CaptchaField != "" {
			// 复用同一次刷新 GET 取验证码图（旧码通常已失效）
			code, cerr := solveCaptcha(p, opts, pageURL, refreshBody, captchaImgs)
			if cerr != nil {
				onProgress(i+2, total, "验证码识别失败，跳过 "+c.u+"："+cerr.Error())
				continue
			}
			fields[form.CaptchaField] = code
		}
		rStatus, rBody, rHeader, rerr := postFormFull(p, form.Action, fields)
		onProgress(i+2, total, c.u+" / "+strings.Repeat("*", len(c.pw)))
		if rerr != nil {
			continue
		}
		// LB-01 锁号保护：失败响应出现锁号/限流特征或 429/403 → 立即停止
		if sig := lockoutSignal(rStatus, rBody); sig != "" {
			return hits, fmt.Errorf("检测到锁号/限流信号（%s）：已立即停止对 %s 的爆破"+
				"（已尝试 %d/%d 组）。请稍后人工复核，避免锁死真实账号", sig, pageURL, i+1, len(combos))
		}
		if isSuccess(rStatus, rBody, bStatus, baseSize) {
			ev := formEvidence(form.Action, fields, rStatus, rBody, rHeader, bStatus, baseSize)
			hits = append(hits, Hit{
				User: c.u, Password: c.pw, URL: form.Action,
				Note:     submitTargetNote,
				Evidence: ev.Summary, Redirect: ev.Redirect,
				SetCookie: ev.SetCookie, Curl: ev.Curl,
			})
			break
		}
		fails++
		if maxFails > 0 && fails >= maxFails {
			if opts.FailBackoffMS > 0 {
				d := backoffDelay(opts.FailBackoffMS, backoffLevel)
				backoffLevel++
				onProgress(i+2, total, fmt.Sprintf("连续失败 %d 次，指数退避 %s 后继续", fails, d))
				time.Sleep(d)
				fails = 0
				continue
			}
			return hits, fmt.Errorf("连续失败 %d 次达到阈值：已停止对 %s 的爆破，避免锁死真实账号"+
				"（可用 Options.MaxConsecutiveFails 调整，负值关闭；或配 Options.FailBackoffMS 改为退避）",
				fails, pageURL)
		}
	}
	return hits, nil
}

// isSuccess 命中判定：不在登录页（无密码框回显）且状态/内容偏离失败基线。
//
// DVWA / pikachu 这类靶场成功登录返回 302 + 空正文，失败返回 200 + 登录页：
// 只看正文会把成功误判成"空页面"。因此重定向状态优先判定为成功，
// 但保留一条反例——重定向回登录页本身（Location 含 login/signin）不算命中。
func isSuccess(status int, body string, baseStatus, baseSize int) bool {
	if status == 0 || status >= 400 {
		return false
	}
	low := strings.ToLower(body)
	if strings.Contains(low, `type="password"`) ||
		strings.Contains(low, "type='password'") {
		return false // 仍在登录页
	}
	// 重定向到非登录页 = 会话已建立（表单登录最可靠的信号）
	if status == 302 || status == 303 || status == 307 || status == 308 {
		if loc := redirectTarget(body); loc != "" && isLoginPath(loc) {
			return false
		}
		return true
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

// redirectTarget 从 302 正文里的 <a href> / Location 提示中取跳转目标。
// PostForm 不跟重定向且不保留响应头，正文里的 meta refresh / 链接是
// 唯一可读线索；取不到就返回空（调用方按"非登录页"处理）。
func redirectTarget(body string) string {
	low := strings.ToLower(body)
	for _, key := range []string{"location.href", "location.replace", "url="} {
		if i := strings.Index(low, key); i >= 0 {
			seg := body[i+len(key):]
			seg = strings.TrimLeft(seg, "= (\"'")
			if j := strings.IndexAny(seg, "\"' )\n"); j > 0 {
				return strings.ToLower(seg[:j])
			}
		}
	}
	return ""
}

// isLoginPath 跳转目标是否仍在登录页（login.php / signin 等）。
func isLoginPath(u string) bool {
	for _, k := range []string{"login", "signin", "sign-in", "auth", "session/new"} {
		if strings.Contains(u, k) {
			return true
		}
	}
	return false
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
