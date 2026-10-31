// 多步登录（LB-02）：先提交用户名 → 再提交密码。
//
// 两种使用方式：
//
//  1. Options.MultiStep = true → Brute 内部转调 BruteMultiStep（步骤自动推导）；
//  2. 直接调用 BruteMultiStep(p, opts, steps, onProgress) 显式给出每步字段
//     （steps 为空 = 自动推导；1 步 = 第二步从第一步响应动态发现；2 步 = 显式）。
//
// 可靠性优先的推导规则：
//   - 登录页已有密码框 → 按「同一表单 URL 两步」执行（先用户名后密码）；
//   - 登录页只有用户名框（用户名优先页）→ 第一步只提交用户名；第一步响应
//     重新出现密码框时才提交第二步，否则第一步响应即最终结果（例如
//     「用户名不存在」会直接短路，不再发第二步请求）；
//   - 第二步的 action / hidden / CSRF 优先取第一步响应里解析到的表单
//     （一次性 token 站点靠它避免用旧 token 提交），显式 Steps 字段优先。
//
// 安全护栏与 Brute 一致：锁号/限流立即停止、连续失败阈值/退避、每账号上限、
// 取消、限速、授权白名单（每一步的提交地址都校验）。命中判定复用 isSuccess。
// 验证码：第二步表单含验证码时复用既有 OCR 通道（ddddocr sidecar）。
package loginbrute

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

// Step 多步登录中的一步（LB-02）。字段缺省时回退到登录页/第一步响应解析结果。
type Step struct {
	Action    string            // 提交地址（空 = 登录页 PageURL；相对地址按登录页解析）
	Fields    map[string]string // 该步固定字段（hidden/CSRF/token 等；值内 {user}/{pass} 会被替换）
	UserField string            // 本步写入用户名的字段名（空 = 自动推断/本步不写用户名）
	PassField string            // 本步写入口令的字段名（空 = 本步不写口令）
}

// stepPlan 多步执行计划。
type stepPlan struct {
	first  Step // 第一步（用户名）
	second Step // 第二步（口令）
	// dynamic = 第二步表单从第一步响应中动态发现（用户名优先页的常见形态）。
	dynamic bool
}

// BruteMultiStep 执行两步登录爆破：返回命中列表（命中一组即停）。
//
// steps 为显式步骤（最多两步）：nil/空 = 按登录页自动推导；1 步 = 第一步
// 显式、第二步动态发现；2 步 = 完整显式。推导/请求前的错误直接返回，
// 且授权白名单不通过时零请求。
func BruteMultiStep(p Poster, opts Options, steps []Step,
	onProgress func(done, total int, msg string)) ([]Hit, error) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	// LB-02：授权白名单（零请求前置检查）
	if err := checkAllowHosts(&opts); err != nil {
		return nil, err
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
	if pageBody == "" {
		_, body, err := p.GetSmall(pageURL)
		if err != nil {
			return nil, fmt.Errorf("登录页请求失败：%v", err)
		}
		pageBody = body
	}
	doc := htmlx.Parse(pageBody)
	plan, err := buildStepPlan(doc, pageURL, steps)
	if err != nil {
		return nil, err
	}
	if plan.first.UserField == "" {
		plan.first.UserField = "username"
	}
	if !plan.dynamic && plan.second.PassField == "" {
		plan.second.PassField = "password"
	}
	// 白名单：显式步骤的提交地址在发请求前就校验（页面解析出的地址在 attempt 内校验）
	if err := requireStepAllowed(&opts, plan.first.Action); err != nil {
		return nil, err
	}
	if !plan.dynamic {
		if err := requireStepAllowed(&opts, plan.second.Action); err != nil {
			return nil, err
		}
	}

	budget := opts.MaxTries - 1
	if budget <= 0 {
		budget = 1
	}
	combos := buildCombos(opts.Users, opts.Passwords, budget, maxPerUser)
	total := len(combos) + 1 // +1 = 失败基线

	runner := &multiStepRunner{p: p, opts: opts, plan: plan, pageURL: pageURL}

	// 失败基线：用 probe 凭据完整走一遍两步（第二步失败响应作为基线）。
	base := runner.attempt("__nl_probe__", "__nl_probe__")
	baseStatus, baseSize := base.status, len(base.body)
	if base.err != nil {
		baseStatus = 0 // 与 Brute 同口径：基线请求失败 → 只按启发式判定
	}
	if base.lockSignal != "" {
		return nil, fmt.Errorf("失败基线即触发锁号/限流信号（%s）：已停止对 %s 的爆破，避免误锁真实账号",
			base.lockSignal, pageURL)
	}
	if plan.dynamic && !base.needSecond {
		// probe 用户名下第一步响应没有密码框（如「用户名不存在」）：
		// 没有可用的第二步基线，退化为启发式判定
		baseStatus, baseSize = 0, 0
	}

	var hits []Hit
	fails, backoffLevel := 0, 0
	for i, c := range combos {
		if opts.Cancel != nil && opts.Cancel() {
			break // 已取消：停止后续登录尝试，命中结果照常返回
		}
		sleepInterval(opts.IntervalMS, i)
		out := runner.attempt(c.u, c.pw)
		progress := attemptProgress(c.u, c.pw)
		if out.captchaFail != nil {
			onProgress(i+2, total, "验证码识别失败，跳过 "+c.u+"："+out.captchaFail.Error())
			continue
		}
		if out.captchaMissing {
			// 第二步需要验证码但没配 OCR：直接报错（与单步模式同口径）
			return hits, out.err
		}
		if out.lockSignal != "" {
			cat := notifyFailure(&opts, c.u, out.status, out.body)
			onProgress(i+2, total, progress+" [失败: "+cat+"]")
			return hits, fmt.Errorf("检测到锁号/限流信号（%s）：已立即停止对 %s 的爆破"+
				"（已尝试 %d/%d 组）。请稍后人工复核，避免锁死真实账号",
				out.lockSignal, pageURL, i+1, len(combos))
		}
		if out.err != nil {
			_ = notifyFailure(&opts, c.u, 0, "")
			onProgress(i+2, total, progress+" [失败: "+FailureUnknown+"]")
			continue
		}
		if isSuccess(out.status, out.body, baseStatus, baseSize) &&
			(!out.singleStepFinal || isRedirectStatus(out.status)) {
			onProgress(i+2, total, progress) // 命中：不标失败
			hits = append(hits, buildMultiStepHit(c.u, c.pw, out, baseStatus, baseSize))
			break
		}
		cat := notifyFailure(&opts, c.u, out.status, out.body)
		onProgress(i+2, total, progress+" [失败: "+cat+"]")
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

// multiStepRunner 多步执行器（一次 BruteMultiStep 调用内复用）。
type multiStepRunner struct {
	p       Poster
	opts    Options
	plan    stepPlan
	pageURL string
}

// multiStepOutcome 一次多步尝试的结果。
type multiStepOutcome struct {
	status int
	body   string
	header http.Header
	err    error
	// 命中证据用（两步 curl）
	step1Action string
	step1Fields map[string]string
	step2Action string
	step2Fields map[string]string
	needSecond  bool   // 是否执行了第二步
	lockSignal  string // 非空 = 响应触发锁号/限流信号
	captchaFail error  // 非空 = 第二步验证码识别失败（未发出第二步请求）
	// captchaMissing = 第二步需要验证码但未配置 OCR（应直接报错，不继续爆破）。
	captchaMissing bool
	// singleStepFinal = 动态模式下第一步响应没有密码框、以第一步响应为最终结果。
	// 此时只认 3xx 重定向为成功——200 更可能是「用户名不存在」等错误页，
	// 按成功处理会误报（宁少报不误报）。
	singleStepFinal bool
}

// attempt 执行一次完整的两步尝试（第一步用户名 → 第二步口令）。
func (r *multiStepRunner) attempt(user, pass string) multiStepOutcome {
	var out multiStepOutcome

	// ---- 第一步：只提交用户名 ----
	fields1 := copyFields(r.plan.first.Fields)
	if r.plan.first.UserField != "" {
		fields1[r.plan.first.UserField] = user
	}
	applyPlaceholders(fields1, user, pass)
	if err := requireStepAllowed(&r.opts, r.plan.first.Action); err != nil {
		out.err = err
		return out
	}
	st1, body1, hdr1, err := postFormFull(r.p, r.plan.first.Action, fields1)
	out.step1Action, out.step1Fields = r.plan.first.Action, fields1
	if err != nil {
		out.err = err
		return out
	}
	if sig := lockoutSignal(st1, body1); sig != "" {
		out.status, out.body, out.header, out.lockSignal = st1, body1, hdr1, sig
		return out
	}

	// ---- 第二步：从第一步响应解析表单（或使用显式步骤） ----
	second, need, captchaField, captchaImgs := r.resolveSecond(body1)
	if !need {
		// 用户名优先页在第一步响应里没有密码框：第一步响应即最终结果
		out.status, out.body, out.header = st1, body1, hdr1
		out.singleStepFinal = true
		return out
	}
	if err := requireStepAllowed(&r.opts, second.Action); err != nil {
		out.err = err
		return out
	}
	fields2 := copyFields(second.Fields)
	if second.UserField != "" {
		fields2[second.UserField] = user
	}
	if second.PassField != "" {
		fields2[second.PassField] = pass
	}
	if captchaField != "" {
		if r.opts.OCRURL == "" {
			out.err = fmt.Errorf("登录表单含验证码字段（%s）但未配置识别服务；"+
				"请在配置 loginbrute.captcha_ocr_url 指向 ddddocr sidecar 后重试", captchaField)
			out.captchaMissing = true
			return out
		}
		// 第一步响应就是第二步表单所在页面：直接复用该正文取验证码图
		code, cerr := solveCaptcha(r.p, r.opts, r.pageURL, body1, captchaImgs)
		if cerr != nil {
			out.captchaFail = cerr
			return out
		}
		fields2[captchaField] = code
	}
	applyPlaceholders(fields2, user, pass)
	st2, body2, hdr2, err := postFormFull(r.p, second.Action, fields2)
	out.step2Action, out.step2Fields, out.needSecond = second.Action, fields2, true
	if err != nil {
		out.err = err
		return out
	}
	if sig := lockoutSignal(st2, body2); sig != "" {
		out.status, out.body, out.header, out.lockSignal = st2, body2, hdr2, sig
		return out
	}
	out.status, out.body, out.header = st2, body2, hdr2
	return out
}

// resolveSecond 解析第二步：显式步骤优先（并用第一步响应的 hidden 字段补齐），
// 动态模式则只在第一步响应重新出现密码框时才返回 need=true。
func (r *multiStepRunner) resolveSecond(firstBody string) (Step, bool, string, []string) {
	if !r.plan.dynamic {
		st := Step{
			Action:    r.plan.second.Action,
			Fields:    copyFields(r.plan.second.Fields),
			UserField: r.plan.second.UserField,
			PassField: r.plan.second.PassField,
		}
		captchaField := r.opts.CaptchaField
		var imgs []string
		if fd := htmlx.Parse(firstBody); fd != nil {
			imgs = fd.CaptchaImgs
			if form := analyze(fd, r.pageURL); form != nil {
				// 一次性 token：第一步响应里的 hidden 字段补齐（显式字段优先）
				for k, v := range form.Hidden {
					if _, ok := st.Fields[k]; !ok {
						st.Fields[k] = v
					}
				}
				if st.PassField == "" {
					st.PassField = form.PassField
				}
				if captchaField == "" {
					captchaField = form.CaptchaField
				}
			}
		}
		return st, true, captchaField, imgs
	}
	// 动态：第一步响应重新出现密码框 → 需要第二步
	fd := htmlx.Parse(firstBody)
	form := analyze(fd, r.pageURL)
	if form == nil {
		return Step{}, false, "", nil
	}
	captchaField := form.CaptchaField
	if r.opts.CaptchaField != "" {
		captchaField = r.opts.CaptchaField
	}
	return Step{
		Action:    form.Action,
		Fields:    copyFields(form.Hidden),
		UserField: form.UserField,
		PassField: form.PassField,
	}, true, captchaField, fd.CaptchaImgs
}

// buildMultiStepHit 组装多步命中（证据含两步提交命令，便于人工复核）。
func buildMultiStepHit(user, pass string, out multiStepOutcome, baseStatus, baseSize int) Hit {
	ev := buildEvidence(out.status, out.body, out.header, baseStatus, baseSize)
	curl := formCurl(out.step1Action, out.step1Fields)
	if out.step2Fields != nil {
		curl += "\n" + formCurl(out.step2Action, out.step2Fields)
	}
	target := out.step2Action
	if target == "" {
		target = out.step1Action
	}
	return Hit{
		Type: "login-form", User: user, Password: pass, URL: target,
		Note:     "多步登录（先用户名后密码）命中：证据含两步提交命令，请人工复核",
		Evidence: ev.Summary, Redirect: ev.Redirect,
		SetCookie: ev.SetCookie, Curl: curl,
	}
}

// buildStepPlan 依据显式 steps / 登录页表单推导执行计划。
func buildStepPlan(doc *htmlx.Doc, pageURL string, steps []Step) (stepPlan, error) {
	switch len(steps) {
	case 0:
		return deriveStepPlan(doc, pageURL)
	case 1:
		// 显式第一步 + 第二步动态发现
		return stepPlan{first: fillStepDefaults(steps[0], pageURL, false), dynamic: true}, nil
	case 2:
		return stepPlan{
			first:  fillStepDefaults(steps[0], pageURL, false),
			second: fillStepDefaults(steps[1], pageURL, true),
		}, nil
	default:
		return stepPlan{}, fmt.Errorf("多步登录最多支持两步（收到 %d 步）", len(steps))
	}
}

// fillStepDefaults 补齐单步缺省：Action 归一为绝对地址；第一步强制不带口令。
func fillStepDefaults(step Step, pageURL string, second bool) Step {
	action := strings.TrimSpace(step.Action)
	if action == "" {
		action = pageURL
	} else {
		action = resolveRef(pageURL, action)
	}
	out := Step{Action: action, Fields: copyFields(step.Fields),
		UserField: step.UserField, PassField: step.PassField}
	if !second {
		out.PassField = "" // 第一步只提交用户名（多步登录语义）
	}
	return out
}

// deriveStepPlan 自动推导执行计划：
//   - 登录页含密码框 → 同一表单 URL 两步（先用户名后密码）；
//   - 登录页只有用户名框 → 第一步显式、第二步从第一步响应动态发现。
func deriveStepPlan(doc *htmlx.Doc, pageURL string) (stepPlan, error) {
	if form := analyze(doc, pageURL); form != nil {
		return stepPlan{
			first: Step{Action: form.Action, UserField: form.UserField,
				Fields: copyFields(form.Hidden)},
			second: Step{Action: form.Action, UserField: form.UserField,
				PassField: form.PassField, Fields: copyFields(form.Hidden)},
		}, nil
	}
	if st, ok := analyzeUserStep(doc, pageURL); ok {
		return stepPlan{first: st, dynamic: true}, nil
	}
	return stepPlan{}, fmt.Errorf("多步登录未解析到登录表单：登录页既无密码框表单，也无用户名输入表单。" +
		"若页面由 JS 动态渲染登录框，请在 crawler.headless 开启无头渲染后重试")
}

// analyzeUserStep 从「用户名优先」页面推断第一步：取首个含 text/email/tel
// 输入的表单（无 form 标签时全文兜底），字段名按常见用户名线索推断。
func analyzeUserStep(doc *htmlx.Doc, baseURL string) (Step, bool) {
	try := func(inputs []htmlx.Input, action, method string) (Step, bool) {
		if strings.EqualFold(strings.TrimSpace(method), "get") {
			return Step{}, false // 登录提交必须是 POST
		}
		step := Step{Action: resolveRef(baseURL, action), Fields: map[string]string{}}
		for _, in := range inputs {
			switch in.Type {
			case "submit", "button", "image", "reset":
				continue
			case "hidden":
				if in.Name != "" {
					step.Fields[in.Name] = in.Value
				}
				continue
			case "password":
				return Step{}, false // 有密码框 → 不是用户名优先页
			}
			if in.Type != "text" && in.Type != "email" && in.Type != "tel" {
				continue
			}
			if step.UserField != "" {
				continue
			}
			key := strings.ToLower(in.Name + " " + in.ID + " " + in.Placeholder)
			if hasAny(key, userHints) ||
				hasAny(strings.ToLower(in.Placeholder), toLower(userHintZh)) {
				step.UserField = firstNonEmpty(in.Name, in.ID, "username")
			}
		}
		if step.UserField == "" {
			return Step{}, false
		}
		if step.Action == "" {
			step.Action = baseURL
		}
		return step, true
	}
	for _, form := range doc.Forms {
		if st, ok := try(form.Inputs, form.Action, form.Method); ok {
			return st, true
		}
	}
	if st, ok := try(allInputs(doc), "", "POST"); ok {
		return st, true
	}
	return Step{}, false
}

// isRedirectStatus 3xx 重定向状态（会话已建立的最可靠信号）。
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// copyFields 复制字段表（nil → 空表）。
func copyFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// applyPlaceholders 替换字段值里的 {user}/{pass} 占位符。
func applyPlaceholders(fields map[string]string, user, pass string) {
	for k, v := range fields {
		if strings.Contains(v, "{user}") || strings.Contains(v, "{pass}") {
			fields[k] = strings.NewReplacer("{user}", user, "{pass}", pass).Replace(v)
		}
	}
}
