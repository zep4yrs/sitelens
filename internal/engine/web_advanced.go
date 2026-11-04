// G09/G10 进阶面接线：把 dast 包的业务逻辑/上传/反序列化/越权原语与
// protochk 协议面检查接进 DAST 阶段（additive，默认全关）。
//
// 纪律：
//   - 五个开关（config.DAST.proto/deser/logic/upload/idor）默认 false；
//     全关时本文件不产生任何请求、不写任何输出，扫描行为与旧版一致。
//   - logic/upload 永远 dry-run（只生成计划写 res.Extras["web_advanced"]，
//     不发请求；端点 AllowWrite=false，双重闸门）。
//   - deser 只做已抓取页面正文的标记识别（零额外请求）。
//   - proto 只对入口 URL 做一次协议面探测（ws/wss 或 h2）。
//   - idor 仅当调用方通过 Options.Sessions 提供会话时才执行，否则跳过。
//   - 所有 Finding 统一为 res.Verified 的 map 形态，至少含
//     check/title/severity/url/evidence 五键，src=dast。
package engine

import (
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/authn"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/protochk"
)

const (
	// webAdvancedDeserPageLimit deser 页面扫描上限（纯 CPU，无请求）。
	webAdvancedDeserPageLimit = 200
	// webAdvancedLogicFormLimit 业务逻辑计划的显式端点上限。
	webAdvancedLogicFormLimit = 5
	// webAdvancedIDORTemplateLimit IDOR 模板上限（防请求预算膨胀）。
	webAdvancedIDORTemplateLimit = 5
	// webAdvancedDefaultMaxRequests 进阶面请求硬上限默认值。
	webAdvancedDefaultMaxRequests = 20
)

// protoCheckFn 协议面检查入口（仅测试可替换，生产= protochk.Check）。
var protoCheckFn = protochk.Check

// idorDetectFn 越权检测入口（仅测试可替换，生产= dast.DetectIDOR）。
var idorDetectFn = dast.DetectIDOR

// webAdvancedEnabled 是否任一进阶面开关开启（取当前配置快照）。
func (e *Engine) webAdvancedEnabled() bool {
	cfg := e.Config()
	if cfg == nil {
		cfg = config.Default()
	}
	return webAdvancedOn(cfg.DAST, Options{})
}

// runWebAdvanced DAST 结果之后的进阶面接线（默认全关 = 立即返回）。
// 独立入口用：取当前配置快照。
func (e *Engine) runWebAdvanced(
	client *httpx.Client,
	blocked *blockedTracker,
	pages []crawlPage,
	forms []dast.FormTarget,
	links []string,
	baseURL string,
	res *Result,
	opts Options,
	sessions []authn.Session,
	onProgress func(int, string),
	live *liveTracker,
	emit func(kind, text string),
) {
	e.runWebAdvancedWith(e.Config(), client, blocked, pages, forms, links, baseURL,
		res, opts, sessions, onProgress, live, emit)
}

// runWebAdvancedWith 用显式配置快照执行进阶面接线（A-09：扫描内部调用，
// 进阶面开关与入口快照一致）。
//
// 参数复用 DAST 阶段的既有上下文：pages（已抓取页面，含首页）、forms（表单
// 目标）、links（带参/同域链接）、baseURL（入口 URL）、sessions（调用方显式
// 提供的多角色会话）。全部输出走 res.Verified / res.Extras["web_advanced"]。
func (e *Engine) runWebAdvancedWith(
	cfg *config.Config,
	client *httpx.Client,
	blocked *blockedTracker,
	pages []crawlPage,
	forms []dast.FormTarget,
	links []string,
	baseURL string,
	res *Result,
	opts Options,
	sessions []authn.Session,
	onProgress func(int, string),
	live *liveTracker,
	emit func(kind, text string),
) {
	if cfg == nil {
		cfg = config.Default()
	}
	adv := cfg.DAST
	if opts.AdvProto {
		adv.Proto = true
	}
	if opts.AdvDeser {
		adv.Deser = true
	}
	if opts.AdvLogic {
		adv.Logic = true
	}
	if opts.AdvUpload {
		adv.Upload = true
	}
	if opts.AdvIDOR {
		adv.IDOR = true
	}
	if opts.AdvMaxRequests > 0 {
		adv.MaxRequests = opts.AdvMaxRequests
	}

	if e == nil || res == nil || !webAdvancedOn(adv, opts) {
		return // 默认全关：零请求零输出
	}
	if emit == nil {
		emit = func(string, string) {}
	}
	if onProgress != nil {
		onProgress(87, "进阶面：协议/反序列化/业务逻辑…")
	}
	if live != nil {
		live.setPhase("web_advanced", "进阶面")
	}

	maxReq := adv.MaxRequests
	if maxReq <= 0 {
		maxReq = webAdvancedDefaultMaxRequests
	}
	if maxReq > 500 {
		maxReq = 500
	}
	info := map[string]any{
		"dry_run":      true,
		"max_requests": maxReq,
	}
	advancedRequests := 0
	hit := func(severity, title, rawURL string) {
		if emit != nil {
			emit("hit", severity+" · "+title+" — "+rawURL)
		}
	}

	if adv.Proto {
		_, reqs := webAdvancedProto(baseURL, res, info, hit)
		advancedRequests += reqs
	}
	if adv.Deser {
		webAdvancedDeser(pages, res, info, hit)
	}
	if adv.Logic {
		targets := buildLogicTargets(forms)
		info["logic"] = dast.BuildLogicPlan(targets, dast.LogicOptions{})
		info["logic_targets"] = len(targets)
	}
	if adv.Upload {
		if plan, ok := buildUploadPlan(forms); ok {
			info["upload"] = plan
		} else {
			info["upload"] = nil
			info["upload_skip"] = "no_file_form"
		}
	}
	if adv.IDOR {
		reqs := webAdvancedIDOR(client, blocked, sessions, links, baseURL, res, info, maxReq, hit)
		advancedRequests += reqs
	}
	info["requests"] = advancedRequests
	if res.Extras == nil {
		res.Extras = map[string]any{}
	}
	res.Extras["web_advanced"] = info
}

// webAdvancedProto 入口 URL 协议面探测：ws/wss 明文/匿名/Origin、h2c/ALPN。
// 返回 (发现数, 请求尝试数)。错误只记诊断，不改变扫描结果。
func webAdvancedProto(baseURL string, res *Result, info map[string]any, hit func(string, string, string)) (int, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	findings, err := protoCheckFn(ctx, baseURL, protochk.Options{Timeout: 5 * time.Second})
	if err != nil {
		info["proto_error"] = err.Error()
		return 0, 1 // 已尝试连接（计入预算，但不产生 Finding）
	}
	for _, f := range findings {
		title := protoFindingTitle(f.Kind)
		res.Verified = append(res.Verified, verifiedMap(map[string]any{
			"check":    "proto-" + f.Kind,
			"title":    title,
			"severity": f.Severity,
			"url":      f.URL,
			"evidence": f.Detail,
			"advice":   protoFindingAdvice(f.Kind),
			"src":      "dast",
		}))
		hit(f.Severity, title, f.URL)
	}
	info["proto_findings"] = len(findings)
	return len(findings), 1
}

// protoFindingTitle 协议面发现的中文标题。
func protoFindingTitle(kind string) string {
	switch kind {
	case protochk.KindCleartextWS:
		return "WebSocket 明文传输（ws://）"
	case protochk.KindWSNoAuth:
		return "WebSocket 匿名握手被接受（未鉴权）"
	case protochk.KindOriginNotChecked:
		return "WebSocket 未校验 Origin（跨站劫持面）"
	case protochk.KindH2CEnabled:
		return "明文 HTTP/2（h2c）可用"
	case protochk.KindH2ALPNEnabled:
		return "HTTP/2 已启用（信息项）"
	}
	return "协议面暴露：" + kind
}

// protoFindingAdvice 协议面修复建议。
func protoFindingAdvice(kind string) string {
	switch kind {
	case protochk.KindCleartextWS, protochk.KindH2CEnabled:
		return "生产环境禁用明文协议（ws/h2c），统一走 TLS"
	case protochk.KindWSNoAuth:
		return "WebSocket 握手阶段做身份校验（Cookie/Token），拒绝匿名连接"
	case protochk.KindOriginNotChecked:
		return "校验 Origin/Referer 白名单，拒绝跨站握手"
	}
	return "确认协议面暴露是否符合预期；敏感场景收敛到 TLS + 鉴权"
}

// webAdvancedDeser 已抓取页面正文反序列化标记识别（零额外请求）。
func webAdvancedDeser(pages []crawlPage, res *Result, info map[string]any, hit func(string, string, string)) {
	seen := map[string]bool{}
	findings := 0
	scanned := 0
	for i := range pages {
		if i >= webAdvancedDeserPageLimit {
			break
		}
		p := pages[i]
		if p.resp == nil {
			continue
		}
		scanned++
		markers := dast.DetectDeserMarkers(p.resp.Headers, p.resp.Body)
		if len(markers) == 0 {
			continue
		}
		rawURL := p.resp.FinalURL
		for _, f := range dast.DeserFindings(markers, rawURL) {
			key := f.Check + "\x00" + rawURL + "\x00" + f.Evidence
			if seen[key] {
				continue
			}
			seen[key] = true
			res.Verified = append(res.Verified, verifiedMap(map[string]any{
				"check":    f.Check,
				"title":    f.Title,
				"severity": f.Severity,
				"url":      f.URL,
				"evidence": f.Evidence,
				"advice":   f.Advice,
				"replay":   f.Replay,
				"src":      "dast",
			}))
			findings++
			hit(f.Severity, f.Title, f.URL)
		}
	}
	info["deser_findings"] = findings
	info["pages_scanned"] = scanned
}

// buildLogicTargets 从爬取到的表单推导业务逻辑探测端点（纯计划输入）。
//
// 只做字段名启发式分类（数量/价格/优惠券/幂等键），AllowWrite 恒 false：
// 计划永远不会被执行（dry-run 红线）。
func buildLogicTargets(forms []dast.FormTarget) []dast.BizTarget {
	var out []dast.BizTarget
	seen := map[string]bool{}
	for _, f := range forms {
		action := strings.TrimSpace(f.Action)
		if action == "" || len(f.Fields) == 0 || seen[action] {
			continue
		}
		seen[action] = true
		fields := make(map[string]string, len(f.Fields))
		for _, name := range f.Fields {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			fields[name] = "1"
		}
		if len(fields) == 0 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(f.Method))
		if method == "" {
			method = "POST"
		}
		t := dast.BizTarget{
			Method: method, URL: action, Fields: fields,
			AllowWrite: false, // 双闸门：计划永不执行
		}
		for _, name := range f.Fields {
			classifyBizField(name, &t)
		}
		out = append(out, t)
		if len(out) >= webAdvancedLogicFormLimit {
			break
		}
	}
	return out
}

// bizQuantityHint 等为字段名启发式关键词（只影响计划分类，不影响请求）。
var bizFieldHints = []struct {
	set  func(*dast.BizTarget, string)
	keys []string
}{
	{func(t *dast.BizTarget, name string) { t.QuantityField = name },
		[]string{"qty", "quantity", "count", "product_count", "num", "items", "pieces"}},
	{func(t *dast.BizTarget, name string) { t.PriceField = name },
		[]string{"price", "cost", "total", "fee", "money", "amount", "cents"}},
	{func(t *dast.BizTarget, name string) { t.CouponField = name },
		[]string{"coupon", "discount", "voucher", "promo", "giftcode", "redeem"}},
	{func(t *dast.BizTarget, name string) { t.IdempotencyField = name },
		[]string{"idem", "idempotency", "request_id", "req_id", "reqid", "nonce", "txn", "transaction_id"}},
}

// classifyBizField 依据字段名语义归类（先命中先得，保持确定性）。
func classifyBizField(name string, t *dast.BizTarget) {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" {
		return
	}
	for _, h := range bizFieldHints {
		for _, k := range h.keys {
			if strings.Contains(low, k) {
				h.set(t, name)
				return
			}
		}
	}
}

// buildUploadPlan 从表单推导上传面 dry-run 计划（仅计划，不请求）。
func buildUploadPlan(forms []dast.FormTarget) (dast.UploadPlan, bool) {
	for _, f := range forms {
		action := strings.TrimSpace(f.Action)
		if action == "" || len(f.FileFields) == 0 {
			continue
		}
		extra := make(map[string]string, len(f.Fields))
		for _, name := range f.Fields {
			name = strings.TrimSpace(name)
			if name != "" {
				extra[name] = "1"
			}
		}
		return dast.BuildUploadPlan(dast.UploadBypassOptions{
			Endpoint:    action,
			FieldName:   f.FileFields[0],
			ExtraFields: extra,
			// DryRun 保持 nil（默认 true）：只生成计划。
		}), true
	}
	return dast.UploadPlan{}, false
}

// webAdvancedIDOR 多会话越权检测（仅调用方提供会话时执行）。
func webAdvancedIDOR(client *httpx.Client, blocked *blockedTracker, sessions []authn.Session,
	links []string, baseURL string, res *Result, info map[string]any, maxReq int,
	hit func(string, string, string)) int {
	if len(sessions) == 0 {
		info["idor"] = "skipped: no sessions"
		return 0
	}
	templates := idorTemplatesFromLinks(links, baseURL)
	if len(templates) == 0 {
		info["idor"] = "skipped: no candidate templates"
		return 0
	}
	fetch := dastFetcher{c: client, blocked: blocked}
	result, err := idorDetectFn(dast.IDORMatrix{
		BaseURL:     baseURL,
		Templates:   templates,
		Sessions:    sessions,
		AdminRoles:  nil, // 未配置管理角色：只跑水平越权矩阵
		MaxRequests: maxReq,
	}, fetch)
	if err != nil {
		info["idor_error"] = err.Error()
		return 0
	}
	for _, f := range result.Findings {
		check := f.Type
		if !strings.HasPrefix(check, "idor-") {
			check = "idor-" + check
		}
		title := idorFindingTitle(f.Type)
		res.Verified = append(res.Verified, verifiedMap(map[string]any{
			"check":    check,
			"title":    title,
			"severity": f.Severity,
			"url":      f.URL,
			"evidence": f.Evidence,
			"replay":   f.Replay,
			"src":      "dast",
		}))
		hit(f.Severity, title, f.URL)
	}
	info["idor_findings"] = len(result.Findings)
	info["idor_requests"] = result.Requests
	info["idor_truncated"] = result.Truncated
	return result.Requests
}

// idorFindingTitle 越权发现的中文标题。
func idorFindingTitle(kind string) string {
	switch kind {
	case "idor-read":
		return "IDOR：跨角色可读资源"
	case "idor-horizontal":
		return "越权：水平越权（同权角色互通资源）"
	case "idor-vertical":
		return "越权：垂直越权（低权访问管理资源）"
	}
	return fmt.Sprintf("越权访问（%s）", kind)
}

// idorIDPattern 资源 ID（数字串）匹配。
var idorIDPattern = regexp.MustCompile(`\d+`)

// idorTemplatesFromLinks 从同域链接推导 IDOR 资源模板（数字 ID → {id}）。
func idorTemplatesFromLinks(links []string, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	host := base.Hostname()
	seen := map[string]bool{}
	var out []string
	for _, raw := range links {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Path == "" {
			continue
		}
		if u.Hostname() != "" && !strings.EqualFold(u.Hostname(), host) {
			continue
		}
		if !idorIDPattern.MatchString(u.Path) {
			continue
		}
		tpl := idorIDPattern.ReplaceAllString(u.Path, "{id}")
		if seen[tpl] {
			continue
		}
		seen[tpl] = true
		out = append(out, tpl)
		if len(out) >= webAdvancedIDORTemplateLimit {
			break
		}
	}
	return out
}

// webAdvancedOn 合并配置与 per-scan 覆盖开关。
func webAdvancedOn(d config.DASTConfig, opts Options) bool {
	return d.Proto || d.Deser || d.Logic || d.Upload || d.IDOR ||
		opts.AdvProto || opts.AdvDeser || opts.AdvLogic || opts.AdvUpload || opts.AdvIDOR
}
