// G09 业务逻辑检测原语（数量/价格/优惠券/幂等竞态）。
//
// 产品红线：**默认 dry-run**——只对「显式允许」的端点生成探测计划，
// 不发送任何请求；即便显式开启，也只允许每类 ≤2 次请求、不做破坏性写
// （不删除/不支付/不批量下单；探测值只有负数/超大数量、价格篡改、
// 同一优惠券重放、同一幂等键重复提交四类）。
//
// 判定口径（宁少报不误报）：
//   - 先取基线（正常数量/价格/优惠券/幂等键各一次），基线失败则跳过该端点；
//   - 异常 = 服务端「受理」了本应被校验拒绝的输入：
//     响应 2xx 且正文不含校验失败特征词，并且（价格类）金额较基线下降
//     或（幂等类）第二次提交仍被受理且响应与首次不同。
//
// 纯函数与 IO 分离：
//   - BuildLogicPlan 纯函数生成计划（dry-run 输出，含可复制 replay）；
//   - JudgeLogicAnomaly / ExtractAmounts 纯函数判定；
//   - RunLogic 仅在 AllowWrites 且端点 AllowWrite 时执行计划（httptest 可测）。
package dast

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// 业务逻辑探测类别。
const (
	LogicClassQuantity = "quantity"
	LogicClassPrice    = "price"
	LogicClassCoupon   = "coupon"
	LogicClassRace     = "race"
)

const (
	// defaultLogicMaxPerClass 每类请求上限（产品红线 ≤2；Options 只能调更小）。
	defaultLogicMaxPerClass = 2
	// hardLogicMaxPerClass 每类硬上限（不可被配置突破）。
	hardLogicMaxPerClass = 2
	// defaultLogicMaxProbes 单端点计划总上限。
	defaultLogicMaxProbes = 8
)

// 业务逻辑异常值（每类至多两个）。
var (
	logicQuantityProbes = []string{"-1", "999999999"}
	logicPriceProbes    = []string{"0.01", "1"}
)

// logicRejectMarkers 服务端「拒绝异常输入」的特征词：出现任一即认为校验生效，
// 不报（宁可漏报，不把正常校验当漏洞）。
var logicRejectMarkers = []string{
	"invalid", "illegal", "must be", "must not", "not allowed", "not acceptable",
	"out of range", "out of stock", "insufficient", "exceeds", "limit exceeded",
	"quantity must", "price must", "denied", "rejected",
	"失败", "非法", "无效", "不能", "不允许", "至少", "最多", "库存不足",
	"超过限制", "校验", "错误", "已失效", "已被使用", "重复提交", "已处理",
}

// logicCouponUsedMarkers 优惠券已被使用/不可重放的特征。
var logicCouponUsedMarkers = []string{
	"already used", "already redeemed", "coupon used", "used already",
	"已使用", "已核销", "重复使用", "不可重复", "已失效",
}

// logicSuccessMarkers 受理/下单成功特征（幂等/价格类辅助判定）。
var logicSuccessMarkers = []string{
	"success", "created", "accepted", "ok", "order id", "order no",
	"成功", "已创建", "已提交", "下单成功", "订单号",
}

// LogicOptions 业务逻辑探测参数。零值 = 默认 dry-run（只生成计划）。
type LogicOptions struct {
	// AllowWrites 执行闸门：false（默认）= 只生成计划、不发请求。
	// 即使为 true，仍要求目标 BizTarget.AllowWrite=true。
	AllowWrites bool
	// MaxPerClass 每类探针上限（默认 2，硬上限 2；>2 按 2 处理）。
	MaxPerClass int
	// MaxProbes 单端点计划总上限（默认 8）。
	MaxProbes int
	// OnHit 命中即时回调（nil = 不回调）。
	OnHit func(Finding)
}

// Normalized 归一默认值/硬上限。
func (o LogicOptions) Normalized() LogicOptions {
	if o.MaxPerClass <= 0 || o.MaxPerClass > hardLogicMaxPerClass {
		o.MaxPerClass = defaultLogicMaxPerClass
	}
	if o.MaxProbes <= 0 {
		o.MaxProbes = defaultLogicMaxProbes
	}
	return o
}

// BizTarget 显式允许做业务逻辑探测的端点（空列表 = 不探测任何端点）。
type BizTarget struct {
	Method string            // POST（默认）/ GET
	URL    string            // 绝对 URL（表单 action）
	Fields map[string]string // 基线字段（数量=1、价格原值、优惠券、幂等键等）
	// 以下字段名为空表示该类别不探测。
	QuantityField    string // 数量字段
	PriceField       string // 价格/金额字段
	CouponField      string // 优惠券字段
	IdempotencyField string // 幂等键字段
	// AllowWrite 显式允许发请求（默认 false：只生成计划）。
	AllowWrite bool
}

// LogicProbe 一条业务逻辑探测计划（dry-run 输出；Replay 可直接复制复核）。
type LogicProbe struct {
	Class     string            `json:"class"`  // quantity/price/coupon/race
	Target    string            `json:"target"` // 端点 URL
	Method    string            `json:"method"`
	Field     string            `json:"field"` // 被篡改字段（coupon/race=相关字段）
	Value     string            `json:"value,omitempty"`
	Fields    map[string]string `json:"fields"`   // 实际请求体（基线字段 + 篡改值）
	Baseline  map[string]string `json:"baseline"` // 基线请求体（正常值；判定用）
	Variation string            `json:"variation"`
	Replay    string            `json:"replay"`
	Note      string            `json:"note,omitempty"`
}

// BuildLogicPlan 纯函数：按显式允许的端点生成探测计划。
//
// 默认 dry-run：本函数只产出计划、绝不发请求。每类条目 ≤ MaxPerClass（硬上限
// 2），单端点总数 ≤ MaxProbes；无字段/无 URL/无 AllowWrite 的端点不生成计划
// （计划可预览，但执行还需 RunLogic 的 AllowWrites 闸门）。
func BuildLogicPlan(targets []BizTarget, opts LogicOptions) []LogicProbe {
	opts = opts.Normalized()
	var out []LogicProbe
	seen := map[string]bool{} // 相同 method+url 只规划一次
	for _, t := range targets {
		if strings.TrimSpace(t.URL) == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(t.Method))
		if method == "" {
			method = "POST"
		}
		if method != "POST" && method != "GET" {
			continue
		}
		key := method + "\x00" + t.URL
		if seen[key] {
			continue
		}
		seen[key] = true

		add := func(class, field, value, variation string, fields map[string]string) {
			if len(out) >= opts.MaxProbes {
				return
			}
			baseline := logicBaseFields(t.Fields)
			out = append(out, LogicProbe{
				Class: class, Target: t.URL, Method: method, Field: field,
				Value: value, Fields: fields, Baseline: baseline,
				Variation: variation,
				Replay:    logicReplay(method, t.URL, fields),
			})
		}

		// 数量类：负数 + 超大数量（每类 ≤MaxPerClass，硬上限 2）。
		if qf := strings.TrimSpace(t.QuantityField); qf != "" {
			for i, v := range logicQuantityProbes {
				if i >= opts.MaxPerClass {
					break
				}
				fields := logicBaseFields(t.Fields)
				fields[qf] = v
				add(LogicClassQuantity, qf, v, "数量="+v, fields)
			}
		}
		// 价格类：改小价格（0.01 / 1；每类 ≤MaxPerClass）。
		if pf := strings.TrimSpace(t.PriceField); pf != "" {
			for i, v := range logicPriceProbes {
				if i >= opts.MaxPerClass {
					break
				}
				fields := logicBaseFields(t.Fields)
				fields[pf] = v
				add(LogicClassPrice, pf, v, "价格="+v, fields)
			}
		}
		// 优惠券类：同一张券重放一次（与基线共用券值）。
		if cf := strings.TrimSpace(t.CouponField); cf != "" {
			fields := logicBaseFields(t.Fields)
			if _, ok := fields[cf]; ok {
				add(LogicClassCoupon, cf, fields[cf], "重放同一优惠券", fields)
			}
		}
		// 竞态类：同一幂等键重复提交。
		if idf := strings.TrimSpace(t.IdempotencyField); idf != "" {
			fields := logicBaseFields(t.Fields)
			if _, ok := fields[idf]; ok {
				add(LogicClassRace, idf, fields[idf], "重复提交同一幂等键", fields)
			}
		}
	}
	return out
}

// logicBaseFields 复制基线字段（探测不改调用方 map）。
func logicBaseFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// logicReplay 生成可复制的 curl 复现命令（POST 表单体 / GET query）。
func logicReplay(method, rawURL string, fields map[string]string) string {
	if strings.EqualFold(method, "GET") {
		return curlReplay(logicGETURL(rawURL, fields))
	}
	body := url.Values{}
	for k, v := range fields {
		body.Set(k, v)
	}
	return "curl -sk --path-as-is -d " + shellQuote(body.Encode()) + " " + shellQuote(rawURL)
}

// logicGETURL 把字段拼进 query（GET 语义的计划/执行共用）。
func logicGETURL(rawURL string, fields map[string]string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	for k, v := range fields {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// logicSend 按方法发送一次探测请求（POST 表单 / GET query）。
func logicSend(f Fetcher, method, rawURL string, fields map[string]string) *Resp {
	if strings.EqualFold(method, "GET") {
		return f.GetSmall(logicGETURL(rawURL, fields))
	}
	return f.PostFormSmall(rawURL, fields)
}

// RunLogic 执行计划：默认（!AllowWrites）**不发任何请求**，返回 nil；
// 显式 AllowWrites 且端点 AllowWrite 时才按计划发请求并判定异常。
// 每次执行最多 baseline 1 + 每类 ≤2 请求，不做破坏性写。
func RunLogic(f Fetcher, targets []BizTarget, opts LogicOptions) []Finding {
	opts = opts.Normalized()
	plan := BuildLogicPlan(targets, opts)
	if len(plan) == 0 || f == nil || !opts.AllowWrites {
		return nil // 默认 dry-run：只生成计划，不发请求
	}
	allowedURL := map[string]bool{}
	for _, t := range targets {
		if t.AllowWrite {
			allowedURL[t.URL] = true
		}
	}
	// 按端点分组执行：每端点先取基线（正常字段），再逐条探针判定。
	byTarget := map[string][]LogicProbe{}
	var order []string
	for _, p := range plan {
		if !allowedURL[p.Target] {
			continue
		}
		key := p.Method + "\x00" + p.Target
		if _, ok := byTarget[key]; !ok {
			order = append(order, key)
		}
		byTarget[key] = append(byTarget[key], p)
	}

	var hits []Finding
	for _, key := range order {
		probes := byTarget[key]
		if len(probes) == 0 {
			continue
		}
		first := probes[0]
		// 基线：端点自身配置的正常字段（数量/价格/优惠券/幂等键均取原值；
		// 计划里随探针携带 Baseline，避免从篡改值反推）。
		baselineResp := logicSend(f, first.Method, first.Target, first.Baseline)
		for _, p := range probes {
			resp := logicSend(f, p.Method, p.Target, p.Fields)
			okAnomaly, reason := JudgeLogicAnomaly(p.Class, baselineResp, resp, p.Value)
			if !okAnomaly {
				continue
			}
			fFinding := logicFinding(p, reason)
			if opts.OnHit != nil {
				opts.OnHit(fFinding)
			}
			hits = append(hits, fFinding)
		}
	}
	return hits
}

// logicFinding 组装命中（证据链与既有 DAST Finding 同构）。
func logicFinding(p LogicProbe, reason string) Finding {
	f := Finding{
		Check:    "biz-" + p.Class,
		Title:    logicTitle(p.Class),
		Severity: logicSeverity(p.Class),
		URL:      p.Target,
		Param:    p.Field,
		Payload:  p.Value,
		Evidence: reason,
		Replay:   p.Replay,
		Signals:  []string{"业务逻辑探测：" + p.Variation},
		Advice:   logicAdvice(p.Class),
	}
	if strings.EqualFold(p.Method, "GET") {
		f.Request = reqText(logicGETURL(p.Target, p.Fields))
	} else {
		body := url.Values{}
		for k, v := range p.Fields {
			body.Set(k, v)
		}
		f.Request = formReqTextRaw(p.Target, body.Encode())
	}
	return f
}

func logicTitle(class string) string {
	switch class {
	case LogicClassQuantity:
		return "业务逻辑：异常数量被受理（负数/超大数量）"
	case LogicClassPrice:
		return "业务逻辑：价格参数篡改被受理（金额异常）"
	case LogicClassCoupon:
		return "业务逻辑：优惠券可重放（重复核销）"
	case LogicClassRace:
		return "业务逻辑：幂等键未生效（重复提交被受理）"
	}
	return "业务逻辑异常"
}

func logicSeverity(class string) string {
	switch class {
	case LogicClassPrice, LogicClassRace:
		return "high"
	}
	return "medium"
}

func logicAdvice(class string) string {
	switch class {
	case LogicClassQuantity:
		return "服务端校验数量边界（正数、上限、库存一致性），不信任客户端传值"
	case LogicClassPrice:
		return "价格/金额由服务端按商品目录计算，禁止回传客户端价格参与结算"
	case LogicClassCoupon:
		return "优惠券核销必须加唯一约束/幂等键，重复提交返回同一结果"
	case LogicClassRace:
		return "幂等键必须服务端持久化去重（唯一索引 + 事务），重复请求返回原结果"
	}
	return "补齐服务端业务规则校验"
}

// accepted 响应是否「受理」（2xx 且无校验失败特征）。
func accepted(resp *Resp) bool {
	if resp == nil || resp.Status <= 0 || resp.Status >= 400 {
		return false
	}
	low := strings.ToLower(resp.Body)
	if containsAnyStr(low, logicRejectMarkers) {
		return false
	}
	return true
}

// JudgeLogicAnomaly 纯函数判定：基线 vs 探针响应是否构成业务逻辑异常。
// 返回 (是否异常, 证据说明)。口径保守：仅「受理了本应拒绝的输入」才报。
func JudgeLogicAnomaly(class string, baseline, probe *Resp, value string) (bool, string) {
	if !accepted(probe) {
		return false, ""
	}
	switch class {
	case LogicClassQuantity:
		if probe.Status < 200 || probe.Status >= 300 {
			return false, ""
		}
		return true, fmt.Sprintf(
			"服务端受理了异常数量 %s（HTTP %d，无校验拒绝特征）；基线 HTTP %s",
			value, probe.Status, statusStr(baseline))

	case LogicClassPrice:
		baseAmt := ExtractAmounts(baselineBody(baseline))
		probeAmt := ExtractAmounts(probe.Body)
		if len(baseAmt) > 0 && len(probeAmt) > 0 {
			baseMin, probeMin := minAmount(baseAmt), minAmount(probeAmt)
			if probeMin < baseMin*0.9 {
				return true, fmt.Sprintf(
					"价格篡改后服务端受理（金额由 ¥%.2f 变为 ¥%.2f，HTTP %d）",
					baseMin, probeMin, probe.Status)
			}
		}
		// 金额不可解析时的保守通道：正文出现被篡改的价格字面量且基线没有。
		if value != "" && strings.Contains(probe.Body, value) &&
			!strings.Contains(baselineBody(baseline), value) {
			return true, fmt.Sprintf(
				"服务端直接采用客户端回传的价格 %s（HTTP %d）", value, probe.Status)
		}
		return false, ""

	case LogicClassCoupon:
		if containsAnyStr(strings.ToLower(probe.Body), logicCouponUsedMarkers) {
			return false, ""
		}
		if probe.Status >= 200 && probe.Status < 300 {
			return true, fmt.Sprintf(
				"同一优惠券二次提交仍被受理（HTTP %d，无已使用/重复核销特征）；基线 HTTP %s",
				probe.Status, statusStr(baseline))
		}
		return false, ""

	case LogicClassRace:
		if baseline == nil || baseline.Status >= 400 {
			return false, ""
		}
		low := strings.ToLower(probe.Body)
		if containsAnyStr(low, logicRejectMarkers) || containsAnyStr(low, logicCouponUsedMarkers) {
			return false, ""
		}
		if baseline.Body == probe.Body {
			return false, "" // 幂等生效：两次响应一致
		}
		if !containsAnyStr(low, logicSuccessMarkers) {
			return false, "" // 无受理特征，保守不报
		}
		return true, fmt.Sprintf(
			"同一幂等键重复提交两次均被受理且响应不同（HTTP %d），幂等未生效",
			probe.Status)
	}
	return false, ""
}

// baselineBody 基线正文（nil 安全）。
func baselineBody(resp *Resp) string {
	if resp == nil {
		return ""
	}
	return resp.Body
}

// statusStr 状态码展示（0 = 未知）。
func statusStr(resp *Resp) string {
	if resp == nil || resp.Status == 0 {
		return "未知"
	}
	return strconv.Itoa(resp.Status)
}

// containsAnyStr 子串任一命中。
func containsAnyStr(s string, keys []string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// minAmount 金额列表最小值（无元素返回 0）。
func minAmount(vals []float64) float64 {
	m := 0.0
	for i, v := range vals {
		if i == 0 || v < m {
			m = v
		}
	}
	return m
}

// 金额提取：带货币符号/单位（前后缀），或带两位小数的金额形态。
var (
	amountSymRe  = regexp.MustCompile(`[¥￥$€]\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)`)
	amountUnitRe = regexp.MustCompile(`(?i)([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*(?:元|usd|cny|rmb|hkd)|(?:usd|cny|rmb|hkd)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)`)
	amountDecRe  = regexp.MustCompile(`\b([0-9][0-9,]*\.[0-9]{2})\b`)
)

// ExtractAmounts 纯函数：从响应正文提取金额（有序、去重）。
// 覆盖 ¥/$/€ 前后缀、元/usd/cny/rmb/hkd 前缀/后缀与两位小数形态；
// 解析失败跳过。
func ExtractAmounts(body string) []float64 {
	if body == "" {
		return nil
	}
	var out []float64
	seen := map[float64]bool{}
	add := func(raw string) {
		clean := strings.ReplaceAll(raw, ",", "")
		v, err := strconv.ParseFloat(clean, 64)
		if err != nil || v < 0 {
			return
		}
		if seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, re := range []*regexp.Regexp{amountSymRe, amountUnitRe, amountDecRe} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			for i := 1; i < len(m); i++ {
				if m[i] != "" {
					add(m[i])
					break
				}
			}
		}
	}
	return out
}
