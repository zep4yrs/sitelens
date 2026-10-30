package httpx

// 本文件实现 E1（效率轮）：per-host 共享令牌桶限速 + WAF/限流识别。
//
// 设计要点（对应用户红线「提速不能影响被扫描机器」）：
//  1. 令牌桶按 host:port 全进程共享（sync.Map）：所有 httpx.Client 实例共用
//     同一限速器；引擎里「爬虫 client + DAST client」叠加后，目标侧看到的
//     仍然只有一个每主机令牌速率，不会翻倍。
//  2. 桶容量 1（不攒突发）：下一个令牌时刻 = max(now, 上一令牌 + 间隔)，先到
//     先得、其余调用者排队等待各自的槽位。任意时刻最多放行一个请求——旧
//     wait() 的缺陷是「每个并发调用者各自睡 interval 后同时齐发」，N 个调用
//     者把实际速率放大成 N/interval；令牌桶从机制上消除这种叠加。
//  3. 硬上限 10 req/s/主机：间隔绝对硬下限 100ms，任何配置/加速/抖动都不能
//     突破（MaxRPS 只能让上限更保守）。引擎默认 MaxRPS=8 → 125ms（8 req/s）。
//  4. polite（Adaptive=false）：固定间隔、无抖动、无自适应调速（WAF 只做
//     标记不改节奏）；adaptive（balanced）：从 base 间隔起步，连续干净成功
//     后逐级减半到下界，命中 WAF/限流/RTT 恶化时退避并锁定低速。

import (
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 自适应限速与 WAF 识别参数。集中定义、不暴露为配置项。
const (
	// adaptiveMinInterval 自适应绝对硬下限 100ms ⇒ 每主机 ≤10 req/s。用户红线
	// 「不能影响被扫描机器」的代码级硬上限，不受任何配置/加速逻辑突破；引擎
	// 默认 MaxRPS=8 时实际下限 125ms（8 req/s），调低更保守、调高最多 10 rps。
	adaptiveMinInterval = 100 * time.Millisecond

	// adaptiveMaxInterval 退避上限 2s（WAF 锁定最高一级同值）。
	adaptiveMaxInterval = 2 * time.Second

	// adaptiveJitterPct 令牌获取时对间隔做 ±20% 抖动（避免固定节奏被 WAF
	// 指纹化）；抖动结果始终夹在 [下限, 2s] 之间，不会让两个请求同时放行。
	adaptiveJitterPct = 0.2

	// adaptiveAccelerateAfter 连续干净成功多少次后把基础间隔减半一次。
	adaptiveAccelerateAfter = 5

	// adaptiveRTTRiseRatio RTT EWMA 相对基线上升超过 50% 即自动退避。
	adaptiveRTTRiseRatio = 1.5

	// adaptiveRTTWarmup RTT 采样预热次数：前几次不判定上升，避免首包/建链抖动。
	adaptiveRTTWarmup = 5

	// adaptiveRTTAbsFloor 触发 RTT 退避的绝对时延门槛：亚 20ms 的「相对上升」
	// 没有保护价值（loopback/内网/GC 噪声也会让 0.3ms→0.9ms 的幅度超 +50%），
	// 只按绝对时延判断可避免把毫秒级噪声当成目标压力信号、误退避拖慢扫描。
	adaptiveRTTAbsFloor = 20 * time.Millisecond

	// adaptiveRTTAEWMAAlpha / adaptiveRTTRefAlpha RTT 快/慢 EWMA 系数。
	adaptiveRTTAEWMAAlpha = 0.3
	adaptiveRTTRefAlpha   = 0.02

	// hostLimiterIdleTTL 空闲限速器回收 TTL（测试/长跑避免 sync.Map 泄漏）。
	hostLimiterIdleTTL = 5 * time.Minute

	// challengeScanBytes 挑战页特征只扫正文前 32KB（拦截页都很小，避免对大
	// 正文做全量大小写折叠）。
	challengeScanBytes = 32 << 10
)

// adaptiveLockLadder WAF/限流命中后的锁定低速阶梯（400ms→1s→2s，只增不减；
// 命中即锁定，此后不再加速）。
var adaptiveLockLadder = [...]time.Duration{400 * time.Millisecond, time.Second, 2 * time.Second}

// Stats 客户端限速/拦截统计快照（诊断包 / CLI 输出用；additive）。
type Stats struct {
	Requests int64         // 已发出的 HTTP 请求数（含重定向逐跳）
	Interval time.Duration // 当前生效的基础间隔（自适应模式动态变化；0=不限速）
	AvgRPS   float64       // 本次会话平均 RPS（自首个请求起算）
	Blocked  int64         // 被判为 WAF/限流拦截的响应数
	Backoffs int64         // 自适应退避次数（WAF/限流/RTT 恶化触发）
}

// limiterConfig 限速器创建参数。同一 host 的多个 Client 共享限速器时按
// 「更保守者优先」合并（见 hostLimiter.merge）。
type limiterConfig struct {
	adaptive   bool
	base       time.Duration // 0 = 不限速（不注册限速器）
	floor      time.Duration // 自适应硬下限（含 MaxRPS 收紧）
	accelAfter int
}

// adaptiveFloor 计算自适应下限：100ms 与 1s/MaxRPS 取大——MaxRPS 小于 10 时
// 按 1s/MaxRPS 收紧（更保守），大于 10（或 0=默认 5）时仍受 100ms 绝对硬下限
// 约束，无法突破 10 req/s。引擎默认 MaxRPS=8 → 125ms（8 req/s）。
func adaptiveFloor(maxRPS int) time.Duration {
	if maxRPS <= 0 {
		maxRPS = 5
	}
	floor := adaptiveMinInterval
	if byRPS := time.Second / time.Duration(maxRPS); byRPS > floor {
		floor = byRPS
	}
	return floor
}

// hostLimiters 全进程的 host:port → 限速器注册表（所有 Client 实例共享）。
var (
	hostLimiters sync.Map // map[string]*hostLimiter
	sweeperOnce  sync.Once
)

// hostKey 归一化 URL 的 host:port（同主机不同写法/默认端口折叠到同一 key）。
func hostKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return host
		}
	}
	return net.JoinHostPort(host, port)
}

// hostLimiterFor 取得（必要时创建）host 级共享限速器。
func hostLimiterFor(key string, cfg limiterConfig) *hostLimiter {
	if v, ok := hostLimiters.Load(key); ok {
		l := v.(*hostLimiter)
		l.merge(cfg)
		return l
	}
	fresh := newHostLimiter(cfg)
	actual, loaded := hostLimiters.LoadOrStore(key, fresh)
	if loaded {
		// 并发首建：以先入者为准，再用本次配置做保守合并。
		l := actual.(*hostLimiter)
		l.merge(cfg)
		return l
	}
	sweeperOnce.Do(startHostLimiterSweeper)
	return fresh
}

// startHostLimiterSweeper 后台回收空闲限速器（长扫描/测试进程内避免注册表膨胀）。
func startHostLimiterSweeper() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for now := range t.C {
			sweepHostLimiters(now)
		}
	}()
}

// sweepHostLimiters 删除空闲超过 hostLimiterIdleTTL 的限速器。
func sweepHostLimiters(now time.Time) {
	hostLimiters.Range(func(k, v any) bool {
		if l := v.(*hostLimiter); l.idleFor(now) > hostLimiterIdleTTL {
			hostLimiters.Delete(k)
		}
		return true
	})
}

// hostLimiter 单个 host:port 的共享限速器：令牌槽位 + （可选）自适应状态。
type hostLimiter struct {
	mu sync.Mutex

	// 限速参数（同一 host 多 Client 合并时取更保守者）。
	adaptive   bool
	base       time.Duration // 配置起点间隔
	floor      time.Duration // 自适应硬下限
	accelAfter int

	interval time.Duration // 当前生效的基础间隔（自适应时动态变化）
	next     time.Time     // 下一个令牌可用时刻（容量 1，不攒突发）
	lastUsed time.Time     // 真实时钟的空闲回收时间戳

	// 自适应共享状态（同 host 所有 Client 共用）。
	locked     bool // WAF/限流锁定：低速运行、不再加速
	lockLevel  int
	streak     int // 连续干净成功计数
	rttEWMA    time.Duration
	rttRef     time.Duration // RTT 慢基线
	lastRTT    time.Duration // 上一次采样（要求连续上升才算目标压力）
	rttSamples int
}

// newHostLimiter 按配置创建限速器。
func newHostLimiter(cfg limiterConfig) *hostLimiter {
	l := &hostLimiter{
		adaptive:   cfg.adaptive,
		base:       cfg.base,
		floor:      cfg.floor,
		accelAfter: cfg.accelAfter,
		interval:   cfg.base,
		lastUsed:   time.Now(),
	}
	if l.adaptive && l.interval < l.floor {
		l.interval = l.floor
	}
	return l
}

// merge 同一 host 的多个 Client 配置合并。
// 一旦出现 polite 客户端就退回「固定间隔、无下限/抖动/调速」的纯旧行为
// （Adaptive=false 必须与旧实现等价；混用姿态时以最保守者为准）。
func (l *hostLimiter) merge(cfg limiterConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cfg.base > l.base {
		l.base = cfg.base
	}
	if !cfg.adaptive {
		if l.adaptive {
			l.adaptive = false
			l.floor = 0
			if cfg.base > 0 {
				l.interval = cfg.base
			}
		}
		return
	}
	if cfg.floor > l.floor {
		l.floor = cfg.floor
	}
}

// idleFor 返回限速器空闲时长（真实时钟，供 TTL 回收）。
func (l *hostLimiter) idleFor(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return now.Sub(l.lastUsed)
}

// currentInterval 返回当前基础间隔（诊断用）。
func (l *hostLimiter) currentInterval() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.interval
}

// acquire 取得一次发送许可：容量 1 的令牌桶——先到先得、按间隔排队，
// 任意时刻最多放行一个请求。polite 档 interval 原样使用（不夹下限、无抖动，
// 与旧实现等价）；adaptive 档才使用硬下限与 ±20% 抖动（下限处只向上抖动，
// 保证目标侧 1s 窗口不超过 5 req/s）。
func (l *hostLimiter) acquire(now func() time.Time, sleep func(time.Duration)) {
	l.mu.Lock()
	t := now()
	slot := l.next
	if slot.IsZero() || slot.Before(t) {
		slot = t // 长空闲后不补偿突发：只放开本次
	}
	eff := l.interval
	if l.adaptive {
		if eff < l.floor {
			eff = l.floor
		}
		eff = jitterInterval(eff, l.floor)
	}
	l.next = slot.Add(eff)
	l.lastUsed = time.Now() // TTL 用真实时钟（与可注入的调度时钟解耦）
	l.mu.Unlock()

	if d := slot.Sub(t); d > 0 {
		sleep(d)
	}
}

// jitterInterval 对间隔做 ±20% 抖动并夹到 [下限, 2s]。
//
// 已经落在硬下限时**不再抖动**（固定 200ms）：若继续向上抖动，平均间隔会被抬到
// ~210ms，有效速率从 5 rps 掉到 ~4.5 rps——实测让默认 balanced 档比旧实现还慢，
// 与「提速」目标相悖。固定 200ms 时 1s 窗口最多 5 个令牌（第 6 个在 1000ms 边界
// 之外），仍满足「≤5 req/s/主机」；只有间隔高于下限（有加速余量）时才抖动，
// 且抖动后仍夹回下限，不会突破硬上限。
func jitterInterval(base, floor time.Duration) time.Duration {
	if base <= floor {
		return floor
	}
	f := 1 - adaptiveJitterPct + rand.Float64()*2*adaptiveJitterPct
	d := time.Duration(float64(base) * f)
	if d < floor {
		d = floor
	}
	if d > adaptiveMaxInterval {
		d = adaptiveMaxInterval
	}
	return d
}

// onClean 记录一次干净成功（2xx / 404 等正常响应）：自适应模式下连续成功
// 达到阈值就把基础间隔减半一次（不低于硬下限）；锁定后不再加速。
func (l *hostLimiter) onClean() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.adaptive {
		return
	}
	l.streak++
	need := l.accelAfter
	if need <= 0 {
		need = adaptiveAccelerateAfter
	}
	if l.locked || l.streak < need {
		return
	}
	l.streak = 0
	next := l.interval / 2
	if next < l.floor {
		next = l.floor
	}
	if next < l.interval {
		l.interval = next
	}
}

// onUnclean 记录一次不干净但非拦截的响应（4xx/5xx 等）：清零加速计数，不加速。
func (l *hostLimiter) onUnclean() {
	if !l.adaptive {
		return
	}
	l.mu.Lock()
	l.streak = 0
	l.mu.Unlock()
}

// onBlock 记录一次拦截图（429/503/WAF 头/挑战页/状态降级）：自适应模式下
// 硬退避 + 锁定低速（400ms→1s→2s，只增不减），此后不再加速。返回是否触发了
// 自适应退避（供 Client 统计）。
func (l *hostLimiter) onBlock() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.streak = 0
	if !l.adaptive {
		return false
	}
	l.locked = true
	if l.lockLevel < len(adaptiveLockLadder) {
		l.lockLevel++
	}
	lv := adaptiveLockLadder[len(adaptiveLockLadder)-1]
	if l.lockLevel > 0 && l.lockLevel <= len(adaptiveLockLadder) {
		lv = adaptiveLockLadder[l.lockLevel-1]
	}
	if lv < l.floor {
		lv = l.floor
	}
	if lv > l.interval {
		l.interval = lv
	}
	return true
}

// onRTT 记录一次真实 RTT 采样：RTT EWMA 相对慢基线上升 >50% 时自动退避
// （间隔翻倍、上限 2s），并重新锚定基线避免同一波延迟反复触发。返回是否退避。
//
// 判定要求「有意义的绝对时延」+「连续两次采样都高于上升阈值」：loopback/内网
// 的亚毫秒抖动经常出现 >50% 的相对波动，只按相对比例会把噪声误判成目标压力、
// 反而把扫描无谓拖慢。真正的过载/WAF 排队表现为持续数十毫秒级上升。
func (l *hostLimiter) onRTT(rtt time.Duration, status int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rtt <= 0 {
		rtt = time.Microsecond
	}
	prev := l.lastRTT
	l.lastRTT = rtt
	if l.rttSamples == 0 {
		l.rttEWMA, l.rttRef = rtt, rtt
	} else {
		l.rttEWMA = ewmaDuration(l.rttEWMA, rtt, adaptiveRTTAEWMAAlpha)
		l.rttRef = ewmaDuration(l.rttRef, rtt, adaptiveRTTRefAlpha)
	}
	l.rttSamples++
	if status >= 500 {
		l.streak = 0 // 5xx：目标侧压力信号，不加速
	}
	if !l.adaptive {
		return false
	}
	if l.rttSamples <= adaptiveRTTWarmup+1 {
		return false
	}
	rise := time.Duration(float64(l.rttRef) * adaptiveRTTRiseRatio)
	if l.rttEWMA < adaptiveRTTAbsFloor || l.rttEWMA <= rise {
		return false
	}
	if rtt <= rise || prev <= rise {
		return false // 只认持续上升，过滤单次尖峰
	}
	l.streak = 0
	next := l.interval * 2
	if next > adaptiveMaxInterval {
		next = adaptiveMaxInterval
	}
	if next > l.interval {
		l.interval = next
	}
	l.rttRef = l.rttEWMA
	return true
}

// ewmaDuration 计算时长的指数加权移动平均。
func ewmaDuration(prev, sample time.Duration, alpha float64) time.Duration {
	return time.Duration(float64(prev)*(1-alpha) + float64(sample)*alpha)
}

// hostLimiterByURL 查找请求目标 host 的限速器（不创建；无则 nil = 不限速）。
func hostLimiterByURL(u *url.URL) *hostLimiter {
	key := hostKey(u)
	if key == "" {
		return nil
	}
	v, ok := hostLimiters.Load(key)
	if !ok {
		return nil
	}
	return v.(*hostLimiter)
}

// hostLimiterByRequest 同 hostLimiterByURL，容错 nil 请求。
func hostLimiterByRequest(req *http.Request) *hostLimiter {
	if req == nil {
		return nil
	}
	return hostLimiterByURL(req.URL)
}

// ---- WAF / 限流识别 ---------------------------------------------------------

// wafHeaderNames WAF/CDN 特征头（小写）；命中说明目标前面挂了 WAF。
var wafHeaderNames = []string{
	"cf-ray", "cf-cache-status", "x-sucuri-id", "x-sucuri-cache",
	"x-akamai-request-id", "x-akamai-session-info", "x-iinfo",
}

// wafServerVendors Server 头值里出现的 WAF/CDN 厂商标识。
var wafServerVendors = []string{
	"cloudflare", "akamai", "safedog", "yunsuo", "waf", "incapsula",
	"imperva", "big-ip", "bigip", "mod_security", "modsecurity", "sucuri",
}

// detectWAFHeader 返回命中的 WAF 特征（头名或 "server:<vendor>"），无则空。
func detectWAFHeader(h http.Header) string {
	if h == nil {
		return ""
	}
	for name := range h {
		ln := strings.ToLower(name)
		for _, want := range wafHeaderNames {
			if ln == want || strings.HasPrefix(ln, want+"-") {
				return ln
			}
		}
		if strings.HasPrefix(ln, "x-akamai-") {
			return ln
		}
	}
	if srv := strings.ToLower(h.Get("Server")); srv != "" {
		for _, v := range wafServerVendors {
			if strings.Contains(srv, v) {
				return "server:" + v
			}
		}
	}
	return ""
}

// classifyStatusBlock 仅凭状态码 + 响应头判定拦截（不含 body），返回 BlockReason。
// WAF 特征头只在 4xx/5xx 时作为佐证：正常 200 页面（如整套跑在 Cloudflare 上
// 的站点）带 cf-ray 不能判成拦截，否则会把正常结果全部误杀。
func classifyStatusBlock(status int, h http.Header, waf string) string {
	retryAfter := h != nil && h.Get("Retry-After") != ""
	switch {
	case status == http.StatusTooManyRequests && retryAfter:
		return "retry-after"
	case status == http.StatusTooManyRequests:
		return "http-429"
	case status == http.StatusServiceUnavailable && retryAfter:
		return "retry-after"
	case status == http.StatusServiceUnavailable:
		return "http-503"
	case (status == http.StatusForbidden || status == http.StatusNotAcceptable) && waf != "":
		return "waf-header:" + waf
	}
	return ""
}

// challengeStrongMarkers 强特征：任意状态码都足以判定是挑战/拦截页。
var challengeStrongMarkers = []string{
	"cf-chl",
	"cdn-cgi/challenge-platform",
	"attention required! | cloudflare",
	"checking your browser before accessing",
}

// challengeWeakMarkers 弱特征：仅在 4xx/5xx 或已命中 WAF 头时判定，避免把正常
// 页面上出现的 "captcha"/"access denied" 字样误判成拦截。
var challengeWeakMarkers = []string{
	"captcha", "access denied", "challenge", "just a moment",
}

// challengeReason 按挑战页特征判定拦截；返回 "challenge-page" 或空。
func challengeReason(status int, waf, body string) string {
	if len(body) > challengeScanBytes {
		body = body[:challengeScanBytes]
	}
	for _, m := range challengeStrongMarkers {
		if containsFoldASCII(body, m) {
			return "challenge-page"
		}
	}
	if status >= 400 || waf != "" {
		for _, m := range challengeWeakMarkers {
			if containsFoldASCII(body, m) {
				return "challenge-page"
			}
		}
	}
	return ""
}

// containsFoldASCII ASCII 大小写不敏感子串匹配（拦截页特征均为 ASCII；避免对
// 大 body 做 ToLower 分配）。s 应按 challengeScanBytes 截断后传入。
func containsFoldASCII(s, sub string) bool {
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lowerASCII(s[i+j]) != lowerASCII(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// maxURLStatusEntries URL 状态历史容量上限（超出后逐出任意一条，防内存膨胀）。
const maxURLStatusEntries = 4096

// observeURLStatus 判定「同一 URL 之前 2xx、现在 403/406」的状态降级拦截，
// 并把本次 2xx 记为后续降级判定的基线。返回是否降级。
func (c *Client) observeURLStatus(finalURL string, status int) bool {
	if finalURL == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, seen := c.urlStatus[finalURL]
	if seen && prev >= 200 && prev < 300 &&
		(status == http.StatusForbidden || status == http.StatusNotAcceptable) {
		return true
	}
	if status >= 200 && status < 300 {
		if !seen && len(c.urlStatus) >= maxURLStatusEntries {
			for k := range c.urlStatus { // 容量满：逐出任意一条（历史仅作降级基线）
				delete(c.urlStatus, k)
				break
			}
		}
		c.urlStatus[finalURL] = status
	}
	return false
}
