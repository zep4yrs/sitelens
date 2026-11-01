// Package httpx 提供限速 HTTP 客户端：手动跟随重定向 + 逐跳 SSRF 校验。
// 行为约定移植自 scanner/fetcher.py（限速 / UA 自报 / 证据留取）。
package httpx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Response 精简响应（对齐 Python get_small 的返回形态）。
// Set-Cookie 单独保真存放：Go http.Header 本就逐条分离，不再合并进 Headers，
// 下游 Cookie 属性/名称解析不需要启发式切分。
type Response struct {
	Status     int
	Headers    map[string]string
	SetCookies []string
	Body       string
	FinalURL   string
	// Blocked/BlockReason：该响应被判为 WAF/限流拦截（additive，既有字段语义
	// 不变）。WAF 错误页常回显 payload，上层据此跳过判定以免假阳性；
	// BlockReason 取值为 http-429 / http-503 / retry-after / waf-header:<name> /
	// challenge-page / status-downgrade 之一。
	Blocked     bool
	BlockReason string
}

// Header 大小写不敏感取响应头。
func (r *Response) Header(name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

const defaultMaxBodyBytes = 3_000_000 // 与 Python 端一致：超 3MB 不留正文

// baseDialer 与 http.DefaultTransport 内置拨号参数对齐（30s 拨号超时 /
// 30s keepalive），避免自建 Transport 后底层行为漂移。
var baseDialer = net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// 拨号层 Happy Eyeballs（RFC 8305）参数。集中定义、不暴露为配置项（产品口径：
// 不加新配置）；取值对齐 RFC 建议与 Go net 包的默认取向。
const (
	// happyEyeballsStagger 相邻两个拨号尝试的最小启动间隔（RFC 8305 §5 的
	// Connection Attempt Delay 建议值 250ms）。首个候选地址立即尝试，之后
	// 每 250ms 追加一个候选：既给前面的地址留出握手时间，又不会让首地址的
	// 黑洞/拒绝把请求一路拖到超时。
	happyEyeballsStagger = 250 * time.Millisecond

	// maxDialAddrs 单次拨号最多并行参与的候选地址数。正常多 A/AAAA 记录远
	// 少于 8；故障/恶意 DNS 返回几十条解析结果时必须限流——每个黑洞地址都会
	// 挂一条连接（goroutine + fd）到 ctx 超时，无上限会耗尽资源。超出部分放弃。
	maxDialAddrs = 8
)

// ClientOptions 客户端参数（全部来自 config.ScanConfig 的装配）。
type ClientOptions struct {
	Interval     time.Duration // 每主机请求最小间隔（令牌桶速率）：polite 原样使用（0=不限速）；Adaptive 时作为自适应起点并受 200ms 硬下限约束
	Timeout      time.Duration // 单请求超时，0=20s
	MaxHops      int           // 重定向最大跳数，0=6
	MaxBodyBytes int           // 正文留存上限，0=3MB
	UserAgent    string        // 空 = SiteLens 自报 UA
	AuthCookie   string        // 附加到每个请求的 Cookie 头（授权扫描用）
	// Resolve=true 时在拨号层执行「一次解析 → 校验 IP 集合 → 按已校验 IP
	// 拨号」，覆盖初始请求与重定向逐跳（BUG-021）。继承引擎 resolve 姿态；
	// 本地/内网靶场矩阵设 false（不做 DNS 级拦截）。
	Resolve bool
	// Adaptive=true 启用 WAF-aware 自适应限速（balanced 档）：起点为 Interval
	// （默认 400ms，polite 档），连续干净成功后逐级减半，硬下限 200ms
	// （≤5 req/s/主机；令牌桶按 host:port 全进程共享，多个 Client 叠加也不
	// 超速）；命中 429/503/WAF 特征/挑战页/RTT 恶化时退避，检出拦截后锁定
	// 低速（400ms→1s→2s）不再加速。false=polite：固定间隔、无抖动、无调速。
	Adaptive bool
	// MaxRPS 每主机硬上限（0=默认 5）。只能让上限更保守（更小）——间隔硬下限
	// 200ms（5 req/s 代码级红线）不因 MaxRPS 变大而突破。
	MaxRPS int
}

// Client 限速 HTTP 客户端（自动重定向禁用，逐跳校验后手动跟随）。
type Client struct {
	http      *http.Client
	resolve   bool
	mu        sync.Mutex
	userAgent string
	maxHops   int
	maxBody   int
	cookie    string
	// extraHeaders 持久附加请求头（CP-02 认证矩阵：Authorization / X-API-Key 等）。
	// 由 SetHeader 注入；newRequest 合并到每个请求（同名头覆盖默认值）。
	extraHeaders map[string]string
	// limiterCfg 限速参数（E1）：令牌桶按 host:port 全进程共享，Client 只携带
	// 配置；base=0 表示不限速（沿用 Interval<=0 的历史语义，不注册限速器）。
	limiterCfg limiterConfig
	// 仅测试注入：限速调度时钟/睡眠钩子（nil = time.Now / time.Sleep）。
	// 注入后令牌节奏可确定性验证；RTT 始终用真实时钟（网络时延语义）。
	now   func() time.Time
	sleep func(time.Duration)
	// 统计与诊断（mu 保护）。
	requests  int64
	blocked   int64
	backoffs  int64
	firstReq  time.Time
	lastHost  *hostLimiter   // 最近一次限速命中的 host 限速器（Stats 读取间隔）
	urlStatus map[string]int // 同 URL 状态历史：2xx 基线 → 后续 403/406 降级判定
	// lookupIP 域名解析钩子（nil = target.ResolveHostIPs）。仅测试注入：
	// 生产路径必须走系统解析，且同一份结果只用于本次「校验 + 拨号」。
	lookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// dial 单次 TCP 建连钩子（nil = baseDialer.DialContext）。仅测试注入：
	// 生产路径必须走真实拨号，注入 fake 只为确定性验证并发拨号调度。
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewWithOptions 按参数创建客户端。
func NewWithOptions(o ClientOptions) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxHops <= 0 {
		o.MaxHops = 6
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = defaultMaxBodyBytes
	}
	if o.UserAgent == "" {
		o.UserAgent = "SiteLens/3.0.0 (+https://cnb.cool/feng-qiao/sitelens)"
	}
	if o.MaxRPS <= 0 {
		o.MaxRPS = 5 // 每主机硬上限默认 5 req/s（用户红线；仅 Adaptive=true 生效）
	}
	c := &Client{
		userAgent: o.UserAgent,
		maxHops:   o.MaxHops,
		maxBody:   o.MaxBodyBytes,
		cookie:    o.AuthCookie,
		resolve:   o.Resolve,
		urlStatus: make(map[string]int),
		limiterCfg: limiterConfig{
			adaptive:   o.Adaptive,
			accelAfter: adaptiveAccelerateAfter,
		},
	}
	// 限速配置：
	//   - polite（Adaptive=false）与旧实现逐字节等价：Interval 原样使用
	//     （0=不限速、1ms=1ms、400ms=400ms），不夹硬下限、不加抖动、不做
	//     WAF/RTT 调速（只做拦截标记）。
	//   - adaptive：起点 = max(Interval, 硬下限)，Interval<=0 时沿用历史
	//     「0=不限速」语义（本地靶场/单测显式表达不限速，生产默认由配置填 400）。
	if o.Adaptive {
		c.limiterCfg.floor = adaptiveFloor(o.MaxRPS)
		if o.Interval > 0 {
			c.limiterCfg.base = o.Interval
			if c.limiterCfg.base < c.limiterCfg.floor {
				c.limiterCfg.base = c.limiterCfg.floor
			}
		}
	} else if o.Interval > 0 {
		c.limiterCfg.base = o.Interval
	}
	// 拨号层接管域名解析：一次解析、全量校验、按已校验 IP 拨号（BUG-021）。
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = c.dialContext
	c.http = &http.Client{
		Timeout:   o.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // 禁自动重定向，逐跳手动校验
		},
	}
	return c
}

// dialContext 一次解析 + 全量校验 + 按已校验 IP 拨号（SSRF 防 DNS 重绑定）。
//
// 背景（BUG-021）：旧链路里 ensurePublicHost / target.Validate 用系统解析器
// 校验完就丢弃结果，真正的连接由 transport 再次调用系统解析器解析——两次
// DNS 查询之间，攻击者可用 TTL≈0 的 DNS 重绑定（校验时回公网、拨号时回
// 127.0.0.1/10.x）绕过私网闸。现在解析只做一次，校验的 IP 集合就是随后
// 拨号的目标（写 IP 字面量），不存在「校验过的名字被重新解析成别的地址」。
//
// 多地址并发拨号（5.2 性能优化）：BUG-021 的初版修法对已校验 IP 串行拨号，
// 丢掉了 Go 默认 Transport 的 Happy Eyeballs（RFC 8305）——首个地址拒绝/黑洞
// 时只能等满 30s 拨号超时，同一域名的其他可用地址全程没被尝试。现在把已校验
// 的 IP 集合交给 dialValidatedIPs 做轻量并行握手。
//
// Host 头与 TLS SNI 不受影响：这里只改底层连接地址，请求身份仍由
// http.Transport 按 URL 主机名生成（Host/SNI 保持原域名）。
// SSRF 语义不变：候选地址全部来自上面一次解析 + target.ValidateIPs 全量校验
// 的集合，只拨 IP 字面量，不重新解析、不新增候选。
// Resolve=false（本地/内网靶场姿态）不做 DNS 级拦截，与原行为一致。
func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !c.resolve {
		return baseDialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// 字面 IP：直接按 IP 规则校验（元数据永久阻断；私网随 allow_private）。
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if verr := target.ValidateIP(ip); verr != nil {
			return nil, verr
		}
		return baseDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	lookup := c.lookupIP
	if lookup == nil {
		lookup = target.ResolveHostIPs
	}
	ips, lerr := lookup(ctx, host)
	if lerr != nil {
		return nil, lerr
	}
	// 全量校验：任一 IP 是私网/保留地址即整体拒绝（不挑一个合规的去拨）。
	if verr := target.ValidateIPs(ips); verr != nil {
		return nil, verr
	}
	// 只拨已校验的 IP 字面量：即使此刻 DNS 已变，也连不到未校验地址。
	// 多地址并发拨号（轻量 Happy Eyeballs），避免串行等首个坏地址。
	return c.dialValidatedIPs(ctx, network, port, ips)
}

// errAttemptSuperseded 落败的拨号尝试（已有别的地址先连上，本尝试被取消）。
// 只用于错误归因：有胜者时直接返回连接，不会走到全失败分支。
var errAttemptSuperseded = errors.New("其余拨号尝试已被取消")

// dialAttempt 单次拨号尝试的结果（idx 为候选序下标，用于确定性错误归因）。
type dialAttempt struct {
	idx int
	err error
}

// dialValidatedIPs 对「已全量校验」的 IP 集合做并发拨号（轻量 Happy Eyeballs）。
//
// 调度设计（RFC 8305 精简版）：
//   - 候选顺序：IPv6/IPv4 按首选族交错（dialCandidates），最多 maxDialAddrs 个；
//   - 首候选地址立即拨号，之后每 happyEyeballsStagger 追加一个尝试（错峰，
//     避免一次握手风暴，也让首选地址先拿到机会）；
//   - 第一个成功连接即返回，同时取消其余尝试（含仍在 stagger 等待的）；
//   - 并发同时成功时由 sync.Once 唯一决定胜者，落败方自己关闭已建连接
//     （否则没人再读 channel，fd 泄漏）；
//   - 全部失败时返回「候选序最靠后地址」的错误，保留原串行实现的 lastErr
//     语义（真实错误信息比笼统的 ctx 取消更利于排障）；
//   - 总时长仍由调用方 ctx（http.Client.Timeout）约束：ctx 取消后各尝试
//     立即返回（net.Dialer 尊重 ctx 取消），因此下面的接收循环不会永久阻塞。
//
// 语义约束：只拨入参携带的已校验 IP 字面量，本函数不解析域名、不新增候选。
func (c *Client) dialValidatedIPs(ctx context.Context, network, port string, ips []netip.Addr) (net.Conn, error) {
	dial := c.dial
	if dial == nil {
		dial = baseDialer.DialContext
	}
	addrs := dialCandidates(ips)
	// 单地址：无并发收益，走最短路径（与串行实现逐字节等价）。
	if len(addrs) == 1 {
		return dial(ctx, network, net.JoinHostPort(addrs[0].String(), port))
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel() // 全失败/提前返回时释放 ctx 资源；胜者路径 cancel 幂等

	var (
		winOnce sync.Once
		winner  net.Conn
	)
	// 带缓冲 len(addrs)：orchestrator 返回后迟到的结果不会阻塞尝试 goroutine。
	resultCh := make(chan dialAttempt, len(addrs))
	for i, ip := range addrs {
		go func() {
			// 错峰启动：第 i 个候选延迟 i*stagger。等待期间已被取消则不再
			// 发起新连接（胜者已定或请求 ctx 结束）。
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * happyEyeballsStagger)
				defer t.Stop()
				select {
				case <-t.C:
				case <-dialCtx.Done():
					resultCh <- dialAttempt{idx: i, err: dialCtx.Err()}
					return
				}
			}
			conn, derr := dial(dialCtx, network, net.JoinHostPort(ip.String(), port))
			if derr != nil {
				resultCh <- dialAttempt{idx: i, err: derr}
				return
			}
			// sync.Once 决定唯一胜者：并发同时成功时只有一个连接被交出去，
			// 其余连接在这里立即关闭（否则 fd 泄漏且无人释放）。
			won := false
			winOnce.Do(func() { winner = conn; won = true })
			if !won {
				_ = conn.Close()
				resultCh <- dialAttempt{idx: i, err: errAttemptSuperseded}
				return
			}
			cancel() // 首个成功 → 取消其余尝试
			resultCh <- dialAttempt{idx: i}
		}()
	}
	// 每个尝试保证恰好回传一条结果（dial 尊重 ctx 取消，baseDialer 如此），
	// 因此这里最多收 len(addrs) 条，不会漏收也不会永久阻塞。
	var (
		lastErr    error
		lastErrIdx = -1
	)
	for pending := len(addrs); pending > 0; pending-- {
		r := <-resultCh
		if r.err == nil {
			return winner, nil
		}
		// 取候选序最靠后地址的真实错误（落败取消不算失败，排除）。
		if r.idx > lastErrIdx && !errors.Is(r.err, errAttemptSuperseded) {
			lastErr, lastErrIdx = r.err, r.idx
		}
	}
	if lastErr == nil {
		lastErr = errAttemptSuperseded
	}
	return nil, lastErr
}

// dialCandidates 从「已全量校验」的 IP 集合生成拨号候选序：先按 RFC 8305 §3
// 做 IPv6/IPv4 地址族交错，再截断到 maxDialAddrs。
//
// 交错规则：首选族 = 首个解析结果的族（系统解析器已按 RFC 6724 排好偏好序，
// 同族内部顺序原样保留），两族轮流取。这样「v6 黑洞 + v4 可用」不会等完所有
// v6 地址才试 v4；反之亦然。单族输入保持原序（无交错收益）。
// 截断放在交错之后：避免「一长串同族地址把另一族全部挤出候选窗口」。
func dialCandidates(ips []netip.Addr) []netip.Addr {
	out := interleaveAddrs(ips)
	if len(out) > maxDialAddrs {
		out = out[:maxDialAddrs]
	}
	return out
}

// interleaveAddrs 按 RFC 8305 §3 对解析结果做 IPv6/IPv4 交错；单族输入原样返回。
func interleaveAddrs(in []netip.Addr) []netip.Addr {
	if len(in) < 2 {
		return in
	}
	var v4, v6 []netip.Addr
	for _, a := range in {
		if a.Is4() { // ::ffff:a.b.c.d（4-in-6）按 IPv6 处理，保持原顺序归类
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	if len(v4) == 0 || len(v6) == 0 {
		return in
	}
	prim, sec := v6, v4
	if in[0].Is4() {
		prim, sec = v4, v6
	}
	out := make([]netip.Addr, 0, len(in))
	for i := 0; i < len(prim) || i < len(sec); i++ {
		if i < len(prim) {
			out = append(out, prim[i])
		}
		if i < len(sec) {
			out = append(out, sec[i])
		}
	}
	return out
}

// New 创建客户端；interval 为相邻请求最小间隔（限速）。
func New(interval time.Duration) *Client {
	return NewWithOptions(ClientOptions{Interval: interval})
}

// nowFn 返回限速调度时钟（测试可注入；生产 = time.Now）。
func (c *Client) nowFn() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// sleepFn 按限速调度时钟睡眠（测试可注入；生产 = time.Sleep）。
func (c *Client) sleepFn(d time.Duration) {
	if c.sleep != nil {
		c.sleep(d)
		return
	}
	time.Sleep(d)
}

// acquire 为本次请求取得 host 级共享令牌桶的发送许可（阻塞到令牌可用）。
//
// 令牌桶按 host:port 全进程共享：多个 Client（爬虫 / DAST）、多个并发调用者
// 合起来仍受同一每主机速率约束，从机制上避免旧的「N 个调用者各自睡 interval
// 后同时齐发 → 实际速率放大成 N/interval」缺陷，也不给多个 Client 叠加翻倍
// 的机会。base<=0（历史「不限速」语义）时直接放行。
func (c *Client) acquire(req *http.Request) {
	if c.limiterCfg.base <= 0 || req == nil || req.URL == nil {
		return
	}
	key := hostKey(req.URL)
	if key == "" {
		return
	}
	lim := hostLimiterFor(key, c.limiterCfg)
	lim.acquire(c.nowFn, c.sleepFn)
	c.mu.Lock()
	c.lastHost = lim
	c.mu.Unlock()
}

// send 执行一次真实 HTTP 请求：请求计数、测量 RTT，并把 RTT/失败反馈给该
// host 的共享限速器（自适应模式据此退避；polite 档只记录不调速）。
func (c *Client) send(req *http.Request) (*http.Response, error) {
	start := time.Now() // RTT 用真实时钟：网络时延语义，与可注入的调度时钟无关
	c.mu.Lock()
	c.requests++
	if c.firstReq.IsZero() {
		c.firstReq = c.nowFn()
	}
	c.mu.Unlock()

	resp, err := c.http.Do(req)
	lim := hostLimiterByRequest(req)
	if err != nil {
		if lim != nil {
			lim.onUnclean() // 连接失败/超时：不加速
		}
		return nil, err
	}
	if lim != nil && lim.onRTT(time.Since(start), resp.StatusCode) {
		c.mu.Lock()
		c.backoffs++
		c.mu.Unlock()
	}
	return resp, nil
}

// finish 读取并关闭响应体、生成 Response，同时做 WAF/限流识别与自适应反馈
// （Blocked/BlockReason 为 additive 字段；polite 档只标记、不改节奏）。
func (c *Client) finish(resp *http.Response, finalURL string, bodyCap int) *Response {
	body, headers, cookies := readBody(resp, bodyCap)
	reason := c.classifyResponse(resp, body, finalURL)
	return &Response{
		Status:      resp.StatusCode,
		Headers:     headers,
		SetCookies:  cookies,
		Body:        body,
		FinalURL:    finalURL,
		Blocked:     reason != "",
		BlockReason: reason,
	}
}

// classifyResponse 识别 WAF/限流拦截并驱动 host 共享限速器反馈，返回
// BlockReason（空 = 未拦截）。
//
// 判定顺序：状态/头级硬信号（429/503/Retry-After/WAF 头）→ 挑战页特征 →
// 同 URL 状态降级（2xx→403/406）。WAF 特征头只在 4xx/5xx 时作佐证：整套跑在
// Cloudflare 上的正常站点每个 200 都带 cf-ray，不能全部误判为拦截。
func (c *Client) classifyResponse(resp *http.Response, body, finalURL string) string {
	status := resp.StatusCode
	waf := detectWAFHeader(resp.Header)
	reason := classifyStatusBlock(status, resp.Header, waf)
	if reason == "" {
		reason = challengeReason(status, waf, body)
	}
	lim := hostLimiterByRequest(resp.Request)
	if c.observeURLStatus(finalURL, status) && reason == "" {
		reason = "status-downgrade"
	}
	if reason != "" {
		c.mu.Lock()
		c.blocked++
		c.mu.Unlock()
		if lim != nil && lim.onBlock() {
			c.mu.Lock()
			c.backoffs++
			c.mu.Unlock()
		}
		return reason
	}
	if lim != nil {
		// 404 是扫描常态，计入干净流量；其余 4xx/5xx 清零加速计数（5xx 的
		// 压力信号已在 send→onRTT 里处理）。
		if status < 400 || status == http.StatusNotFound {
			lim.onClean()
		} else {
			lim.onUnclean()
		}
	}
	return ""
}

// readBody 读取响应体（上限 bodyCap）并关闭，收集普通头与 Set-Cookie。
func readBody(resp *http.Response, bodyCap int) (string, map[string]string, []string) {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, int64(bodyCap)+1))
	if len(raw) > bodyCap {
		raw = raw[:bodyCap]
	}
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue // 单独保真存放
		}
		headers[k] = strings.Join(vs, ", ")
	}
	return string(raw), headers, resp.Header.Values("Set-Cookie")
}

// Stats 返回限速/拦截统计快照（诊断包 / CLI 输出用；additive API）。
func (c *Client) Stats() Stats {
	c.mu.Lock()
	reqs, blocked, backoffs := c.requests, c.blocked, c.backoffs
	first, lim := c.firstReq, c.lastHost
	c.mu.Unlock()

	interval := c.limiterCfg.base
	if lim != nil {
		interval = lim.currentInterval()
	}
	var avg float64
	if !first.IsZero() {
		if el := c.nowFn().Sub(first); el > 0 {
			avg = float64(reqs) / el.Seconds()
		}
	}
	return Stats{
		Requests: reqs,
		Interval: interval,
		AvgRPS:   avg,
		Blocked:  blocked,
		Backoffs: backoffs,
	}
}

// newRequest 构造带自报 UA、授权 Cookie 与持久附加头的请求。
func (c *Client) newRequest(method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// 快照持久头（SetHeader 可能并发更新）：拷贝后即释放锁，不持锁发请求。
	c.mu.Lock()
	cookie := c.cookie
	var extra map[string]string
	if len(c.extraHeaders) > 0 {
		extra = make(map[string]string, len(c.extraHeaders))
		for k, v := range c.extraHeaders {
			extra[k] = v
		}
	}
	c.mu.Unlock()

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	// 附加头最后应用：同头名覆盖默认 UA/Accept/Cookie（认证注入优先）。
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req, nil
}

// SetCookie 运行时注入会话 Cookie（登录流捕获后供整次扫描复用）。
func (c *Client) SetCookie(cookie string) {
	c.mu.Lock()
	c.cookie = cookie
	c.mu.Unlock()
}

// SetHeader 运行时注入/覆盖一个持久请求头（CP-02 认证矩阵入口）。
// 头名去空白后为空则忽略（不 panic、不改客户端状态）；注入后对所有后续
// 请求生效，同名头覆盖默认 UA/Accept/Cookie。凭据非空由调用方校验
// （authn.Config 已做空凭据拒绝）。
func (c *Client) SetHeader(name, value string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	c.mu.Lock()
	if c.extraHeaders == nil {
		c.extraHeaders = make(map[string]string, 2)
	}
	c.extraHeaders[name] = value
	c.mu.Unlock()
}

// SetTimeout 运行时调整单请求超时。
func (c *Client) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.http.Timeout = d
	c.mu.Unlock()
}

// GetFollow 手动跟随重定向的 GET：每一跳都过 target.Validate SSRF 校验
// （协议白名单 + DNS 解析 + 私网拒绝）。返回最终到达的响应。
func (c *Client) GetFollow(rawURL string) (*Response, error) {
	return c.GetFollowWith(rawURL, nil)
}

// GetFollowWith 同 GetFollow，附加额外请求头（403 绕过重试等场景）。
func (c *Client) GetFollowWith(rawURL string, extra map[string]string) (*Response, error) {
	return c.MethodFollowWith(http.MethodGet, rawURL, extra)
}

// MethodFollowWith 指定方法的跟随重定向请求（HEAD/OPTIONS 等只读变体）。
// 非法方法直接拒绝；每一跳都过 target.Validate SSRF 校验（同 GetFollowWith）。
func (c *Client) MethodFollowWith(method, rawURL string, extra map[string]string) (*Response, error) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return nil, &target.Error{Msg: "方法不允许（仅 GET/HEAD/OPTIONS，无害化红线）"}
	}
	cur := rawURL
	var resp *http.Response
	var err error
	for hop := 0; hop < c.maxHops; hop++ {
		req, rerr := c.newRequest(method, cur)
		if rerr != nil {
			return nil, &target.Error{Msg: "URL 构造失败"}
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		c.acquire(req) // 逐跳都过 host 级令牌桶（每次真实请求都占一个令牌）
		resp, err = c.send(req)
		if err != nil {
			// 底层错误原样带出（refused/timeout/proxy 一目了然）
			return nil, &target.Error{Msg: "连接失败：" + cur + "：" + err.Error()}
		}
		if !isRedirect(resp.StatusCode) {
			break
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		next, perr := resolveRef(cur, loc)
		if perr != nil {
			break
		}
		// 逐跳静态校验（协议白名单 / 主机黑名单 / 元数据字面 IP / gov.cn / 端口）。
		// DNS 级私网校验不再在这里做——交给拨号层 c.dialContext：每次真正
		// 建连时「一次解析 → 全量校验 → 按已校验 IP 拨号」（BUG-021），因此
		// 每一跳校验的都是即将拨号的那份解析结果，DNS 重绑定拿不到窗口。
		// resolve=false（本地/内网靶场矩阵）时拨号层不做 DNS 级拦截。
		if _, _, _, verr := target.Validate(next, false); verr != nil {
			// 拒绝跟随：当前跳 body 必须先排空并关闭，否则连接与
			// transport readLoop goroutine 泄漏（BUG-008）。
			drainAndClose(resp.Body)
			return nil, verr
		}
		// 进入下一跳前释放上一跳响应体：不排空会让连接无法复用，不关闭
		// 则每跳泄漏一个连接 + 一个 goroutine，长扫描下 fd 单调增长（BUG-008）。
		drainAndClose(resp.Body)
		cur = next
	}
	return c.finish(resp, cur, defaultMaxBodyBytes), nil
}

// drainAndClose 排空并关闭中间跳响应体。
//
// 排空（有上限）是为了让 keep-alive 连接回到空闲池可复用；只 Close 不读，
// Go transport 会直接丢弃该连接（下一次请求重新握手，且旧连接读完残留数据
// 前不会释放）。上限 64KB：重定向 body 通常极小，超限就放弃复用直接关。
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

// GetDirect 单请求 GET：不跟随重定向、不做重定向逐跳校验（URL 需预先 Validate；
// resolve=true 时拨号层仍会做「一次解析 + IP 集合校验 + 按已校验 IP 拨号」，BUG-021）。
// 供 DAST 开放重定向判定等需要看原始 30x 响应的探测使用；正文上限 1MB。
func (c *Client) GetDirect(rawURL string) (*Response, error) {
	req, err := c.newRequest(http.MethodGet, rawURL)
	if err != nil {
		return nil, err
	}
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 1_000_000), nil
}

// GetWithHeaders 带自定义请求头的 GET（单请求，不跟随重定向；Cookie/头注入探测用）。
func (c *Client) GetWithHeaders(rawURL string, headers map[string]string) (*Response, error) {
	req, err := c.newRequest(http.MethodGet, rawURL)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 512_000), nil
}

// PostForm POST 表单提交（单请求，不跟随重定向；登录爆破用）。
func (c *Client) PostForm(rawURL string, fields map[string]string) (*Response, error) {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	payload := form.Encode()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(strings.NewReader(payload))
	req.ContentLength = int64(len(payload))
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 512_000), nil
}

// PostRaw POST 自定义 Content-Type 的原始请求体（Nuclei POST 模板等）。
func (c *Client) PostRaw(rawURL, contentType, body string) (*Response, error) {
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 512_000), nil
}

// PostMultipart 多段表单上传（单请求，不跟随重定向；上传面探测用）。
// fileField 为文件字段名，fileName 为文件名，content 为文件内容。
func (c *Client) PostMultipart(rawURL, fileField, fileName, content string,
	extra map[string]string) (*Response, error) {
	return c.postMultipart(rawURL, fileField, fileName, content, "application/octet-stream", extra)
}

// postMultipart 多段上传共用实现（可指定文件字段 Content-Type）。
func (c *Client) postMultipart(rawURL, fileField, fileName, content, contentType string,
	extra map[string]string) (*Response, error) {
	const boundary = "----sitelensUploadBoundary7e3a9f"
	var b strings.Builder
	for k, v := range extra {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(`Content-Disposition: form-data; name="` + k + `"\r\n\r\n`)
		b.WriteString(v + "\r\n")
	}
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString(`Content-Disposition: form-data; name="` + fileField + `"; filename="` + fileName + `"` + "\r\n")
	b.WriteString("Content-Type: " + contentType + "\r\n\r\n")
	b.WriteString(content + "\r\n")
	b.WriteString("--" + boundary + "--\r\n")

	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	payload := b.String()
	req.Body = io.NopCloser(strings.NewReader(payload))
	req.ContentLength = int64(len(payload))
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 512_000), nil
}

// PostMultipartCT 与 PostMultipart 相同，但显式指定文件字段的 Content-Type。
// 上传绕过验证需要「危险扩展名 + 伪造 image/png」组合（目标只查 MIME 时的绕过）。
func (c *Client) PostMultipartCT(rawURL, fileField, fileName, content, contentType string,
	extra map[string]string) (*Response, error) {
	return c.postMultipart(rawURL, fileField, fileName, content, contentType, extra)
}

// PostJSON POST JSON 请求体（单请求，不跟随重定向；JSON API 登录用）。
func (c *Client) PostJSON(rawURL, body string) (*Response, error) {
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	c.acquire(req)
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return c.finish(resp, rawURL, 512_000), nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// resolveRef 以 base 解析可能为相对路径的 Location。
func resolveRef(base, ref string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return bu.ResolveReference(ru).String(), nil
}
