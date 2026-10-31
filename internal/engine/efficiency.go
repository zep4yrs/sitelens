// 效率轮 E2：请求账本 / 只读 GET 复用 / 逐页流式分析 / WAF 拦截隔离。
//
// 设计纪律（与产品红线一致）：
//   - 去重只做「语义安全的重复」：只读页面复用 + DAST benign 基线复用；
//     payload 请求、登录、目录探测一律不复用（宁少报不误报）。
//   - 被 WAF/限流拦截的响应（httpx.Response.Blocked）不参与任何判定：
//     DAST fetcher 直接返回 nil，爬取页不进分析集，主页被拦直接报错终止。
//   - 流水线只改「CPU 分析与网络抓取的时序」，不改判定逻辑；合并顺序与
//     串行实现逐条一致。
package engine

import (
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/passive"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// ---- 只读 GET 复用 --------------------------------------------------------

// readOnlyCache 单次扫描内的只读 GET 响应复用（引擎显式调用，不改 httpx）。
//
// 只缓存引擎自己抓过的只读页面（首页/种子/爬取页）的响应；DAST payload、
// 登录、目录探测等有判定语义的请求一律不进来（见 dast fetcher 注释）。
// key = 规范化 URL（scheme+host+path+排序后 query）；单次扫描内 UA/Cookie
// 由同一 client 固定，故不单列头维度。生命周期 = 单次 Scan。
type readOnlyCache struct {
	mu   sync.Mutex
	m    map[string]*httpx.Response
	hits int64
}

func newReadOnlyCache() *readOnlyCache {
	return &readOnlyCache{m: map[string]*httpx.Response{}}
}

// cacheKey 规范化 URL：fragment 去掉、query 键排序（与 httpx setParam 编码
// 语义一致，避免参数顺序差异把同一个 GET 认成两个请求）。
func cacheKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	u.RawQuery = u.Query().Encode()
	return u.String()
}

// put 缓存一份只读响应（Blocked 响应不入缓存——它不参与判定）。
func (c *readOnlyCache) put(resp *httpx.Response) {
	if resp == nil || resp.Blocked || resp.FinalURL == "" {
		return
	}
	k := cacheKey(resp.FinalURL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[k]; !ok {
		c.m[k] = resp
	}
}

// get 命中返回缓存响应并计数。
func (c *readOnlyCache) get(rawURL string) (*httpx.Response, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, ok := c.m[cacheKey(rawURL)]
	if ok {
		c.hits++
	}
	return resp, ok
}

// Hits 复用命中数（诊断用）。
func (c *readOnlyCache) Hits() int64 { return atomic.LoadInt64(&c.hits) }

// ---- WAF/限流拦截追踪 -----------------------------------------------------

// errBlockedResponse 被 WAF/限流拦截的响应（不参与判定，按「无响应」处理）。
var errBlockedResponse = errors.New("响应被 WAF/限流拦截，不参与判定")

// blockedTracker 记录被拦截的 URL（引擎与 dast/jsmap fetcher 共享）。
// 计数以 httpx.Client.Stats().Blocked 为权威口径；这里只存 URL 集合，
// 供「命中后过滤」与页级排除使用。
type blockedTracker struct {
	mu      sync.Mutex
	urls    map[string]bool
	reasons map[string]int64
}

func newBlockedTracker() *blockedTracker {
	return &blockedTracker{urls: map[string]bool{}, reasons: map[string]int64{}}
}

// note 若响应被拦截则登记并返回 true（调用方据此当作无响应）。
func (b *blockedTracker) note(resp *httpx.Response) bool {
	if resp == nil || !resp.Blocked {
		return false
	}
	b.mu.Lock()
	b.urls[cacheKey(resp.FinalURL)] = true
	if resp.BlockReason != "" {
		b.reasons[resp.BlockReason]++
	}
	b.mu.Unlock()
	return true
}

// isBlockedURL 该 URL 是否曾返回拦截响应。
func (b *blockedTracker) isBlockedURL(rawURL string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.urls[cacheKey(rawURL)]
}

// reasonsSnapshot 拦截原因计数（诊断用）。
func (b *blockedTracker) reasonsSnapshot() map[string]int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.reasons) == 0 {
		return nil
	}
	out := make(map[string]int64, len(b.reasons))
	for k, v := range b.reasons {
		out[k] = v
	}
	return out
}

// ---- 阶段请求账本 ---------------------------------------------------------

// diagRecorder 阶段级诊断（请求数/blocked/去重命中/耗时/RPS）。
type diagRecorder struct {
	mu        sync.Mutex
	client    *httpx.Client
	blocked   *blockedTracker
	phases    []PhaseDiagnostics
	streaming bool
	rateMode  string
	maxRPS    int
	// preflightReused：本次扫描首页复用了预检响应（未重复请求）。
	preflightReused bool
}

func newDiagRecorder(client *httpx.Client, blocked *blockedTracker, streaming bool, rateMode string, maxRPS int) *diagRecorder {
	return &diagRecorder{client: client, blocked: blocked, streaming: streaming, rateMode: rateMode, maxRPS: maxRPS}
}

// begin 阶段起点（返回时间与 httpx 统计快照）。
func (d *diagRecorder) begin() (time.Time, httpx.Stats) {
	return time.Now(), d.client.Stats()
}

// end 阶段终点：写一条 PhaseDiagnostics（dedupHits 为本阶段复用命中数）。
func (d *diagRecorder) end(name string, t0 time.Time, s0 httpx.Stats, dedupHits int64) {
	el := time.Since(t0)
	s1 := d.client.Stats()
	p := PhaseDiagnostics{
		Phase:      name,
		Requests:   s1.Requests - s0.Requests,
		Blocked:    s1.Blocked - s0.Blocked,
		DedupHits:  dedupHits,
		DurationMS: el.Milliseconds(),
	}
	if el > 0 {
		p.AvgRPS = float64(p.Requests) / el.Seconds()
	}
	d.mu.Lock()
	d.phases = append(d.phases, p)
	d.mu.Unlock()
}

// result 汇总账本（finish 时调用一次）。
func (d *diagRecorder) result(start time.Time) *ScanDiagnostics {
	s := d.client.Stats()
	el := time.Since(start)
	out := &ScanDiagnostics{
		Phases:          append([]PhaseDiagnostics{}, d.phases...),
		Requests:        s.Requests,
		Blocked:         s.Blocked,
		Backoffs:        s.Backoffs,
		DurationMS:      el.Milliseconds(),
		RateMode:        d.rateMode,
		MaxRPS:          d.maxRPS,
		EffectiveMS:     s.Interval.Milliseconds(),
		StreamingUsed:   d.streaming,
		PreflightReused: d.preflightReused,
	}
	if d.blocked != nil {
		out.WAFReasons = d.blocked.reasonsSnapshot()
	}
	for _, p := range out.Phases {
		out.DedupHits += p.DedupHits
	}
	if el > 0 {
		out.AvgRPS = float64(out.Requests) / el.Seconds()
	}
	return out
}

// ---- jsmap 的拦截隔离 fetcher --------------------------------------------

// blockedAwareFetcher 给 jsmap 的字节拉取加拦截隔离：WAF 挑战页/限流页的
// 正文不参与 SourceMap/API 端点提取（否则会把挑战页里的字符串当攻击面）。
type blockedAwareFetcher struct {
	c       *httpx.Client
	blocked *blockedTracker
	live    *liveTracker
}

func (f blockedAwareFetcher) FetchBytes(rawURL string) ([]byte, error) {
	r, err := f.c.GetDirect(rawURL)
	if r == nil {
		return nil, err
	}
	if f.live != nil {
		f.live.touch()
	}
	if f.blocked != nil && f.blocked.note(r) {
		return nil, errBlockedResponse
	}
	return []byte(r.Body), nil
}

// ---- 逐页流式分析 ---------------------------------------------------------

// pageStream 爬取过程中的逐页流水线：每拿到一页就启动该页的指纹匹配与被动
// 检查，不等全站爬完（指纹是 CPU 热点，与限速等待窗口重叠）。
//
// 确定性保证：
//   - pages 按「首页 → 爬取顺序」存放，与串行实现的 pages 顺序一致；
//   - 被动检查在 push 内串行执行（Deduper 状态必须按页序推进）；
//   - 指纹在 worker 并行执行、结果按页下标存放，合并时仍按页序累加；
//   - 因此 Technologies/verified 的条目顺序与串行实现逐条一致。
type pageStream struct {
	matcher   *sitelens.Matcher
	favHash   int64
	passiveOn bool
	deduper   *passive.Deduper

	pages       []crawlPage
	fpHits      [][]sitelens.MatchHit
	passiveHits [][]passive.Hit

	// CSP 首个命中页（页序第一个带 CSP 的页面；首页由安全头阶段单独评估）。
	cspHeaders map[string]string
	cspURL     string

	wg  sync.WaitGroup
	sem chan struct{}

	// mu 保护 pages/passiveHits/fpHits 的追加与元素回填：crawler 的 pageHook
	// 可能在并发 goroutine 中回调（-race 实抓：append 扩容与 worker 写元素
	// 竞争），因此追加、CSP 首命中记录、被动检查与指纹结果回填都在锁内串行。
	mu sync.Mutex
}

func newPageStream(matcher *sitelens.Matcher, favHash int64, passiveOn bool, workers int) *pageStream {
	if workers < 1 {
		workers = 1
	}
	s := &pageStream{matcher: matcher, favHash: favHash, passiveOn: passiveOn}
	if passiveOn {
		s.deduper = passive.NewDeduper()
	}
	if matcher != nil {
		s.sem = make(chan struct{}, workers)
	}
	return s
}

// push 收入一页并启动该页分析。crawler 的 pageHook 可能在并发 goroutine 中
// 回调，因此 pages/passiveHits/fpHits 追加、CSP 首命中记录与被动检查都在
// s.mu 下串行执行；指纹匹配派发 worker，但结果回填同样在锁内（避免 append
// 扩容与元素写入的数据竞争）。顺序仍按 push 调用顺序（= 页序）。
func (s *pageStream) push(resp *httpx.Response, doc *htmlx.Doc) {
	if resp == nil {
		return
	}
	cp := crawlPage{resp: resp, doc: doc}
	if cp.doc == nil {
		cp.doc = htmlx.Parse(resp.Body)
	}
	s.mu.Lock()
	idx := len(s.pages)
	s.pages = append(s.pages, cp)
	s.passiveHits = append(s.passiveHits, nil)
	s.fpHits = append(s.fpHits, nil)

	// CSP 逐页策略：记录页序第一个带 CSP 的页面（供安全头阶段补评）。
	if s.cspURL == "" && hasCSPHeader(resp.Headers) {
		s.cspHeaders, s.cspURL = resp.Headers, resp.FinalURL
	}

	// 被动检查：零额外请求、CPU 轻；Deduper 必须按页序串行推进。
	if s.passiveOn {
		s.passiveHits[idx] = passive.RunDedup(resp, cp.doc, resp.FinalURL, s.deduper)
	}
	s.mu.Unlock()

	// 指纹匹配：CPU 热点，派发 worker（结果按 idx 回填，合并仍按页序）。
	if s.matcher != nil {
		s.wg.Add(1)
		go func(i int, r *httpx.Response) {
			defer s.wg.Done()
			s.sem <- struct{}{}
			defer func() { <-s.sem }()
			ev := sitelens.Extract(r)
			ev.FaviconHash = s.favHash
			hits := s.matcher.Match(ev)
			s.mu.Lock()
			s.fpHits[i] = hits
			s.mu.Unlock()
		}(idx, resp)
	}
}

// wait 等待所有并行指纹匹配完成。
func (s *pageStream) wait() { s.wg.Wait() }
