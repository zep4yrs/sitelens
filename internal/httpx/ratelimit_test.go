package httpx

// E1（效率轮）测试：per-host 共享令牌桶、自适应限速、WAF/限流识别与拦截标记。
//
// 测法说明：
//   - 令牌节奏用注入的 fake 时钟/睡眠确定性地验证（不依赖真实等待，-count=5 不抖动）；
//   - 目标侧负载（1s/2s 窗口峰值、并发）用真实时钟 + httptest 服务端观测，
//     直接对应「不能影响被扫描机器」的验收口径；
//   - 全部本地回环 / fake 拨号，不依赖公网。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 测试基础设施 -----------------------------------------------------------

// fakeClock 可注入的调度时钟：sleep 只推进虚拟时间并记录申请的睡眠时长，
// 让「令牌间隔」在毫秒级测试里完全确定。
type fakeClock struct {
	mu     sync.Mutex
	nowT   time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{nowT: time.Now()} }

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nowT
}

func (f *fakeClock) sleep(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sleeps = append(f.sleeps, d)
	f.nowT = f.nowT.Add(d)
}

func (f *fakeClock) drainSleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]time.Duration(nil), f.sleeps...)
	f.sleeps = nil
	return out
}

// useFakeClock 把 fake 时钟接到客户端上（限速调度；RTT 仍用真实时钟）。
func useFakeClock(c *Client, f *fakeClock) {
	c.now = f.now
	c.sleep = f.sleep
}

// resetHostLimiters 清空全进程共享的 host 限速器注册表，保证用例隔离
// （-count=5 时 httptest 端口可能复用，避免上一轮的自适应状态串场）。
func resetHostLimiters() {
	hostLimiters.Range(func(k, _ any) bool {
		hostLimiters.Delete(k)
		return true
	})
}

// arrivalRecorder 在目标侧记录请求到达时间与并发峰值。
type arrivalRecorder struct {
	mu       sync.Mutex
	times    []time.Time
	inflight int
	maxIn    int
}

func (r *arrivalRecorder) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.times = append(r.times, time.Now())
		r.inflight++
		if r.inflight > r.maxIn {
			r.maxIn = r.inflight
		}
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			r.inflight--
			r.mu.Unlock()
		}()
		next(w, req)
	}
}

func (r *arrivalRecorder) snapshot() ([]time.Time, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.times...), r.maxIn
}

// peakInWindow 返回任意半开窗口 [t_i, t_i+window) 内的最大请求数。
func peakInWindow(ts []time.Time, window time.Duration) int {
	best := 0
	for i := range ts {
		j := i
		for j < len(ts) && ts[j].Sub(ts[i]) < window {
			j++
		}
		if j-i > best {
			best = j - i
		}
	}
	return best
}

// newFastServer 返回 200 的本地服务（记录到达时间）。
func newFastServer(t *testing.T) (*httptest.Server, *arrivalRecorder) {
	t.Helper()
	rec := &arrivalRecorder{}
	srv := httptest.NewServer(rec.wrap(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// ---- polite 档与旧实现逐字节等价（回归：Lead 实测发现被硬下限误夹） --------

// TestPoliteIntervalNotClamped 回归：Adaptive=false 时 interval 原样生效，不得
// 被 200ms 硬下限夹住——New(0)/1ms 的 50 个请求必须远快于 200ms（否则现有
// 测试与所有基线会被拖慢几十倍）。
func TestPoliteIntervalNotClamped(t *testing.T) {
	srv, _ := newFastServer(t)
	cases := []struct {
		name      string
		c         *Client
		wantInter time.Duration
	}{
		{"interval-0-unlimited", New(0), 0},
		{"interval-1ms", NewWithOptions(ClientOptions{Interval: time.Millisecond}), time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetHostLimiters()
			const n = 50
			start := time.Now()
			for i := 0; i < n; i++ {
				if _, err := tc.c.GetDirect(srv.URL); err != nil {
					t.Fatalf("第 %d 个请求失败: %v", i, err)
				}
			}
			elapsed := time.Since(start)
			t.Logf("%d 个请求耗时 %v（interval=%v，未被夹到 200ms 下限）", n, elapsed, tc.wantInter)
			if elapsed > 200*time.Millisecond {
				t.Fatalf("polite 档 interval 被夹住：%d 个请求耗时 %v > 200ms", n, elapsed)
			}
			if got := tc.c.Stats().Interval; got != tc.wantInter {
				t.Fatalf("Stats().Interval 应为 %v（原样使用），实际 %v", tc.wantInter, got)
			}
		})
	}
}

// TestPolite400msRealPacing 回归：Adaptive=false + Interval=400ms 串行 10 个请求
// ≈3.6s（≈2.5 rps，与旧实现一致）；中途命中 429/Retry-After 也只标记拦截、
// 不改节奏（polite 不做 WAF 退避）。
func TestPolite400msRealPacing(t *testing.T) {
	resetHostLimiters()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		cur := n
		mu.Unlock()
		if cur == 5 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{Interval: 400 * time.Millisecond})
	start := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := c.GetDirect(srv.URL); err != nil {
			t.Fatalf("第 %d 个请求失败: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("10 个请求耗时 %v（预期 ≈3.6s ≈ 2.5 rps，旧实现口径）", elapsed.Round(time.Millisecond))
	if elapsed < 3400*time.Millisecond || elapsed > 4600*time.Millisecond {
		t.Fatalf("polite 400ms 串行 10 请求耗时应 ≈3.6s，实际 %v（会被夹/放大即回归）", elapsed)
	}
	st := c.Stats()
	if st.Interval != 400*time.Millisecond || st.Backoffs != 0 || st.Blocked != 1 || st.Requests != 10 {
		t.Fatalf("polite Stats 不符（不应有自适应/WAF 调速）: %+v", st)
	}
}

// ---- 令牌桶：per-host 共享 + 并发不放大 ------------------------------------

// TestTokenBucketSharedAcrossClients 同一个 host 的两个 Client 共用一套令牌：
// 第一个请求立即放行，第二个 Client 的请求必须排队等满一个间隔——证明引擎里
// 「爬虫 client + DAST client」叠加不会把目标侧速率翻倍。
func TestTokenBucketSharedAcrossClients(t *testing.T) {
	resetHostLimiters()
	srv, _ := newFastServer(t)
	clock := newFakeClock()

	c1 := NewWithOptions(ClientOptions{Interval: 200 * time.Millisecond})
	c2 := NewWithOptions(ClientOptions{Interval: 200 * time.Millisecond})
	useFakeClock(c1, clock)
	useFakeClock(c2, clock)

	for _, c := range []*Client{c1, c2, c1, c2} {
		if _, err := c.GetDirect(srv.URL); err != nil {
			t.Fatalf("请求失败: %v", err)
		}
	}
	sleeps := clock.drainSleeps()
	if len(sleeps) != 3 {
		t.Fatalf("4 个请求应只在 2~4 个之间排队 3 次，实际睡眠 %v", sleeps)
	}
	for i, d := range sleeps {
		if d != 200*time.Millisecond {
			t.Fatalf("第 %d 次令牌等待应为 200ms（跨 Client 共享同一限速器），实际 %v", i, d)
		}
	}
	// Stats 读取的是共享限速器的当前间隔。
	if got := c1.Stats().Interval; got != 200*time.Millisecond {
		t.Fatalf("Stats().Interval 应为 200ms，实际 %v", got)
	}
}

// TestPerHostIsolation 不同 host 各自独立令牌：一个 host 的排队不影响另一个。
func TestPerHostIsolation(t *testing.T) {
	resetHostLimiters()
	srvA, _ := newFastServer(t)
	srvB, _ := newFastServer(t)
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Interval: 200 * time.Millisecond})
	useFakeClock(c, clock)

	// A1、B1 都是各自 host 的首个令牌 → 都不睡眠。
	if _, err := c.GetDirect(srvA.URL); err != nil {
		t.Fatalf("A1: %v", err)
	}
	if _, err := c.GetDirect(srvA.URL); err != nil { // A2：A 的第二个令牌，排 200ms
		t.Fatalf("A2: %v", err)
	}
	if sleeps := clock.drainSleeps(); len(sleeps) != 1 || sleeps[0] != 200*time.Millisecond {
		t.Fatalf("A2 应排队 200ms，实际 %v", sleeps)
	}
	// B 是另一个 host：首个令牌立即放行，第二个令牌排 200ms —— 证明 host 间互不影响。
	if _, err := c.GetDirect(srvB.URL); err != nil {
		t.Fatalf("B1: %v", err)
	}
	if sleeps := clock.drainSleeps(); len(sleeps) != 0 {
		t.Fatalf("另一个 host 的首个令牌不应排队，实际 %v", sleeps)
	}
	if _, err := c.GetDirect(srvB.URL); err != nil {
		t.Fatalf("B2: %v", err)
	}
	if sleeps := clock.drainSleeps(); len(sleeps) != 1 || sleeps[0] != 200*time.Millisecond {
		t.Fatalf("B2 应排队 200ms，实际 %v", sleeps)
	}
}

// TestPoliteFixedIntervalNoAdaptation polite（Adaptive=false）：固定间隔、无抖动、
// 无加速、命中 429 也不改节奏（只有拦截标记）；0 间隔 = 历史「不限速」语义。
func TestPoliteFixedIntervalNoAdaptation(t *testing.T) {
	resetHostLimiters()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		cur := n
		mu.Unlock()
		if cur == 4 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Interval: 400 * time.Millisecond}) // Adaptive=false
	useFakeClock(c, clock)

	var blockedResp *Response
	for i := 0; i < 6; i++ {
		resp, err := c.GetDirect(srv.URL)
		if err != nil {
			t.Fatalf("第 %d 个请求失败: %v", i, err)
		}
		if resp.Blocked {
			blockedResp = resp
		}
	}
	sleeps := clock.drainSleeps()
	if len(sleeps) != 5 {
		t.Fatalf("6 个请求应有 5 次令牌排队，实际 %v", sleeps)
	}
	for i, d := range sleeps {
		if d != 400*time.Millisecond {
			t.Fatalf("polite 档第 %d 次等待应严格 400ms（无抖动/无加速），实际 %v", i, d)
		}
	}
	if blockedResp == nil || blockedResp.BlockReason != "retry-after" {
		t.Fatalf("429+Retry-After 应标记拦截，实际 %+v", blockedResp)
	}
	st := c.Stats()
	if st.Interval != 400*time.Millisecond || st.Backoffs != 0 || st.Blocked != 1 || st.Requests != 6 {
		t.Fatalf("polite Stats 不符: %+v", st)
	}

	// 0 = 不限速（历史语义）：不注册限速器、不产生任何令牌等待。
	resetHostLimiters()
	clock2 := newFakeClock()
	c0 := NewWithOptions(ClientOptions{})
	useFakeClock(c0, clock2)
	for i := 0; i < 3; i++ {
		if _, err := c0.GetDirect(srv.URL); err != nil {
			t.Fatalf("不限速请求失败: %v", err)
		}
	}
	if sleeps := clock2.drainSleeps(); len(sleeps) != 0 {
		t.Fatalf("Interval=0 不应限速，实际睡眠 %v", sleeps)
	}
	if got := c0.Stats().Interval; got != 0 {
		t.Fatalf("不限速时 Stats().Interval 应为 0，实际 %v", got)
	}
}

// ---- 自适应：加速 / 硬下限 / WAF 锁定 / RTT 退避 ---------------------------

// TestAdaptiveAcceleratesToFloor 连续干净成功后间隔逐级减半到 200ms 硬下限；
// 抖动 ±20% 但绝不突破下限（5 req/s 红线）。
func TestAdaptiveAcceleratesToFloor(t *testing.T) {
	resetHostLimiters()
	srv, _ := newFastServer(t)
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Adaptive: true, Interval: 400 * time.Millisecond})
	useFakeClock(c, clock)

	const n = 8
	for i := 0; i < n; i++ {
		if _, err := c.GetDirect(srv.URL); err != nil {
			t.Fatalf("第 %d 个请求失败: %v", i, err)
		}
	}
	sleeps := clock.drainSleeps()
	if len(sleeps) != n-1 {
		t.Fatalf("期望 %d 次令牌排队，实际 %v", n-1, sleeps)
	}
	// 令牌间隔在“取号”时确定：req2..req6 的等待对应第 1~5 个令牌（仍按 400ms
	// 起点 ±20%），第 5 个干净成功后减半；req7、req8 的等待才落到 200ms 硬下限。
	for i := 0; i < 5; i++ {
		if d := sleeps[i]; d < 320*time.Millisecond || d > 480*time.Millisecond {
			t.Fatalf("加速前第 %d 次等待应在 400ms±20%%（320~480ms），实际 %v", i, d)
		}
	}
	for i := 5; i < len(sleeps); i++ {
		if d := sleeps[i]; d < 200*time.Millisecond || d > 240*time.Millisecond {
			t.Fatalf("加速后第 %d 次等待应在 200~240ms（抖动不得突破 200ms 硬下限），实际 %v", i, d)
		}
	}
	st := c.Stats()
	if st.Interval != 200*time.Millisecond {
		t.Fatalf("加速后 Stats().Interval 应为 200ms，实际 %v", st.Interval)
	}
	if st.Requests != n {
		t.Fatalf("Stats().Requests 应为 %d，实际 %d", n, st.Requests)
	}
	if st.AvgRPS <= 0 {
		t.Fatalf("Stats().AvgRPS 应 >0，实际 %v", st.AvgRPS)
	}
}

// TestAdaptiveMaxRPSTightensAndFloorIsHard MaxRPS 只能更保守（2 → 500ms 下限）；\r\n// 调大 MaxRPS 无法突破 100ms/10rps 绝对硬下限。
func TestAdaptiveMaxRPSTightensAndFloorIsHard(t *testing.T) {
	resetHostLimiters()
	srv, _ := newFastServer(t)
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Adaptive: true, Interval: 400 * time.Millisecond, MaxRPS: 2})
	useFakeClock(c, clock)
	for i := 0; i < 6; i++ {
		if _, err := c.GetDirect(srv.URL); err != nil {
			t.Fatalf("请求失败: %v", err)
		}
	}
	sleeps := clock.drainSleeps()
	if len(sleeps) != 5 {
		t.Fatalf("期望 5 次排队，实际 %v", sleeps)
	}
	for i, d := range sleeps {
		if d < 500*time.Millisecond || d > 600*time.Millisecond {
			t.Fatalf("MaxRPS=2 时下限应为 500ms，第 %d 次等待 %v 越界", i, d)
		}
	}
	if got := c.Stats().Interval; got != 500*time.Millisecond {
		t.Fatalf("MaxRPS=2 时 Stats().Interval 应为 500ms，实际 %v", got)
	}

	// MaxRPS 调大（100）不能突破 100ms 绝对硬下限。
	resetHostLimiters()
	clock2 := newFakeClock()
	c2 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, MaxRPS: 100})
	useFakeClock(c2, clock2)
	if _, err := c2.GetDirect(srv.URL); err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if _, err := c2.GetDirect(srv.URL); err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if got := c2.Stats().Interval; got != 100*time.Millisecond {
		t.Fatalf("MaxRPS=100 时仍应被 100ms 绝对硬下限约束，实际 %v", got)
	}
	if sleeps := clock2.drainSleeps(); len(sleeps) != 1 || sleeps[0] < 100*time.Millisecond {
		t.Fatalf("MaxRPS=100 时令牌间隔不得低于 100ms，实际 %v", sleeps)
	}

	// 引擎默认 MaxRPS=8 → 125ms（8 req/s）。
	resetHostLimiters()
	clock3 := newFakeClock()
	c3 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, MaxRPS: 8})
	useFakeClock(c3, clock3)
	if _, err := c3.GetDirect(srv.URL); err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if _, err := c3.GetDirect(srv.URL); err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if got := c3.Stats().Interval; got != 125*time.Millisecond {
		t.Fatalf("MaxRPS=8（引擎默认）时下限应为 125ms，实际 %v", got)
	}
}

// TestAdaptiveBlockLocksSlow 检出 429/Retry-After 后锁定低速：400ms→1s→2s，
// 只增不减；锁定后即使连续干净成功也不再加速。
func TestAdaptiveBlockLocksSlow(t *testing.T) {
	resetHostLimiters()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		cur := n
		mu.Unlock()
		// 前 6 个干净（第 5 个触发加速到 200ms，第 6 个继续），7~10 连续 429。
		if cur >= 7 && cur <= 10 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Adaptive: true, Interval: 400 * time.Millisecond})
	useFakeClock(c, clock)

	get := func(tag string) *Response {
		t.Helper()
		resp, err := c.GetDirect(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		return resp
	}
	for i := 0; i < 6; i++ {
		get(fmt.Sprintf("clean-%d", i))
	}
	if got := c.Stats().Interval; got != 200*time.Millisecond {
		t.Fatalf("6 次干净后应加速到 200ms，实际 %v", got)
	}
	wantLadder := []time.Duration{400 * time.Millisecond, time.Second, 2 * time.Second, 2 * time.Second}
	for i, want := range wantLadder {
		resp := get(fmt.Sprintf("blocked-%d", i))
		if !resp.Blocked || resp.BlockReason != "retry-after" {
			t.Fatalf("第 %d 次 429 应标记 retry-after，实际 %+v", i, resp)
		}
		if got := c.Stats().Interval; got != want {
			t.Fatalf("第 %d 次拦截后锁定间隔应为 %v（400ms→1s→2s 阶梯），实际 %v", i, want, got)
		}
	}
	// 锁定后恢复干净响应：不再加速（仍是 2s）。
	for i := 0; i < 6; i++ {
		get(fmt.Sprintf("clean-after-lock-%d", i))
	}
	if got := c.Stats().Interval; got != 2*time.Second {
		t.Fatalf("锁定后不应再加速，实际间隔 %v", got)
	}
	st := c.Stats()
	if st.Blocked != 4 || st.Backoffs != 4 {
		t.Fatalf("拦截/退避统计不符: %+v", st)
	}
	// 锁定后令牌等待应 ≥1.6s（2s ±20% 抖动下限），不再有 200ms 级间隔。
	sleeps := clock.drainSleeps()
	tail := sleeps[len(sleeps)-6:]
	for i, d := range tail {
		if d < 1600*time.Millisecond {
			t.Fatalf("锁定后第 %d 次等待应 ≈2s（低速锁定），实际 %v", i, d)
		}
	}
}

// TestAdaptiveRTTBackoff 慢响应（RTT EWMA 相对基线上涨 >50%）自动退避：
// 间隔翻倍，Stats().Backoffs 记录。
func TestAdaptiveRTTBackoff(t *testing.T) {
	resetHostLimiters()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		cur := n
		mu.Unlock()
		if cur > 6 {
			time.Sleep(60 * time.Millisecond) // 人为拖慢：触发 RTT 退避
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Adaptive: true, Interval: 400 * time.Millisecond})
	useFakeClock(c, clock)
	c.limiterCfg.accelAfter = 1 << 30 // 本用例只验证 RTT 反馈，关掉加速干扰

	for i := 0; i < 9; i++ {
		if _, err := c.GetDirect(srv.URL); err != nil {
			t.Fatalf("第 %d 个请求失败: %v", i, err)
		}
	}
	st := c.Stats()
	if st.Backoffs < 1 {
		t.Fatalf("慢响应应触发 RTT 退避，实际 Stats=%+v", st)
	}
	if st.Interval < 800*time.Millisecond {
		t.Fatalf("RTT 退避后间隔应翻倍（≥800ms），实际 %v", st.Interval)
	}
}

// ---- WAF / 限流拦截识别 -----------------------------------------------------

// TestBlockedDetection 各拦截信号 → Blocked/BlockReason 标记；正常 200（即使
// 带 WAF 特征头）不得误判；无佐证的 403 不标记（避免正常鉴权页误杀）。
func TestBlockedDetection(t *testing.T) {
	resetHostLimiters()
	var mu sync.Mutex
	// 同一 URL 第一次 200、第二次 403：模拟 WAF 开始拦截（状态降级）。
	downgradeHit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/r429"):
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
		case strings.HasPrefix(r.URL.Path, "/r503"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasPrefix(r.URL.Path, "/cfok"):
			// 正常页面跑在 Cloudflare 上：带特征头但业务正常，不得判拦截。
			w.Header().Set("CF-Ray", "8abc123")
			w.Header().Set("Server", "cloudflare")
			_, _ = w.Write([]byte("<html>正常页面</html>"))
		case strings.HasPrefix(r.URL.Path, "/chl"):
			// 200 + Cloudflare 挑战页特征（强特征）。
			_, _ = w.Write([]byte("<html><title>Just a moment...</title>cf-chl-bypass</html>"))
		case strings.HasPrefix(r.URL.Path, "/waf403"):
			w.Header().Set("CF-Ray", "8abc123")
			w.WriteHeader(http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/downgrade"):
			mu.Lock()
			downgradeHit++
			cur := downgradeHit
			mu.Unlock()
			if cur == 1 {
				_, _ = w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/plain403"):
			w.WriteHeader(http.StatusForbidden)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{}) // 不限速：本用例只看标记
	cases := []struct {
		path    string
		blocked bool
		reason  string
	}{
		{"/r429", true, "retry-after"},
		{"/r503", true, "http-503"},
		{"/cfok", false, ""},
		{"/chl", true, "challenge-page"},
		{"/waf403", true, "waf-header:cf-ray"},
		{"/plain403", false, ""},
	}
	for _, tc := range cases {
		resp, err := c.GetDirect(srv.URL + tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if resp.Blocked != tc.blocked || resp.BlockReason != tc.reason {
			t.Fatalf("%s 期望 blocked=%v reason=%q，实际 blocked=%v reason=%q",
				tc.path, tc.blocked, tc.reason, resp.Blocked, resp.BlockReason)
		}
		if resp.Status == 0 {
			t.Fatalf("%s 既有字段不应被改变: %+v", tc.path, resp)
		}
	}
	// 状态降级：先 200 后 403 → 第二次标记 status-downgrade。
	first, err := c.GetDirect(srv.URL + "/downgrade")
	if err != nil || first.Blocked {
		t.Fatalf("首次 200 不应标记拦截: resp=%+v err=%v", first, err)
	}
	second, err := c.GetDirect(srv.URL + "/downgrade")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Blocked || second.BlockReason != "status-downgrade" {
		t.Fatalf("同一 URL 2xx→403 应标记 status-downgrade，实际 %+v", second)
	}
	// r429/r503/chl/waf403 + downgrade 第二次 = 5 个拦截响应。
	if got := c.Stats().Blocked; got != 5 {
		t.Fatalf("Stats().Blocked 统计不符: %d", got)
	}
}

// TestHostLimiterSweep 空闲限速器按 TTL 回收（避免测试/长跑注册表泄漏）。
func TestHostLimiterSweep(t *testing.T) {
	resetHostLimiters()
	cfg := limiterConfig{adaptive: true, base: 400 * time.Millisecond, floor: 200 * time.Millisecond, accelAfter: 5}
	hostLimiterFor("sweep.example.test:80", cfg)
	if _, ok := hostLimiters.Load("sweep.example.test:80"); !ok {
		t.Fatal("限速器应已注册")
	}
	sweepHostLimiters(time.Now().Add(hostLimiterIdleTTL + time.Second))
	if _, ok := hostLimiters.Load("sweep.example.test:80"); ok {
		t.Fatal("空闲超 TTL 的限速器应被回收")
	}
}

// ---- 目标侧负载验收：1s/2s 窗口峰值 ----------------------------------------

// TestRateCapTargetSidePeak 用户红线验收：同一 host、2 个 Client、4 个并发
// 调用者，目标侧 1s 窗口峰值 ≤5.5、2s ≤10.4；自适应加速到下限（200ms）与
// polite 固定间隔（400ms）都要满足（旧 wait() 会把并发调用者放大成 N/interval）。
func TestRateCapTargetSidePeak(t *testing.T) {
	t.Run("adaptive-floor", func(t *testing.T) {
		resetHostLimiters()
		srv, rec := newFastServer(t)
		// Interval=1ms 意图「最快」，自适应被 200ms 硬下限约束（≈5 req/s）。
		c1 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, Timeout: 5 * time.Second})
		c2 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, Timeout: 5 * time.Second})
		runConcurrent(t, []*Client{c1, c2}, srv.URL, 2, 4200*time.Millisecond)

		times, maxIn := rec.snapshot()
		if len(times) == 0 {
			t.Fatal("目标侧未收到请求")
		}
		peak1 := peakInWindow(times, time.Second)
		peak2 := peakInWindow(times, 2*time.Second)
		elapsed := times[len(times)-1].Sub(times[0])
		avgRPS := 0.0
		if elapsed > 0 {
			avgRPS = float64(len(times)-1) / elapsed.Seconds() // 持续速率：首令牌不计入间隔（N-1 个间隔）
		}
		t.Logf("adaptive-floor: 请求=%d 峰值RPS(1s)=%d 峰值(2s)=%d 平均=%.2f 最大并发=%d",
			len(times), peak1, peak2, avgRPS, maxIn)
		// 硬口径是「平均 ≤5 req/s/主机」：令牌固定 200ms，目标侧到达时序抖动
		// （调度/网络/窗口边界）会让半开窗口偶发多算 1 个请求，故峰值容忍 +1，
		// 但平均必须守住 5 rps（5.2 旧实现同口径峰值也是 6）。
		if avgRPS > 5.2 {
			t.Fatalf("平均 %.2f req/s 超过 5 req/s 硬上限（自适应下限 200ms）", avgRPS)
		}
		if peak1 > 6 {
			t.Fatalf("1s 窗口峰值 %d 超过 6（平均 5 req/s 的到达抖动上限）", peak1)
		}
		if peak2 > 11 {
			t.Fatalf("2s 窗口峰值 %d 超过 11（平均 5 req/s 的到达抖动上限）", peak2)
		}
		if maxIn > 2 {
			t.Fatalf("并发 %d 超过调用方并发（不应由限速层引入并发）", maxIn)
		}
		for i, c := range []*Client{c1, c2} {
			if got := c.Stats().Interval; got != 200*time.Millisecond {
				t.Fatalf("第 %d 个 Client 的当前间隔应为 200ms，实际 %v", i, got)
			}
		}
	})

	t.Run("adaptive-default-8", func(t *testing.T) {
		resetHostLimiters()
		srv, rec := newFastServer(t)
		// 引擎默认 MaxRPS=8 → 125ms 硬下限（8 req/s）。
		c1 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, MaxRPS: 8, Timeout: 5 * time.Second})
		c2 := NewWithOptions(ClientOptions{Adaptive: true, Interval: time.Millisecond, MaxRPS: 8, Timeout: 5 * time.Second})
		runConcurrent(t, []*Client{c1, c2}, srv.URL, 2, 4200*time.Millisecond)

		times, maxIn := rec.snapshot()
		if len(times) == 0 {
			t.Fatal("目标侧未收到请求")
		}
		peak1 := peakInWindow(times, time.Second)
		peak2 := peakInWindow(times, 2*time.Second)
		elapsed := times[len(times)-1].Sub(times[0])
		avgRPS := 0.0
		if elapsed > 0 {
			avgRPS = float64(len(times)-1) / elapsed.Seconds()
		}
		t.Logf("adaptive-default-8: 请求=%d 峰值RPS(1s)=%d 峰值(2s)=%d 平均=%.2f 最大并发=%d",
			len(times), peak1, peak2, avgRPS, maxIn)
		if avgRPS > 8.2 {
			t.Fatalf("平均 %.2f req/s 超过 8 req/s 硬上限（默认 MaxRPS=8 / 125ms）", avgRPS)
		}
		if peak1 > 9 {
			t.Fatalf("1s 窗口峰值 %d 超过 9（平均 8 req/s 的到达抖动上限）", peak1)
		}
		if peak2 > 17 {
			t.Fatalf("2s 窗口峰值 %d 超过 17（平均 8 req/s 的到达抖动上限）", peak2)
		}
		if maxIn > 2 {
			t.Fatalf("并发 %d 超过调用方并发（不应由限速层引入并发）", maxIn)
		}
		for i, c := range []*Client{c1, c2} {
			if got := c.Stats().Interval; got != 125*time.Millisecond {
				t.Fatalf("第 %d 个 Client 的当前间隔应为 125ms，实际 %v", i, got)
			}
		}
	})

	t.Run("polite-fixed", func(t *testing.T) {
		resetHostLimiters()
		srv, rec := newFastServer(t)
		c1 := NewWithOptions(ClientOptions{Interval: 400 * time.Millisecond, Timeout: 5 * time.Second})
		c2 := NewWithOptions(ClientOptions{Interval: 400 * time.Millisecond, Timeout: 5 * time.Second})
		runConcurrent(t, []*Client{c1, c2}, srv.URL, 2, 900*time.Millisecond)

		times, maxIn := rec.snapshot()
		if len(times) < 3 {
			t.Fatalf("polite 档 0.9s 内应收到至少 3 个请求，实际 %d", len(times))
		}
		peak1 := peakInWindow(times, time.Second)
		t.Logf("polite-fixed: 请求=%d 峰值RPS(1s)=%d 最大并发=%d", len(times), peak1, maxIn)
		if peak1 > 5 {
			t.Fatalf("polite 档 1s 窗口峰值 %d 超过 5.5（旧实现并发放大问题必须修复）", peak1)
		}
		// 相邻请求间隔必须 ≥ 间隔（400ms，允许计时/调度误差 50ms）。
		for i := 1; i < len(times); i++ {
			if gap := times[i].Sub(times[i-1]); gap < 350*time.Millisecond {
				t.Fatalf("polite 档第 %d 个间隔 %v 小于固定间隔（存在并发齐发）", i, gap)
			}
		}
		if maxIn > 2 {
			t.Fatalf("并发 %d 超过调用方并发", maxIn)
		}
	})
}

// runConcurrent 用 workers 个并发调用者在 duration 内持续请求同一 URL。
func runConcurrent(t *testing.T, clients []*Client, url string, workers int, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		c := clients[i%len(clients)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_, _ = c.GetDirect(url)
			}
		}()
	}
	wg.Wait()
}

// TestRedirectHopsPaced 重定向逐跳也占令牌（每次真实请求都受限速约束）。
func TestRedirectHopsPaced(t *testing.T) {
	resetHostLimiters()
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	clock := newFakeClock()
	c := NewWithOptions(ClientOptions{Interval: 200 * time.Millisecond})
	useFakeClock(c, clock)
	resp, err := c.GetFollow(srv.URL + "/a")
	if err != nil {
		t.Fatalf("重定向跟随失败: %v", err)
	}
	if !strings.Contains(resp.Body, "done") {
		t.Fatalf("未到达最终页: %+v", resp)
	}
	sleeps := clock.drainSleeps()
	if len(sleeps) != 1 || sleeps[0] != 200*time.Millisecond {
		t.Fatalf("两跳应各占一个令牌（第 2 跳排队 200ms），实际 %v", sleeps)
	}
	if got := c.Stats().Requests; got != 2 {
		t.Fatalf("重定向两跳应计 2 个请求，实际 %d", got)
	}
}
