// httpx 客户端测试：重定向逐跳校验的 resolve 姿态、Cookie 透传。
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// TestRedirectFollowLocalDefault 默认姿态（resolve=false，本地靶场矩阵
// 用途）：回环目标的重定向正常跟随——修复前逐跳校验写死 resolve=true，
// 私网/回行目标一跳就被 SSRF 拦截。
func TestRedirectFollowLocalDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(0)
	resp, err := c.GetFollow(srv.URL + "/a")
	if err != nil {
		t.Fatalf("回环重定向应正常跟随: %v", err)
	}
	if !strings.Contains(resp.Body, "done") {
		t.Fatalf("未到达最终页: %+v", resp)
	}
}

// TestRedirectSSRFBlockOnResolve resolve=true（公网默认）时回环重定向
// 目标必须被拦截——防公网目标重定向进内网的 SSRF。
func TestRedirectSSRFBlockOnResolve(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewWithOptions(ClientOptions{Resolve: true})
	if _, err := c.GetFollow(srv.URL + "/a"); err == nil {
		t.Fatal("resolve=true 时回环重定向目标应被拦截")
	}
}

// TestAuthCookiePassthrough 授权 Cookie 附加到每个请求。
func TestAuthCookiePassthrough(t *testing.T) {
	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewWithOptions(ClientOptions{AuthCookie: "security=low; PHPSESSID=abc"})
	if _, err := c.GetFollow(srv.URL); err != nil {
		t.Fatal(err)
	}
	if seen != "security=low; PHPSESSID=abc" {
		t.Fatalf("Cookie 未透传: %q", seen)
	}
}

// TestRedirectHopsReleaseBodies BUG-008 验收：重定向中间跳的 resp.Body 必须
// 排空并关闭。5 跳重定向连续请求后：不应为每一跳新建连接（连接复用），
// goroutine 也不应随请求轮次增长（泄漏实现下每跳残留一个 readLoop）。
func TestRedirectHopsReleaseBodies(t *testing.T) {
	var mu sync.Mutex
	newConns := 0

	mux := http.NewServeMux()
	for i := 0; i < 5; i++ {
		i := i
		mux.HandleFunc(fmt.Sprintf("/r%d", i), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("/r%d", i+1), http.StatusFound)
		})
	}
	mux.HandleFunc("/r5", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("done"))
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			mu.Lock()
			newConns++
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()

	c := New(0)
	// 预热一条 keep-alive 连接，基线连接数/goroutine 数都从稳态起算。
	resp, err := c.GetFollow(srv.URL + "/r0")
	if err != nil || !strings.Contains(resp.Body, "done") {
		t.Fatalf("预热请求失败: resp=%+v err=%v", resp, err)
	}
	mu.Lock()
	baseConns := newConns
	mu.Unlock()
	baseGoroutines := runtime.NumGoroutine()

	const rounds = 8
	for i := 0; i < rounds; i++ {
		r, ferr := c.GetFollow(srv.URL + "/r0")
		if ferr != nil || !strings.Contains(r.Body, "done") {
			t.Fatalf("第 %d 轮重定向跟随失败: resp=%+v err=%v", i, r, ferr)
		}
	}

	mu.Lock()
	got := newConns - baseConns
	mu.Unlock()
	// 正确实现：中间跳 body 排空关闭 → 5 跳全部复用同一条连接，新增连接 0。
	// 允许 1 条余量（transport 在空闲连接竞态下偶尔重建），但绝不能随跳数增长。
	if got > 1 {
		t.Fatalf("%d 轮 × 5 跳重定向后新增连接 %d 条（中间跳 body 未排空关闭 → 每跳新建连接）",
			rounds, got)
	}

	// goroutine 不增长：泄漏实现下每跳残留 readLoop，会到 40+。
	deadline := time.Now().Add(2 * time.Second)
	for {
		now := runtime.NumGoroutine()
		if now <= baseGoroutines+4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("重定向后 goroutine 增长到 %d（基线 %d）：中间跳响应体未关闭导致 readLoop 泄漏",
				now, baseGoroutines)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---- BUG-021：DNS 重绑定防护 ----------------------------------------------
//
// 旧链路的漏洞：ensurePublicHost / target.Validate 用系统解析器校验后即丢弃
// 结果，实际拨号由 http.Transport 再次调用系统解析器 → 两次 DNS 查询之间
// 目标可用 TTL≈0 的重绑定把「校验时的公网 IP」换成「拨号时的内网 IP」。
// 新链路在 DialContext 里一次解析、全量校验、按已校验 IP 字面量拨号。
//
// 测试手法：用系统解析不了的 .invalid 域名 + 注入解析器（c.lookupIP），
// 能连上就说明拨号目标是「解析出来并被校验过的那份 IP」，而不是二次解析
// 的结果；同时断言 Host 头保持原域名（Host/SNI 语义不变）。

// testServerPort 取 httptest 服务的端口。
func testServerPort(t *testing.T, srvURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v（%s）", err, srvURL)
	}
	return port
}

// TestDialContextDialsValidatedIPKeepHost 拨号目标是已解析/已校验的 IP，
// 且 Host 头仍是原域名（只改底层地址，不改请求身份）。
func TestDialContextDialsValidatedIPKeepHost(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true) // 授权靶场姿态：允许连回环
	defer target.SetAllowPrivate(old)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Host)) // 回显 Host 供断言
	}))
	defer srv.Close()
	port := testServerPort(t, srv.URL)

	var mu sync.Mutex
	var looked []string
	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		looked = append(looked, host)
		mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	// rebind-a.invalid 系统解析必然失败：能连通说明拨的是注入的已解析 IP。
	const hostName = "rebind-a.invalid"
	resp, err := c.GetDirect("http://" + hostName + ":" + port + "/x")
	if err != nil {
		t.Fatalf("应按已解析 IP 拨通（%s → 127.0.0.1）：%v", hostName, err)
	}
	gotHost, _, herr := net.SplitHostPort(resp.Body)
	if herr != nil || gotHost != hostName {
		t.Fatalf("Host 头应保留原域名 %q，实际 %q（err=%v）", hostName, resp.Body, herr)
	}

	mu.Lock()
	n := len(looked)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("每次建连应只解析一次，实际 %d 次：%v", n, looked)
	}
}

// TestDialContextRedirectEachHopValidated 重定向逐跳同样走「解析→校验→拨号」：
// 两种不同（系统解析不了的）域名各触发一次注入解析，且每一跳都按解析 IP 连。
func TestDialContextRedirectEachHopValidated(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true)
	defer target.SetAllowPrivate(old)

	var mu sync.Mutex
	var looked, hosts []string
	var port string
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://rebind-b.invalid:"+port+"/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	port = testServerPort(t, srv.URL)

	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		looked = append(looked, host)
		mu.Unlock()
		if !strings.HasSuffix(host, ".invalid") {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	resp, err := c.GetFollow("http://rebind-a.invalid:" + port + "/a")
	if err != nil {
		t.Fatalf("重定向应逐跳按已解析 IP 跟随：%v", err)
	}
	if !strings.Contains(resp.Body, "ok") {
		t.Fatalf("未到达最终页：%+v", resp)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(looked) != 2 {
		t.Fatalf("两跳两个域名应各解析一次，实际 %v", looked)
	}
	if len(hosts) != 1 || hosts[0] != "rebind-b.invalid:"+port {
		t.Fatalf("重定向后 Host 头应保持目标域名，实际 %v", hosts)
	}
}

// TestDialContextRejectsPrivateLiteralTarget resolve=true 时字面私网/回环 IP
// 必须在拨号层被拒——旧链路 GetDirect 完全不过校验，回环 IP 会被直接连上。
func TestDialContextRejectsPrivateLiteralTarget(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(false)
	defer target.SetAllowPrivate(old)

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("secret"))
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{Resolve: true})
	if _, err := c.GetDirect(srv.URL + "/meta"); err == nil {
		t.Fatal("resolve=true 时回环字面 IP 必须被拨号层拒绝（SSRF 闸）")
	}
	if reached.Load() {
		t.Fatal("被拒目标不应收到连接")
	}
}

// TestDialContextRejectsPrivateResolvedDomain 域名解析结果落在私网/保留段时
// 拨号层必须拒绝（模拟 DNS 重绑定后的私网答案）；答案集合混入私网时整体
// 拒绝——不能挑一个合规 IP 去拨。
func TestDialContextRejectsPrivateResolvedDomain(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(false)
	defer target.SetAllowPrivate(old)

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("secret"))
	}))
	defer srv.Close()
	port := testServerPort(t, srv.URL)

	c := NewWithOptions(ClientOptions{Resolve: true, Timeout: 2 * time.Second})
	// 重绑定后的答案：私网回环。
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := c.GetDirect("http://rebind.invalid:" + port + "/x"); err == nil {
		t.Fatal("解析到内网/保留地址必须拒绝")
	}
	if reached.Load() {
		t.Fatal("被拒目标不应收到连接")
	}

	// 混合答案：含公网地址也必须整体拒绝（宁少报，不给重绑定留可用路径）。
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.9"), // TEST-NET-3：本身合规
			netip.MustParseAddr("127.0.0.1"),   // 混入私网 → 整体拒绝
		}, nil
	}
	if _, err := c.GetDirect("http://rebind.invalid:" + port + "/x"); err == nil {
		t.Fatal("解析答案混入私网地址时必须整体拒绝")
	}
	if reached.Load() {
		t.Fatal("混合答案不应拨出任何连接")
	}
}

// ---- 5.2 性能优化：拨号层轻量 Happy Eyeballs（RFC 8305） --------------------
//
// 回归背景：BUG-021 的初版修法为了消除 DNS 重绑定窗口，对已校验 IP 串行
// 拨号，丢失了 Go 默认 Transport 的 Happy Eyeballs。多 A 记录 / IPv6 黑洞
// 场景下首个地址拒绝或丢包会把请求一路拖到超时（每地址最长 30s）。
//
// 测试手法：拨号动作已抽成可注入的 c.dial（生产 nil = baseDialer），用 fake
// 拨号器精确控制「哪个地址何时成功/黑洞」，不依赖真实网络、无公网。
// 所有耗时断言都留 ≥8 倍余量，-count=5 不抖动。

// stubAddr / stubConn 单次拨号返回的占位连接：只关心 Close 状态与身份，
// 不承载真实 IO（Happy Eyeballs 调度与 HTTP 报文无关）。
type stubAddr struct{}

func (stubAddr) Network() string { return "tcp" }
func (stubAddr) String() string  { return "stub" }

type stubConn struct{ closed atomic.Bool }

func (c *stubConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *stubConn) Close() error                { c.closed.Store(true); return nil }
func (c *stubConn) LocalAddr() net.Addr         { return stubAddr{} }
func (c *stubConn) RemoteAddr() net.Addr        { return stubAddr{} }
func (c *stubConn) SetDeadline(time.Time) error { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func addrStrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}

// TestDialCandidatesInterleaveAndCap 候选序：IPv6/IPv4 交错（首选族取首个解析
// 结果）、单族原序、交错后再截断到 maxDialAddrs（避免一长串同族地址把另一族
// 全挤出窗口）。
func TestDialCandidatesInterleaveAndCap(t *testing.T) {
	v4 := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i)) }
	v6 := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", i)) }

	cases := []struct {
		name string
		in   []netip.Addr
		want string
	}{
		{"空输入", nil, ""},
		{"单地址", []netip.Addr{v4(1)}, "203.0.113.1"},
		{"单族保持原序", []netip.Addr{v4(1), v4(2), v4(3)}, "203.0.113.1,203.0.113.2,203.0.113.3"},
		{
			"v6 优先交错",
			[]netip.Addr{v6(1), v4(1), v6(2), v4(2)},
			"2001:db8::1,203.0.113.1,2001:db8::2,203.0.113.2",
		},
		{
			"v4 优先交错",
			[]netip.Addr{v4(1), v6(1), v4(2), v6(2)},
			"203.0.113.1,2001:db8::1,203.0.113.2,2001:db8::2",
		},
		{
			// v6 全在前 + 两族各 6 条：先交错再截断 → 未截断时会只剩 v6。
			"交错后截断到上限",
			[]netip.Addr{v6(1), v6(2), v6(3), v6(4), v6(5), v6(6),
				v4(1), v4(2), v4(3), v4(4), v4(5), v4(6)},
			"2001:db8::1,203.0.113.1,2001:db8::2,203.0.113.2," +
				"2001:db8::3,203.0.113.3,2001:db8::4,203.0.113.4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := addrStrs(dialCandidates(tc.in)); got != tc.want {
				t.Fatalf("候选序不符\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestHappyEyeballsBlackholeFirstIP 验收①：首候选地址黑洞、次候选可用时，
// 必须在 ~stagger 后连上第二个地址，而不是等首地址超时。
//
// 同时验收②：落败尝试（黑洞那个）必须收到取消并及时退出（不泄漏 goroutine）；
// 胜者连接被原样返回。
func TestHappyEyeballsBlackholeFirstIP(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true)
	defer target.SetAllowPrivate(old)

	const (
		blackholeIP = "203.0.113.9"
		goodIP      = "198.51.100.7"
	)
	var (
		mu          sync.Mutex
		dials       []string
		cancelOnce  sync.Once
		blackholeCh = make(chan struct{})
		goodConn    = &stubConn{}
		goodDials   atomic.Int32
	)
	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr(blackholeIP),
			netip.MustParseAddr(goodIP),
		}, nil
	}
	c.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		mu.Lock()
		dials = append(dials, host)
		mu.Unlock()
		if host == goodIP {
			goodDials.Add(1)
			return goodConn, nil
		}
		<-ctx.Done() // 黑洞：真实网络里会挂到 30s 拨号超时 / ctx 超时
		cancelOnce.Do(func() { close(blackholeCh) })
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseGoroutines := runtime.NumGoroutine()
	start := time.Now()
	conn, err := c.dialContext(ctx, "tcp", net.JoinHostPort("he-blackhole.invalid", "443"))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("次候选可用时应在 stagger 后连上，实际失败（耗时 %v）：%v", elapsed, err)
	}
	if conn != goodConn {
		t.Fatalf("返回的连接应来自可用地址 %s", goodIP)
	}
	if goodDials.Load() != 1 {
		t.Fatalf("可用地址应只拨一次，实际 %d 次", goodDials.Load())
	}
	// 上界：远小于黑洞地址挂满 ctx/30s 的串行实现（本机无网络、仅 fake 拨号，
	// 留 12 倍余量防 CI/并发构建下的调度抖动）。
	if elapsed > 3*time.Second {
		t.Fatalf("黑洞首地址把拨号拖了 %v（应 ≈ stagger %v + 握手）：仍是串行拨号",
			elapsed, happyEyeballsStagger)
	}
	// 下界：第二个尝试必须错峰（不是同时发起）——完成后才启动/立即发起都会小于 100ms。
	if elapsed < 100*time.Millisecond {
		t.Fatalf("次尝试在 %v 就绪，早于 stagger %v：未按 RFC 8305 错峰",
			elapsed, happyEyeballsStagger)
	}
	// 落败的黑洞尝试必须被取消（否则它要挂到 ctx 超时，每个请求泄漏一条连接）。
	select {
	case <-blackholeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("黑洞首地址的尝试未被取消：胜者未 cancel 其余尝试 → goroutine/连接泄漏")
	}
	// 取消传导后尝试 goroutine 应回落（轮询给调度器一点时间，容忍 4 个余量）。
	deadline := time.Now().Add(2 * time.Second)
	for {
		if n := runtime.NumGoroutine(); n <= baseGoroutines+4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("拨号结束后 goroutine 为 %d（基线 %d）：尝试 goroutine 泄漏",
				runtime.NumGoroutine(), baseGoroutines)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dials) != 2 || dials[0] != blackholeIP || dials[1] != goodIP {
		t.Fatalf("拨号顺序应是「首地址先试、stagger 后追加次地址」，实际 %v", dials)
	}
}

// TestHappyEyeballsSingleIPFastPath 验收③：单地址正常路径不变——只拨一次、
// 不等 stagger、成功连接原样返回。
func TestHappyEyeballsSingleIPFastPath(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true)
	defer target.SetAllowPrivate(old)

	want := &stubConn{}
	var calls atomic.Int32
	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return want, nil
	}

	start := time.Now()
	conn, err := c.dialContext(context.Background(), "tcp", "single.invalid:80")
	elapsed := time.Since(start)
	if err != nil || conn != want {
		t.Fatalf("单地址正常拨号失败：conn=%v err=%v", conn, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("单地址应只拨一次，实际 %d 次", calls.Load())
	}
	if elapsed > 2*happyEyeballsStagger {
		t.Fatalf("单地址不应有 stagger 等待，实际耗时 %v", elapsed)
	}
}

// TestHappyEyeballsAllFailReturnsLastAddrError 全部地址失败：返回候选序最靠后
// 地址的真实错误（保留串行实现的 lastErr 语义），并在 ctx 到期前结束。
func TestHappyEyeballsAllFailReturnsLastAddrError(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true)
	defer target.SetAllowPrivate(old)

	const (
		firstIP  = "203.0.113.9"
		secondIP = "203.0.113.10"
	)
	errFirst := errors.New("dial 203.0.113.9: connection refused")
	errSecond := errors.New("dial 203.0.113.10: connection refused")
	var calls atomic.Int32
	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(firstIP), netip.MustParseAddr(secondIP)}, nil
	}
	c.dial = func(_ context.Context, _ string, addr string) (net.Conn, error) {
		calls.Add(1)
		switch host, _, _ := net.SplitHostPort(addr); host {
		case firstIP:
			return nil, errFirst
		case secondIP:
			return nil, errSecond
		default:
			return nil, fmt.Errorf("unexpected addr %q", addr)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := c.dialContext(ctx, "tcp", "he-allfail.invalid:443")
	elapsed := time.Since(start)
	if conn != nil {
		t.Fatal("全部地址失败时不应返回连接")
	}
	if !errors.Is(err, errSecond) {
		t.Fatalf("应返回候选序最靠后地址的错误 %v，实际 %v", errSecond, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("两个候选地址都应尝试，实际 %d 次", calls.Load())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("全部失败应收敛于 stagger 级别，实际耗时 %v", elapsed)
	}
}

// TestHappyEyeballsValidatesAllBeforeDial SSRF 语义不变：解析结果混入私网
// 地址时必须整体拒绝，且一个连接都不发——并行握手只能拨「已校验 IP」，
// 不能借并行去挑一个合规地址先连（那正是 BUG-021 要堵的重绑定路径）。
func TestHappyEyeballsValidatesAllBeforeDial(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(false)
	defer target.SetAllowPrivate(old)

	var calls atomic.Int32
	c := NewWithOptions(ClientOptions{Resolve: true})
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.9"), // 合规
			netip.MustParseAddr("127.0.0.1"),   // 私网 → 整体拒绝
		}, nil
	}
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return &stubConn{}, nil
	}
	if _, err := c.dialContext(context.Background(), "tcp", "mixed.invalid:443"); err == nil {
		t.Fatal("解析结果混入私网地址时必须整体拒绝")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("全量校验未通过时不应发起任何拨号，实际 %d 次", n)
	}
}

// TestResolveFalsePathUnchanged resolve=false（本地/内网靶场矩阵）路径必须
// 完全不变：直接交给 baseDialer，不解析、不走 Happy Eyeballs 层。
func TestResolveFalsePathUnchanged(t *testing.T) {
	var injected atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(0) // New 默认 Resolve=false
	c.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		injected.Store(true)
		return nil, errors.New("resolve=false 不应走并发拨号层")
	}
	resp, err := c.GetDirect(srv.URL + "/x")
	if err != nil {
		t.Fatalf("resolve=false 时回环请求应直接由 baseDialer 建连：%v", err)
	}
	if resp.Body != "ok" {
		t.Fatalf("响应体不符：%q", resp.Body)
	}
	if injected.Load() {
		t.Fatal("resolve=false 路径被改道到 Happy Eyeballs 拨号层")
	}
}

// TestHappyEyeballsThroughHTTPClient 端到端：resolve=true 时多地址解析结果经
// transport 拨号，黑洞首地址不拖慢请求；Host 头仍由 Transport 按域名生成。
func TestHappyEyeballsThroughHTTPClient(t *testing.T) {
	old := target.AllowPrivate()
	target.SetAllowPrivate(true)
	defer target.SetAllowPrivate(old)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Host)) // 回显 Host 供断言
	}))
	defer srv.Close()
	port := testServerPort(t, srv.URL)

	var calls atomic.Int32
	c := NewWithOptions(ClientOptions{Resolve: true, Timeout: 5 * time.Second})
	c.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.9"), // 黑洞首地址（文档段，合法）
			netip.MustParseAddr("127.0.0.1"),   // 真实可达（授权靶场姿态）
		}, nil
	}
	c.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		if host, _, _ := net.SplitHostPort(addr); host == "127.0.0.1" {
			return baseDialer.DialContext(ctx, network, addr)
		}
		<-ctx.Done() // 黑洞
		return nil, ctx.Err()
	}

	const hostName = "he-e2e.invalid"
	start := time.Now()
	resp, err := c.GetDirect("http://" + hostName + ":" + port + "/x")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("黑洞首地址不应拖垮请求（耗时 %v）：%v", elapsed, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("黑洞首地址把请求拖了 %v（应 ≈ stagger %v）", elapsed, happyEyeballsStagger)
	}
	if gotHost, _, herr := net.SplitHostPort(resp.Body); herr != nil || gotHost != hostName {
		t.Fatalf("Host 头应保留原域名 %q，实际 %q（err=%v）", hostName, resp.Body, herr)
	}
	if calls.Load() != 2 {
		t.Fatalf("应恰好尝试黑洞地址与可达地址各一次，实际 %d 次", calls.Load())
	}
}
