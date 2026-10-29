// httpx 客户端测试：重定向逐跳校验的 resolve 姿态、Cookie 透传。
package httpx

import (
	"context"
	"fmt"
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
