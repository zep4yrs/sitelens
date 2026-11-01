package protochk

// G10-1 WebSocket 检查测试：RFC 6455 Accept 计算、101 握手、伪造 Origin 被拒/
// 被接受、匿名基线、错误 Accept、无效 URL。用 httptest 起真实握手服务端。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsServerOpts 控制测试用 WebSocket 服务端的闸门行为。
type wsServerOpts struct {
	allowOrigin    string // 非空：要求 Origin == allowOrigin
	acceptNoOrigin bool   // allowOrigin 非空时，额外接受「无 Origin」的握手（模拟只校验非空 Origin）
	wrongAccept    bool   // 返回错误的 Sec-WebSocket-Accept
	requireCookie  bool   // 无 Cookie 时 401
}

// newWSServer 起一个真实完成 101 握手的测试服务端（http 或 https）。
func newWSServer(t *testing.T, tlsSrv bool, opts wsServerOpts) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.requireCookie && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if opts.allowOrigin != "" {
			origin := r.Header.Get("Origin")
			if origin != opts.allowOrigin && !(opts.acceptNoOrigin && origin == "") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accept := wsAccept(key)
		if opts.wrongAccept {
			accept = "wrong-accept-value"
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: "+accept+"\r\n\r\n")
	})
	if tlsSrv {
		srv := httptest.NewTLSServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// wsURL 把 httptest 服务端 URL 换成 ws/wss 形式。
func wsURL(srv *httptest.Server, tlsSrv bool) string {
	if tlsSrv {
		return "wss" + strings.TrimPrefix(srv.URL, "https")
	}
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func wsFindingKinds(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func TestWSAcceptRFC6455Vector(t *testing.T) {
	// RFC 6455 §1.3 官方示例：Key → Accept。
	got := wsAccept("dGhlIHNhbXBsZSBub25jZQ==")
	if got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("Sec-WebSocket-Accept 计算错误：%q", got)
	}
}

func TestCheckWebSocketCleartextAnonymousForgedOrigin(t *testing.T) {
	srv := newWSServer(t, false, wsServerOpts{})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, false), Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	kinds := wsFindingKinds(fs)
	for _, want := range []string{KindCleartextWS, KindWSNoAuth, KindOriginNotChecked} {
		if !containsKind(kinds, want) {
			t.Fatalf("缺少 %s，实得 %v", want, kinds)
		}
	}
	// 每条 Finding 应带 URL/Detail/Severity，便于落库。
	for _, f := range fs {
		if f.URL == "" || f.Detail == "" || f.Severity == "" {
			t.Fatalf("Finding 字段不完整：%+v", f)
		}
	}
}

func TestCheckWebSocketWSSAccepted(t *testing.T) {
	srv := newWSServer(t, true, wsServerOpts{})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, true), Options{Insecure: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	kinds := wsFindingKinds(fs)
	if containsKind(kinds, KindCleartextWS) {
		t.Fatalf("wss 不应报 cleartext-ws：%v", kinds)
	}
	if !containsKind(kinds, KindWSNoAuth) || !containsKind(kinds, KindOriginNotChecked) {
		t.Fatalf("应报 ws-no-auth + origin-not-checked，实得 %v", kinds)
	}
}

func TestCheckWebSocketOriginRejectedFallsBackToAnonymous(t *testing.T) {
	// 服务端校验非空 Origin（接受空 Origin），伪造 Origin 会被 403。
	srv := newWSServer(t, false, wsServerOpts{allowOrigin: "https://app.example", acceptNoOrigin: true})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, false), Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	kinds := wsFindingKinds(fs)
	if containsKind(kinds, KindOriginNotChecked) {
		t.Fatalf("Origin 有校验时不应报 origin-not-checked：%v", kinds)
	}
	if !containsKind(kinds, KindWSNoAuth) {
		t.Fatalf("无 Origin 匿名握手被接受时应收敛报 ws-no-auth：%v", kinds)
	}
}

func TestCheckWebSocketFullyRejected(t *testing.T) {
	srv := newWSServer(t, false, wsServerOpts{allowOrigin: "https://app.example"})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, false), Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	// ws:// 的明文项与握手无关，仍应保留；握手失败不得产出 ws 结论。
	for _, f := range fs {
		if f.Kind == KindWSNoAuth || f.Kind == KindOriginNotChecked {
			t.Fatalf("握手被拒时不应报 ws 相关 Finding：%+v", fs)
		}
	}
}

func TestCheckWebSocketWrongAccept(t *testing.T) {
	srv := newWSServer(t, false, wsServerOpts{wrongAccept: true})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, false), Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	for _, f := range fs {
		if f.Kind == KindWSNoAuth || f.Kind == KindOriginNotChecked {
			t.Fatalf("Accept 校验失败时不应报 ws 握手结论：%+v", fs)
		}
	}
}

func TestCheckWebSocketRequiresCookie(t *testing.T) {
	srv := newWSServer(t, false, wsServerOpts{requireCookie: true})
	fs, err := CheckWebSocket(context.Background(), wsURL(srv, false), Options{})
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	for _, f := range fs {
		if f.Kind == KindWSNoAuth {
			t.Fatalf("带鉴权的服务端不应误报 ws-no-auth：%+v", fs)
		}
	}
}

func TestCheckWebSocketInvalidInput(t *testing.T) {
	if _, err := CheckWebSocket(context.Background(), "https://example.com", Options{}); err == nil {
		t.Fatal("非 ws/wss URL 应报错")
	}
	if _, err := CheckWebSocket(context.Background(), "not a url", Options{}); err == nil {
		t.Fatal("非法 URL 应报错")
	}
	if _, err := Check(context.Background(), "ftp://example.com", Options{}); err == nil {
		t.Fatal("不支持的 scheme 应报错")
	}
}

func TestCheckDispatch(t *testing.T) {
	srv := newWSServer(t, false, wsServerOpts{})
	fs, err := Check(context.Background(), wsURL(srv, false), Options{})
	if err != nil || len(fs) == 0 {
		t.Fatalf("Check 应分派到 WebSocket 检查：fs=%+v err=%v", fs, err)
	}
	if fs[0].Kind != KindCleartextWS {
		t.Fatalf("ws URL 首个 Finding 应为 cleartext-ws：%+v", fs)
	}
}

// containsKind 判断 Finding 列表是否含指定 kind。
func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
