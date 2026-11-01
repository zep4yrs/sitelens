// CP-02 回归：httpx.Client.SetHeader 持久请求头（additive）。
package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSetHeaderInjected 持久头注入到每个请求；同名覆盖；空头名忽略；
// 默认 UA/Accept 不受影响。
func TestSetHeaderInjected(t *testing.T) {
	var gotXKey, gotUA, gotAccept, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXKey = r.Header.Get("X-Api-Key")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{})
	c.SetHeader("X-Api-Key", "first")
	c.SetHeader("X-Api-Key", "second") // 覆盖
	c.SetHeader("", "ignored")         // 空头名忽略（不 panic）
	if _, err := c.GetFollow(srv.URL); err != nil {
		t.Fatal(err)
	}
	if gotXKey != "second" {
		t.Fatalf("持久头未注入/覆盖失败：%q", gotXKey)
	}
	if gotUA == "" || gotAccept == "" {
		t.Fatalf("默认 UA/Accept 被破坏：ua=%q accept=%q", gotUA, gotAccept)
	}
	if gotCookie != "" {
		t.Fatalf("未设置 Cookie 时不应注入：%q", gotCookie)
	}
}

// TestSetHeaderOverridesCookie 认证矩阵注入的 Cookie 头覆盖既有 AuthCookie
// （同名头最后应用，认证注入优先）。
func TestSetHeaderOverridesCookie(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{AuthCookie: "a=1"})
	c.SetHeader("Cookie", "b=2")
	if _, err := c.GetFollow(srv.URL); err != nil {
		t.Fatal(err)
	}
	if got != "b=2" {
		t.Fatalf("Cookie 头 = %q，期望 b=2", got)
	}
}

// TestNoExtraHeadersDefault 未调用 SetHeader 时行为与旧版一致（无附加头）。
func TestNoExtraHeadersDefault(t *testing.T) {
	seen := http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewWithOptions(ClientOptions{})
	if _, err := c.GetFollow(srv.URL); err != nil {
		t.Fatal(err)
	}
	if seen.Get("X-Api-Key") != "" || seen.Get("Authorization") != "" {
		t.Fatalf("默认不应带认证头：%v", seen)
	}
}
