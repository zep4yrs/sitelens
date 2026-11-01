// CP-02 接线回归：engine 从 SLENS_AUTH_* 构造 authn.Config 并注入 httpx.Client。
package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// clearAuthEnv 清空全部 SLENS_AUTH_* 变量（避免宿主环境干扰）。
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"MODE", "HEADER", "VALUE", "TOKEN", "USERNAME", "PASSWORD", "COOKIE", "TIMEOUT"} {
		t.Setenv("SLENS_AUTH_"+k, "")
	}
}

// httpHeaderProbe 起一个回显请求头的测试服务，返回客户端。
func httpHeaderProbe(t *testing.T) (string, func() http.Header) {
	t.Helper()
	var last http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() http.Header { return last }
}

// TestApplyAuthMatrixBearer 环境变量 bearer → Authorization 注入真实请求。
func TestApplyAuthMatrixBearer(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "bearer")
	t.Setenv("SLENS_AUTH_TOKEN", "tok-abc")
	url, last := httpHeaderProbe(t)

	c := httpx.NewWithOptions(httpx.ClientOptions{})
	mode, err := applyAuthMatrix(c)
	if err != nil || mode != "bearer" {
		t.Fatalf("applyAuthMatrix = %q/%v，期望 bearer", mode, err)
	}
	if _, err := c.GetFollow(url); err != nil {
		t.Fatal(err)
	}
	if got := last().Get("Authorization"); got != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q", got)
	}
}

// TestApplyAuthMatrixCookie cookie 模式注入 Cookie 头。
func TestApplyAuthMatrixCookie(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "cookie")
	t.Setenv("SLENS_AUTH_COOKIE", "sid=1; role=admin")
	url, last := httpHeaderProbe(t)

	c := httpx.NewWithOptions(httpx.ClientOptions{})
	if mode, err := applyAuthMatrix(c); err != nil || mode != "cookie" {
		t.Fatalf("applyAuthMatrix = %q/%v", mode, err)
	}
	if _, err := c.GetFollow(url); err != nil {
		t.Fatal(err)
	}
	if got := last().Get("Cookie"); got != "sid=1; role=admin" {
		t.Fatalf("Cookie = %q", got)
	}
}

// TestApplyAuthMatrixHeader header 模式注入自定义头。
func TestApplyAuthMatrixHeader(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "header")
	t.Setenv("SLENS_AUTH_HEADER", "X-API-Key")
	t.Setenv("SLENS_AUTH_VALUE", "k-123")
	url, last := httpHeaderProbe(t)

	c := httpx.NewWithOptions(httpx.ClientOptions{})
	if mode, err := applyAuthMatrix(c); err != nil || mode != "header" {
		t.Fatalf("applyAuthMatrix = %q/%v", mode, err)
	}
	if _, err := c.GetFollow(url); err != nil {
		t.Fatal(err)
	}
	if got := last().Get("X-Api-Key"); got != "k-123" {
		t.Fatalf("X-API-Key = %q", got)
	}
}

// TestApplyAuthMatrixNoConfig 无配置 = 零行为变化（不注入、不报错）。
func TestApplyAuthMatrixNoConfig(t *testing.T) {
	clearAuthEnv(t)
	url, last := httpHeaderProbe(t)
	c := httpx.NewWithOptions(httpx.ClientOptions{})
	mode, err := applyAuthMatrix(c)
	if err != nil || mode != "" {
		t.Fatalf("无配置应 = 空/无错误，实际 %q/%v", mode, err)
	}
	if _, err := c.GetFollow(url); err != nil {
		t.Fatal(err)
	}
	if got := last().Get("Authorization"); got != "" {
		t.Fatalf("无配置不应注入 Authorization：%q", got)
	}
	// MODE=none 显式关闭同样不注入
	t.Setenv("SLENS_AUTH_MODE", "none")
	if mode, err := applyAuthMatrix(c); err != nil || mode != "" {
		t.Fatalf("MODE=none 应不注入：%q/%v", mode, err)
	}
}

// TestApplyAuthMatrixInvalid 非法配置显式报错且不泄露凭据值。
func TestApplyAuthMatrixInvalid(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "bogus")
	c := httpx.NewWithOptions(httpx.ClientOptions{})
	_, err := applyAuthMatrix(c)
	if err == nil {
		t.Fatal("未知认证方式应报错")
	}
	if !strings.Contains(err.Error(), "未知认证方式") {
		t.Fatalf("错误信息异常：%v", err)
	}

	// 空令牌：明确报错，且错误文本不含后续凭据（此处无凭据可泄）
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "bearer")
	if _, err := applyAuthMatrix(c); err == nil || !strings.Contains(err.Error(), "令牌") {
		t.Fatalf("空 bearer 令牌应报错：%v", err)
	}
	// 头注入（CR/LF）拒绝
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "header")
	t.Setenv("SLENS_AUTH_HEADER", "X-API-Key")
	t.Setenv("SLENS_AUTH_VALUE", "a\r\nInjected: 1")
	if _, err := applyAuthMatrix(c); err == nil {
		t.Fatal("请求头值含 CR/LF 应报错")
	}
}

// TestApplyAuthMatrixNilClient nil 客户端安全。
func TestApplyAuthMatrixNilClient(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("SLENS_AUTH_MODE", "bearer")
	t.Setenv("SLENS_AUTH_TOKEN", "x")
	if mode, err := applyAuthMatrix(nil); err != nil || mode != "" {
		t.Fatalf("nil client = %q/%v", mode, err)
	}
}
