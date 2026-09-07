package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 内置 SPA 靶页自测：静态 HTML 无表单（JS 延迟注入），登录校验 admin/admin123。
func TestSPATargetPageAndLogin(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(hSPATarget))
	defer page.Close()

	login := httptest.NewServer(http.HandlerFunc(hSPATargetLogin))
	defer login.Close()

	resp, err := page.Client().Get(page.URL + "/dev/spa-target")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	body := string(buf[:n])
	if strings.Contains(body, "<form") {
		t.Fatal("静态 HTML 不应直接含表单（应由 JS 注入）")
	}
	if !strings.Contains(body, "setTimeout") {
		t.Fatal("SPA 靶页应含 JS 注入脚本")
	}

	// 正确凭据 → 200 欢迎页
	resp2, err := login.Client().Post(login.URL+"/dev/spa-target/login",
		"application/x-www-form-urlencoded", strings.NewReader("user=admin&pass=admin123"))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("正确凭据应 200: %d", resp2.StatusCode)
	}

	// 错误凭据 → 403
	resp3, err := login.Client().Post(login.URL+"/dev/spa-target/login",
		"application/x-www-form-urlencoded", strings.NewReader("user=admin&pass=wrong"))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 403 {
		t.Fatalf("错误凭据应 403: %d", resp3.StatusCode)
	}
}
