// 企业化 6.x RBAC 接线回归：none 模式零变化、token 模式 Bearer/角色/租户。
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/authz"
	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// newAuthTestServer 构造指定认证模式的 Server + 测试 HTTP 服务。
func newAuthTestServer(t *testing.T, mode, secret string) (*Server, *httptest.Server) {
	t.Helper()
	t.Chdir("../..") // 数据路径按「从项目根启动」约定解析
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Scan.MaxConcurrent = 2
	cfg.Store.DataDir = t.TempDir()
	cfg.Web.AuthMode = mode
	cfg.Web.AuthSecret = secret
	s, err := New(cfg, filepath.Join(t.TempDir(), "cfg.yml"))
	if err != nil {
		t.Fatalf("New(%s): %v", mode, err)
	}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return s, api
}

// issueAuthToken 签发测试令牌。
func issueAuthToken(t *testing.T, secret string, role authz.Role, tenant string) string {
	t.Helper()
	tok, err := authz.IssueToken([]byte(secret), authz.Claims{
		Subject: "test-user", Tenant: tenant, Role: role,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	return tok
}

// authDo 发一次请求，可带 Bearer 令牌与租户头。
func authDo(t *testing.T, method, url, token, tenant string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestAuthNoneModeUnchanged none 模式（默认）：不带任何凭据的 /api/* 仍放行。
func TestAuthNoneModeUnchanged(t *testing.T) {
	_, api := newAuthTestServer(t, "none", "")
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", "", ""); code != 200 {
		t.Fatalf("none 模式 GET /api/version 应 200，实际 %d", code)
	}
	// 写接口无凭据不应被 401/403 拦截（无 body → 400 属正常业务错误）
	if code, _ := authDo(t, http.MethodPost, api.URL+"/api/scan", "", ""); code == 401 || code == 403 {
		t.Fatalf("none 模式写接口不应鉴权拦截，实际 %d", code)
	}
}

// TestAuthTokenRequiresBearer token 模式：无/坏/过期令牌一律 401。
func TestAuthTokenRequiresBearer(t *testing.T) {
	const secret = "test-secret-0123456789"
	_, api := newAuthTestServer(t, "token", secret)
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", "", ""); code != 401 {
		t.Fatalf("缺 Bearer 应 401，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", "not-a-token", ""); code != 401 {
		t.Fatalf("非法令牌应 401，实际 %d", code)
	}
	expired, err := authz.IssueToken([]byte(secret), authz.Claims{
		Subject: "u", Tenant: "tenant-a", Role: authz.RoleViewer,
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", expired, ""); code != 401 {
		t.Fatalf("过期令牌应 401，实际 %d", code)
	}
}

// TestAuthTokenViewerWriteForbidden 只读角色：读放行、写 403。
func TestAuthTokenViewerWriteForbidden(t *testing.T) {
	const secret = "test-secret-0123456789"
	_, api := newAuthTestServer(t, "token", secret)
	viewer := issueAuthToken(t, secret, authz.RoleViewer, "tenant-a")
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", viewer, ""); code != 200 {
		t.Fatalf("viewer 读接口应 200，实际 %d", code)
	}
	for _, path := range []string{"/api/scan", "/api/history/clear", "/api/batch"} {
		if code, _ := authDo(t, http.MethodPost, api.URL+path, viewer, ""); code != 403 {
			t.Fatalf("viewer 写 %s 应 403，实际 %d", path, code)
		}
	}
	if code, _ := authDo(t, http.MethodDelete, api.URL+"/api/history/1", viewer, ""); code != 403 {
		t.Fatalf("viewer DELETE 应 403，实际 %d", code)
	}
}

// TestAuthTokenAdminAllowed 管理员：读写均放行（业务错误不算鉴权失败）。
func TestAuthTokenAdminAllowed(t *testing.T) {
	const secret = "test-secret-0123456789"
	_, api := newAuthTestServer(t, "token", secret)
	admin := issueAuthToken(t, secret, authz.RoleAdmin, "tenant-a")
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", admin, ""); code != 200 {
		t.Fatalf("admin 读接口应 200，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodPost, api.URL+"/api/scan", admin, ""); code == 401 || code == 403 {
		t.Fatalf("admin 写接口不应被鉴权拦截，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodDelete, api.URL+"/api/history/999999", admin, ""); code == 401 || code == 403 {
		t.Fatalf("admin DELETE 不应被鉴权拦截，实际 %d", code)
	}
}

// TestAuthTokenTenantMismatch 租户不匹配 403；匹配放行。
func TestAuthTokenTenantMismatch(t *testing.T) {
	const secret = "test-secret-0123456789"
	_, api := newAuthTestServer(t, "token", secret)
	viewer := issueAuthToken(t, secret, authz.RoleViewer, "tenant-a")
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", viewer, "tenant-a"); code != 200 {
		t.Fatalf("租户匹配应放行，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/version", viewer, "tenant-b"); code != 403 {
		t.Fatalf("租户不匹配应 403，实际 %d", code)
	}
}

// TestAuthConfigValidation 认证模式配置校验：token 缺 secret / 未知模式 → 启动报错。
func TestAuthConfigValidation(t *testing.T) {
	t.Chdir("../..")
	base := func() *config.Config {
		cfg := config.Default()
		cfg.Store.DataDir = t.TempDir()
		return cfg
	}
	cfg := base()
	cfg.Web.AuthMode = "token"
	if _, err := New(cfg, filepath.Join(t.TempDir(), "c.yml")); err == nil {
		t.Fatal("token 模式缺 auth_secret 应启动报错")
	}
	cfg = base()
	cfg.Web.AuthMode = "basic"
	if _, err := New(cfg, filepath.Join(t.TempDir(), "c.yml")); err == nil {
		t.Fatal("未知 auth_mode 应启动报错")
	}
}
