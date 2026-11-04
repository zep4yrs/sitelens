package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// newSettingsTokenServer 构造一个带初始 API token 的服务（none 模式）。
func newSettingsTokenServer(t *testing.T, initialToken string) (*Server, *httptest.Server) {
	t.Helper()
	t.Chdir("../..")
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Store.DataDir = t.TempDir()
	cfg.Web.APIToken = initialToken
	s, err := New(cfg, filepath.Join(t.TempDir(), "cfg.yml"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return s, api
}

// settingsBodyNoAPIToken 构造"不含 api_token 字段"的设置体（D-04：缺省=不变更）。
func settingsBodyNoAPIToken(t *testing.T) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(settingsBody("")), &m); err != nil {
		t.Fatalf("settingsBody: %v", err)
	}
	if web, ok := m["web"].(map[string]any); ok {
		delete(web, "api_token")
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// settingsBodyAPIToken 构造显式携带 api_token 的设置体。
func settingsBodyAPIToken(t *testing.T, token string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(settingsBody("")), &m); err != nil {
		t.Fatalf("settingsBody: %v", err)
	}
	if web, ok := m["web"].(map[string]any); ok {
		web["api_token"] = token
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func putSettingsRaw(t *testing.T, url, body, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func getSettingsRaw(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestSettingsAPITokenContract D-04 契约回归（F6 前端按此发送）：
// ① 字段缺省 = 保持不变；② 显式 "" = 清除；③ 非空 = 覆盖；
// ④ GET 不回明文 token，api_token_set 正确。
func TestSettingsAPITokenContract(t *testing.T) {
	s, api := newSettingsTokenServer(t, "init-token")
	settingsURL := api.URL + "/api/settings"

	// ① 请求体不含 api_token → token 不变，且 yml 不被写入/抹掉该键
	code, _ := putSettingsRaw(t, settingsURL, settingsBodyNoAPIToken(t), "init-token")
	if code != 200 {
		t.Fatalf("无 api_token 字段的 PUT 应 200，实际 %d", code)
	}
	if got := s.token(); got != "init-token" {
		t.Fatalf("字段缺省应保持 token 不变，实际 %q", got)
	}
	if cfgBytes, err := os.ReadFile(s.cfgPath); err == nil {
		if strings.Contains(string(cfgBytes), "api_token") {
			t.Fatalf("字段缺省时不应写 api_token 键：\n%s", cfgBytes)
		}
	}

	// ② 显式 "" → 清除（X-Token 鉴权关闭）
	code, body := putSettingsRaw(t, settingsURL, settingsBodyAPIToken(t, ""), "init-token")
	if code != 200 {
		t.Fatalf("显式清空 token 的 PUT 应 200，实际 %d", code)
	}
	if got := s.token(); got != "" {
		t.Fatalf("显式 \"\" 应清除 token，实际 %q", got)
	}
	if cleared, _ := body["token_cleared"].(bool); !cleared {
		t.Fatalf("清空 token 应回执 token_cleared=true：%v", body)
	}

	// ③ 非空 → 覆盖（此时已无鉴权，无需带 token）
	code, _ = putSettingsRaw(t, settingsURL, settingsBodyAPIToken(t, "new-token"), "")
	if code != 200 {
		t.Fatalf("覆盖 token 的 PUT 应 200，实际 %d", code)
	}
	if got := s.token(); got != "new-token" {
		t.Fatalf("非空 api_token 应覆盖，实际 %q", got)
	}
	if cfgBytes, err := os.ReadFile(s.cfgPath); err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	} else if !strings.Contains(string(cfgBytes), "new-token") {
		t.Fatalf("覆盖后应落盘 api_token：\n%s", cfgBytes)
	}

	// ④ GET 不回明文；api_token_set=true
	code, body = getSettingsRaw(t, settingsURL, "new-token")
	if code != 200 {
		t.Fatalf("GET /api/settings 应 200，实际 %d", code)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "new-token") {
		t.Fatalf("GET /api/settings 泄露明文 token：%s", raw)
	}
	if set, _ := body["api_token_set"].(bool); !set {
		t.Fatalf("api_token_set 应为 true：%v", body)
	}
	web, ok := body["web"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺少 web 段：%v", body)
	}
	if _, has := web["api_token"]; has {
		t.Fatalf("不应回显 api_token 字段：%v", web)
	}

	// 清除后 api_token_set=false
	if code, body = putSettingsRaw(t, settingsURL, settingsBodyAPIToken(t, ""), "new-token"); code != 200 {
		t.Fatalf("再次清空应 200，实际 %d", code)
	}
	code, body = getSettingsRaw(t, settingsURL, "")
	if code != 200 {
		t.Fatalf("清空后 GET 应 200（无鉴权），实际 %d", code)
	}
	if set, _ := body["api_token_set"].(bool); set {
		t.Fatalf("清空后 api_token_set 应为 false：%v", body)
	}
}

// TestSettingsPutRejectsOversizeBody V-21：PUT /api/settings 有 64KB 硬上限。
func TestSettingsPutRejectsOversizeBody(t *testing.T) {
	_, api := newServer(t)
	huge := `{"web":{"listen":"127.0.0.1:5000","api_token":""},"crawler":{"max_pages":1},"pad":"` +
		strings.Repeat("x", 70<<10) + `"}`
	code, _ := putSettingsRaw(t, api.URL+"/api/settings", huge, "")
	if code != http.StatusBadRequest {
		t.Fatalf("超大请求体应 400，实际 %d", code)
	}
}
