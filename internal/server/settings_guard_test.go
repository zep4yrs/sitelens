package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// settingsBody 构造一份会被 hSettingsPut 接受的设置体（listen/max_pages 必填）。
func settingsBody(overridesPath string) string {
	b, _ := json.Marshal(map[string]any{
		"web":     map[string]any{"listen": "127.0.0.1:5000", "api_token": ""},
		"crawler": map[string]any{"max_pages": 200, "respect_robots": true, "max_links_per_page": 500, "timeout_sec": 10},
		"scan":    map[string]any{"rate_interval_ms": 0, "timeout_sec": 10},
		"checks":  map[string]any{"nuclei_cap": 100},
		"exploit": map[string]any{"enabled": false},
		"intel":   map[string]any{"overrides_path": overridesPath},
		"batch":   map[string]any{"max_urls": 10},
		"ml":      map[string]any{"predict": false, "sev_linear": true, "sev_onnx": false},
	})
	return string(b)
}

// putJSONReq PUT 请求（设置页保存用）。
func putJSONReq(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestSettingsRejectsOverridesPathEscape BUG-006 回归：overrides_path 会被
// OSV 同步当落盘路径写入，属远程可写的「任意文件写」入口。数据目录外的
// 路径（../ 穿越、其它绝对目录）必须整单拒绝，且不改变已有配置。
func TestSettingsRejectsOverridesPathEscape(t *testing.T) {
	s, api := newServer(t)
	before := s.settingsCfg().Intel.OverridesPath
	absDir, err := filepath.Abs(s.cfgSnap().Store.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "evil.json")

	for _, esc := range []string{
		"../../evil.json",
		"sub/../../evil.json",
		"../evil.json",
		outside, // 绝对路径但在数据目录外
	} {
		code, body := putJSONReq(t, api.URL+"/api/settings", settingsBody(esc))
		if code != 400 {
			t.Errorf("越界 overrides_path %q 应 400，实际 %d %v", esc, code, body)
		}
		if _, ok := body["error"]; !ok {
			t.Errorf("拒绝时应带 error 字段: %v", body)
		}
		if got := s.settingsCfg().Intel.OverridesPath; got != before {
			t.Errorf("拒绝后配置不得被改写: %q → %q", before, got)
		}
		// 相对穿越按「相对数据目录」解析后的真实落点必须不存在
		target := esc
		if !filepath.IsAbs(target) {
			target = filepath.Join(absDir, esc)
		}
		if _, err := os.Stat(filepath.Clean(target)); err == nil {
			t.Errorf("越界路径不应被创建: %s", target)
		}
	}
}

// TestSettingsAcceptsOverridesPathInsideDataDir BUG-006 正面对照：数据目录
// 内的相对路径应归一为绝对路径并被接受（不能把功能修死）。
func TestSettingsAcceptsOverridesPathInsideDataDir(t *testing.T) {
	s, api := newServer(t)
	absDir, err := filepath.Abs(s.cfgSnap().Store.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"ov.json":     filepath.Join(absDir, "ov.json"),
		"sub/ov.json": filepath.Join(absDir, "sub", "ov.json"),
		"":            filepath.Join(absDir, defaultOverridesName),
	}
	for in, want := range cases {
		code, body := putJSONReq(t, api.URL+"/api/settings", settingsBody(in))
		if code != 200 {
			t.Fatalf("目录内 overrides_path %q 应 200，实际 %d %v", in, code, body)
		}
		if got := s.settingsCfg().Intel.OverridesPath; got != want {
			t.Errorf("overrides_path %q 应归一为 %q，实际 %q", in, want, got)
		}
	}
}

// TestSettingsPersistFileMode BUG-024 回归：配置写回含 web.api_token 明文，
// 应以 0600 落盘（Windows 无 POSIX 权限位，严格断言交 Linux/macOS CI）。
func TestSettingsPersistFileMode(t *testing.T) {
	s, api := newServer(t)
	if code, body := putJSONReq(t, api.URL+"/api/settings", settingsBody("ov.json")); code != 200 {
		t.Fatalf("保存设置失败 %d: %v", code, body)
	}
	fi, err := os.Stat(s.cfgPath)
	if err != nil {
		t.Fatalf("配置应已写回: %v", err)
	}
	if runtime.GOOS == "windows" {
		if fi.Mode().Perm()&0o200 == 0 {
			t.Fatalf("Windows 上配置文件不应为只读: %v", fi.Mode())
		}
		return
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("配置写回权限应为 0600, got %04o", got)
	}
}

// TestStatsNilResultNoPanic BUG-009 回归：导入一条 result:null 的历史记录后
// GET /api/stats 必须 200（TopTechs 此前 nil 解引用 → 连接被重置）。
func TestStatsNilResultNoPanic(t *testing.T) {
	s, api := newServer(t)
	if _, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{
			ID: 7777, URL: "http://nil-result.example", Host: "nil-result.example",
			ScannedAt: "2026-01-01T00:00:00Z",
		},
		Result: nil,
	}); err != nil {
		t.Fatalf("导入 nil result 记录: %v", err)
	}
	resp, err := http.Get(api.URL + "/api/stats")
	if err != nil {
		t.Fatalf("stats 请求被重置（panic 炸连接）: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("stats 响应应为 JSON: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("nil result 记录不应影响 stats: %d %v", resp.StatusCode, m)
	}
	if _, ok := m["top_techs"]; !ok {
		t.Fatalf("stats 缺 top_techs: %v", m)
	}
}
