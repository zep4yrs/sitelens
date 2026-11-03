package main

// A-01 / D-02 / C-17 的壳侧回归测试：写用户配置时的 token 注入语义。
//
// 契约：
//   - 没有 web.api_token（或格式非法）→ 生成 32 字节随机 hex（64 字符）并写回；
//   - 已经是合法 64-hex（本壳格式）→ 原样保留（重启不换 token，否则浏览器
//     里已保存的 token 立刻失效）；
//   - 用户手填的其它格式 token 视为"企业部署的固定 token"，不覆盖；
//   - 配置 YAML 解析失败 → 不注入（只按行合并 web.listen），且不打印 token。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"sitelens-wails/internal/usercfg"
)

func readConfigWeb(t *testing.T, p string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读配置失败：%v", err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("配置不是合法 YAML：%v\n%s", err, data)
	}
	web, _ := cfg["web"].(map[string]any)
	if web == nil {
		t.Fatalf("配置缺 web 段：%s", data)
	}
	return web
}

func TestWriteUserConfigInjectsToken(t *testing.T) {
	dir := t.TempDir()
	m := usercfg.Resolve(dir, dir)

	p, tok, err := writeUserConfigAt(dir, "127.0.0.1:5087", m)
	if err != nil {
		t.Fatalf("写配置失败：%v", err)
	}
	if !usercfg.ValidAPIToken(tok) {
		t.Fatalf("生成的 token 不是 64 位 hex：%q", tok)
	}
	web := readConfigWeb(t, p)
	if got, _ := web["api_token"].(string); got != tok {
		t.Fatalf("配置里的 api_token=%q，与返回值 %q 不一致", got, tok)
	}
	if got, _ := web["listen"].(string); got != "127.0.0.1:5087" {
		t.Errorf("listen 未写入：%q", got)
	}

	// 幂等：第二次启动必须沿用同一个 token（否则 localStorage 里的旧 token 失效）
	_, tok2, err := writeUserConfigAt(dir, "127.0.0.1:5088", m)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok {
		t.Errorf("重启后 token 变了（%q → %q），已保存的浏览器 token 会立即 401", tok, tok2)
	}
}

// TestWriteUserConfigReplacesNonShellToken 契约（Lead 定稿）：只有 64-hex 被视为
// 有效 token；用户手填的其它格式（长度/字符集不符）一律替换为新的 64-hex。
// 理由：壳必须持有 token 才能经 fragment 注入前端，格式统一是"本壳管理"的判据。
func TestWriteUserConfigReplacesNonShellToken(t *testing.T) {
	dir := t.TempDir()
	m := usercfg.Resolve(dir, dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yml"),
		[]byte("web:\n  listen: 127.0.0.1:5000\n  api_token: corp-fixed-token\nscan:\n  timeout_sec: 60\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, tok, err := writeUserConfigAt(dir, "127.0.0.1:5087", m)
	if err != nil {
		t.Fatal(err)
	}
	if tok == "corp-fixed-token" || !usercfg.ValidAPIToken(tok) {
		t.Fatalf("非 64-hex token 应被替换，实际 %q", tok)
	}
	web := readConfigWeb(t, p)
	if got, _ := web["api_token"].(string); got != tok {
		t.Errorf("配置里的 token 未同步：%q != %q", got, tok)
	}
	// 用户其它键必须保留
	var cfg map[string]any
	data, _ := os.ReadFile(p)
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if scan, _ := cfg["scan"].(map[string]any); scan == nil || scan["timeout_sec"] != 60 {
		t.Errorf("用户自定义键被抹掉：%s", data)
	}
}

func TestWriteUserConfigReplacesInvalidToken(t *testing.T) {
	dir := t.TempDir()
	m := usercfg.Resolve(dir, dir)
	// 非法：太短
	if err := os.WriteFile(filepath.Join(dir, "config.yml"),
		[]byte("web:\n  listen: 127.0.0.1:5000\n  api_token: short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, tok, err := writeUserConfigAt(dir, "127.0.0.1:5087", m)
	if err != nil {
		t.Fatal(err)
	}
	if !usercfg.ValidAPIToken(tok) {
		t.Errorf("非法 token 应被替换成 64-hex，实际 %q", tok)
	}
	if tok == "short" {
		t.Error("非法 token 未被替换")
	}
}

func TestWriteUserConfigBrokenYAMLSkipsToken(t *testing.T) {
	dir := t.TempDir()
	m := usercfg.Resolve(dir, dir)
	broken := "web:\n  listen: 127.0.0.1:5000\n\tbad-tab: 1\nscan:\n  timeout_sec: 60\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	p, tok, err := writeUserConfigAt(dir, "127.0.0.1:5087", m)
	if err != nil {
		t.Fatalf("坏 YAML 不应导致写配置失败：%v", err)
	}
	if tok != "" {
		t.Errorf("坏 YAML 时不应注入 token（写不进去），实际 %q", tok)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "timeout_sec: 60") {
		t.Errorf("坏 YAML 的其余行应原样保留：%s", data)
	}
	if !strings.Contains(string(data), "127.0.0.1:5087") {
		t.Errorf("web.listen 应按行合并为新端口：%s", data)
	}
}
