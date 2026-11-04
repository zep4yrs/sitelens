package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// ConfigurePlugins 幂等：重复调用不重复注入插件；空目录静默。
func TestConfigurePluginsIdempotent(t *testing.T) {
	before := len(AllChecks())
	ConfigurePlugins(t.TempDir()) // 空目录
	ConfigurePlugins(t.TempDir())
	if after := len(AllChecks()); after != before {
		t.Fatalf("空插件目录不应改变 check 数量: %d -> %d", before, after)
	}
}

// TestEmptyMatchNeverHits B-02 回归：无任何判定条件的 Match 不得命中任何响应。
//
// 旧实现里「零条件」会跳过全部比较走到 return true —— 插件 JSON 把 "c"
// 写成 "contains"（或整体漏写 "m"）就静默变成「对任何响应命中」的全站误报。
func TestEmptyMatchNeverHits(t *testing.T) {
	for _, status := range []int{200, 302, 403, 500} {
		if matchBody(Match{}, status, "anything", map[string]string{"Server": "nginx"}, "a.com") {
			t.Fatalf("空 Match 不得命中（status=%d）", status)
		}
	}
	// 反例：有条件但只命中状态码的 check 必须继续命中——B-02 的修复
	// 不能把内置的 status-only check（bak-dump 等）误杀。
	if !matchBody(Match{Status: 200}, 200, "", nil, "a.com") {
		t.Fatal("status-only check 应命中")
	}
	if !matchBody(Match{Status: 200, Contains: []string{"DIRC"}}, 200, "xx DIRC yy", nil, "a.com") {
		t.Fatal("status+contains check 应命中")
	}
}

// TestLoadPluginsRejectsUnconditional B-02 回归：无 m / 无 p 的插件在加载期被丢弃。
func TestLoadPluginsRejectsUnconditional(t *testing.T) {
	dir := t.TempDir()
	data := `[
	  {"id":"no-match","lv":0,"p":"/x","title":"漏写 m"},
	  {"id":"typo-match","lv":0,"p":"/x","title":"字段名拼错","contains":["x"]},
	  {"id":"no-path","lv":0,"title":"漏写 p","m":{"s":200,"c":["x"]}},
	  {"id":"ok","lv":0,"p":"/y","title":"正常","m":{"s":200,"c":["y"]}}
	]`
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadPlugins(dir)
	if len(got) != 1 {
		t.Fatalf("应只保留 1 条有效插件，实际 %d 条: %+v", len(got), got)
	}
	if got[0].ID != "ok" {
		t.Fatalf("保留的插件 id = %q, 期望 ok", got[0].ID)
	}
}
