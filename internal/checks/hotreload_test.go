package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsExtendedHotReload BUG-013 回归：checkIndex 曾由 sync.Once 建一次，
// ConfigurePlugins 热重载插件集后不失效 → IsExtended 对新插件永久 false
// （引擎低档位增量纳入静默漏检）。本用例先逼索引快照落地，再投放插件，
// 断言新插件可被 IsExtended 命中；撤下插件后同样必须失效。
func TestIsExtendedHotReload(t *testing.T) {
	// 先跑一次，逼 checkIndex 快照落地（模拟引擎已跑过一轮调度）
	if !IsExtended("wp-readme") {
		t.Fatal("前置：wp-readme 应为扩展集")
	}

	dir := t.TempDir()
	plugin := `[{"id":"hot-reload-013","lv":1,"p":"/hot-reload-013",
		"title":"热加载插件","sev":"low","m":{"s":200,"c":["hot-marker"]}}]`
	if err := os.WriteFile(filepath.Join(dir, "hot.json"), []byte(plugin), 0o644); err != nil {
		t.Fatal(err)
	}
	// 无论断言成败都还原全局插件集，避免污染同包其它用例
	t.Cleanup(func() { ConfigurePlugins(t.TempDir()) })

	ConfigurePlugins(dir)
	if !IsExtended("hot-reload-013") {
		t.Fatal("热加载后新插件应被 IsExtended 命中（索引未失效 = 静默漏检）")
	}

	// 撤下插件（空目录重载）后同样必须从索引消失
	ConfigurePlugins(t.TempDir())
	if IsExtended("hot-reload-013") {
		t.Fatal("插件撤下后不应仍判定为扩展集（索引快照未换代）")
	}
	if !IsExtended("wp-readme") {
		t.Fatal("清空插件后内置扩展集应仍在")
	}
}
