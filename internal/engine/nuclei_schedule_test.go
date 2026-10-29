package engine

// BUG-012 调度表加载兜底回归。

import (
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestLoadNucleiLRUNullSafe BUG-012 回归：nuclei_schedule.json 内容为
// JSON `null` 时 json.Unmarshal 会把目标 map 置 nil 且 err==nil（合法
// 解出空值），旧实现让 e.nucleiLRU 变 nil，随后 nucleiSubset 写调度表
// 直接 panic: assignment to entry in nil map。空文件/损坏内容同理必须
// 落成「可写空表」而不是 nil。
func TestLoadNucleiLRUNullSafe(t *testing.T) {
	cases := map[string]string{
		"json-null": "null",
		"corrupt":   "{not-json",
		"empty":     "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Store.DataDir = t.TempDir()
			path := filepath.Join(cfg.Store.DataDir, "nuclei_schedule.json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			e := &Engine{cfg: cfg}
			e.loadNucleiLRU()
			if e.nucleiLRU == nil {
				t.Fatalf("%s: 调度表不得为 nil（后续写表会 panic）", name)
			}
			// 复现触发点：nucleiSubset 选中模板后写调度表
			e.nucleiLRU["templates/x.yaml"] = 1
		})
	}

	// 合法内容仍按原语义恢复
	cfg := &config.Config{}
	cfg.Store.DataDir = t.TempDir()
	path := filepath.Join(cfg.Store.DataDir, "nuclei_schedule.json")
	if err := os.WriteFile(path, []byte(`{"templates/a.yaml":123}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: cfg}
	e.loadNucleiLRU()
	if got := e.nucleiLRU["templates/a.yaml"]; got != 123 {
		t.Fatalf("合法调度表未恢复: %v", e.nucleiLRU)
	}
}
