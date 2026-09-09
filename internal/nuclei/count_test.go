package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCountConvertible 全库可运行模板计数（索引建库即完整漏斗验证）。
// 模板库不入仓库（.gitignore 排除，fetch_nuclei + import 可再生）：
// 本地缺失时跳过而非失败——CI 环境无该目录。
func TestCountConvertible(t *testing.T) {
	dir := "../../data/nuclei"
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skip("模板库不在本地（data/nuclei 未拉取），跳过全库计数")
	}
	entries, err := Index(dir, filepath.Join(t.TempDir(), "idx.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("全库可运行模板: %d", len(entries))
	if len(entries) < 2000 {
		t.Fatalf("可运行模板应 ≥2000: %d", len(entries))
	}
}
