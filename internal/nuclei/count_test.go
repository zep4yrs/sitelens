package nuclei

import (
	"path/filepath"
	"testing"
)

// TestCountConvertible 全库可运行模板计数（索引建库即完整漏斗验证）。
func TestCountConvertible(t *testing.T) {
	dir := "../../data/nuclei"
	entries, err := Index(dir, filepath.Join(t.TempDir(), "idx.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("全库可运行模板: %d", len(entries))
	if len(entries) < 2000 {
		t.Fatalf("可运行模板应 ≥2000: %d", len(entries))
	}
}
