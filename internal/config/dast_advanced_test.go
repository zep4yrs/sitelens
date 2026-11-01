// G09/G10 配置回归：DAST 进阶面五个开关默认全关 + max_requests 默认/覆盖。
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDASTAdvancedDefaultsOff 默认配置：五个开关全关、max_requests 有默认值。
func TestDASTAdvancedDefaultsOff(t *testing.T) {
	c := Default()
	d := c.DAST
	if d.Proto || d.Deser || d.Logic || d.Upload || d.IDOR {
		t.Fatalf("进阶面开关应默认全关：%+v", d)
	}
	if d.MaxRequests != 20 {
		t.Fatalf("max_requests 默认 = %d，期望 20", d.MaxRequests)
	}
}

// TestDASTAdvancedYAMLOverrides YAML 可覆盖开关与 max_requests。
func TestDASTAdvancedYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sitelens.yml")
	raw := "" +
		"dast:\n" +
		"  proto: true\n" +
		"  deser: true\n" +
		"  logic: true\n" +
		"  upload: true\n" +
		"  idor: true\n" +
		"  max_requests: 7\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c := LoadOrDefault(path)
	d := c.DAST
	if !d.Proto || !d.Deser || !d.Logic || !d.Upload || !d.IDOR {
		t.Fatalf("YAML 开关未生效：%+v", d)
	}
	if d.MaxRequests != 7 {
		t.Fatalf("max_requests = %d，期望 7", d.MaxRequests)
	}
	// 未覆盖时回退默认 20
	path2 := filepath.Join(dir, "sitelens2.yml")
	if err := os.WriteFile(path2, []byte("dast:\n  proto: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadOrDefault(path2).DAST.MaxRequests; got != 20 {
		t.Fatalf("未覆盖 max_requests 应回退默认 20，实际 %d", got)
	}
}
