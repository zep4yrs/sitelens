package config

import (
	"os"
	"path/filepath"
	"testing"
)

// URL 自动修正默认开启；显式配置可关闭。这两个行为决定 5.2.3 的兼容口径。
func TestAutoNormalizeDefaultOn(t *testing.T) {
	if !Default().Target.AutoNormalize {
		t.Fatal("Default().Target.AutoNormalize 应为 true")
	}
}

func TestAutoNormalizeCanBeDisabledByConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg.yml")
	if err := os.WriteFile(p, []byte("target:\n  auto_normalize: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Target.AutoNormalize {
		t.Fatal("配置 target.auto_normalize=false 后应关闭（bool 默认值未生效）")
	}
}

func TestAutoNormalizeMissingConfigKeepsDefault(t *testing.T) {
	cfg := LoadOrDefault(filepath.Join(t.TempDir(), "not-exist.yml"))
	if !cfg.Target.AutoNormalize {
		t.Fatal("缺省配置文件应保持默认 true")
	}
}
