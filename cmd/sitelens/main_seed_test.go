package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUpdateSeedCommandDeliversOnce 覆盖交付语义的端到端断言：
// 版本变化覆盖包内种子、保留用户成果、同版本二次调用 no-op。
func TestUpdateSeedCommandDeliversOnce(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	mk := func(root, rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(seed, "nvd_cves.json.gz", "nvd-new")
	mk(seed, "go/technologies.json", "fp-new")
	mk(seed, "wordlists/dirs.txt", "words-new")
	mk(user, "data/nvd_cves.json.gz", "nvd-old")
	mk(user, "state/history.json", "history")

	if code := updateSeedCommand(seed, user); code != 0 {
		t.Fatalf("交付退出码 = %d，期望 0", code)
	}
	got, _ := os.ReadFile(filepath.Join(user, "data", "nvd_cves.json.gz"))
	if string(got) != "nvd-new" {
		t.Errorf("包内种子未覆盖，实际 %q", got)
	}
	if _, err := os.Stat(filepath.Join(user, ".seed-manifest.json")); err != nil {
		t.Errorf("交付清单未落地：%v", err)
	}
	if _, err := os.Stat(filepath.Join(user, "data", "wordlists", "dirs.txt")); err == nil {
		t.Error("词表不应由本通道交付")
	}
	if h, _ := os.ReadFile(filepath.Join(user, "state", "history.json")); string(h) != "history" {
		t.Error("扫描历史被改动")
	}
	// 二次调用：清单版本已等于包版本 → 跳过
	if code := updateSeedCommand(seed, user); code != 0 {
		t.Fatalf("二次交付退出码 = %d，期望 0", code)
	}
}
