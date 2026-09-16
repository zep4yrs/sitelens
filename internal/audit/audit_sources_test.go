package audit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCollectSources：文本入树入内容；二进制不入树；超限只入树不回传内容。
func TestCollectSources(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "import os\nos.system('ls')\n")
	write("lib/db.php", "<?php eval($_GET['x']);\n")
	write("blob.bin", "ok\x00binary")                // 含 NUL：二进制，不入树
	write("invalid.txt", "ok\xff\xfe junk")          // 内容非 UTF-8：不入树
	write("huge.log", strings.Repeat("a", 600*1024)) // 600KB > 512KB：入树无内容

	sources, contents := CollectSources(dir, MaxContentBytes)

	got := strings.Join(sources, ",")
	if !strings.Contains(got, "app.py") || !strings.Contains(got, "lib/db.php") {
		t.Fatalf("文本文件应入树: %v", sources)
	}
	if strings.Contains(got, "blob.bin") || strings.Contains(got, "invalid") {
		t.Fatalf("二进制不应入树: %v", sources)
	}
	for _, s := range sources {
		if strings.Contains(s, "\\") {
			t.Fatalf("路径应为斜杠风格: %s", s)
		}
	}
	if !sort.StringsAreSorted(sources) {
		t.Fatal("sources 应有序")
	}
	if contents["app.py"] == "" || contents["lib/db.php"] == "" {
		t.Fatalf("小文本应有内容: %v", contents)
	}
	if _, ok := contents["huge.log"]; ok {
		t.Fatal("超限文件不应回传内容")
	}
	if len(contents["app.py"]) > MaxContentBytes {
		t.Fatal("内容超限")
	}
}
