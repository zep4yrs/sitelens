package audit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCollectSources：文本入树入内容（全量，不截断）；二进制不入树。
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
	// 用良性 PHP 片段做「子目录文本文件」样本：本机 AV 会把
	// `<?php eval($_GET[...])` 形态的 webshell 测试样本直接删除，
	// 导致用例随机丢失文件（与本函数行为无关）。
	write("lib/db.php", "<?php echo 'ok';\n")
	write("blob.bin", "ok\x00binary")                // 含 NUL：二进制，不入树
	write("invalid.txt", "ok\xff\xfe junk")          // 内容非 UTF-8：不入树
	write("huge.log", strings.Repeat("a", 600*1024)) // 600KB > 512KB：入树无内容

	sources, contents := CollectSources(dir)

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
	// 25A 终版（用户拍板拒绝截断）：文本文件全量回传，不带任何截断标记
	if c, ok := contents["huge.log"]; !ok || strings.Contains(c, "预览已截断") {
		t.Fatal("超 512KB 文本应全量回传且无截断标记")
	}
	if len(contents["huge.log"]) != 600*1024 {
		t.Fatalf("全量回传长度应等于原文件: %d", len(contents["huge.log"]))
	}
}
