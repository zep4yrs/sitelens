package store

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestTopTechsNilResult BUG-009 回归：history 里 result 为 null 的记录
// （导入迁移/写库中断均可产生）此前在 TopTechs 直接解引用 Result.Technologies
// → nil 指针 panic（GET /api/stats 可达）。现应跳过该记录继续统计。
func TestTopTechsNilResult(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ScanRecord{
		ScanSummary: ScanSummary{ID: 9001, URL: "http://nil-result.example",
			Host: "nil-result.example", ScannedAt: "2026-01-01T00:00:00Z"},
		Result: nil,
	}); err != nil {
		t.Fatalf("导入 nil result 记录: %v", err)
	}
	s.Save(sampleResult("good.example", "GOOD", 2), nil)

	got := s.TopTechs(8) // 绝不 panic
	names := map[string]bool{}
	for _, x := range got {
		if n, ok := x["name"].(string); ok {
			names[n] = true
		}
	}
	if !names["Tech0"] || !names["Tech1"] {
		t.Fatalf("nil result 记录应被跳过、正常记录仍统计: %v", got)
	}
}

// TestHistoryFilesMode0600 BUG-024 回归：history.json / history.archive.jsonl
// 含目标响应片段与命中详情，应以 0600 落盘。
//
// Windows 不实现 POSIX 权限位（os.WriteFile 的 perm 仅映射只读位），
// 权限断言交由 Linux/macOS CI 承担；本机只验证文件仍可正常读写。
func TestHistoryFilesMode0600(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 1) // 上限 1：第二次 Save 触发裁剪 → 写归档
	if err != nil {
		t.Fatal(err)
	}
	s.Save(sampleResult("a.example", "A", 1), nil)
	s.Save(sampleResult("b.example", "B", 1), nil)

	for _, name := range []string{"history.json", "history.archive.jsonl"} {
		p := filepath.Join(dir, name)
		if _, err := os.ReadFile(p); err != nil {
			t.Fatalf("%s 应可读: %v", name, err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			// 平台无 0600 语义：只确认未被误设为只读（追加/覆盖仍需可用）。
			if fi.Mode().Perm()&0o200 == 0 {
				t.Errorf("Windows 上 %s 不应为只读: %v", name, fi.Mode())
			}
			continue
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s 权限应为 0600, got %04o", name, got)
		}
	}
}

// captureStderr 捕获 fn 执行期间写入 os.Stderr 的内容（测试串行，无并发干扰）。
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestFlushFailureWarnsStderr BUG-031 回归：flush 写失败此前静默（磁盘满时
// 历史静默丢失）。现应只在失败路径向 stderr 告警，成功路径零输出。
func TestFlushFailureWarnsStderr(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := filepath.Join(dir, "history.json.tmp")
	// 用目录占住 tmp 路径 → os.WriteFile 必然失败（EISDIR/EPERM）
	if err := os.Mkdir(tmpPath, 0o755); err != nil {
		t.Fatal(err)
	}
	out := captureStderr(t, func() {
		s.Save(sampleResult("a.example", "A", 1), nil)
	})
	if !strings.Contains(out, "落盘失败") {
		t.Fatalf("写失败应告警到 stderr（含「落盘失败」），实际 %q", out)
	}
	// 内存态不丢：记录仍在
	if n := len(s.List(10, "")); n != 1 {
		t.Fatalf("落盘失败不应丢内存记录: %d", n)
	}

	// 恢复可写路径：成功落盘且不再告警
	if err := os.Remove(tmpPath); err != nil {
		t.Fatal(err)
	}
	out = captureStderr(t, func() {
		s.Save(sampleResult("b.example", "B", 1), nil)
	})
	if strings.Contains(out, "警告") {
		t.Fatalf("成功路径不应告警: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "history.json")); err != nil {
		t.Fatalf("恢复后应正常落盘: %v", err)
	}
}
