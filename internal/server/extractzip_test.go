package server

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type zipEntry struct {
	Content  string
	IsSymlnk bool
}

// buildTestZip 构造内存 zip：可指定条目是否符号链接。
func buildTestZip(t *testing.T, entries map[string]zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, e := range entries {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if e.IsSymlnk {
			hdr.SetMode(os.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.Content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractZipZipSlip 越界路径条目被拦截，安全条目正常释放。
func TestExtractZipZipSlip(t *testing.T) {
	dir := t.TempDir()
	entries := map[string]zipEntry{
		"../evil.txt":   {Content: "evil"},
		"/abs/evil.txt": {Content: "evil"},
		"safe/ok.txt":   {Content: "ok"},
	}
	data := buildTestZip(t, entries)
	if err := extractZip(bytes.NewReader(data), int64(len(data)), dir, 8<<20); err != nil {
		t.Fatalf("解压报错: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "safe", "ok.txt")); err != nil {
		t.Fatalf("安全条目应正常释放: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.txt")); err == nil {
		t.Fatal("zip-slip 条目被写出")
	}
	if _, err := os.Stat(filepath.Dir(dir) + "/abs/evil.txt"); err == nil {
		t.Fatal("绝对路径条目被写出")
	}
}

// TestExtractZipSymlinkSkipped 符号链接条目被跳过（不落盘为链接）。
func TestExtractZipSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	entries := map[string]zipEntry{
		"link.txt":  {Content: "/etc/passwd", IsSymlnk: true},
		"plain.txt": {Content: "plain"},
	}
	data := buildTestZip(t, entries)
	if err := extractZip(bytes.NewReader(data), int64(len(data)), dir, 8<<20); err != nil {
		t.Fatalf("解压报错: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "link.txt"))
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("符号链接条目不应落盘为链接")
	}
}

// TestExtractZipOExcl 已存在同名文件不被覆盖（O_EXCL 语义）。
func TestExtractZipOExcl(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(existing, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := map[string]zipEntry{
		"keep.txt": {Content: "OVERWRITE-ATTEMPT"},
	}
	data := buildTestZip(t, entries)
	if err := extractZip(bytes.NewReader(data), int64(len(data)), dir, 8<<20); err != nil {
		t.Fatalf("解压报错: %v", err)
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("已存在文件被覆盖: %q", string(got))
	}
}
