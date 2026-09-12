package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptHistoryIsolatedNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "history.json")
	if err := os.WriteFile(p, []byte("{not valid json!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	// 损坏文件应被隔离且唯一命名（B6：多次损坏不互相覆盖）
	matches, _ := filepath.Glob(p + ".*.corrupt")
	if len(matches) == 0 {
		t.Fatal("应保留 .corrupt 唯一命名副本供人工抢救")
	}
	// 从空库继续工作
	s.Save(sampleResult("a.com", "A", 1), nil)
	if len(s.List(10, "")) != 1 {
		t.Fatal("损坏隔离后应可正常写入")
	}
}
