package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPruneArchivesDroppedRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	s.Save(sampleResult("a.com", "A", 1), nil)
	s.Save(sampleResult("b.com", "B", 1), nil)
	s.Save(sampleResult("c.com", "C", 1), nil) // 触发裁剪 a.com

	// 主库只剩 2 条
	if got := len(s.List(10, "")); got != 2 {
		t.Fatalf("应保留 2 条: %d", got)
	}
	// 归档文件应含被裁的 a.com 记录
	data, err := os.ReadFile(filepath.Join(dir, "history.archive.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"host":"a.com"`) {
		t.Fatalf("归档应含被裁记录: %s", data)
	}
	// 归档是合法 JSON Lines（每行可解析）
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("归档行非法 JSON: %v", err)
		}
	}
}
