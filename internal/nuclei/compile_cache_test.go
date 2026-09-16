package nuclei

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const tplYAML = `id: cache-test
info:
  name: cache-test
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}"
    matchers:
      - type: word
        words: ["cache-test-marker"]
`

// TestLoadFileCached：命中缓存（同路径同 mtime 第二次直接返回）。
func TestLoadFileCached(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(p, []byte(tplYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := LoadFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("应编译出 check")
	}
	// 二次命中：同实例（缓存切片）。
	second, err := LoadFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Error("缓存命中应返回等长结果")
	}
}

// TestLoadFileCacheInvalidatedOnUpdate：模板文件更新后缓存自然失效。
func TestLoadFileCacheInvalidatedOnUpdate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(p, []byte(tplYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileCached(p); err != nil {
		t.Fatal(err)
	}
	// 更新内容（改成无法转换的形态 → 编译结果应为 0 条）。
	if err := os.WriteFile(p, []byte("id: broken\nnot-a-template: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mtime 精度：确保 mtime 明确变化（Windows 时钟粒度粗，推 2 秒）。
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	cs, err := LoadFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 0 {
		t.Errorf("更新后旧缓存应失效（期望 0 条），实得 %d", len(cs))
	}
}

// TestLoadFileCacheConcurrent：并发取同一模板不竞争出错。
func TestLoadFileCacheConcurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(p, []byte(tplYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = LoadFileCached(p)
		}()
	}
	wg.Wait()
}
