package nuclei

// 模板索引热路径测试（目录 mtime 戳校验 + 进程内 memo）。
//
// 语义目标：模板目录的增/删/改名必须在下一次 Index 调用被感知；目录戳
// 不变时不得重建（不重复 walk/转换）；memo 命中时不得再读/解码缓存文件。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// resetIndexMemo 清空进程内 memo，避免测试间互相干扰。
func resetIndexMemo() {
	indexMemoMu.Lock()
	indexMemo = nil
	indexMemoMu.Unlock()
}

// withCacheReadCounter 挂钩缓存文件读取计数（Hook 只存在于测试侧）。
func withCacheReadCounter(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	prev := indexCacheReadHook
	indexCacheReadHook = func() { n.Add(1) }
	t.Cleanup(func() { indexCacheReadHook = prev })
	return &n
}

// writeHotCorpus 热路径测试语料：多目录 + legacy + 协议模板。
func writeHotCorpus(t *testing.T, dir string) {
	t.Helper()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("http/cves/cve-a.yaml", `
id: cve-a
info:
  name: CVE A
  severity: high
http:
  - method: GET
    path: "{{BaseURL}}/a"
    matchers:
      - type: word
        words: ["a"]
`)
	write("http/cves/cve-b.yaml", `
id: cve-b
info:
  name: CVE B
  severity: medium
http:
  - method: GET
    path: "{{BaseURL}}/b"
    matchers:
      - type: word
        words: ["b"]
`)
	write("http/panels/panel.yaml", `
id: panel
info:
  name: Panel
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/panel"
    matchers:
      - type: word
        words: ["panel"]
`)
	write("network/redis.yaml", `
id: tcp-redis
info:
  name: Redis
  severity: info
tcp:
  - inputs:
      - data: "PING\r\n"
    matchers:
      - type: word
        words: ["PONG"]
`)
	write("legacy/old.yaml", `
id: legacy-old
info:
  name: Legacy Old
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/old"
    matchers:
      - type: word
        words: ["old"]
`)
	waitDirMtimesSettled(t, dir)
}

// snapshotDirMtimes 采集模板目录树内所有目录的 mtime。
func snapshotDirMtimes(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	m := map[string]int64{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil || !d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		m[p] = info.ModTime().UnixNano()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// waitDirMtimesSettled 等待目录 mtime 稳定：NTFS 目录时间戳更新有毫秒级延迟
// 批处理/懒写（实测批量建树后约 5-10ms 内仍可能变化），测试建索引前必须
// 等稳定，否则会把平台级时间戳延迟误当成业务失效。
func waitDirMtimesSettled(t *testing.T, dir string) {
	t.Helper()
	prev := snapshotDirMtimes(t, dir)
	stable := 0
	for i := 0; i < 400; i++ { // 最多 ~2s
		time.Sleep(5 * time.Millisecond)
		cur := snapshotDirMtimes(t, dir)
		same := len(cur) == len(prev)
		for k, v := range cur {
			if prev[k] != v {
				same = false
				break
			}
		}
		if same {
			stable++
			if stable >= 2 {
				return
			}
		} else {
			stable = 0
		}
		prev = cur
	}
	t.Fatal("目录 mtime 未在 2s 内稳定")
}

// waitDirMtimesChanged 等待目录 mtime 反映变更（平台时间戳延迟写入的兜底），
// 避免测试在「OS 尚未记录变更」的窗口里断言业务失效检测。
func waitDirMtimesChanged(t *testing.T, dir string, before map[string]int64) {
	t.Helper()
	for i := 0; i < 400; i++ { // 最多 ~2s
		cur := snapshotDirMtimes(t, dir)
		same := len(cur) == len(before)
		for k, v := range cur {
			if before[k] != v {
				same = false
				break
			}
		}
		if !same {
			waitDirMtimesSettled(t, dir)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("目录 mtime 未在 2s 内反映变更")
}

// TestIndexHotCacheHitNoRebuild 目录戳不变：热路径不重写缓存、不重复解码，
// 返回同一份 entries（memo 复用）。
func TestIndexHotCacheHitNoRebuild(t *testing.T) {
	resetIndexMemo()
	dir := t.TempDir()
	writeHotCorpus(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	reads := withCacheReadCounter(t)

	cold, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(cold) == 0 {
		t.Fatal("冷构建应产出条目")
	}
	st1, err := os.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	readsAfterCold := reads.Load()

	// 第一次热调用：memo 已有（冷构建落盘后写入）→ 不应读缓存文件。
	hot1, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != readsAfterCold {
		t.Fatalf("热路径 memo 命中却读了缓存文件: %d → %d", readsAfterCold, got)
	}
	if !reflect.DeepEqual(cold, hot1) {
		t.Fatal("热路径 entries 与冷构建不一致")
	}
	if len(hot1) > 0 && &hot1[0] != &cold[0] {
		t.Fatal("memo 命中应复用同一份 entries（未复用说明又重建/解码了）")
	}

	// 缓存文件未被重写（没有发生重建）。
	st2, err := os.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	if st2.ModTime() != st1.ModTime() || st2.Size() != st1.Size() {
		t.Fatalf("目录戳未变却重写了缓存文件: %v/%d → %v/%d",
			st1.ModTime(), st1.Size(), st2.ModTime(), st2.Size())
	}

	// 清掉 memo 后：热路径应读一次缓存（解码），再调用则再次 memo 命中。
	resetIndexMemo()
	if _, err := Index(dir, cache); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != readsAfterCold+1 {
		t.Fatalf("memo 清空后应读缓存 1 次，实际 %d", got-readsAfterCold)
	}
	if _, err := Index(dir, cache); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != readsAfterCold+1 {
		t.Fatalf("二次热调用仍读缓存文件: %d", got-readsAfterCold)
	}
}

// TestIndexHotInvalidation 模板目录增/删/改名：下一次 Index 必须感知
// （重建后的 entries 与全量冷重建逐条相等）。
func TestIndexHotInvalidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{
			name: "新增文件",
			mutate: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "http", "cves", "new.yaml")
				if err := os.WriteFile(p, []byte(`
id: new-tpl
info:
  name: New Template
  severity: high
http:
  - method: GET
    path: "{{BaseURL}}/new"
    matchers:
      - type: word
        words: ["new"]
`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "新增目录+文件",
			mutate: func(t *testing.T, dir string) {
				sub := filepath.Join(dir, "http", "newcat")
				if err := os.MkdirAll(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(sub, "x.yaml"), []byte(`
id: newcat-x
info:
  name: Newcat X
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/x"
    matchers:
      - type: word
        words: ["x"]
`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "删除文件",
			mutate: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "http", "panels", "panel.yaml")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "改名文件",
			mutate: func(t *testing.T, dir string) {
				old := filepath.Join(dir, "http", "cves", "cve-a.yaml")
				if err := os.Rename(old, filepath.Join(dir, "http", "cves", "cve-a-renamed.yaml")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "删除整个目录",
			mutate: func(t *testing.T, dir string) {
				if err := os.RemoveAll(filepath.Join(dir, "http", "panels")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "根目录新增文件",
			mutate: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "root.yaml"), []byte(`
id: root-tpl
info:
  name: Root Template
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/root"
    matchers:
      - type: word
        words: ["root"]
`), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			resetIndexMemo()
			dir := t.TempDir()
			writeHotCorpus(t, dir)
			cache := filepath.Join(t.TempDir(), "idx.json")
			if _, err := Index(dir, cache); err != nil {
				t.Fatal(err)
			}
			before := snapshotDirMtimes(t, dir)
			c.mutate(t, dir)
			waitDirMtimesChanged(t, dir, before)
			got, err := Index(dir, cache)
			if err != nil {
				t.Fatal(err)
			}
			want, err := indexLegacyForTest(dir, "") // 全量冷重建（参考真值）
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("目录变化未被感知（entries 与全量重建不等）\n got=%d 条\nwant=%d 条", len(got), len(want))
			}
			// 缓存应已按新目录树重写：目录戳与全量 walk 结果一致
			waitDirMtimesSettled(t, dir)
			cached := readCacheForTest(t, cache)
			if !reflect.DeepEqual(cached.Dirs, mustWalkStamps(t, dir)) {
				t.Fatal("重建后的缓存目录戳与当前目录树不一致")
			}
		})
	}
}

// TestIndexHotSchemaUpgradeRebuild 旧 schema 缓存必须失效并整库重建一次。
func TestIndexHotSchemaUpgradeRebuild(t *testing.T) {
	resetIndexMemo()
	dir := t.TempDir()
	writeHotCorpus(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	cold, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟旧版本 v9 缓存（无目录戳）
	data, err := json.Marshal(cacheFile{Schema: cacheSchema - 1, Files: 999, Entries: cold})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, data, 0o644); err != nil {
		t.Fatal(err)
	}
	resetIndexMemo()
	reads := withCacheReadCounter(t)
	got, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cold) {
		t.Fatal("旧 schema 缓存失效后重建的 entries 与首次冷构建不一致")
	}
	if reads.Load() == 0 {
		t.Fatal("旧 schema 缓存应被读取校验后拒绝（读计数为 0 说明跳过校验）")
	}
	cached := readCacheForTest(t, cache)
	if cached.Schema != cacheSchema {
		t.Fatalf("重建后缓存 schema=%d, want %d", cached.Schema, cacheSchema)
	}
	if len(cached.Dirs) == 0 {
		t.Fatal("重建后缓存应包含目录戳")
	}
	// IndexCached 对旧 schema 返回 nil（升级后重建完成前不静默返回旧条目）
	oldData, _ := json.Marshal(cacheFile{Schema: cacheSchema - 1, Entries: cold})
	if err := os.WriteFile(cache, oldData, 0o644); err != nil {
		t.Fatal(err)
	}
	resetIndexMemo()
	if entries := IndexCached(cache); entries != nil {
		t.Fatal("IndexCached 不应接受旧 schema 缓存")
	}
}

// TestIndexHotEquivalence 同一语料：冷构建 / 热路径 / 旧顺序实现条目逐条相等。
func TestIndexHotEquivalence(t *testing.T) {
	resetIndexMemo()
	dir := t.TempDir()
	writeEquivCorpus(t, dir)
	waitDirMtimesSettled(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	cold, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	hot, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := indexLegacyForTest(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cold, hot) {
		t.Fatalf("热路径 entries 与冷构建不等: cold=%d hot=%d", len(cold), len(hot))
	}
	if !reflect.DeepEqual(cold, legacy) {
		t.Fatalf("新实现 entries 与旧顺序实现不等: new=%d old=%d", len(cold), len(legacy))
	}
}

// TestIndexCachedMemo 只读缓存版同样复用 memo；缓存文件变化后自然失效。
func TestIndexCachedMemo(t *testing.T) {
	resetIndexMemo()
	dir := t.TempDir()
	writeHotCorpus(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	full, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	resetIndexMemo()
	reads := withCacheReadCounter(t)

	first := IndexCached(cache)
	if !reflect.DeepEqual(first, full) {
		t.Fatal("IndexCached 首次解码结果与 Index 不一致")
	}
	if reads.Load() != 1 {
		t.Fatalf("IndexCached 首次应读缓存 1 次，实际 %d", reads.Load())
	}
	second := IndexCached(cache)
	if !reflect.DeepEqual(second, first) {
		t.Fatal("IndexCached 二次结果不一致")
	}
	if reads.Load() != 1 {
		t.Fatalf("IndexCached memo 命中仍读了缓存: %d", reads.Load())
	}
	// 缓存文件被改写（内容变化 → size 变化）→ memo 失效，读到新内容。
	trimmed, err := json.Marshal(cacheFile{Schema: cacheSchema, Files: 1, Dirs: mustWalkStamps(t, dir), Entries: full[:1]})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, trimmed, 0o644); err != nil {
		t.Fatal(err)
	}
	third := IndexCached(cache)
	if len(third) != 1 {
		t.Fatalf("缓存改写后 IndexCached 应返回新内容（1 条），实际 %d 条", len(third))
	}
	if reads.Load() != 2 {
		t.Fatalf("缓存改写后应重新读 1 次，实际总读 %d", reads.Load())
	}
}

// TestIndexHotCacheCorrupt 损坏缓存 / 缺目录戳：回落重建而不是返回坏数据。
func TestIndexHotCacheCorrupt(t *testing.T) {
	resetIndexMemo()
	dir := t.TempDir()
	writeHotCorpus(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	cold, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"损坏 JSON", []byte("{not json")},
		{"空目录戳", mustMarshal(t, cacheFile{Schema: cacheSchema, Files: 1, Entries: cold})},
		{"schema 不符", mustMarshal(t, cacheFile{Schema: 1, Files: 1, Dirs: mustWalkStamps(t, dir), Entries: cold})},
	} {
		if err := os.WriteFile(cache, tc.data, 0o644); err != nil {
			t.Fatal(err)
		}
		resetIndexMemo()
		got, err := Index(dir, cache)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, cold) {
			t.Fatalf("%s: 重建结果与冷构建不一致", tc.name)
		}
	}
}

// ---- 测试辅助 ----

func readCacheForTest(t *testing.T, cache string) cacheFile {
	t.Helper()
	data, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var c cacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func mustWalkStamps(t *testing.T, dir string) []dirStamp {
	t.Helper()
	_, stamps, err := walkTemplateFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return stamps
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
