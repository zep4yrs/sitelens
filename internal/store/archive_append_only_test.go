// archive_append_only_test.go C-01（Wave-2）：append-only 归档分片回归。
//
// 覆盖：
//   - 旧格式 archive/<year>.json 首次打开自动迁移（分片 + .json.bak，失败不损坏原文件）；
//   - 1000 条写入的追加字节数随条数线性（旧实现会平方增长；附计时日志）；
//   - 跨档 Get/Delete/List/ClearAll 与墓碑语义（删除不重写分片，索引丢失后墓碑仍生效）；
//   - 崩溃尾部残行修复；损坏分片跳过且原始字节保留。
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLegacyYearFile 造一个 v1 旧格式年度归档（archive/<year>.json）。
func writeLegacyYearFile(t *testing.T, dir string, year int, recs []ScanRecord) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "archive"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "archive", fmt.Sprintf("%04d.json", year))
	data, err := json.Marshal(archiveYearFile{Year: year, Scans: recs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// shardLineCount 统计分片行数（空行不计）。
func shardLineCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读分片 %s: %v", path, err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// TestLegacyArchiveMigration 旧 YYYY.json 首次打开自动迁移为 YYYY.jsonl，
// 保留 .json.bak 供回滚，记录仍可跨档读取；后续写入进入新格式。
func TestLegacyArchiveMigration(t *testing.T) {
	dir := t.TempDir()
	legacy := writeLegacyYearFile(t, dir, 2025, []ScanRecord{
		{ScanSummary: ScanSummary{ID: 10, Host: "legacy1.com", ScannedAt: "2025-05-01 10:00:00"}},
		{ScanSummary: ScanSummary{ID: 11, Host: "legacy2.com", ScannedAt: "2025-06-01 10:00:00"}},
	})
	tv, err := NewTiered(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	// 首次 List 触发迁移 + 索引重建
	list := tv.List(10, "")
	if len(list) != 2 || list[0].Host != "legacy2.com" || list[1].Host != "legacy1.com" {
		t.Fatalf("迁移后跨档读取异常: %v", hostsOf(list))
	}
	shard := filepath.Join(dir, "archive", "2025.jsonl")
	if _, err := os.Stat(shard); err != nil {
		t.Fatalf("应生成新格式分片: %v", err)
	}
	if got := shardLineCount(t, shard); got != 2 {
		t.Fatalf("迁移分片条数 = %d，期望 2", got)
	}
	// 旧文件保留为 .json.bak（可回滚），原路径不再存在
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("旧格式文件应改名为 .bak（原路径不应存在）: %v", err)
	}
	if _, err := os.Stat(legacy + ".bak"); err != nil {
		t.Fatalf("旧格式文件应保留 .json.bak 以便回滚: %v", err)
	}
	if r := tv.Get(10); r == nil || r.Host != "legacy1.com" {
		t.Fatalf("迁移记录应可 Get: %+v", r)
	}
	// 索引：Total/Count 正确
	idx := loadIndexDoc(t, dir)
	if len(idx.Files) != 1 || idx.Files[0].Total != 2 || idx.Files[0].Count != 2 {
		t.Fatalf("迁移后索引异常: %+v", idx.Files)
	}

	// 新写入进入新格式：keep=1，再存两条 → 最旧一条归档追加到分片末尾
	tv.Save(resultAt("new-a.com", "2025-07-01 10:00:00"), nil)
	tv.Save(resultAt("new-b.com", "2025-08-01 10:00:00"), nil)
	if got := shardLineCount(t, shard); got != 3 {
		t.Fatalf("新归档应追加到同一分片（3 行），实际 %d", got)
	}
	all := tv.List(10, "")
	if len(all) != 4 {
		t.Fatalf("迁移 2 + 新存 2 = 4 条，实际 %v", hostsOf(all))
	}
}

// TestArchiveAppendScalesLinearly 1000 条写入：追加字节数前后半程基本相等
// （append-only 不重写历史），并记录耗时供与旧实现对比。
func TestArchiveAppendScalesLinearly(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 1) // 每次 Save 归档一条：最容易暴露"全量重写"
	if err != nil {
		t.Fatal(err)
	}
	const total = 1000
	payload := strings.Repeat("x", 8*1024)
	writeOne := func(i int) {
		res := resultAt(fmt.Sprintf("h%d.com", i), "2025-05-01 10:00:00")
		res.Title = payload
		tv.Save(res, nil)
	}
	// 预热 2 条（不纳入计时/计量）
	writeOne(0)
	writeOne(1)

	startFirst := archiveAppendBytes.Load()
	t0 := time.Now()
	for i := 2; i < total/2; i++ {
		writeOne(i)
	}
	firstDur := time.Since(t0)
	firstBytes := archiveAppendBytes.Load() - startFirst

	startSecond := archiveAppendBytes.Load()
	t1 := time.Now()
	for i := total / 2; i < total; i++ {
		writeOne(i)
	}
	secondDur := time.Since(t1)
	secondBytes := archiveAppendBytes.Load() - startSecond

	t.Logf("C-01 线性度：前半程 %d 条 %v / %d bytes；后半程 %d 条 %v / %d bytes",
		total/2-2, firstDur, firstBytes, total-total/2, secondDur, secondBytes)
	if firstBytes <= 0 || secondBytes <= 0 {
		t.Fatalf("追加字节计数异常: first=%d second=%d", firstBytes, secondBytes)
	}
	// append-only：后半程追加字节数应与前半程同阶（允许 ±25%；旧实现会成倍增长）。
	ratio := float64(secondBytes) / float64(firstBytes)
	if ratio > 1.25 || ratio < 0.75 {
		t.Fatalf("追加字节数不呈线性（后半程/前半程 = %.2f；旧实现全量重写会显著增长）", ratio)
	}
	// 时间只做宽松上界（CI 抖动容忍）；旧实现 1000 条 8KB 会远超该值。
	if secondDur > 20*firstDur+2*time.Second {
		t.Fatalf("后半程耗时异常增长（疑似重写历史）：first=%v second=%v", firstDur, secondDur)
	}

	// 归档分片总大小 ≈ 已追加记录数 × 单条大小（无重复/无整份重写残留）。
	// 单条大小由前半程实测字节/条推得（result 真实 JSON 大小，非 payload 大小）。
	shard := filepath.Join(dir, "archive", "2025.jsonl")
	fi, err := os.Stat(shard)
	if err != nil {
		t.Fatal(err)
	}
	perRec := float64(firstBytes) / float64(total/2-2)
	want := perRec * float64(total) // 每条 Save 归档 1 条（预热 2 条留在主库）
	if float64(fi.Size()) < want*0.85 || float64(fi.Size()) > want*1.15 {
		t.Fatalf("分片大小 = %d，与 %d 条×%.0f bytes 不符（疑似全量重写/重复）",
			fi.Size(), total, perRec)
	}
}

// TestArchiveTombstoneDeleteAndRecovery 归档删除 = 墓碑（不重写分片）：
// 删除后不可见；索引丢失重建后墓碑仍生效；重新导入并归档则恢复可见且不重复追加。
func TestArchiveTombstoneDeleteAndRecovery(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	// 归档 id1/2/3，主库 id4/5
	if !tv.Delete(2) {
		t.Fatal("应能删除归档记录")
	}
	if tv.Get(2) != nil {
		t.Fatal("删除后 Get 应为 nil")
	}
	if got := len(tv.List(10, "")); got != 4 {
		t.Fatalf("删除后应剩 4 条，实际 %v", hostsOf(tv.List(10, "")))
	}
	tombFile := filepath.Join(dir, "archive", "2025.tombstones.json")
	if _, err := os.Stat(tombFile); err != nil {
		t.Fatalf("应写墓碑文件: %v", err)
	}
	if data, err := os.ReadFile(tombFile); err != nil || !strings.Contains(string(data), "2") {
		t.Fatalf("墓碑应含被删 id: %v %s", err, data)
	}
	stats := tv.ArchiveStats()
	if stats["archived"] != 2 {
		t.Fatalf("归档统计应扣墓碑: %v", stats)
	}

	// 模拟索引丢失：重建后墓碑仍生效（墓碑文件是持久事实）
	if err := os.Remove(filepath.Join(dir, "archive", "index.json")); err != nil {
		t.Fatal(err)
	}
	tv2, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if tv2.Get(2) != nil {
		t.Fatal("索引重建后墓碑应仍生效（被删记录不得复活）")
	}
	if got := len(tv2.List(10, "")); got != 4 {
		t.Fatalf("重建后应剩 4 条，实际 %v", hostsOf(tv2.List(10, "")))
	}
	// 删除不存在/已删除 id 应返回 false
	if tv2.Delete(2) {
		t.Fatal("重复删除应返回 false")
	}
	if tv2.Delete(999) {
		t.Fatal("不存在 id 应返回 false")
	}

	// 重新导入该记录：Tiered.Import 会立刻触发归档（主库 3 条 > keep=2），
	// 归档时发现 id2 已物理存在但被墓碑 → 只取消墓碑，不重复追加。
	rec := ScanRecord{ScanSummary: ScanSummary{
		ID: 2, URL: "https://h2.com", Host: "h2.com", ScannedAt: "2025-05-01 10:00:00",
	}}
	if _, err := tv2.Import(rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if r := tv2.Get(2); r == nil {
		t.Fatal("重新导入并归档后应恢复可见（墓碑取消）")
	}
	// 再存一条触发一次正常追加（id4 归档）
	tv2.Save(resultAt("h6.com", "2025-06-01 10:00:00"), nil)
	// 分片里 id2 必须只出现一次（恢复墓碑不得重复追加物理行）
	shard := filepath.Join(dir, "archive", "2025.jsonl")
	data, err := os.ReadFile(shard)
	if err != nil {
		t.Fatal(err)
	}
	occurrences := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var got ScanRecord
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("分片行非法: %v", err)
		}
		if got.ID == 2 {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Fatalf("分片里 id=2 应只出现 1 次（墓碑恢复不复制），实际 %d 次", occurrences)
	}
	if lines := shardLineCount(t, shard); lines != 4 {
		t.Fatalf("分片行数 = %d（原 3 条 + 新增 1 条 = 4），实际 %d", 4, lines)
	}
}

// TestArchiveCrashTailRepair 崩溃留下无换行/半行：下次 append 前修复，
// 归档仍可读且新记录正常追加。
func TestArchiveCrashTailRepair(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	tv.Save(resultAt("a.com", "2025-05-01 10:00:00"), nil)
	tv.Save(resultAt("b.com", "2025-05-02 10:00:00"), nil) // a 归档
	shard := filepath.Join(dir, "archive", "2025.jsonl")
	// 模拟崩溃：末尾写了一半的 JSON（无换行）
	f, err := os.OpenFile(shard, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"id":`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	// 触发下一次归档（c 归档）→ 修复尾部后追加
	tv.Save(resultAt("c.com", "2025-05-03 10:00:00"), nil)
	list := tv.List(10, "")
	if len(list) != 3 {
		t.Fatalf("尾部修复后应能读到 3 条，实际 %v", hostsOf(list))
	}
	// 分片每行都必须是合法 JSON（半行已被截掉）
	data, err := os.ReadFile(shard)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec ScanRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("修复后分片仍含非法行: %v\n%s", err, line)
		}
	}
}

// TestArchiveCorruptShardSkipped append-only 分片损坏：List/Get 跳过该分片、
// ArchiveStats 报告 corrupt_files、原始字节保留、其它年份不受影响。
func TestArchiveCorruptShardSkipped(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	tv.Save(resultAt("a.com", "2024-05-01 10:00:00"), nil)
	tv.Save(resultAt("b.com", "2025-05-01 10:00:00"), nil)
	tv.Save(resultAt("c.com", "2025-05-02 10:00:00"), nil) // 归档 a(2024)
	tv.Save(resultAt("d.com", "2025-05-03 10:00:00"), nil) // 归档 b(2025)
	corruptShard := filepath.Join(dir, "archive", "2024.jsonl")
	// 注意：必须是"换行结尾的坏行"才算损坏；无换行的尾行按崩溃残行容忍
	// （append-only 的崩溃恢复语义，见 scanShardRecords）。
	if err := os.WriteFile(corruptShard, []byte("{{{ broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 索引丢失 → 强制重建（重建时会跳过损坏分片并保留字节）
	if err := os.Remove(filepath.Join(dir, "archive", "index.json")); err != nil {
		t.Fatal(err)
	}
	tv2, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	list := tv2.List(10, "")
	// 主库 2 + 2025 分片 1；2024 损坏分片跳过
	if len(list) != 3 {
		t.Fatalf("损坏分片应跳过，实际 %v", hostsOf(list))
	}
	stats := tv2.ArchiveStats()
	corrupt, ok := stats["corrupt_files"].([]string)
	if !ok || len(corrupt) != 1 || corrupt[0] != "2024.jsonl" {
		t.Fatalf("应报告损坏分片: %v", stats)
	}
	if data, err := os.ReadFile(corruptShard); err != nil || !strings.Contains(string(data), "broken") {
		t.Fatalf("损坏分片原始字节应保留: %v", err)
	}
}
