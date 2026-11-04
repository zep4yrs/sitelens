package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
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

// ---- CP-06 持久化分层/归档 ----

// resultAt 构造指定扫描时间的样本结果（年度归档分组用）。
func resultAt(host, scannedAt string, techs ...string) *engine.Result {
	res := sampleResult(host, host, 0)
	res.ScannedAt = scannedAt
	res.Technologies = make([]engine.Tech, 0, len(techs))
	for _, name := range techs {
		res.Technologies = append(res.Technologies, engine.Tech{Name: name, Categories: []string{"cms"}})
	}
	return res
}

// loadYearDoc 读取并解析 archive/<year>.jsonl（C-01 append-only 分片）为
// 测试视图 archiveYearFile（Scans 按文件行序）。旧格式断言保持等价。
func loadYearDoc(t *testing.T, dir string, year int) archiveYearFile {
	t.Helper()
	path := filepath.Join(dir, "archive", fmt.Sprintf("%04d.jsonl", year))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读年度归档分片 %d: %v", year, err)
	}
	yf := archiveYearFile{Year: year}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec ScanRecord
		if uerr := json.Unmarshal([]byte(line), &rec); uerr != nil {
			t.Fatalf("年度归档分片 %d 行非法 JSON: %v\n%s", year, uerr, line)
		}
		yf.Scans = append(yf.Scans, rec)
	}
	return yf
}

// loadIndexDoc 读取并解析 archive/index.json。
func loadIndexDoc(t *testing.T, dir string) ArchiveIndex {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "archive", archiveIndexName))
	if err != nil {
		t.Fatalf("读归档索引: %v", err)
	}
	var idx ArchiveIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatalf("归档索引非法 JSON: %v", err)
	}
	return idx
}

// hostsOf 摘要列表 → host 列表（失败信息用）。
func hostsOf(list []ScanSummary) []string {
	out := make([]string, len(list))
	for i := range list {
		out[i] = list[i].Host
	}
	return out
}

// hostsOfScan 记录列表 → host 列表（失败信息用）。
func hostsOfScan(recs []ScanRecord) []string {
	out := make([]string, len(recs))
	for i := range recs {
		out[i] = recs[i].Host
	}
	return out
}

// TestTieredArchiveTrigger 超过阈值自动归档：主库只留 keep 条，旧记录进
// dataDir/archive/<year>.json + index.json；既有 Store.List/Get 只看主库，
// Tiered.List/Get 跨档透明。
func TestTieredArchiveTrigger(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00", "Nginx"), nil)
	}
	// 既有 API：主库只保留最近 3 条
	if got := len(tv.Store.List(10, "")); got != 3 {
		t.Fatalf("主库应保留 3 条，实际 %d", got)
	}
	// 分层视图：跨档透明读到 5 条（新→旧）
	list := tv.List(10, "")
	want := []string{"h5.com", "h4.com", "h3.com", "h2.com", "h1.com"}
	if len(list) != len(want) {
		t.Fatalf("跨档应读到 %d 条，实际 %v", len(want), hostsOf(list))
	}
	for i := range want {
		if list[i].Host != want[i] {
			t.Fatalf("跨档顺序应为 %v，实际 %v", want, hostsOf(list))
		}
	}
	// 年度文件按 ScannedAt 年份分组，按 id 升序
	yf := loadYearDoc(t, dir, 2025)
	if yf.Year != 2025 || len(yf.Scans) != 2 {
		t.Fatalf("2025 年度归档异常: year=%d n=%d", yf.Year, len(yf.Scans))
	}
	if yf.Scans[0].Host != "h1.com" || yf.Scans[1].Host != "h2.com" {
		t.Fatalf("年度归档内容/顺序异常: %v", hostsOfScan(yf.Scans))
	}
	// 索引记录条数与 id 区间
	idx := loadIndexDoc(t, dir)
	if idx.Version != archiveIndexVersion || len(idx.Files) != 1 {
		t.Fatalf("索引结构异常: %+v", idx)
	}
	ent := idx.Files[0]
	if ent.Year != 2025 || ent.Count != 2 || ent.MinID != 1 || ent.MaxID != 2 || ent.Bytes <= 0 {
		t.Fatalf("索引项异常: %+v", ent)
	}
	// 既有 Store.Get 只看主库；Tiered.Get 跨档可取完整记录
	if r := tv.Store.Get(1); r != nil {
		t.Fatalf("既有 Store.Get 不应看到归档记录: %+v", r)
	}
	arch := tv.Get(1)
	if arch == nil || arch.Host != "h1.com" || arch.Result == nil {
		t.Fatalf("Tiered.Get 应跨档读到归档记录: %+v", arch)
	}
}

// TestTieredCrossArchiveRead 跨档读取：多年度文件、limit、tech 过滤、缺失 id。
func TestTieredCrossArchiveRead(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	tv.Save(resultAt("a.com", "2024-01-02 03:04:05", "ArchOnly"), nil)
	tv.Save(resultAt("b.com", "2024-06-01 00:00:00", "Common"), nil)
	tv.Save(resultAt("c.com", "2025-02-01 00:00:00", "Common"), nil)
	tv.Save(resultAt("d.com", "2025-03-01 00:00:00", "Common"), nil)
	tv.Save(resultAt("e.com", "2026-01-01 00:00:00", "Common"), nil)

	all := tv.List(10, "")
	if len(all) != 5 || all[0].Host != "e.com" || all[4].Host != "a.com" {
		t.Fatalf("跨档全量读取异常: %v", hostsOf(all))
	}
	// limit 生效（截断最新 N 条）
	top := tv.List(2, "")
	if len(top) != 2 || top[0].Host != "e.com" || top[1].Host != "d.com" {
		t.Fatalf("limit 截断异常: %v", hostsOf(top))
	}
	if got := tv.List(0, ""); len(got) != 0 {
		t.Fatalf("limit<=0 应返回空列表（同既有语义）: %v", hostsOf(got))
	}
	// tech 过滤跨档命中（ArchOnly 只在归档层）
	archOnly := tv.List(10, "archonly")
	if len(archOnly) != 1 || archOnly[0].Host != "a.com" {
		t.Fatalf("跨档 tech 过滤异常: %v", hostsOf(archOnly))
	}
	// 两个年度文件（2024 / 2025）；2026 记录还在主库
	idx := loadIndexDoc(t, dir)
	if len(idx.Files) != 2 || idx.Files[0].Year != 2024 || idx.Files[1].Year != 2025 {
		t.Fatalf("年度索引异常: %+v", idx.Files)
	}
	// Get：归档命中 / 不存在
	if r := tv.Get(1); r == nil || r.Host != "a.com" || r.Result == nil {
		t.Fatalf("归档记录应可读: %+v", r)
	}
	if r := tv.Get(999); r != nil {
		t.Fatalf("不存在 id 应返回 nil: %+v", r)
	}
}

// TestTieredKeepAndStats 上限：每次 Save 后主库都不超过 keep；统计口径正确。
func TestTieredKeepAndStats(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
		if n := len(tv.Store.List(100, "")); n > 3 {
			t.Fatalf("第 %d 次保存后主库超过 keep=3: %d", i+1, n)
		}
	}
	stats := tv.ArchiveStats()
	if stats["keep"] != 3 || stats["main"] != 3 || stats["archived"] != 7 || stats["total"] != 10 {
		t.Fatalf("归档统计口径异常: %v", stats)
	}
	if stats["files"] != 1 || stats["index_rebuilt"] != false {
		t.Fatalf("文件数/索引状态异常: %v", stats)
	}
	years, ok := stats["years"].([]int)
	if !ok || len(years) != 1 || years[0] != 2025 {
		t.Fatalf("年份统计异常: %v", stats["years"])
	}
	// 默认阈值 2000
	if DefaultArchiveThreshold != 2000 {
		t.Fatalf("默认阈值应为 2000，实际 %d", DefaultArchiveThreshold)
	}
	tvDef, err := NewTiered(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if tvDef.Keep() != DefaultArchiveThreshold || tvDef.ArchiveStats()["keep"] != DefaultArchiveThreshold {
		t.Fatalf("keep<=0 应回落到默认阈值: keep=%d", tvDef.Keep())
	}
}

// TestArchiveNowManual 手动归档：默认阈值下不触发、显式 keep 触发、幂等。
func TestArchiveNowManual(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	// 默认阈值 2000：5 条不触发，也不创建归档目录
	if n, err := s.ArchiveNow(); err != nil || n != 0 {
		t.Fatalf("未超默认阈值不应归档: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "archive")); err == nil {
		t.Fatal("未触发归档时不应创建 archive 目录")
	}
	// 显式 keep=2 → 归档 3 条
	if n, err := s.ArchiveNowKeep(2); err != nil || n != 3 {
		t.Fatalf("ArchiveNowKeep(2) 应归档 3 条: n=%d err=%v", n, err)
	}
	if got := len(s.List(10, "")); got != 2 {
		t.Fatalf("手动归档后主库应剩 2 条: %d", got)
	}
	stats := s.ArchiveStats()
	if stats["main"] != 2 || stats["archived"] != 3 || stats["total"] != 5 {
		t.Fatalf("手动归档统计异常: %v", stats)
	}
	// 幂等：再归档 0 条；keep<=0 回落默认阈值也 0 条
	if n, err := s.ArchiveNowKeep(2); err != nil || n != 0 {
		t.Fatalf("重复归档应为 0: n=%d err=%v", n, err)
	}
	if n, err := s.ArchiveNowKeep(0); err != nil || n != 0 {
		t.Fatalf("keep<=0 回落默认阈值应为 0: n=%d err=%v", n, err)
	}
}

// TestArchiveIndexRebuild 索引缺失/损坏自动重建；未入索引的年度文件被拾取。
func TestArchiveIndexRebuild(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	indexPath := filepath.Join(dir, "archive", archiveIndexName)
	// 1) 索引被删：重建
	if err := os.Remove(indexPath); err != nil {
		t.Fatal(err)
	}
	stats := tv.ArchiveStats()
	if stats["archived"] != 3 || stats["files"] != 1 || stats["index_rebuilt"] != true {
		t.Fatalf("索引缺失应重建: %v", stats)
	}
	if _, err := os.Stat(indexPath); err != nil {
		t.Fatalf("重建后应写回索引: %v", err)
	}
	if got := len(tv.List(10, "")); got != 5 {
		t.Fatalf("索引重建后跨档读取应正常: %v", hostsOf(tv.List(10, "")))
	}
	// 2) 索引损坏：隔离留档后重建
	if err := os.WriteFile(indexPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	tv2, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	stats = tv2.ArchiveStats()
	if stats["archived"] != 3 || stats["index_rebuilt"] != true {
		t.Fatalf("损坏索引应重建: %v", stats)
	}
	if data, err := os.ReadFile(indexPath); err != nil || !json.Valid(data) {
		t.Fatalf("损坏索引应被合法索引替换: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "archive", "index.json.*.corrupt")); len(matches) == 0 {
		t.Fatal("损坏索引应隔离留档")
	}
	// 3) 年度文件已写、索引未更新（中途崩溃）：读取时自愈拾取
	extra := archiveYearFile{Year: 2023, Scans: []ScanRecord{{
		ScanSummary: ScanSummary{ID: 99, Host: "extra.com", ScannedAt: "2023-01-01 00:00:00"},
	}}}
	if err := atomicWriteJSON(filepath.Join(dir, "archive", "2023.json"), &extra); err != nil {
		t.Fatal(err)
	}
	if got := len(tv2.List(10, "")); got != 6 {
		t.Fatalf("未入索引的年度文件应被拾取: %v", hostsOf(tv2.List(10, "")))
	}
}

// TestArchiveCorruptYearFileSkip 损坏年度文件跳过：读取不 panic、其它年份仍可读、
// 原始损坏字节保留（便于人工抢救）、ArchiveStats 可查 corrupt_files。
func TestArchiveCorruptYearFileSkip(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	tv.Save(resultAt("a.com", "2024-05-01 10:00:00"), nil) // id1 → 2024
	tv.Save(resultAt("b.com", "2025-05-01 10:00:00"), nil) // id2 → 2025
	tv.Save(resultAt("c.com", "2025-06-01 10:00:00"), nil) // id3 → 归档 id1
	tv.Save(resultAt("d.com", "2025-07-01 10:00:00"), nil) // id4 → 归档 id2
	// C-01 新格式下"损坏可查"分两条路径：① 旧格式 v1 文件损坏（迁移解析失败，
	// 原字节保留）；② append-only 分片损坏（重建时跳过）。这里构造 ①：
	// 移除已写出的 2024 分片，放一个损坏的旧格式 2024.json 模拟历史遗留损坏文件。
	corruptPath := filepath.Join(dir, "archive", "2024.json")
	if err := os.Remove(filepath.Join(dir, "archive", "2024.jsonl")); err != nil {
		t.Fatalf("移除 2024 分片: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte("{{{ broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	tv2, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	list := tv2.List(10, "")
	if len(list) != 3 { // 主库 2 条 + 2025 归档 1 条（2024 跳过）
		t.Fatalf("损坏年度文件应跳过，实际 %v", hostsOf(list))
	}
	if tv2.Get(1) != nil {
		t.Fatal("损坏归档里的记录应不可读")
	}
	if tv2.Get(2) == nil {
		t.Fatal("未损坏年度文件里的记录应可读")
	}
	stats := tv2.ArchiveStats()
	corrupt, ok := stats["corrupt_files"].([]string)
	if !ok || len(corrupt) != 1 || corrupt[0] != "2024.json" {
		t.Fatalf("应报告损坏文件: %v", stats)
	}
	if stats["archived"] != 1 {
		t.Fatalf("统计应只计未损坏归档: %v", stats)
	}
	if data, err := os.ReadFile(corruptPath); err != nil || !strings.Contains(string(data), "broken") {
		t.Fatalf("损坏文件原始字节应保留: %v", err)
	}
}

// TestArchiveAtomicWritesClean 归档写入原子：无 .tmp 残留，所有归档文件内容合法。
// C-01 起年度归档是 append-only JSONL（整文件不是单个 JSON 文档）→ 分片按行校验，
// 其余文件（索引/墓碑/旧格式 .bak）仍要求整份合法 JSON。
func TestArchiveAtomicWritesClean(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	assertNoTempLeftover(t, dir)
	assertNoTempLeftover(t, filepath.Join(dir, "archive"))
	entries, err := os.ReadDir(filepath.Join(dir, "archive"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, rerr := os.ReadFile(filepath.Join(dir, "archive", e.Name()))
		if rerr != nil {
			t.Fatalf("归档文件 %s 不可读: %v", e.Name(), rerr)
		}
		if strings.HasSuffix(e.Name(), ".jsonl") {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				if !json.Valid([]byte(line)) {
					t.Fatalf("归档分片 %s 存在非法 JSON 行: %s", e.Name(), line)
				}
			}
			continue
		}
		if !json.Valid(data) {
			t.Fatalf("归档文件 %s 非合法 JSON", e.Name())
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "history.json")); err != nil || !json.Valid(data) {
		t.Fatalf("主库文件应保持合法 JSON: %v", err)
	}
}

// TestTieredDeleteAndClearAll 归档层删除 + 清空含归档（隐私：不留正文）。
func TestTieredDeleteAndClearAll(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	// 归档 id1/2/3，主库 id4/5
	if !tv.Delete(1) {
		t.Fatal("应能删除归档记录")
	}
	if tv.Get(1) != nil {
		t.Fatal("删除后不应再读到")
	}
	if !tv.Delete(4) {
		t.Fatal("应能删除主库记录")
	}
	if tv.Delete(999) {
		t.Fatal("不存在的 id 应返回 false")
	}
	if got := len(tv.List(10, "")); got != 3 {
		t.Fatalf("删除后应剩 3 条，实际 %v", hostsOf(tv.List(10, "")))
	}
	// 清空：主库 1 条 + 归档 2 条 = 3 条；归档目录移除
	if n := tv.ClearAll(); n != 3 {
		t.Fatalf("ClearAll 应返回主库+归档总数 3，实际 %d", n)
	}
	if got := len(tv.List(10, "")); got != 0 {
		t.Fatalf("清空后应无记录: %v", hostsOf(tv.List(10, "")))
	}
	if _, err := os.Stat(filepath.Join(dir, "archive")); err == nil {
		t.Fatal("清空后归档目录应移除（隐私操作不留正文）")
	}
	stats := tv.ArchiveStats()
	if stats["main"] != 0 || stats["archived"] != 0 || stats["total"] != 0 {
		t.Fatalf("清空后统计应归零: %v", stats)
	}
}

// TestTieredArchiveFailureDoesNotBreakSave 归档不可用（磁盘/权限）时不阻断保存：
// 既有 JSONL 裁剪兜底、主库有界、ArchiveNow 明确报错。
func TestTieredArchiveFailureDoesNotBreakSave(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	// 让 archive 目录无法创建：同名路径放普通文件
	if err := os.WriteFile(filepath.Join(dir, "archive"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t, func() {
		for i := 0; i < 5; i++ {
			if id := tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil); id != int64(i+1) {
				t.Fatalf("归档失败不应影响 Save 返回 id: %d", id)
			}
		}
	})
	if !strings.Contains(stderr, "分层归档失败") {
		t.Fatalf("归档失败应有 stderr 提示（不静默）: %q", stderr)
	}
	// 主库不会无限增长：既有 Save 的 JSONL 裁剪兜底（max = keep+1 = 3）
	if n := len(tv.Store.List(100, "")); n > 3 {
		t.Fatalf("归档失败时主库应由既有裁剪兜底，实际 %d", n)
	}
	// 既有 JSONL 归档兜底保留被裁记录（不丢数据）
	data, err := os.ReadFile(filepath.Join(dir, "history.archive.jsonl"))
	if err != nil || !strings.Contains(string(data), "h1.com") {
		t.Fatalf("既有 JSONL 归档应兜底: %v", err)
	}
	if _, err := tv.ArchiveNow(); err == nil {
		t.Fatal("归档目录不可用时 ArchiveNow 应返回明确错误")
	}
}

// TestWrapTieredExistingStore 包装既有 *Store：保留已加载记录，接线后自动归档。
func TestWrapTieredExistingStore(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.Save(resultAt(fmt.Sprintf("pre%d.com", i+1), "2025-01-01 00:00:00"), nil)
	}
	tv := WrapTiered(s, 2)
	if tv.Keep() != 2 {
		t.Fatalf("keep 应为 2: %d", tv.Keep())
	}
	tv.Save(resultAt("new.com", "2025-01-02 00:00:00"), nil)
	if n := len(s.List(100, "")); n != 2 {
		t.Fatalf("包装后主库应保持 keep=2，实际 %d", n)
	}
	if n := len(tv.List(100, "")); n != 4 {
		t.Fatalf("包装后跨档应读到 4 条，实际 %v", hostsOf(tv.List(100, "")))
	}
	if tv.Get(1) == nil {
		t.Fatal("包装后应能跨档读到既有旧记录")
	}
}
