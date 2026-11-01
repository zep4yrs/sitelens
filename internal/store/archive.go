// CP-06 持久化分层/归档（additive；不改 store.go 既有 API 与行为）。
//
// 主库 history.json 只保留最近 keep 条（默认 2000）；更旧的记录按
// ScannedAt 年份移入 dataDir/archive/<year>.json（原子写），索引
// dataDir/archive/index.json 记录每个年度文件的条数 / id 区间 / 字节数。
//
// 透明读取：Tiered 视图内嵌 *Store（复用 Save/Delete/ClearAll/HistoryStats/
// Graph… 全部既有能力），只把 List/Get 扩展为跨档透明读取——方法签名与既有
// List/Get 完全一致，接线方把 store.New 换成 store.NewTiered（或 WrapTiered
// 包装既有实例）即可，调用点无需改签名。
//
// 容错：
//   - 索引缺失 / 损坏 / 与目录不一致 → 扫描年度文件重建（损坏索引隔离留档）；
//   - 年度文件损坏 → List/Get 跳过该文件（不 panic），ArchiveStats 的
//     corrupt_files 可查，原始字节保留便于人工抢救；
//   - 写入顺序「先年度文件、后索引」：中途失败时索引落后，下次读取自愈。
//
// 隐私/权限：归档文件与索引 0600（复用 atomicWriteJSON 的临时文件+rename）；
// ClearAll 连归档目录一起清空（清空是隐私操作，不留正文）；归档不删图目录
// （记录仍可跨档 Get，图是证据），只有 Delete/ClearAll 删图。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

const (
	// DefaultArchiveThreshold 分层归档默认保留条数：主库超过该值即把最旧
	// 记录移入年度归档（CP-06；接线方可用 NewTiered(dir, n) 覆盖）。
	DefaultArchiveThreshold = 2000

	archiveDirName      = "archive"
	archiveIndexName    = "index.json"
	archiveIndexVersion = 1
)

// ArchiveIndexEntry 单个年度归档文件的索引项。
type ArchiveIndexEntry struct {
	File      string `json:"file"` // 相对 archive 目录的文件名，如 2025.json
	Year      int    `json:"year"`
	Count     int    `json:"count"`
	MinID     int64  `json:"min_id"`
	MaxID     int64  `json:"max_id"`
	Bytes     int64  `json:"bytes"`
	UpdatedAt string `json:"updated_at"`
}

// ArchiveIndex 归档索引（archive/index.json）。
type ArchiveIndex struct {
	Version   int                 `json:"version"`
	UpdatedAt string              `json:"updated_at"`
	Files     []ArchiveIndexEntry `json:"files"`
}

// archiveYearFile 单个年度归档文件（archive/<year>.json）。
type archiveYearFile struct {
	Year  int          `json:"year"`
	Scans []ScanRecord `json:"scans"`
}

// archivedEntry 归档记录的轻量视图：摘要 + 小写技术名（供跨档 List 过滤）。
type archivedEntry struct {
	summary ScanSummary
	techs   []string
}

// hasTech 技术名包含匹配（与既有 scanHasTech 同语义）。
func (e *archivedEntry) hasTech(techLower string) bool {
	for _, n := range e.techs {
		if strings.Contains(n, techLower) {
			return true
		}
	}
	return false
}

// archiveDirOf 归档目录（dataDir/archive）。
func (s *Store) archiveDirOf() string { return filepath.Join(s.dataDir, archiveDirName) }

// archiveYearOf 记录归入的年份：优先解析 ScannedAt（兼容历史格式），
// 解析失败回退当前年份（不丢记录）。
func archiveYearOf(rec *ScanRecord) int {
	for _, layout := range []string{
		"2006-01-02 15:04:05", time.RFC3339, "2006-01-02T15:04:05", "2006-01-02",
	} {
		if t, err := time.Parse(layout, strings.TrimSpace(rec.ScannedAt)); err == nil {
			return t.Year()
		}
	}
	return time.Now().Year()
}

// recordCount 主库记录数（只读快照）。
func (s *Store) recordCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.h.Scans)
}

// ---- 归档写入（Store 层；不改既有 API 签名） ----

// ArchiveNow 立即把超出默认阈值（DefaultArchiveThreshold）的最旧记录移入
// 年度归档，返回归档条数。
func (s *Store) ArchiveNow() (int, error) {
	return s.ArchiveNowKeep(DefaultArchiveThreshold)
}

// ArchiveNowKeep 立即归档到主库只保留 keep 条（keep<=0 用默认阈值）。
// 先写年度文件与索引，成功后才裁剪主库：写入失败不动主库，可重试且不丢数据。
func (s *Store) ArchiveNowKeep(keep int) (int, error) {
	if keep <= 0 {
		keep = DefaultArchiveThreshold
	}
	return s.archiveKeep(keep)
}

// archiveKeep 归档到只保留 keep 条（内部实现；调用方不得持 s.mu）。
func (s *Store) archiveKeep(keep int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	over := len(s.h.Scans) - keep
	if over <= 0 {
		return 0, nil
	}
	ordered := make([]ScanRecord, len(s.h.Scans))
	copy(ordered, s.h.Scans)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	victims := ordered[:over]
	if err := s.writeArchiveLocked(victims); err != nil {
		return 0, fmt.Errorf("写入年度归档失败：%w", err)
	}
	// 年度文件落盘成功后才裁剪主库（失败路径主库保持原样，重试安全）。
	// 归档记录仍可经跨档 Get 读取，因此不删图目录（图是证据）。
	s.h.Scans = append([]ScanRecord(nil), ordered[over:]...)
	s.flush()
	return over, nil
}

// writeArchiveLocked 把 recs 追加进对应年份的归档文件并更新索引（调用方持 s.mu）。
// 顺序：先写年度文件（原子），全部成功后再写索引（原子）；中途失败时索引
// 落后于年度文件，下次 loadOrRebuildIndex 检测到不一致会重建。
func (s *Store) writeArchiveLocked(recs []ScanRecord) error {
	dir := s.archiveDirOf()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	byYear := make(map[int][]ScanRecord, 4)
	for i := range recs {
		y := archiveYearOf(&recs[i])
		byYear[y] = append(byYear[y], recs[i])
	}
	years := make([]int, 0, len(byYear))
	for y := range byYear {
		years = append(years, y)
	}
	sort.Ints(years)

	idx, _, _, err := loadOrRebuildIndex(dir)
	if err != nil {
		return err
	}
	for _, y := range years {
		path := filepath.Join(dir, fmt.Sprintf("%04d.json", y))
		yf := archiveYearFile{Year: y}
		old, rerr := readArchiveYearFile(path)
		switch {
		case rerr == nil:
			yf.Scans = old.Scans
		case errors.Is(rerr, os.ErrNotExist):
			// 该年份首次归档
		default:
			// 年度文件损坏：隔离留档后按空文件重建（不覆盖原始字节）
			quarantineCorrupt(path, rerr)
		}
		yf.Scans = append(yf.Scans, byYear[y]...)
		sort.SliceStable(yf.Scans, func(i, j int) bool { return yf.Scans[i].ID < yf.Scans[j].ID })
		if err := atomicWriteJSON(path, &yf); err != nil {
			return err
		}
		info, ierr := os.Stat(path)
		if ierr != nil {
			return ierr
		}
		upsertArchiveEntry(idx, ArchiveIndexEntry{
			File: filepath.Base(path), Year: y, Count: len(yf.Scans),
			MinID: yf.Scans[0].ID, MaxID: yf.Scans[len(yf.Scans)-1].ID,
			Bytes: info.Size(), UpdatedAt: time.Now().Format(time.RFC3339),
		})
	}
	return writeArchiveIndex(dir, idx)
}

// upsertArchiveEntry 写入/更新索引项（按文件名去重）。
func upsertArchiveEntry(idx *ArchiveIndex, ent ArchiveIndexEntry) {
	for i := range idx.Files {
		if idx.Files[i].File == ent.File {
			idx.Files[i] = ent
			return
		}
	}
	idx.Files = append(idx.Files, ent)
}

// writeArchiveIndex 排序并原子写索引。
func writeArchiveIndex(dir string, idx *ArchiveIndex) error {
	idx.Version = archiveIndexVersion
	idx.UpdatedAt = time.Now().Format(time.RFC3339)
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].Year < idx.Files[j].Year })
	return atomicWriteJSON(filepath.Join(dir, archiveIndexName), idx)
}

// ---- 索引读取 / 重建 / 损坏容错 ----

// readArchiveYearFile 读取年度归档文件；不存在返回 os.ErrNotExist。
func readArchiveYearFile(path string) (*archiveYearFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var yf archiveYearFile
	if err := json.Unmarshal(data, &yf); err != nil {
		return nil, err
	}
	if yf.Scans == nil {
		yf.Scans = []ScanRecord{}
	}
	return &yf, nil
}

// parseArchiveYearName 解析年度文件名（NNNN.json，1970..9999）。
func parseArchiveYearName(name string) (int, bool) {
	if !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	base := strings.TrimSuffix(name, ".json")
	if len(base) != 4 {
		return 0, false
	}
	y, err := strconv.Atoi(base)
	if err != nil || y < 1970 || y > 9999 {
		return 0, false
	}
	return y, true
}

// indexStale 索引与目录不一致（有未入索引 / 已缺失 / 大小变化的年度文件）。
// 目录不可读时视为过期（触发重建，由重建路径返回具体错误）。
func indexStale(dir string, idx *ArchiveIndex) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	files := make(map[string]int64, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := parseArchiveYearName(e.Name()); !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			return true
		}
		files[e.Name()] = info.Size()
	}
	if len(files) != len(idx.Files) {
		return true
	}
	for _, ent := range idx.Files {
		size, ok := files[ent.File]
		if !ok || size != ent.Bytes {
			return true
		}
	}
	return false
}

// loadOrRebuildIndex 读索引；缺失 / 损坏 / 与目录不一致时从年度文件重建。
// 返回索引、损坏（被跳过）的年度文件名、是否发生重建、错误。
func loadOrRebuildIndex(dir string) (*ArchiveIndex, []string, bool, error) {
	indexPath := filepath.Join(dir, archiveIndexName)
	data, err := os.ReadFile(indexPath)
	if err == nil {
		var idx ArchiveIndex
		jerr := json.Unmarshal(data, &idx)
		if jerr == nil && idx.Version == archiveIndexVersion && !indexStale(dir, &idx) {
			return &idx, nil, false, nil
		}
		if jerr != nil {
			quarantineCorrupt(indexPath, jerr) // 损坏索引隔离留档后重建
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, err
	}
	return rebuildArchiveIndex(dir)
}

// rebuildArchiveIndex 扫描年度文件重建索引；损坏文件跳过并列入 corrupt。
func rebuildArchiveIndex(dir string) (*ArchiveIndex, []string, bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		// 尚未产生归档：空索引，不创建目录/文件
		return &ArchiveIndex{Version: archiveIndexVersion}, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	idx := &ArchiveIndex{Version: archiveIndexVersion}
	var corrupt []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		year, ok := parseArchiveYearName(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(dir, e.Name())
		yf, rerr := readArchiveYearFile(path)
		if rerr != nil {
			corrupt = append(corrupt, e.Name())
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			corrupt = append(corrupt, e.Name())
			continue
		}
		ent := ArchiveIndexEntry{
			File: e.Name(), Year: year, Count: len(yf.Scans), Bytes: info.Size(),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}
		if n := len(yf.Scans); n > 0 {
			ent.MinID, ent.MaxID = yf.Scans[0].ID, yf.Scans[0].ID
			for i := 1; i < n; i++ {
				if yf.Scans[i].ID < ent.MinID {
					ent.MinID = yf.Scans[i].ID
				}
				if yf.Scans[i].ID > ent.MaxID {
					ent.MaxID = yf.Scans[i].ID
				}
			}
		}
		idx.Files = append(idx.Files, ent)
	}
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].Year < idx.Files[j].Year })
	if werr := writeArchiveIndex(dir, idx); werr != nil {
		// 索引写失败不阻断读取：内存索引仍可用，下次读取继续尝试自愈
		fmt.Fprintf(os.Stderr, "警告：归档索引写入失败（%s）：%v\n", filepath.Join(dir, archiveIndexName), werr)
	}
	return idx, corrupt, true, nil
}

// ArchiveStats 归档统计（Store 层，默认阈值口径；只读，必要时自愈重建索引）。
// 字段：keep/main/archived/total/files/years/bytes/corrupt_files/index_rebuilt。
func (s *Store) ArchiveStats() map[string]any {
	main := s.recordCount()
	stats := map[string]any{
		"keep": DefaultArchiveThreshold, "main": main, "archived": 0, "total": main,
		"files": 0, "years": []int{}, "bytes": int64(0),
		"corrupt_files": []string{}, "index_rebuilt": false,
	}
	dir := s.archiveDirOf()
	idx, corrupt, rebuilt, err := loadOrRebuildIndex(dir)
	stats["index_rebuilt"] = rebuilt
	if len(corrupt) > 0 {
		stats["corrupt_files"] = corrupt
	}
	if err != nil {
		stats["error"] = err.Error()
		return stats
	}
	years := make([]int, 0, len(idx.Files))
	var archived int
	var bytes int64
	for _, ent := range idx.Files {
		archived += ent.Count
		bytes += ent.Bytes
		years = append(years, ent.Year)
	}
	stats["archived"], stats["files"], stats["bytes"], stats["years"] = archived, len(idx.Files), bytes, years
	stats["total"] = main + archived
	return stats
}

// ---- Tiered 分层视图：List/Get 跨档透明（签名与既有 API 一致） ----

// Tiered 分层归档视图：内嵌 *Store 复用既有全部能力，只把 List/Get 扩展为
// 主库 + 年度归档透明合并，并在 Save/Import 后按 keep 自动归档。
//
// 接线（不改既有 API 签名）：
//
//	tv, err := store.NewTiered(dataDir, 2000) // 或 store.WrapTiered(existingStore, 2000)
//	tv.Save(res, opts)                        // 超阈值自动归档
//	tv.List(20, "") / tv.Get(id)              // 跨档透明
//	tv.ArchiveNow() / tv.ArchiveStats()       // 手动归档 / 统计
//
// 未使用本视图时既有 Store 行为完全不变（List/Get 仍只看主库）。
type Tiered struct {
	*Store
	keep       int
	archiveDir string

	mu        sync.Mutex
	loaded    bool
	archCache []archivedEntry // 归档摘要缓存（按 ID 降序）
}

// NewTiered 打开分层归档存储：主库保留最近 keep 条（<=0 用默认 2000），
// 更旧记录自动移入 dataDir/archive/<year>.json。
func NewTiered(dataDir string, keep int) (*Tiered, error) {
	if keep <= 0 {
		keep = DefaultArchiveThreshold
	}
	// 主库内存上限 = keep+1：给「刚超阈值」的瞬时记录留位，避免既有 Save
	// 的内建裁剪（写 history.archive.jsonl）抢在分层归档之前。
	s, err := New(dataDir, keep+1)
	if err != nil {
		return nil, err
	}
	return WrapTiered(s, keep), nil
}

// WrapTiered 把既有 *Store 包装成分层视图（复用其 dataDir 与内存数据）。
func WrapTiered(s *Store, keep int) *Tiered {
	if keep <= 0 {
		keep = DefaultArchiveThreshold
	}
	s.mu.Lock()
	if s.max < keep+1 {
		s.max = keep + 1
	}
	s.mu.Unlock()
	return &Tiered{
		Store:      s,
		keep:       keep,
		archiveDir: filepath.Join(s.dataDir, archiveDirName),
	}
}

// Keep 当前保留条数阈值。
func (t *Tiered) Keep() int { return t.keep }

// Save 保存扫描结果：主库超过 keep 条时自动把最旧记录移入年度归档。
// 归档失败不阻断保存（主库继续增长，下一次 Save 由既有 JSONL 裁剪兜底，不丢数据）。
func (t *Tiered) Save(res *engine.Result, options map[string]any) int64 {
	id := t.Store.Save(res, options)
	t.archiveOverflow()
	return id
}

// Import 迁移导入：同 Save，导入后超阈值自动归档。
func (t *Tiered) Import(rec ScanRecord) (int64, error) {
	id, err := t.Store.Import(rec)
	if err == nil {
		t.archiveOverflow()
	}
	return id, err
}

// archiveOverflow 主库超过 keep 条时归档（失败只在 stderr 提示，不阻断主路径）。
func (t *Tiered) archiveOverflow() {
	if t.Store.recordCount() <= t.keep {
		return
	}
	if _, err := t.Store.ArchiveNowKeep(t.keep); err != nil {
		fmt.Fprintf(os.Stderr, "警告：历史分层归档失败（%s）：%v\n", t.archiveDir, err)
		return
	}
	t.invalidate()
}

// ArchiveNow 立即归档到本视图的 keep 条（覆盖 Store 默认阈值口径）。
func (t *Tiered) ArchiveNow() (int, error) {
	return t.ArchiveNowKeep(t.keep)
}

// ArchiveNowKeep 立即归档到主库只保留 keep 条（<=0 用本视图阈值）。
func (t *Tiered) ArchiveNowKeep(keep int) (int, error) {
	if keep <= 0 {
		keep = t.keep
	}
	n, err := t.Store.ArchiveNowKeep(keep)
	if err == nil {
		t.invalidate()
	}
	return n, err
}

// ArchiveStats 归档统计（keep 为本视图阈值）。
func (t *Tiered) ArchiveStats() map[string]any {
	stats := t.Store.ArchiveStats()
	stats["keep"] = t.keep
	return stats
}

// invalidate 丢弃归档摘要缓存（归档/删除/清空后调用）。
func (t *Tiered) invalidate() {
	t.mu.Lock()
	t.loaded = false
	t.archCache = nil
	t.mu.Unlock()
}

// archivedEntries 归档记录轻量视图（按 ID 降序；损坏文件跳过；首次读缓存）。
func (t *Tiered) archivedEntries() []archivedEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.loaded {
		return t.archCache
	}
	t.loaded = true
	t.archCache = nil
	idx, _, _, err := loadOrRebuildIndex(t.archiveDir)
	if err != nil {
		return nil
	}
	var out []archivedEntry
	for _, ent := range idx.Files {
		yf, rerr := readArchiveYearFile(filepath.Join(t.archiveDir, ent.File))
		if rerr != nil {
			continue // 损坏文件跳过（ArchiveStats 可查 corrupt_files）
		}
		for i := range yf.Scans {
			out = append(out, archivedEntry{
				summary: yf.Scans[i].ScanSummary,
				techs:   techNames(&yf.Scans[i]),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].summary.ID > out[j].summary.ID })
	t.archCache = out
	return out
}

// mainEntries 主库记录轻量视图（按 ID 降序）。
func (t *Tiered) mainEntries() []archivedEntry {
	t.Store.mu.RLock()
	out := make([]archivedEntry, 0, len(t.Store.h.Scans))
	for i := range t.Store.h.Scans {
		r := &t.Store.h.Scans[i]
		out = append(out, archivedEntry{summary: r.ScanSummary, techs: techNames(r)})
	}
	t.Store.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].summary.ID > out[j].summary.ID })
	return out
}

// techNames 记录的技术名（小写，供 tech 过滤）。
func techNames(r *ScanRecord) []string {
	if r.Result == nil {
		return nil
	}
	out := make([]string, 0, len(r.Result.Technologies))
	for _, t := range r.Result.Technologies {
		out = append(out, strings.ToLower(t.Name))
	}
	return out
}

// List 历史列表（新→旧）：主库 + 年度归档透明合并；tech 过滤与既有语义一致。
// 签名与 Store.List 一致（limit<=0 返回空列表，同既有语义）。
func (t *Tiered) List(limit int, tech string) []ScanSummary {
	if limit <= 0 {
		return []ScanSummary{}
	}
	techLower := strings.ToLower(strings.TrimSpace(tech))
	main := t.mainEntries()
	arch := t.archivedEntries()
	out := make([]ScanSummary, 0, limit)
	i, j := 0, 0
	for len(out) < limit && (i < len(main) || j < len(arch)) {
		var pick *archivedEntry
		switch {
		case j >= len(arch):
			pick = &main[i]
			i++
		case i >= len(main):
			pick = &arch[j]
			j++
		case main[i].summary.ID > arch[j].summary.ID:
			pick = &main[i]
			i++
		default:
			pick = &arch[j]
			j++
		}
		if techLower != "" && !pick.hasTech(techLower) {
			continue
		}
		out = append(out, pick.summary)
	}
	return out
}

// Get 按 id 取完整记录：先主库，再按索引 id 区间定位年度归档文件。
// 签名与 Store.Get 一致；归档文件损坏时跳过（返回 nil）。
func (t *Tiered) Get(id int64) *ScanRecord {
	if r := t.Store.Get(id); r != nil {
		return r
	}
	idx, _, _, err := loadOrRebuildIndex(t.archiveDir)
	if err != nil {
		return nil
	}
	for _, ent := range idx.Files {
		if ent.Count == 0 || id < ent.MinID || id > ent.MaxID {
			continue
		}
		yf, rerr := readArchiveYearFile(filepath.Join(t.archiveDir, ent.File))
		if rerr != nil {
			continue // 损坏文件跳过
		}
		for i := range yf.Scans {
			if yf.Scans[i].ID == id {
				r := yf.Scans[i]
				return &r
			}
		}
	}
	return nil
}

// Delete 删除一条历史（主库或归档层；归档层删除会重写年度文件并重建索引）。
// 图目录同步删除（与既有 Delete 的「不留孤儿」语义一致）。
func (t *Tiered) Delete(id int64) bool {
	if t.Store.Delete(id) {
		t.invalidate()
		return true
	}
	deleted, err := t.deleteArchived(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告：删除归档记录失败（%s）：%v\n", t.archiveDir, err)
		return false
	}
	if deleted {
		t.Store.deleteGraph(id)
		t.invalidate()
	}
	return deleted
}

// deleteArchived 从年度归档文件删除一条记录（重写文件 + 重建索引）。
func (t *Tiered) deleteArchived(id int64) (bool, error) {
	idx, _, _, err := loadOrRebuildIndex(t.archiveDir)
	if err != nil {
		return false, err
	}
	for _, ent := range idx.Files {
		if ent.Count == 0 || id < ent.MinID || id > ent.MaxID {
			continue
		}
		path := filepath.Join(t.archiveDir, ent.File)
		yf, rerr := readArchiveYearFile(path)
		if rerr != nil {
			continue
		}
		kept := make([]ScanRecord, 0, len(yf.Scans))
		found := false
		for i := range yf.Scans {
			if yf.Scans[i].ID == id {
				found = true
				continue
			}
			kept = append(kept, yf.Scans[i])
		}
		if !found {
			continue
		}
		if len(kept) == 0 {
			if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				return false, rerr
			}
		} else {
			yf.Scans = kept
			if werr := atomicWriteJSON(path, yf); werr != nil {
				return false, werr
			}
		}
		if _, _, _, rerr := rebuildArchiveIndex(t.archiveDir); rerr != nil {
			return false, rerr
		}
		return true, nil
	}
	return false, nil
}

// ClearAll 清空全部历史（含年度归档；隐私操作不保留归档正文）。
// 返回清除总条数（主库 + 归档），与既有「清除 N 条」语义兼容。
func (t *Tiered) ClearAll() int {
	archived := t.archivedCount()
	n := t.Store.ClearAll()
	if err := os.RemoveAll(t.archiveDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "警告：清理归档目录失败（%s）：%v\n", t.archiveDir, err)
	}
	t.invalidate()
	return n + archived
}

// archivedCount 归档记录总数（索引口径；索引不可读时返回 0）。
func (t *Tiered) archivedCount() int {
	idx, _, _, err := loadOrRebuildIndex(t.archiveDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, ent := range idx.Files {
		n += ent.Count
	}
	return n
}
