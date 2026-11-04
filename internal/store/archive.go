// CP-06 持久化分层/归档（additive；不改 store.go 既有 API 与行为）。
//
// 主库 history.json 只保留最近 keep 条（默认 2000）；更旧的记录按
// ScannedAt 年份移入 dataDir/archive/<year>.jsonl（**append-only 分片**，
// 每行一条 ScanRecord），索引 dataDir/archive/index.json 记录每个分片的
// 条数 / id 区间 / 字节数 / 时间范围。
//
// C-01（Wave-2）：原实现每次归档都「全量读年度 JSON + append + 全量重写」，
// 超过阈值后每次 Save 的 I/O 随归档量线性增长 → 累计平方级（240 条 8KB
// 实测 6.5s）。改为 append-only：
//   - 写：open(O_APPEND) 追加若干行 + fsync，只更新索引计数，不重写分片；
//   - 读：List/Get/Stats 流式扫描分片（按需），索引给 id 区间做定位；
//   - 删：append-only 下不重写数据，写 `<year>.tombstones.json` 墓碑 +
//     索引 Count 递减（跨档 Get/List/Delete/ClearAll 语义不变）；
//   - 旧格式 `archive/<year>.json`（v1 整份 JSON）首次打开自动迁移为
//     `<year>.jsonl`（临时文件 + rename，成功后旧文件改名为 `.json.bak`
//     保留回滚；解析失败/迁移失败**不删除也不改写**原文件）。
//
// 透明读取：Tiered 视图内嵌 *Store（复用 Save/Delete/ClearAll/HistoryStats/
// Graph… 全部既有能力），只把 List/Get 扩展为跨档透明读取——方法签名与既有
// List/Get 完全一致，接线方把 store.New 换成 store.NewTiered（或 WrapTiered
// 包装既有实例）即可，调用点无需改签名。
//
// 容错：
//   - 索引缺失 / 损坏 / 与目录不一致 → 扫描分片重建（损坏索引隔离留档）；
//   - 分片损坏 → List/Get 跳过该分片（不 panic），ArchiveStats 的
//     corrupt_files 可查，原始字节保留便于人工抢救；
//   - 崩溃留下的半行（append 未写完）→ 读侧容忍末尾半行；下次 append 前
//     修复分片尾部（保留末行换行 / 截掉未写完的半行）；
//   - 写入顺序「先分片、后索引」：中途失败时索引落后，下次读取自愈重建。
//
// 隐私/权限：归档分片/墓碑/索引 0600（复用 atomicWriteJSON 的临时文件+rename）；
// ClearAll 连归档目录一起清空（清空是隐私操作，不留正文）；归档不删图目录
// （记录仍可跨档 Get，图是证据），只有 Delete/ClearAll 删图。
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

const (
	// DefaultArchiveThreshold 分层归档默认保留条数：主库超过该值即把最旧
	// 记录移入年度归档（CP-06；接线方可用 NewTiered(dir, n) 覆盖）。
	DefaultArchiveThreshold = 2000

	archiveDirName      = "archive"
	archiveIndexName    = "index.json"
	archiveIndexVersion = 2 // v1: 年度整份 JSON；v2: append-only JSONL 分片

	archiveShardSuffix     = ".jsonl"
	archiveLegacySuffix    = ".json"
	archiveTombstoneSuffix = ".tombstones.json"
)

// archiveFileMu 串行化归档目录的「读-改-写」（迁移 / 索引重建 / 追加 /
// 墓碑 / 索引写）。多个 Tiered 方法（List/Get/Delete/Save）可并发调用，
// 而索引与分片是一致性单元，必须整体互斥。
var archiveFileMu sync.Mutex

// archiveAppendBytes 累计追加写入归档分片的字节数。
//
// C-01 回归的可观测口径：append-only 下每次 Save 的追加字节数与单条记录
// 大小同阶（不随历史增长）；旧实现每次重写整年文件，该值会随条数平方增长。
var archiveAppendBytes atomic.Int64

// ArchiveIndexEntry 单个年度归档分片的索引项。
type ArchiveIndexEntry struct {
	File      string `json:"file"` // 相对 archive 目录的文件名，如 2025.jsonl
	Year      int    `json:"year"`
	Count     int    `json:"count"` // 可见条数（= Total - 墓碑数）
	MinID     int64  `json:"min_id"`
	MaxID     int64  `json:"max_id"`
	Bytes     int64  `json:"bytes"`
	UpdatedAt string `json:"updated_at"`
	// Total 物理条数（含墓碑；append-only 下只增不减）。
	Total int `json:"total"`
	// 时间范围（ScannedAt 字符串的最小/最大值；同格式下可直接字典序比较）。
	FirstAt string `json:"first_at,omitempty"`
	LastAt  string `json:"last_at,omitempty"`

	// deleted 运行时墓碑集合（来自 <year>.tombstones.json；不落 index.json）。
	deleted map[int64]bool
}

// ArchiveIndex 归档索引（archive/index.json）。
type ArchiveIndex struct {
	Version   int                 `json:"version"`
	UpdatedAt string              `json:"updated_at"`
	Files     []ArchiveIndexEntry `json:"files"`
	// Corrupt 已知损坏、按设计跳过且**保留原字节**的分片/旧格式文件名。
	// 记住它可避免每次读取都重新解析损坏文件（并让 corrupt_files 稳定可查）。
	Corrupt []string `json:"corrupt,omitempty"`
}

// archiveYearFile 单个旧格式年度归档（archive/<year>.json，v1）与测试视图。
type archiveYearFile struct {
	Year  int          `json:"year"`
	Scans []ScanRecord `json:"scans"`
}

// archiveShardTombstones 单个分片的墓碑文件（archive/<year>.tombstones.json）。
type archiveShardTombstones struct {
	Version int     `json:"version"`
	Year    int     `json:"year"`
	IDs     []int64 `json:"ids"`
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

// ---- 路径 / 年份工具 ----

// archiveDirOf 归档目录（dataDir/archive）。
func (s *Store) archiveDirOf() string { return filepath.Join(s.dataDir, archiveDirName) }

// shardPath 某年份的 append-only 分片路径。
func shardPath(dir string, year int) string {
	return filepath.Join(dir, fmt.Sprintf("%04d%s", year, archiveShardSuffix))
}

// legacyPath 某年份的旧格式（v1 整份 JSON）路径。
func legacyPath(dir string, year int) string {
	return filepath.Join(dir, fmt.Sprintf("%04d%s", year, archiveLegacySuffix))
}

// tombstonePath 某年份的墓碑文件路径。
func tombstonePath(dir string, year int) string {
	return filepath.Join(dir, fmt.Sprintf("%04d%s", year, archiveTombstoneSuffix))
}

// parseShardName 解析分片文件名（NNNN.jsonl，1970..9999）。
func parseShardName(name string) (int, bool) {
	if !strings.HasSuffix(name, archiveShardSuffix) {
		return 0, false
	}
	return parseYearBase(strings.TrimSuffix(name, archiveShardSuffix))
}

// parseArchiveYearName 解析旧格式文件名（NNNN.json，1970..9999）。
func parseArchiveYearName(name string) (int, bool) {
	if !strings.HasSuffix(name, archiveLegacySuffix) {
		return 0, false
	}
	return parseYearBase(strings.TrimSuffix(name, archiveLegacySuffix))
}

func parseYearBase(base string) (int, bool) {
	if len(base) != 4 {
		return 0, false
	}
	y, err := strconv.Atoi(base)
	if err != nil || y < 1970 || y > 9999 {
		return 0, false
	}
	return y, true
}

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
// 先写分片与索引，成功后才裁剪主库：写入失败不动主库，可重试且不丢数据。
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
	// 分片落盘成功后才裁剪主库（失败路径主库保持原样，重试安全）。
	// 归档记录仍可经跨档 Get 读取，因此不删图目录（图是证据）。
	s.h.Scans = append([]ScanRecord(nil), ordered[over:]...)
	s.flush()
	return over, nil
}

// writeArchiveLocked 把 recs 追加进对应年份的 append-only 分片，并更新索引
// （调用方持 s.mu）。
//
// 顺序：先修复分片尾部 → 追加行 + fsync → 再写墓碑/索引（原子）。
// 中途失败时索引落后于分片，下次 loadOrRebuildIndex 检测到不一致会重建。
// 判重/恢复墓碑语义：
//   - 已物理写入过的 id 不再追加（防回灌/崩溃窗口/重试重复）；
//   - 若该 id 此前被墓碑删除，则**取消墓碑**（记录本就在分片里，恢复可见）；
//   - 新 id 追加到分片末尾。
func (s *Store) writeArchiveLocked(recs []ScanRecord) error {
	dir := s.archiveDirOf()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	archiveFileMu.Lock()
	defer archiveFileMu.Unlock()

	idx, corruptNames, _, err := loadOrRebuildIndexLocked(dir)
	if err != nil {
		return err
	}
	corruptSet := make(map[string]bool, len(corruptNames))
	for _, n := range corruptNames {
		corruptSet[n] = true
	}
	everIDs, err := s.archivedIDsLocked(dir)
	if err != nil {
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

	for _, y := range years {
		shard := shardPath(dir, y)
		name := filepath.Base(shard)
		if corruptSet[name] {
			// 目标分片已损坏：隔离留档（不丢原始字节）后按新分片重建。
			quarantineCorrupt(shard, errors.New("追加前发现分片损坏"))
			idx = dropIndexEntry(idx, y)
			corruptSet[name] = false
		}
		deleted, derr := readTombstonesLocked(dir, y)
		if derr != nil {
			return derr
		}
		ent := ensureIndexEntry(idx, y)
		ent.deleted = deleted

		var toAppend []ScanRecord
		tombChanged := false
		for _, rec := range byYear[y] {
			if everIDs[rec.ID] {
				if ent.deleted[rec.ID] {
					// 记录物理存在但此前被删除：恢复可见（不重复写行）。
					delete(ent.deleted, rec.ID)
					tombChanged = true
				}
				continue
			}
			toAppend = append(toAppend, rec)
			everIDs[rec.ID] = true
		}
		if tombChanged {
			if werr := writeTombstonesLocked(dir, y, ent.deleted); werr != nil {
				return werr
			}
		}
		if len(toAppend) > 0 {
			if aerr := appendShardRecords(shard, toAppend); aerr != nil {
				return aerr
			}
			ent.Total += len(toAppend)
			for i := range toAppend {
				rec := &toAppend[i]
				if ent.Total == len(toAppend) && i == 0 {
					ent.MinID, ent.MaxID = rec.ID, rec.ID
				} else {
					if rec.ID < ent.MinID {
						ent.MinID = rec.ID
					}
					if rec.ID > ent.MaxID {
						ent.MaxID = rec.ID
					}
				}
				updateTimeRange(ent, rec.ScannedAt)
			}
			if fi, serr := os.Stat(shard); serr == nil {
				ent.Bytes = fi.Size()
			}
		} else if ent.Total == 0 {
			// 全是重复 id 且无新增：不建空分片条目。
			idx = dropIndexEntry(idx, y)
			continue
		}
		ent.Count = ent.Total - len(ent.deleted)
		ent.UpdatedAt = time.Now().Format(time.RFC3339)
	}
	return writeArchiveIndexLocked(dir, idx)
}

// ensureIndexEntry 取（或新建）某年份索引项（返回指针，可就地更新）。
func ensureIndexEntry(idx *ArchiveIndex, year int) *ArchiveIndexEntry {
	for i := range idx.Files {
		if idx.Files[i].Year == year {
			return &idx.Files[i]
		}
	}
	idx.Files = append(idx.Files, ArchiveIndexEntry{
		File: fmt.Sprintf("%04d%s", year, archiveShardSuffix), Year: year,
	})
	return &idx.Files[len(idx.Files)-1]
}

// dropIndexEntry 移除某年份索引项（分片被隔离/无新增时）。
func dropIndexEntry(idx *ArchiveIndex, year int) *ArchiveIndex {
	out := idx.Files[:0]
	for _, e := range idx.Files {
		if e.Year != year {
			out = append(out, e)
		}
	}
	idx.Files = out
	return idx
}

// updateTimeRange 用记录的 ScannedAt 扩展索引的时间范围。
func updateTimeRange(ent *ArchiveIndexEntry, scannedAt string) {
	at := strings.TrimSpace(scannedAt)
	if at == "" {
		return
	}
	if ent.FirstAt == "" || at < ent.FirstAt {
		ent.FirstAt = at
	}
	if ent.LastAt == "" || at > ent.LastAt {
		ent.LastAt = at
	}
}

// appendShardRecords 追加若干条记录到分片末尾（O_APPEND + 一次 fsync）。
//
// 追加前修复尾部：上次崩溃可能留下「无换行的完整行」或「写了一半的残行」。
// 完整行补换行；残行截断（残行从未被索引/读取接受过，不构成已提交数据）。
func appendShardRecords(path string, recs []ScanRecord) error {
	if err := repairShardTail(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(0o600) // 历史遗留宽权限分片同样收紧（Windows 下仅只读位生效）
	bw := bufio.NewWriterSize(f, 64*1024)
	var written int64
	for i := range recs {
		line, merr := json.Marshal(&recs[i])
		if merr != nil {
			return fmt.Errorf("序列化归档记录 %d 失败：%w", recs[i].ID, merr)
		}
		if _, werr := bw.Write(append(line, '\n')); werr != nil {
			return werr
		}
		written += int64(len(line)) + 1
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	archiveAppendBytes.Add(written)
	return nil
}

// repairShardTail 修复分片尾部（见 appendShardRecords 注释）。
func repairShardTail(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // 新分片
		}
		return err
	}
	size := fi.Size()
	if size == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// 从尾部向前找最后一个换行。
	const chunk = 64 * 1024
	lastNL := int64(-1)
	buf := make([]byte, chunk)
	for end := size; end > 0 && lastNL < 0; {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		n, rerr := f.ReadAt(buf[:end-start], start)
		if rerr != nil && rerr != io.EOF {
			return rerr
		}
		for i := n - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				lastNL = start + int64(i)
				break
			}
		}
		end = start
	}
	tailStart := lastNL + 1
	if tailStart >= size {
		return nil // 末尾就是换行：无残行
	}
	tail := make([]byte, size-tailStart)
	if _, rerr := f.ReadAt(tail, tailStart); rerr != nil && rerr != io.EOF {
		return rerr
	}
	trimmed := strings.TrimSpace(string(tail))
	if trimmed == "" {
		return f.Truncate(tailStart) // 只有空白
	}
	var probe ScanRecord
	if json.Unmarshal([]byte(trimmed), &probe) == nil {
		// 完整行但缺换行：补一个换行，避免下一条粘连。
		if _, werr := f.WriteAt([]byte("\n"), size); werr != nil {
			return werr
		}
		return f.Sync()
	}
	// 半行：截掉（从未完整提交）。
	return f.Truncate(tailStart)
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

// writeArchiveIndexLocked 排序并原子写索引（调用方持 archiveFileMu）。
func writeArchiveIndexLocked(dir string, idx *ArchiveIndex) error {
	idx.Version = archiveIndexVersion
	idx.UpdatedAt = time.Now().Format(time.RFC3339)
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].Year < idx.Files[j].Year })
	return atomicWriteJSON(filepath.Join(dir, archiveIndexName), idx)
}

// ---- 分片读取 ----

// scanShardRecords 流式读取分片，逐条回调（回调返回 false 停止）。
//
// 返回 err != nil 表示分片损坏（非末尾半行）。末尾无换行的半行被容忍
// （崩溃残留，不当作整片损坏）；但若是首行即损坏 → 视为损坏。
func scanShardRecords(path string, fn func(rec ScanRecord) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64*1024)
	valid := 0
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				var rec ScanRecord
				if jerr := json.Unmarshal([]byte(trimmed), &rec); jerr != nil {
					if rerr == io.EOF {
						return nil // 末尾半行：容忍
					}
					return fmt.Errorf("归档分片 %s 损坏（offset 前已读 %d 条）：%w",
						filepath.Base(path), valid, jerr)
				}
				valid++
				if fn != nil && !fn(rec) {
					return nil
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// readTombstonesLocked 读分片墓碑（不存在返回空集合；调用方持 archiveFileMu）。
func readTombstonesLocked(dir string, year int) (map[int64]bool, error) {
	out := map[int64]bool{}
	data, err := os.ReadFile(tombstonePath(dir, year))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	var t archiveShardTombstones
	if jerr := json.Unmarshal(data, &t); jerr != nil {
		// 墓碑损坏：隔离留档后按空墓碑继续（宁可让已删记录暂时可见，
		// 也不能让整年归档不可读）。
		quarantineCorrupt(tombstonePath(dir, year), jerr)
		return out, nil
	}
	for _, id := range t.IDs {
		out[id] = true
	}
	return out, nil
}

// writeTombstonesLocked 原子写墓碑（ids 为空时删除墓碑文件）。
func writeTombstonesLocked(dir string, year int, deleted map[int64]bool) error {
	path := tombstonePath(dir, year)
	if len(deleted) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	ids := make([]int64, 0, len(deleted))
	for id := range deleted {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return atomicWriteJSON(path, archiveShardTombstones{Version: archiveIndexVersion, Year: year, IDs: ids})
}

// mergeTombstonesLocked 把墓碑合并进索引项并重算 Count（调用方持 archiveFileMu）。
func mergeTombstonesLocked(dir string, idx *ArchiveIndex) error {
	for i := range idx.Files {
		ent := &idx.Files[i]
		deleted, derr := readTombstonesLocked(dir, ent.Year)
		if derr != nil {
			return derr
		}
		ent.deleted = deleted
		if ent.Total > 0 {
			ent.Count = ent.Total - len(deleted)
			if ent.Count < 0 {
				ent.Count = 0
			}
		}
	}
	return nil
}

// ---- 旧格式迁移 ----

// migrateLegacyLocked 把 archive/<year>.json（v1）迁移为 <year>.jsonl。
//
// 返回迁移文件数与新发现（解析失败、原字节保留）的损坏文件名。
// 规则：
//   - 分片已存在（迁移过或已由新版本产生）→ 旧文件改名为 `.json.bak` 保留回滚；
//   - 分片不存在 → 写临时分片 + rename，成功后旧文件改名为 `.json.bak`；
//   - 解析失败 → 不改动、不删除原文件，列入 corrupt（由调用方持久化到索引，
//     避免每次读取都重新解析）。
func migrateLegacyLocked(dir string, knownCorrupt map[string]bool) (int, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	migrated := 0
	var corrupt []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		year, ok := parseArchiveYearName(name)
		if !ok {
			continue
		}
		if knownCorrupt[name] {
			corrupt = append(corrupt, name) // 已知损坏：保留原文件，不重复解析
			continue
		}
		oldPath := filepath.Join(dir, name)
		yf, rerr := readArchiveYearFile(oldPath)
		if rerr != nil {
			corrupt = append(corrupt, name)
			continue
		}
		shard := shardPath(dir, year)
		if _, serr := os.Stat(shard); errors.Is(serr, os.ErrNotExist) {
			if werr := writeShardAtomic(shard, yf.Scans); werr != nil {
				return migrated, corrupt, werr
			}
		} else if serr != nil {
			return migrated, corrupt, serr
		}
		// 迁移完成（或此前已完成）：旧文件留 .json.bak 供回滚。
		if rerr := os.Rename(oldPath, oldPath+".bak"); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return migrated, corrupt, rerr
		}
		migrated++
	}
	return migrated, corrupt, nil
}

// writeShardAtomic 把记录写成一个新分片（临时文件 + fsync + rename）。
func writeShardAtomic(shard string, recs []ScanRecord) error {
	tmp := shard + ".migrate.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 64*1024)
	for i := range recs {
		line, merr := json.Marshal(&recs[i])
		if merr != nil {
			f.Close()
			os.Remove(tmp)
			return merr
		}
		if _, werr := bw.Write(append(line, '\n')); werr != nil {
			f.Close()
			os.Remove(tmp)
			return werr
		}
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, shard); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readArchiveYearFile 读取旧格式年度归档文件；不存在返回 os.ErrNotExist。
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

// ---- 索引读取 / 重建 / 损坏容错 ----

// loadOrRebuildIndex 读索引；缺失 / 损坏 / 与目录不一致时从分片重建。
// 返回索引、损坏（被跳过）的文件名、是否发生重建、错误。
func loadOrRebuildIndex(dir string) (*ArchiveIndex, []string, bool, error) {
	archiveFileMu.Lock()
	defer archiveFileMu.Unlock()
	return loadOrRebuildIndexLocked(dir)
}

// loadOrRebuildIndexLocked 同 loadOrRebuildIndex（调用方持 archiveFileMu）。
func loadOrRebuildIndexLocked(dir string) (*ArchiveIndex, []string, bool, error) {
	indexPath := filepath.Join(dir, archiveIndexName)
	var cached *ArchiveIndex
	data, rerr := os.ReadFile(indexPath)
	if rerr == nil {
		var idx ArchiveIndex
		if jerr := json.Unmarshal(data, &idx); jerr != nil {
			quarantineCorrupt(indexPath, jerr) // 损坏索引隔离留档后重建
		} else if idx.Version == archiveIndexVersion {
			cached = &idx
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return nil, nil, false, rerr
	}

	knownCorrupt := map[string]bool{}
	if cached != nil {
		for _, n := range cached.Corrupt {
			knownCorrupt[n] = true
		}
	}
	migrated, newCorrupt, merr := migrateLegacyLocked(dir, knownCorrupt)
	if merr != nil {
		return nil, nil, false, merr
	}

	if cached != nil && migrated == 0 && !indexStaleLocked(dir, cached) {
		if err := mergeTombstonesLocked(dir, cached); err != nil {
			return nil, nil, false, err
		}
		corrupt := existingFiles(dir, cached.Corrupt)
		return cached, corrupt, false, nil
	}

	corruptIn := append([]string{}, existingCorrupt(cached)...)
	corruptIn = append(corruptIn, newCorrupt...)
	return rebuildArchiveIndexLocked(dir, corruptIn)
}

// existingCorrupt 取缓存索引里的损坏名单（可能为 nil）。
func existingCorrupt(idx *ArchiveIndex) []string {
	if idx == nil {
		return nil
	}
	return append([]string{}, idx.Corrupt...)
}

// existingFiles 过滤出目录里仍然存在的文件名（保持顺序）。
func existingFiles(dir string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// indexStale 索引与目录不一致（有未入索引 / 已缺失 / 大小变化 / 未知旧文件）。
// 目录不可读时视为过期（触发重建，由重建路径返回具体错误）。
func indexStaleLocked(dir string, idx *ArchiveIndex) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	shards := make(map[string]int64, len(entries))
	knownCorrupt := make(map[string]bool, len(idx.Corrupt))
	for _, n := range idx.Corrupt {
		knownCorrupt[n] = true
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, ok := parseShardName(name); ok {
			info, ierr := e.Info()
			if ierr != nil {
				return true
			}
			shards[name] = info.Size()
			continue
		}
		if _, ok := parseArchiveYearName(name); ok && !knownCorrupt[name] {
			return true // 未迁移/未登记的旧格式文件
		}
	}
	if len(shards) != len(idx.Files) {
		return true
	}
	for _, ent := range idx.Files {
		size, ok := shards[ent.File]
		if !ok || size != ent.Bytes {
			return true
		}
	}
	return false
}

// rebuildArchiveIndexLocked 扫描分片重建索引；损坏分片跳过并列入 corrupt。
func rebuildArchiveIndexLocked(dir string, corruptIn []string) (*ArchiveIndex, []string, bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		// 尚未产生归档：空索引，不创建目录/文件
		return &ArchiveIndex{Version: archiveIndexVersion}, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	idx := &ArchiveIndex{Version: archiveIndexVersion}
	corrupt := existingFiles(dir, corruptIn)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		year, ok := parseShardName(name)
		if !ok {
			continue
		}
		path := filepath.Join(dir, name)
		info, ierr := e.Info()
		if ierr != nil {
			corrupt = append(corrupt, name)
			continue
		}
		ent := ArchiveIndexEntry{
			File: name, Year: year, Bytes: info.Size(),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}
		scanErr := scanShardRecords(path, func(rec ScanRecord) bool {
			if ent.Total == 0 {
				ent.MinID, ent.MaxID = rec.ID, rec.ID
			} else {
				if rec.ID < ent.MinID {
					ent.MinID = rec.ID
				}
				if rec.ID > ent.MaxID {
					ent.MaxID = rec.ID
				}
			}
			ent.Total++
			updateTimeRange(&ent, rec.ScannedAt)
			return true
		})
		if scanErr != nil {
			corrupt = append(corrupt, name)
			continue
		}
		deleted, derr := readTombstonesLocked(dir, year)
		if derr != nil {
			return nil, nil, false, derr
		}
		ent.deleted = deleted
		ent.Count = ent.Total - len(deleted)
		if ent.Count < 0 {
			ent.Count = 0
		}
		idx.Files = append(idx.Files, ent)
	}
	sort.Slice(idx.Files, func(i, j int) bool { return idx.Files[i].Year < idx.Files[j].Year })
	idx.Corrupt = dedupeStrings(corrupt)
	if werr := writeArchiveIndexLocked(dir, idx); werr != nil {
		// 索引写失败不阻断读取：内存索引仍可用，下次读取继续尝试自愈
		fmt.Fprintf(os.Stderr, "警告：归档索引写入失败（%s）：%v\n", filepath.Join(dir, archiveIndexName), werr)
	}
	return idx, idx.Corrupt, true, nil
}

// dedupeStrings 去重并保持顺序。
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// archivedIDsLocked 返回已物理写入分片的 id 集合（调用方持 s.mu 与 archiveFileMu）。
// 首次调用扫描全部分片构建并缓存；之后 append 只需 O(1) 判重。
func (s *Store) archivedIDsLocked(dir string) (map[int64]bool, error) {
	if s.archiveIDs != nil {
		return s.archiveIDs, nil
	}
	ids := map[int64]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := parseShardName(e.Name()); !ok {
			continue
		}
		if serr := scanShardRecords(filepath.Join(dir, e.Name()), func(rec ScanRecord) bool {
			ids[rec.ID] = true
			return true
		}); serr != nil {
			// 损坏分片：保留字节并跳过（写入前已由 loadOrRebuildIndex 隔离/登记）。
			continue
		}
	}
	s.archiveIDs = ids
	return ids, nil
}

// resetArchiveCaches 清空归档缓存（ClearAll 后调用）。
func (s *Store) resetArchiveCaches() {
	s.mu.Lock()
	s.archiveIDs = nil
	s.mu.Unlock()
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
	// C-05：最近一次裁剪归档失败原因（/api/stats 归档面板可见，不再只有 stderr）。
	if aerr := s.ArchiveError(); aerr != "" {
		stats["archive_error"] = aerr
	}
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
// 更旧记录自动移入 dataDir/archive/<year>.jsonl。
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
	return t.SaveForTenant(res, options, "")
}

// SaveForTenant 同 Save，但把归属租户写入记录与归档分片（BL-5）。
func (t *Tiered) SaveForTenant(res *engine.Result, options map[string]any, tenant string) int64 {
	id := t.Store.SaveForTenant(res, options, tenant)
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

// archivedEntries 归档记录轻量视图（按 ID 降序；损坏分片跳过；首次读缓存）。
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
	for i := range idx.Files {
		ent := &idx.Files[i]
		if ent.Count == 0 {
			continue
		}
		path := filepath.Join(t.archiveDir, ent.File)
		if serr := scanShardRecords(path, func(rec ScanRecord) bool {
			if ent.deleted[rec.ID] {
				return true // 墓碑：对读侧不可见
			}
			out = append(out, archivedEntry{
				summary: rec.ScanSummary,
				techs:   techNames(&rec),
			})
			return true
		}); serr != nil {
			continue // 损坏分片跳过（ArchiveStats 可查 corrupt_files）
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
	return t.listFiltered(limit, tech, "")
}

// ListForTenant 历史列表（新→旧）：tenant 非空时只返回该租户记录（BL-5）。
// 归档分片里的记录同样带 tenant 字段（旧分片缺省 "" 视为 legacy）。
func (t *Tiered) ListForTenant(limit int, tech, tenant string) []ScanSummary {
	return t.listFiltered(limit, tech, strings.TrimSpace(tenant))
}

// listFiltered List/ListForTenant 的共同实现（tenant 为空 = 不过滤）。
func (t *Tiered) listFiltered(limit int, tech, tenant string) []ScanSummary {
	if limit <= 0 {
		return []ScanSummary{}
	}
	techLower := strings.ToLower(strings.TrimSpace(tech))
	main := t.mainEntries()
	arch := t.archivedEntries()
	out := make([]ScanSummary, 0, limit)
	// C-06：按 id 去重。主库与归档可能同时持有同一条记录（崩溃窗口：
	// 分片已写、主库 trim 未完成；或 Import 把归档记录导回主库），
	// 归并时同 id 只输出一次，避免 /api/history 出重复行。
	seen := make(map[int64]bool, limit)
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
		if tenant != "" && pick.summary.Tenant != tenant {
			continue
		}
		if techLower != "" && !pick.hasTech(techLower) {
			continue
		}
		if seen[pick.summary.ID] {
			continue
		}
		seen[pick.summary.ID] = true
		out = append(out, pick.summary)
	}
	return out
}

// GetForTenant 按 id 取完整记录并校验租户归属（不匹配返回 nil，server 映射 404）。
func (t *Tiered) GetForTenant(id int64, tenant string) *ScanRecord {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return t.Get(id)
	}
	rec := t.Get(id)
	if rec == nil || rec.Tenant != tenant {
		return nil
	}
	return rec
}

// DeleteForTenant 删除一条记录并校验租户归属（不匹配/不存在返回 false）。
func (t *Tiered) DeleteForTenant(id int64, tenant string) bool {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return t.Delete(id)
	}
	if rec := t.GetForTenant(id, tenant); rec == nil {
		return false
	}
	return t.Delete(id)
}

// HistoryStatsForTenant 历史统计（主库 + 归档，tenant 非空时只统计该租户）。
func (t *Tiered) HistoryStatsForTenant(tenant string) map[string]any {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return t.Store.HistoryStatsForTenant("")
	}
	// 先取 Store 侧（主库）统计以复用 backend/degraded 诊断键，再用跨档口径覆盖计数。
	stats := t.Store.HistoryStatsForTenant(tenant)
	hosts := map[string]bool{}
	total, n := 0, 0
	for _, list := range [][]archivedEntry{t.mainEntries(), t.archivedEntries()} {
		for i := range list {
			s := list[i].summary
			if s.Tenant != tenant {
				continue
			}
			hosts[s.Host] = true
			total += s.TechCount
			n++
		}
	}
	avg := 0.0
	if n > 0 {
		avg = math.Round(float64(total)/float64(n)*10) / 10
	}
	stats["scans"], stats["hosts"], stats["avg_techs"] = n, len(hosts), avg
	return stats
}

// Get 按 id 取完整记录：先主库，再按索引 id 区间定位分片流式查找。
// 签名与 Store.Get 一致；分片损坏时跳过（返回 nil）。
func (t *Tiered) Get(id int64) *ScanRecord {
	if r := t.Store.Get(id); r != nil {
		return r
	}
	idx, _, _, err := loadOrRebuildIndex(t.archiveDir)
	if err != nil {
		return nil
	}
	for i := range idx.Files {
		ent := &idx.Files[i]
		if ent.Count == 0 || id < ent.MinID || id > ent.MaxID {
			continue
		}
		if ent.deleted[id] {
			return nil // 已墓碑删除
		}
		var found *ScanRecord
		path := filepath.Join(t.archiveDir, ent.File)
		if serr := scanShardRecords(path, func(rec ScanRecord) bool {
			if rec.ID == id {
				r := rec
				found = &r
				return false
			}
			return true
		}); serr != nil {
			continue // 损坏分片跳过
		}
		if found != nil {
			return found
		}
	}
	return nil
}

// Delete 删除一条历史（主库或归档层；归档层用墓碑标记，不重写分片）。
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

// deleteArchived 从归档层删除一条记录：确认存在后写墓碑 + 更新索引计数。
//
// append-only 下数据行保留（不重写分片），读侧靠墓碑过滤；墓碑持久化在
// <year>.tombstones.json，索引丢失后 rebuild 也能恢复删除语义。
func (t *Tiered) deleteArchived(id int64) (bool, error) {
	archiveFileMu.Lock()
	defer archiveFileMu.Unlock()
	idx, _, _, err := loadOrRebuildIndexLocked(t.archiveDir)
	if err != nil {
		return false, err
	}
	for i := range idx.Files {
		ent := &idx.Files[i]
		if ent.Count == 0 || id < ent.MinID || id > ent.MaxID {
			continue
		}
		if ent.deleted[id] {
			return false, nil // 已是墓碑
		}
		found := false
		if serr := scanShardRecords(filepath.Join(t.archiveDir, ent.File), func(rec ScanRecord) bool {
			if rec.ID == id {
				found = true
				return false
			}
			return true
		}); serr != nil {
			continue
		}
		if !found {
			continue
		}
		deleted, derr := readTombstonesLocked(t.archiveDir, ent.Year)
		if derr != nil {
			return false, derr
		}
		deleted[id] = true
		if werr := writeTombstonesLocked(t.archiveDir, ent.Year, deleted); werr != nil {
			return false, werr
		}
		ent.deleted = deleted
		if ent.Total > 0 {
			ent.Count = ent.Total - len(deleted)
			if ent.Count < 0 {
				ent.Count = 0
			}
		}
		ent.UpdatedAt = time.Now().Format(time.RFC3339)
		if werr := writeArchiveIndexLocked(t.archiveDir, idx); werr != nil {
			return false, werr
		}
		return true, nil
	}
	return false, nil
}

// ClearAllForTenant 清空指定租户的全部历史（主库 + 归档；BL-5）。
//
// tenant 为空 = 全局（同 ClearAll）；非空时主库按租户过滤删除，归档记录
// 逐条写墓碑（append-only 语义，不重写分片），返回删除总条数。
func (t *Tiered) ClearAllForTenant(tenant string) int {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return t.ClearAll()
	}
	n := t.Store.ClearAllForTenant(tenant)
	for _, e := range t.archivedEntries() {
		if e.summary.Tenant != tenant {
			continue
		}
		if ok, err := t.deleteArchived(e.summary.ID); err == nil && ok {
			n++
		}
	}
	t.invalidate()
	return n
}

// ClearAll 清空全部历史（含年度归档；隐私操作不保留归档正文）。
// 返回清除总条数（主库 + 归档），与既有「清除 N 条」语义兼容。
func (t *Tiered) ClearAll() int {
	archived := t.archivedCount()
	n := t.Store.ClearAll()
	if err := os.RemoveAll(t.archiveDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "警告：清理归档目录失败（%s）：%v\n", t.archiveDir, err)
	}
	t.Store.resetArchiveCaches()
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
	for i := range idx.Files {
		n += idx.Files[i].Count
	}
	return n
}
