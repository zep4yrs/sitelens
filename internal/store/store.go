// Package store 扫描历史持久化 + 异步作业管理。
//
// 文件式存储（data/state/history.json，全量载入内存 + 写时落盘），
// 替代 Python 版的 PG 依赖，保持单二进制可携带；
// 行字段与 Python ScanStore 的 API 输出对齐，前端无感迁移。
// jobs 仅存内存（作业生命周期不跨进程重启）。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

// ScanSummary 历史列表行（字段对齐 Python list_scans）。
//
// Tenant（BL-5/A-04）：数据归属租户。旧数据缺省 "" = legacy（单机/认证关闭
// 时全局可见）；认证开启后新记录写入令牌租户，按 id 读取时校验归属。
type ScanSummary struct {
	ID            int64   `json:"id"`
	URL           string  `json:"url"`
	Host          string  `json:"host"`
	Title         string  `json:"title"`
	Status        int     `json:"status"`
	SecurityGrade string  `json:"security_grade"`
	SecurityScore int     `json:"security_score"`
	TechCount     int     `json:"tech_count"`
	VulnCount     int     `json:"vuln_count"`
	Duration      float64 `json:"duration"`
	ScannedAt     string  `json:"scanned_at"`
	Tenant        string  `json:"tenant,omitempty"`
}

// ScanRecord 完整记录：摘要 + 选项 + 结果。
type ScanRecord struct {
	ScanSummary
	Options map[string]any `json:"options"`
	Result  *engine.Result `json:"result"`
}

// history 磁盘结构。
type history struct {
	NextID int64        `json:"next_id"`
	Scans  []ScanRecord `json:"scans"`
}

// Store 扫描历史存储。
type Store struct {
	mu          sync.RWMutex
	path        string
	archivePath string
	dataDir     string // 数据目录（图另存 <dataDir>/graph/<id>/，见 graph.go）
	max         int
	h           history

	// 归档诊断（C-05）：最近一次裁剪归档失败的原因。成功归档后清空；
	// 失败时主库记录**不裁剪**（宁可内存增长也不丢数据），并计入 stderr。
	archiveErr string
	// fallbackReason（C-03）：本实例作为 SQL 后端的回退存储时的原因。
	// 非空表示「配置要 SQL、实际落 JSON」，由 HistoryStats 暴露给 /api/stats。
	fallbackReason string

	// triage/whitelist 状态（C-19）：每个 Store 一份（替代原按 *Store 的
	// 全局 sync.Map，后者对每个新建 Store 都留一份永不回收的状态）。
	triageMu sync.Mutex
	triage   *triageState

	// 归档 append-only 去重缓存（C-01）：已物理写入 archive/<year>.jsonl 的
	// record id。首次归档/写入时惰性扫描分片构建（s.mu 守护、写侧持有）；
	// 清空历史后重置。作用：append 前跳过重复 id（回灌/崩溃窗口/重试），
	// 不必再为判重去全量读年度文件。
	archiveIDs map[int64]bool
}

// New 打开（或创建）历史存储。目录不存在会自动创建。
//
// C-04：只有 history.json **不存在**（首启正常态）才按空库继续；
// 其他读取错误（权限/占用/断连/同名目录等）必须返回错误——否则内存按空库
// 启动，下一次 flush 会把「只有新记录」的内容写回该路径，静默覆盖原历史。
func New(dataDir string, maxRecords int) (*Store, error) {
	if maxRecords <= 0 {
		maxRecords = 500
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "history.json"),
		archivePath: filepath.Join(dataDir, "history.archive.jsonl"),
		dataDir:     dataDir,
		max:         maxRecords, h: history{NextID: 1}}
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if uerr := json.Unmarshal(data, &s.h); uerr != nil {
			// 历史文件损坏：隔离为 .corrupt 后从空库继续（ID 从头计，
			// 不覆盖原始损坏文件以便人工抢救）
			_ = os.Rename(s.path, fmt.Sprintf("%s.%d.corrupt", s.path, time.Now().UnixNano()))
			s.h = history{NextID: 1}
		}
	case errors.Is(err, os.ErrNotExist):
		// 首次启动：正常空库
	default:
		return nil, fmt.Errorf("读取扫描历史失败（%s）：%w（拒绝按空库启动，避免覆盖原文件）", s.path, err)
	}
	if s.h.NextID < 1 {
		s.h.NextID = 1
	}
	return s, nil
}

// Save 保存一次扫描结果，返回记录 id（legacy/单机路径：租户为空）。
func (s *Store) Save(res *engine.Result, options map[string]any) int64 {
	return s.SaveForTenant(res, options, "")
}

// SaveForTenant 保存一次扫描结果并写入归属租户（BL-5）。
//
// tenant 为空保持既有 Save 行为（认证关闭/单机部署，记录视为 legacy，
// 全局可见）；非空时记录带租户，按租户过滤的读取只返回本租户记录。
func (s *Store) SaveForTenant(res *engine.Result, options map[string]any, tenant string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(res, options, tenant)
}

// saveLocked Save 的内部实现（调用方持 s.mu）。
func (s *Store) saveLocked(res *engine.Result, options map[string]any, tenant string) int64 {
	id := s.h.NextID
	s.h.NextID++

	rec := ScanRecord{
		ScanSummary: ScanSummary{
			ID: id, URL: res.URL, Host: res.Host, Title: res.Title,
			Status: res.Status, TechCount: len(res.Technologies),
			VulnCount: len(res.Vulnerabilities), Duration: res.Duration,
			ScannedAt: res.ScannedAt, Tenant: strings.TrimSpace(tenant),
		},
		Options: options,
		Result:  res,
	}
	// 4.0 P8：图另存独立文件，记录里剥离（history.json 保持 3.0 形态、不膨胀）。
	// 仅在记录副本上置 nil，调用方 res 与 job 结果仍持有图。
	//
	// C-20：**不在调用方 res.Graph 上回填 ScanID**（原实现有副作用：同一个
	// *engine.Result 二次保存时 ScanID 已被钉在旧 id，导出 JSONL header 会
	// 指向错误扫描）。改成在副本上回填，调用方对象保持只读。
	if res.Graph != nil {
		// 落盘时才有 scan_id：回填到图副本（与扫描记录一致），使导出的
		// JSONL header 自带 scan_id——5.0 读端可据此关联来源扫描。
		g := *res.Graph
		if g.ScanID == "" {
			g.ScanID = strconv.FormatInt(id, 10)
		}
		_ = s.saveGraph(id, &g, res.URL)
		cp := *res
		cp.Graph = nil
		rec.Result = &cp
	}
	if res.Security != nil {
		rec.SecurityGrade = res.Security.Grade
		rec.SecurityScore = res.Security.Score
	}
	s.h.Scans = append(s.h.Scans, rec)

	// 超上限裁掉最旧：被裁记录先归档到 history.archive.jsonl（JSON Lines，
	// 可人工查看/回灌），避免"裁剪即数据丢失"。
	//
	// C-05：归档写失败时**不裁剪主库、不删图**，并显式报错——原实现忽略
	// archive 错误仍然裁剪，磁盘满/只读/路径被占用时会静默丢记录（图已先删）。
	// 失败后主库暂时超上限，下一次 Save 重试归档，成功后再裁剪。
	if over := len(s.h.Scans) - s.max; over > 0 {
		sort.Slice(s.h.Scans, func(i, j int) bool { return s.h.Scans[i].ID < s.h.Scans[j].ID })
		victims := s.h.Scans[:over]
		if aerr := s.archive(victims); aerr != nil {
			s.archiveErr = aerr.Error()
			fmt.Fprintf(os.Stderr, "警告：扫描历史归档失败，已保留主库记录（%s）：%v\n", s.archivePath, aerr)
		} else {
			s.archiveErr = ""
			// 图随记录走：被裁记录已不可经 API 触达（Get 404），图目录须同步
			// 删除，否则永久泄漏（与 Delete 的"不留孤儿"语义对齐）。
			for _, r := range victims {
				s.deleteGraph(r.ID)
			}
			s.h.Scans = s.h.Scans[over:]
		}
	}
	s.flush()
	return id
}

// archive 把被裁剪的记录追加到归档文件（JSON Lines）。
// 0600（BUG-024）：归档含目标响应片段/命中详情，按最小权限落盘。
//
// 返回错误供 Save 决定是否裁剪（C-05）：归档没落盘就裁剪主库 = 丢数据。
// 写入后 Sync：避免"主库已裁剪、归档还在页缓存"的崩溃窗口。
func (s *Store) archive(recs []ScanRecord) error {
	f, err := os.OpenFile(s.archivePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打开归档文件失败：%w", err)
	}
	defer f.Close()
	// 历史遗留的 0644 归档文件同样收紧（Windows 下仅只读位生效）。
	_ = f.Chmod(0o600)
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("写入归档记录失败：%w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("归档 fsync 失败：%w", err)
	}
	return nil
}

// Import 迁移导入：保留原始记录 id（PG 历史无损搬迁用）。
// next_id 自动抬到已导入最大 id + 1，后续新扫描 id 不冲突。
// 幂等：同 id 已存在则跳过。（锁不可重入，勿在回调中调用其他方法。）
func (s *Store) Import(rec ScanRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.ID <= 0 {
		return 0, errors.New("导入记录缺少有效 id")
	}
	for i := range s.h.Scans {
		if s.h.Scans[i].ID == rec.ID {
			return rec.ID, nil // 已存在：幂等跳过
		}
	}
	if rec.ID >= s.h.NextID {
		s.h.NextID = rec.ID + 1
	}
	s.h.Scans = append(s.h.Scans, rec)
	s.flush()
	return rec.ID, nil
}

// List 历史列表（新→旧）；tech 非空时按技术名过滤。
func (s *Store) List(limit int, tech string) []ScanSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanSummary, 0, limit)
	tech = strings.ToLower(tech)
	for i := len(s.h.Scans) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.h.Scans[i]
		if tech != "" && !scanHasTech(&r, tech) {
			continue
		}
		out = append(out, r.ScanSummary)
	}
	return out
}

// Get 按 id 取完整记录。
func (s *Store) Get(id int64) *ScanRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.h.Scans {
		if s.h.Scans[i].ID == id {
			r := s.h.Scans[i]
			return &r
		}
	}
	return nil
}

// Delete 删除一条历史。
func (s *Store) Delete(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.h.Scans {
		if s.h.Scans[i].ID == id {
			s.h.Scans = append(s.h.Scans[:i], s.h.Scans[i+1:]...)
			s.deleteGraph(id) // 4.0 P8：同步删除图目录（不留孤儿）
			s.flush()
			return true
		}
	}
	return false
}

// ---- 多租户读取（BL-5/A-04） ----
//
// 约定：tenant 为空 = 不过滤（认证关闭/单机部署，保持既有语义，legacy 记录
// 全局可见）；tenant 非空 = 只返回该租户记录，空 tenant 的 legacy 记录对
// 非空租户不可见（防止历史数据被任意租户读取）。按 id 读取不匹配时返回 nil，
// 由 server 统一映射 404（不泄露存在性）。

// ListForTenant 历史列表（新→旧）：tenant 非空时只返回该租户记录。
func (s *Store) ListForTenant(limit int, tech, tenant string) []ScanSummary {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return s.List(limit, tech)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanSummary, 0, limit)
	tech = strings.ToLower(tech)
	for i := len(s.h.Scans) - 1; i >= 0 && len(out) < limit; i-- {
		r := &s.h.Scans[i]
		if r.Tenant != tenant {
			continue
		}
		if tech != "" && !scanHasTech(r, tech) {
			continue
		}
		out = append(out, r.ScanSummary)
	}
	return out
}

// GetForTenant 按 id 取记录并校验租户归属（不匹配返回 nil）。
func (s *Store) GetForTenant(id int64, tenant string) *ScanRecord {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return s.Get(id)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.h.Scans {
		if s.h.Scans[i].ID == id && s.h.Scans[i].Tenant == tenant {
			r := s.h.Scans[i]
			return &r
		}
	}
	return nil
}

// DeleteForTenant 删除一条记录并校验租户归属（不匹配/不存在返回 false）。
func (s *Store) DeleteForTenant(id int64, tenant string) bool {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return s.Delete(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.h.Scans {
		if s.h.Scans[i].ID != id || s.h.Scans[i].Tenant != tenant {
			continue
		}
		s.h.Scans = append(s.h.Scans[:i], s.h.Scans[i+1:]...)
		s.deleteGraph(id)
		s.flush()
		return true
	}
	return false
}

// ClearAll 清空全部历史（设置页·数据管理）。返回清除条数。
// 刻意不走归档：清空是隐私操作，用户预期是记录彻底消失
// （归档文件会保留正文，与预期相悖）。
func (s *Store) ClearAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.h.Scans)
	// 4.0 P8：清空历史同样清空图（隐私操作，用户预期记录彻底消失）。
	// 先清图再判空：历史为空时图目录可能仍残留（history.json 损坏重建、
	// 孤儿图），不能因记录数为 0 就提前返回放过磁盘数据。
	for _, id := range s.GraphIDs() {
		s.deleteGraph(id)
	}
	_ = os.RemoveAll(filepath.Join(s.dataDir, "graph"))
	if n == 0 {
		return 0
	}
	s.h.Scans = nil
	s.flush()
	return n
}

// ClearAllForTenant 清空指定租户的全部历史（BL-5）。tenant 为空 = 全局
// （同 ClearAll，既有行为）；非空只删本租户记录并同步删图，返回删除条数。
func (s *Store) ClearAllForTenant(tenant string) int {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return s.ClearAll()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]ScanRecord, 0, len(s.h.Scans))
	removed := 0
	for i := range s.h.Scans {
		if s.h.Scans[i].Tenant == tenant {
			s.deleteGraph(s.h.Scans[i].ID)
			removed++
			continue
		}
		kept = append(kept, s.h.Scans[i])
	}
	if removed > 0 {
		s.h.Scans = kept
		s.flush()
	}
	return removed
}

// SetFallbackReason 标记「本实例是 SQL 后端的回退存储」及原因（C-03）。
// 由接线方在 SQL 打开/迁移失败回退 JSON 时调用；HistoryStats 会把它暴露成
// backend/fallback_reason/degraded，使 /api/stats 可观测到降级，而不是只留
// 一行启动日志。
func (s *Store) SetFallbackReason(reason string) {
	s.mu.Lock()
	s.fallbackReason = strings.TrimSpace(reason)
	s.mu.Unlock()
}

// ArchiveError 返回最近一次裁剪归档失败的原因（空 = 正常）。
func (s *Store) ArchiveError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.archiveErr
}

// HistoryStats 历史统计（次数/站点数/平均技术数 + 后端/降级诊断）。
func (s *Store) HistoryStats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := map[string]bool{}
	total := 0
	for i := range s.h.Scans {
		hosts[s.h.Scans[i].Host] = true
		total += s.h.Scans[i].TechCount
	}
	avg := 0.0
	if len(s.h.Scans) > 0 {
		avg = math.Round(float64(total)/float64(len(s.h.Scans))*10) / 10
	}
	// C-03：后端可观测。JSON 默认后端 backend=json；SQL 失败回退时
	// fallback_reason 非空、degraded=true，前端/运维可直接从 /api/stats 看到。
	stats := map[string]any{
		"scans": len(s.h.Scans), "hosts": len(hosts), "avg_techs": avg,
		"backend": "json", "degraded": false,
	}
	if s.fallbackReason != "" {
		stats["degraded"] = true
		stats["fallback_reason"] = s.fallbackReason
	}
	if s.archiveErr != "" {
		stats["degraded"] = true
		stats["archive_error"] = s.archiveErr
	}
	return stats
}

// HistoryStatsForTenant 历史统计（tenant 非空时只统计该租户记录；空=全局）。
//
// 返回字段与 HistoryStats 完全一致（backend/degraded 诊断键保留），供
// /api/stats 在 token 模式下按租户隔离计数（避免跨租户条数泄露）。
func (s *Store) HistoryStatsForTenant(tenant string) map[string]any {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return s.HistoryStats()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := map[string]bool{}
	total, n := 0, 0
	for i := range s.h.Scans {
		r := &s.h.Scans[i]
		if r.Tenant != tenant {
			continue
		}
		hosts[r.Host] = true
		total += r.TechCount
		n++
	}
	avg := 0.0
	if n > 0 {
		avg = math.Round(float64(total)/float64(n)*10) / 10
	}
	stats := map[string]any{
		"scans": n, "hosts": len(hosts), "avg_techs": avg,
		"backend": "json", "degraded": false,
	}
	if s.fallbackReason != "" {
		stats["degraded"] = true
		stats["fallback_reason"] = s.fallbackReason
	}
	if s.archiveErr != "" {
		stats["degraded"] = true
		stats["archive_error"] = s.archiveErr
	}
	return stats
}

// TopTechs 历史扫描中最常见技术 TOP N（对齐 Python top_techs）。
// result 为 null 的历史记录（导入迁移/写库中断都可能产生）直接跳过：
// 此前无判空 → GET /api/stats 触发 nil 指针 panic（BUG-009）。
func (s *Store) TopTechs(limit int) []map[string]any {
	return s.TopTechsForTenant(limit, "")
}

// TopTechsForTenant 同 TopTechs，但只统计指定租户记录（BL-5；空租户=全局）。
func (s *Store) TopTechsForTenant(limit int, tenant string) []map[string]any {
	tenant = strings.TrimSpace(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := map[string]int{}
	for i := range s.h.Scans {
		r := &s.h.Scans[i]
		if r.Result == nil || (tenant != "" && r.Tenant != tenant) {
			continue
		}
		for _, t := range r.Result.Technologies {
			count[t.Name]++
		}
	}
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range count {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	out := make([]map[string]any, 0, limit)
	for i, x := range arr {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{"name": x.k, "n": x.v})
	}
	return out
}

// Verified 跨扫描汇总已验证漏洞（新→旧，上限 limit）。
func (s *Store) Verified(limit int) []map[string]any {
	return s.VerifiedForTenant(limit, "")
}

// VerifiedForTenant 同 Verified，但只汇总指定租户记录（BL-5；空租户=全局）。
func (s *Store) VerifiedForTenant(limit int, tenant string) []map[string]any {
	tenant = strings.TrimSpace(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []map[string]any{}
	for i := len(s.h.Scans) - 1; i >= 0 && len(out) < limit; i-- {
		r := &s.h.Scans[i]
		if r.Result == nil || (tenant != "" && r.Tenant != tenant) {
			continue
		}
		for _, v := range r.Result.Verified {
			if len(out) >= limit {
				break
			}
			item := map[string]any{
				"scan_id": r.ID, "host": r.Host, "scanned_at": r.ScannedAt,
			}
			for k, val := range v {
				item[k] = val
			}
			out = append(out, item)
		}
	}
	return out
}

// flush 落盘（调用方须持锁）。0600（BUG-024）：history.json 含目标响应
// 片段与登录爆破命中，按最小权限写。
//
// 失败不再静默（BUG-031）：磁盘满/权限异常会让历史静默丢失，此前无任何
// 痕迹可查。只在失败路径打 stderr（成功路径零输出，不引入噪声）。
func (s *Store) flush() {
	data, err := json.Marshal(&s.h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告：扫描历史序列化失败，本次未落盘（%s）：%v\n", s.path, err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "警告：扫描历史落盘失败（%s）：%v\n", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		fmt.Fprintf(os.Stderr, "警告：扫描历史替换失败（%s）：%v\n", s.path, err)
	}
}

func scanHasTech(r *ScanRecord, techLower string) bool {
	if r.Result == nil {
		return false
	}
	for _, t := range r.Result.Technologies {
		if strings.Contains(strings.ToLower(t.Name), techLower) {
			return true
		}
	}
	return false
}

// ---- 作业管理（内存） ----

// Job 一次异步任务（扫描/批量/爆破）的状态。
// Job 作业状态。
type Job struct {
	ID       string         `json:"job_id"`
	Kind     string         `json:"kind"`
	Status   string         `json:"status"` // pending/running/cancelling/cancelled/done/error
	Progress int            `json:"progress"`
	Message  string         `json:"message"`
	Done     int            `json:"done"`
	Total    int            `json:"total"`
	Payload  map[string]any `json:"payload"`
	Result   map[string]any `json:"result"`
	Events   []JobEvent     `json:"events,omitempty"` // 实时事件流（环形，新事件在尾部）
	Live     *LiveStats     `json:"live,omitempty"`   // 扫描实时统计（请求/页面/拦截/速率；仅扫描任务）
	// Tenant（BL-5）：作业归属租户；空 = legacy/单机（认证关闭）。按 job id
	// 读取时校验归属，避免跨租户读取任务进度/结果（含目标 URL）。
	Tenant string `json:"tenant,omitempty"`
}

// LiveStats 扫描进行中的实时统计（与 engine.LiveStats 同构；store 不依赖
// engine，服务端负责转换）。只读展示，不参与判定。
type LiveStats struct {
	Phase     string  `json:"phase"`
	PhaseName string  `json:"phase_name"`
	Requests  int64   `json:"requests"`
	Pages     int64   `json:"pages"`
	Blocked   int64   `json:"blocked"`
	Rate      float64 `json:"rate"`
	ElapsedMS int64   `json:"elapsed_ms"`
}

// JobEvent 扫描实时事件（阶段切换/命中/认证/绕过…），供前端实时动态面板。
type JobEvent struct {
	TS   int64  `json:"ts"`
	Kind string `json:"kind"` // stage/hit/bypass/auth/deser/info
	Text string `json:"text"`
}

// JobManager 作业注册表。
type JobManager struct {
	mu    sync.RWMutex
	jobs  map[string]*Job
	order []string // 插入顺序（用于淘汰最旧作业）
	max   int      // 保留上限（0 = 不限；长驻服务防内存缓慢增长）
}

// NewJobManager 创建作业管理器（不限量）。
func NewJobManager() *JobManager { return &JobManager{jobs: map[string]*Job{}} }

// NewJobManagerWithCap 创建带容量上限的作业管理器：超出后淘汰最旧作业。
func NewJobManagerWithCap(maxJobs int) *JobManager {
	m := &JobManager{jobs: map[string]*Job{}}
	if maxJobs > 0 {
		m.max = maxJobs
	}
	return m
}

// Create 注册新作业。
func (m *JobManager) Create(id, kind string, payload map[string]any, total int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[id] = &Job{ID: id, Kind: kind, Status: "pending",
		Payload: payload, Total: total}
	m.order = append(m.order, id)
	if m.max > 0 {
		for len(m.order) > m.max {
			oldest := m.order[0]
			m.order = m.order[1:]
			delete(m.jobs, oldest)
		}
	}
}

// Update 非空字段更新（对齐 Python JobStore.update 的 COALESCE 语义）。
// 注意：RWMutex 不可重入——回调 fn 内不得再调用本管理器的任何方法
// （Get/Update/CancelRequested），需要组合状态时先在回调外读取。
func (m *JobManager) Update(id string, fn func(j *Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.jobs[id]; ok {
		fn(j)
	}
}

// jobEventCap 实时事件环形上限（超出淘汰最旧）。
const jobEventCap = 80

// AppendEvent 追加一条实时事件（时间戳服务端生成）。
func (m *JobManager) AppendEvent(id, kind, text string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok || text == "" {
		return
	}
	j.Events = append(j.Events, JobEvent{TS: time.Now().Unix(), Kind: kind, Text: text})
	if len(j.Events) > jobEventCap {
		j.Events = j.Events[len(j.Events)-jobEventCap:]
	}
}

// Get 取作业（深拷贝快照）。
//
// C-18：原实现只复制 Job 结构体，Payload/Result map、Events slice、Live
// 指针仍与写方共享。当前所有写路径都是整体替换字段，尚未构成 fatal race；
// 但任何一次 in-place 写（j.Result["x"]=… / j.Live.Progress++）都会变成
// HTTP handler 与 job goroutine 的并发 map/结构体读写（concurrent map read
// and map write 会直接杀进程）。这里做深拷贝，把该隐患从"靠调用方自律"
// 变成结构上不可能。
func (m *JobManager) Get(id string) *Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil
	}
	c := *j
	c.Payload = cloneAnyMap(j.Payload)
	c.Result = cloneAnyMap(j.Result)
	if j.Events != nil {
		c.Events = append([]JobEvent(nil), j.Events...)
	}
	if j.Live != nil {
		live := *j.Live
		c.Live = &live
	}
	return &c
}

// cloneAnyMap 深拷贝 map[string]any（nil 保持 nil）。
func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneJobValue(v)
	}
	return out
}

// cloneJobValue 按具体类型深拷贝作业载荷里的值。
//
// **必须保留具体类型**（尤其 []map[string]any）：任务结果里的 rows 以
// []map[string]any 形态被 API 与前端消费，若统一转成 []any 会破坏类型断言。
func cloneJobValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneAnyMap(x)
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i := range x {
			out[i] = cloneAnyMap(x[i])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = cloneJobValue(x[i])
		}
		return out
	case []string:
		return append([]string(nil), x...)
	case []int:
		return append([]int(nil), x...)
	case []int64:
		return append([]int64(nil), x...)
	case []float64:
		return append([]float64(nil), x...)
	case []bool:
		return append([]bool(nil), x...)
	default:
		return v // 标量/未知类型：值语义，直接共享安全
	}
}

// CancelRequested 标记取消（作业执行方轮询 job.Status）。
func (m *JobManager) CancelRequested(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return ok && (j.Status == "cancelling" || j.Status == "cancelled")
}
