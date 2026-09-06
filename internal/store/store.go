// Package store 扫描历史持久化 + 异步作业管理。
//
// 文件式存储（data/state/history.json，全量载入内存 + 写时落盘），
// 替代 Python 版的 PG 依赖，保持单二进制可携带；
// 行字段与 Python ScanStore 的 API 输出对齐，前端无感迁移。
// jobs 仅存内存（作业生命周期不跨进程重启）。
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

// ScanSummary 历史列表行（字段对齐 Python list_scans）。
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
	mu   sync.RWMutex
	path string
	max  int
	h    history
}

// New 打开（或创建）历史存储。目录不存在会自动创建。
func New(dataDir string, maxRecords int) (*Store, error) {
	if maxRecords <= 0 {
		maxRecords = 500
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "history.json"), max: maxRecords,
		h: history{NextID: 1}}
	data, err := os.ReadFile(s.path)
	if err == nil {
		if uerr := json.Unmarshal(data, &s.h); uerr != nil {
			// 历史文件损坏：隔离为 .corrupt 后从空库继续（ID 从头计，
			// 不覆盖原始损坏文件以便人工抢救）
			_ = os.Rename(s.path, s.path+".corrupt")
			s.h = history{NextID: 1}
		}
	}
	if s.h.NextID < 1 {
		s.h.NextID = 1
	}
	return s, nil
}

// Save 保存一次扫描结果，返回记录 id。
func (s *Store) Save(res *engine.Result, options map[string]any) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.h.NextID
	s.h.NextID++

	rec := ScanRecord{
		ScanSummary: ScanSummary{
			ID: id, URL: res.URL, Host: res.Host, Title: res.Title,
			Status: res.Status, TechCount: len(res.Technologies),
			VulnCount: len(res.Vulnerabilities), Duration: res.Duration,
			ScannedAt: res.ScannedAt,
		},
		Options: options,
		Result:  res,
	}
	if res.Security != nil {
		rec.SecurityGrade = res.Security.Grade
		rec.SecurityScore = res.Security.Score
	}
	s.h.Scans = append(s.h.Scans, rec)

	// 超上限裁掉最旧（id 最小）
	if over := len(s.h.Scans) - s.max; over > 0 {
		sort.Slice(s.h.Scans, func(i, j int) bool { return s.h.Scans[i].ID < s.h.Scans[j].ID })
		s.h.Scans = s.h.Scans[over:]
	}
	s.flush()
	return id
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
			s.flush()
			return true
		}
	}
	return false
}

// HistoryStats 历史统计（次数/站点数/平均技术数）。
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
		avg = float64(int(float64(total)/float64(len(s.h.Scans))*10)) / 10
	}
	return map[string]any{
		"scans": len(s.h.Scans), "hosts": len(hosts), "avg_techs": avg,
	}
}

// TopTechs 历史扫描中最常见技术 TOP N（对齐 Python top_techs）。
func (s *Store) TopTechs(limit int) []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := map[string]int{}
	for i := range s.h.Scans {
		for _, t := range s.h.Scans[i].Result.Technologies {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []map[string]any{}
	for i := len(s.h.Scans) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.h.Scans[i]
		if r.Result == nil {
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

// flush 落盘（调用方须持锁）。失败静默：存储异常不阻塞扫描主流程。
func (s *Store) flush() {
	data, err := json.Marshal(&s.h)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, s.path)
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

// Get 取作业（副本快照）。
func (m *JobManager) Get(id string) *Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if j, ok := m.jobs[id]; ok {
		c := *j
		return &c
	}
	return nil
}

// CancelRequested 标记取消（作业执行方轮询 job.Status）。
func (m *JobManager) CancelRequested(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return ok && (j.Status == "cancelling" || j.Status == "cancelled")
}
