package server

// 本文件实现 BT-03「批量定时任务」的能力层：Schedule 模型 + 持久化 +
// 到期判断 + 后台调度。路由与启动接线由 Lead 在 server.go 完成（本文件不改
// server.go / config / web），文末「接线说明」列出需要 Lead 接的点。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

const (
	// schedulesFileName 定时任务持久化文件名：<dataDir>/batches/schedules.json。
	schedulesFileName = "schedules.json"

	// scheduleMinEveryMinutes 最小周期（分钟）：0/负值会让调度变成紧循环。
	scheduleMinEveryMinutes = 1
)

// batchSchedulerInterval 后台调度检查间隔（任务口径：每 30s）。
// 包级 var 而非 const：测试可缩短它，避免每轮真实等 30s。
var batchSchedulerInterval atomic.Int64 // 纳秒；0=默认 30s（测试可缩短，atomic 防并发读写竞争）

// batchJobStarter 定时调度启动批量任务的钩子（生产固定走 startBatchJob；
// 测试可替换它以避免真的拉起扫描）。
var batchJobStarter atomic.Value // func(*Server, []batchItem) (string, int)

func init() {
	batchJobStarter.Store(func(s *Server, entries []batchItem) (string, int) {
		return s.startBatchJob(entries)
	})
}

// batchSchedulesMu 串行化 schedules.json 的「读-改-写」。
// Server 结构体在 server.go（本任务不改），因此用包级锁：单进程单数据目录
// 场景下足够，路由并发 Upsert/Delete 不会互相覆盖。
var batchSchedulesMu sync.Mutex

// Schedule 定时批量任务（BT-03）。
//
// EveryMinutes 表示「每 N 分钟执行一次」；NextRunAt 为下一次到期时间
// （RFC3339，空/损坏视为首跑即到期）；Enabled=false 时永不自动触发。
type Schedule struct {
	ID           string      `json:"id"`
	EveryMinutes int         `json:"every_minutes"`
	Entries      []batchItem `json:"entries"`
	CreatedAt    string      `json:"created_at,omitempty"`
	LastRunAt    string      `json:"last_run_at,omitempty"`
	NextRunAt    string      `json:"next_run_at,omitempty"`
	Enabled      bool        `json:"enabled"`
	// Tag 分组标签（additive）：执行时写入各 batchItem.Tag 与 job metadata，
	// 供结果筛选/通知分组。
	Tag string `json:"tag,omitempty"`
}

// schedulesPath 定时任务配置文件路径；未配置数据目录时返回空串。
func (s *Server) schedulesPath() string {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	if cfg == nil || strings.TrimSpace(cfg.Store.DataDir) == "" {
		return ""
	}
	return filepath.Join(s.batchStateDir(), schedulesFileName)
}

// parseScheduleTime 解析 RFC3339 时间；兼容 "2006-01-02 15:04:05"（本地时区）。
func parseScheduleTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", raw, time.Local); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// scheduleDue 判断备份任务是否到期：禁用→否；未排期/时间损坏→视为到期（首跑）。
func scheduleDue(sc Schedule, now time.Time) bool {
	if !sc.Enabled {
		return false
	}
	ts, ok := parseScheduleTime(sc.NextRunAt)
	if !ok {
		return true
	}
	return !ts.After(now)
}

// nextRunAfter 计算本次执行后的下一次到期时间。
func (sc Schedule) nextRunAfter(now time.Time) time.Time {
	mins := sc.EveryMinutes
	if mins < scheduleMinEveryMinutes {
		mins = scheduleMinEveryMinutes
	}
	return now.Add(time.Duration(mins) * time.Minute)
}

// scheduleEntries 生成执行用的目标列表副本：去空 URL、档位归一化、并把
// schedule.Tag 下发给未单独设置标签的条目（不修改持久化的 Schedule 本体）。
func scheduleEntries(sc Schedule) []batchItem {
	out := make([]batchItem, 0, len(sc.Entries))
	for _, it := range sc.Entries {
		it.URL = strings.TrimSpace(it.URL)
		if it.URL == "" {
			continue
		}
		lv := strings.ToLower(strings.TrimSpace(it.Level))
		if !batchLevels[lv] {
			lv = ""
		}
		it.Level = lv
		it.Tag = strings.TrimSpace(it.Tag)
		if it.Tag == "" {
			it.Tag = strings.TrimSpace(sc.Tag)
		}
		out = append(out, it)
	}
	return out
}

// normalizeSchedule 归一化新建/编辑的定时任务：补齐 ID/创建时间、周期夹到
// ≥1 分钟、清理条目；启用且未排期时按 now+周期 计算 NextRunAt，禁用则清空。
// 已存在的合法 NextRunAt 原样保留（编辑标签不应打乱既有节奏）。
func normalizeSchedule(sc Schedule, now time.Time) Schedule {
	sc.ID = strings.TrimSpace(sc.ID)
	if sc.ID == "" {
		sc.ID = newID()
	}
	if sc.EveryMinutes < scheduleMinEveryMinutes {
		sc.EveryMinutes = scheduleMinEveryMinutes
	}
	sc.Tag = strings.TrimSpace(sc.Tag)
	sc.CreatedAt = strings.TrimSpace(sc.CreatedAt)
	if sc.CreatedAt == "" {
		sc.CreatedAt = now.Format(time.RFC3339)
	}
	sc.Entries = scheduleEntries(sc)
	sc.LastRunAt = strings.TrimSpace(sc.LastRunAt)
	sc.NextRunAt = strings.TrimSpace(sc.NextRunAt)
	if !sc.Enabled {
		sc.NextRunAt = ""
		return sc
	}
	if _, ok := parseScheduleTime(sc.NextRunAt); !ok {
		sc.NextRunAt = sc.nextRunAfter(now).Format(time.RFC3339)
	}
	return sc
}

// sortSchedules 稳定排序（创建时间→ID），保证列表/文件内容可复现。
func sortSchedules(list []Schedule) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].CreatedAt != list[j].CreatedAt {
			return list[i].CreatedAt < list[j].CreatedAt
		}
		return list[i].ID < list[j].ID
	})
}

// loadSchedulesLocked 读取 schedules.json；文件不存在返回 (nil, nil)。
// 若「正式文件缺失但 .bak 存在」（原子替换中途崩溃的残留），从备份恢复。
// 调用方必须持有 batchSchedulesMu。
func (s *Server) loadSchedulesLocked() ([]Schedule, error) {
	p := s.schedulesPath()
	if p == "" {
		return nil, errors.New("数据目录未配置")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		bak := p + ".bak"
		bdata, berr := os.ReadFile(bak)
		if berr != nil {
			return nil, nil // 首次使用：无配置文件
		}
		_ = os.Rename(bak, p) // 恢复：备份转正
		data = bdata
	}
	return parseSchedules(data, p)
}

// parseSchedules 解析 schedules.json 内容（空内容视为空列表）。
func parseSchedules(data []byte, path string) ([]Schedule, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var list []Schedule
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("定时任务配置损坏（%s）：%w", path, err)
	}
	sortSchedules(list)
	return list, nil
}

// saveSchedulesLocked 原子写 schedules.json：临时文件 + fsync + rename。
// 调用方必须持有 batchSchedulesMu。
func (s *Server) saveSchedulesLocked(list []Schedule) error {
	p := s.schedulesPath()
	if p == "" {
		return errors.New("数据目录未配置")
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if list == nil {
		list = []Schedule{}
	}
	sortSchedules(list)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, schedulesFileName+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功后 rename 已移走，失败则清理残留
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// 先尝试直接 rename（POSIX 原子替换）；Windows 上目标已存在会失败，退回
	// 「备份→替换→删备份」，替换失败则回滚，避免留下无配置文件的窗口。
	if err := os.Rename(tmpName, p); err == nil {
		return nil
	}
	bak := p + ".bak"
	_ = os.Remove(bak)
	if err := os.Rename(p, bak); err != nil {
		return fmt.Errorf("替换定时任务配置失败：%w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		_ = os.Rename(bak, p) // 回滚：宁可保留旧配置
		return err
	}
	_ = os.Remove(bak)
	return nil
}

// LoadSchedules 读取全部定时任务（不存在/为空返回空列表，损坏返回错误）。
func (s *Server) LoadSchedules() ([]Schedule, error) {
	batchSchedulesMu.Lock()
	defer batchSchedulesMu.Unlock()
	return s.loadSchedulesLocked()
}

// SaveSchedules 覆盖写入全部定时任务（原子写）。低层接口，不做归一化：
// 路由的新建/编辑请走 UpsertSchedule（会补 ID/周期/排期）。
func (s *Server) SaveSchedules(list []Schedule) error {
	batchSchedulesMu.Lock()
	defer batchSchedulesMu.Unlock()
	return s.saveSchedulesLocked(list)
}

// UpsertSchedule 新建或按 ID 更新定时任务，返回归一化后的最终对象。
// 归一化：ID 为空→生成；EveryMinutes<1→1；空 URL 条目丢弃；启用且未排期→
// now+周期；禁用→清空 NextRunAt；schedule.Tag 下发给未单独设标签的条目。
func (s *Server) UpsertSchedule(sc Schedule) (Schedule, error) {
	batchSchedulesMu.Lock()
	defer batchSchedulesMu.Unlock()
	list, err := s.loadSchedulesLocked()
	if err != nil {
		return Schedule{}, err
	}
	now := time.Now()
	sc = normalizeSchedule(sc, now)
	if len(sc.Entries) == 0 {
		return Schedule{}, errors.New("定时任务至少需要一个有效目标 URL")
	}
	replaced := false
	for i := range list {
		if list[i].ID == sc.ID {
			list[i] = sc
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, sc)
	}
	sortSchedules(list)
	if err := s.saveSchedulesLocked(list); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

// DeleteSchedule 按 ID 删除定时任务；返回是否删到（幂等：不存在→false,nil）。
func (s *Server) DeleteSchedule(id string) (bool, error) {
	id = strings.TrimSpace(id)
	batchSchedulesMu.Lock()
	defer batchSchedulesMu.Unlock()
	list, err := s.loadSchedulesLocked()
	if err != nil {
		return false, err
	}
	out := list[:0]
	deleted := false
	for _, sc := range list {
		if sc.ID == id {
			deleted = true
			continue
		}
		out = append(out, sc)
	}
	if !deleted {
		return false, nil
	}
	if err := s.saveSchedulesLocked(out); err != nil {
		return false, err
	}
	return true, nil
}

// DueSchedules 返回 now 时刻到期的启用任务（按 NextRunAt/周期判断，不修改状态）。
func (s *Server) DueSchedules(now time.Time) []Schedule {
	batchSchedulesMu.Lock()
	list, err := s.loadSchedulesLocked()
	batchSchedulesMu.Unlock()
	if err != nil {
		return nil
	}
	out := make([]Schedule, 0, len(list))
	for _, sc := range list {
		if scheduleDue(sc, now) {
			out = append(out, sc)
		}
	}
	return out
}

// runDueSchedules 检查并执行到期任务：逐个启动批量任务，回写 LastRunAt 与
// 下一次 NextRunAt，最后一次性原子落盘。返回本轮触发的任务数。
//
// 注意：先算完再落盘（持锁期间不启动扫描的阻塞操作——batchJobStarter 只做
// 轻量的任务登记 + 后台 goroutine 启动，不阻塞）。
func (s *Server) runDueSchedules(now time.Time) int {
	batchSchedulesMu.Lock()
	defer batchSchedulesMu.Unlock()
	list, err := s.loadSchedulesLocked()
	if err != nil || len(list) == 0 {
		return 0
	}
	triggered := 0
	changed := false
	for i := range list {
		sc := &list[i]
		if !scheduleDue(*sc, now) {
			continue
		}
		starter := batchJobStarter.Load().(func(*Server, []batchItem) (string, int))
		jobID, _ := starter(s, scheduleEntries(*sc))
		if jobID != "" {
			sc.LastRunAt = now.Format(time.RFC3339)
			triggered++
		}
		sc.NextRunAt = sc.nextRunAfter(now).Format(time.RFC3339)
		changed = true
	}
	if !changed {
		return 0
	}
	if err := s.saveSchedulesLocked(list); err != nil {
		return triggered // 已启动的任务不回滚；落盘失败留给下一轮重试
	}
	return triggered
}

// RunScheduler 后台调度循环：每 batchSchedulerInterval 检查一次到期任务。
// ctx 取消即退出；Lead 在服务启动时 `go s.RunScheduler(ctx)`，ctx 与服务器
// 生命周期同源（关闭时自动停）。
func (s *Server) RunScheduler(ctx context.Context) {
	interval := time.Duration(batchSchedulerInterval.Load())
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			// V-09：单次调度内的 panic 不能让常驻调度协程/进程退出。
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("[panic] 定时批量调度已恢复：%v\n%s", rec, debug.Stack())
					}
				}()
				s.runDueSchedules(now)
			}()
		}
	}
}

// batchTagOf 取目标列表里的分组标签（首个非空 Tag）；无则空串。
func batchTagOf(items []batchItem) string {
	for _, it := range items {
		if tag := strings.TrimSpace(it.Tag); tag != "" {
			return tag
		}
	}
	return ""
}

// startBatchJob 从目标列表创建并启动一个批量任务（普通批量接口与定时调度共用）。
// 返回任务 ID 与有效目标数；全空返回 ("", 0) 且不创建任务。
//
// 行为与原 hBatch 内联逻辑一致：落断点续跑状态 → 登记 job（metadata 带
// urls/items，有分组标签时额外带 tag）→ 后台 runBatch。调用方负责解析/截断
// 目标列表（parseBatchItems）与错误响应。
//
// 接线说明（Lead，改 server.go 时）：
//  1. hBatch 中「拼 urls / newID / newBatchState / saveBatchState / jobs.Create /
//     go runBatch」六步整体替换为：
//     jobID, total := s.startBatchJob(items)
//     if total == 0 { writeJSON(w, 400, map[string]any{"error": "URL 列表为空"}); return }
//     writeJSON(w, 200, map[string]any{"job_id": jobID, "total": total})
//  2. 服务启动处（Handler/Start 同级生命周期）加：`go s.RunScheduler(ctx)`。
//  3. 定时任务路由（Lead 接线，均调用本文件能力）：
//     GET    /api/batch/schedules            → LoadSchedules
//     POST   /api/batch/schedules            → decode Schedule + UpsertSchedule
//     DELETE /api/batch/schedules/{id}       → DeleteSchedule（false→404）
//     PATCH  /api/batch/schedules/{id}       → 读取现有 + 合并 + UpsertSchedule
//     POST   /api/batch/schedules/{id}/run   → 手动触发：LoadSchedules 找到后
//     `jobID, total := s.startBatchJob(scheduleEntries(sc))`，并回写
//     LastRunAt/NextRunAt（可复用 runDueSchedules 的落盘方式或单独 Upsert）。
func (s *Server) startBatchJob(entries []batchItem) (string, int) {
	return s.startBatchJobForTenant(entries, "")
}

// startBatchJobForTenant 同 startBatchJob，但把批量作业归属到指定租户（BL-5）：
// 作业收尾保存扫描结果时按该租户写入，/api/job 与历史列表也只对该租户可见。
func (s *Server) startBatchJobForTenant(entries []batchItem, tenant string) (string, int) {
	items := make([]batchItem, 0, len(entries))
	for _, it := range entries {
		it.URL = strings.TrimSpace(it.URL)
		if it.URL == "" {
			continue
		}
		it.Level = strings.ToLower(strings.TrimSpace(it.Level))
		it.Tag = strings.TrimSpace(it.Tag)
		items = append(items, it)
	}
	if len(items) == 0 {
		return "", 0
	}
	urls := make([]string, len(items))
	for i, it := range items {
		urls[i] = it.URL
	}
	jobID := newID()
	st := newBatchState(jobID, items)
	st.Tenant = strings.TrimSpace(tenant) // BL-5：批量状态归属租户
	_ = s.saveBatchState(st)
	meta := map[string]any{"urls": urls, "items": items}
	if tag := batchTagOf(items); tag != "" {
		meta["tag"] = tag // 分组标签进 job metadata（结果筛选/通知用）
	}
	if s.jobs != nil {
		s.jobs.Create(jobID, "batch", meta, len(items))
		if tenant = strings.TrimSpace(tenant); tenant != "" {
			s.jobs.Update(jobID, func(j *store.Job) { j.Tenant = tenant })
		}
	}
	go s.runBatch(jobID, items, st)
	return jobID, len(items)
}
