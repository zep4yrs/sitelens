package server

// 任务中心后端（XC-01）：把分散的任务来源聚合成一份「最近任务」列表，
// 供前端任务中心页轮询。
//
// 数据来源（均为只读，不新增持久化）：
//   - batch：<dataDir>/batches/*.json 批量任务状态（含未完成与刚完成、尚未被
//     清理的状态文件），字段最完整，可跨进程重启；
//   - scan：store 历史里最近完成的扫描（已完成 = 任务完成，进度 100）；
//   - live：若 JobManager 未来提供 List() 方法（当前 store 包没有），本文件
//     通过可选接口自动接入，无需改 server.go；
//   - loginbrute：当前 JobManager 无枚举接口且结果不落盘，暂无数据来源
//     （见 loginBruteTaskItems 注释），不伪造条目。
//
// 输出契约（GET /api/tasks）：{tasks:[{id,kind,status,progress,message,created}], total}
// 按 created 倒序（时间不可解析的排最后），字段为稳定 JSON 名。

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// taskItem 一条任务中心条目（对外契约固定六字段）。
type taskItem struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"` // batch / scan / loginbrute
	Status   string `json:"status"`
	Progress int    `json:"progress"` // 0-100
	Message  string `json:"message"`
	Created  string `json:"created"` // RFC3339（解析失败的来源保留原串）
}

// maxTaskLimit GET /api/tasks 单次返回上限（防一次拉爆历史）。
const maxTaskLimit = 200

// taskJobLister 可选接口：store.JobManager 若未来提供 List()，任务中心
// 自动聚合内存中的活跃作业（当前 store 包没有该方法，这里保持零依赖）。
type taskJobLister interface {
	List() []*store.Job
}

// hTasks GET /api/tasks?limit=N —— 最近任务聚合列表。
func (s *Server) hTasks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxTaskLimit {
		limit = maxTaskLimit
	}
	tasks := s.collectTasksForTenant(limit, tenantFromRequest(r))
	writeJSON(w, 200, map[string]any{"tasks": tasks, "total": len(tasks)})
}

// collectTasks 合并全部来源 → 排序 → 截断（legacy 空租户）。
func (s *Server) collectTasks(limit int) []taskItem {
	return s.collectTasksForTenant(limit, "")
}

// collectTasksForTenant 同 collectTasks，但按租户过滤（BL-5）：
// scan 历史 / 活跃 job / 批量状态均只返回本租户条目；auth 关闭时 tenant 空
// = 不过滤（既有行为不变）。nil 服务返回空数组（而非 null）。
func (s *Server) collectTasksForTenant(limit int, tenant string) []taskItem {
	items := []taskItem{}
	if s == nil {
		return items
	}
	items = append(items, s.batchTaskItems(tenant)...)
	items = append(items, s.scanTaskItems(limit, tenant)...)
	items = append(items, s.liveJobTaskItemsForTenant(tenant)...)
	items = append(items, s.loginBruteTaskItems()...)
	sortTaskItems(items)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// batchTaskItems 批量任务：直接读状态目录（不调用 listBatchStates——那会
// 把已完成状态文件当陈旧数据清掉，任务中心需要保留最近完成记录）。
// tenant 非空时只返回归属该租户的批量状态（BL-5）。
func (s *Server) batchTaskItems(tenant string) []taskItem {
	entries, err := os.ReadDir(s.batchStateDir())
	if err != nil {
		return nil
	}
	out := make([]taskItem, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		st := s.loadBatchState(strings.TrimSuffix(name, ".json"))
		if st == nil {
			continue
		}
		if tenant != "" && st.Tenant != tenant {
			continue
		}
		out = append(out, batchTaskItem(st))
	}
	return out
}

// batchTaskItem 批量状态 → 任务条目（状态/进度按条目完成数推导）。
func batchTaskItem(st *batchState) taskItem {
	if st == nil {
		return taskItem{}
	}
	done, failed, running, total := 0, 0, 0, len(st.Items)
	for _, it := range st.Items {
		switch it.Status {
		case "done":
			done++
		case "failed":
			failed++
		case "running":
			running++
		}
	}
	status := "pending"
	switch {
	case st.Cancelled:
		status = "cancelled"
	case st.Finished:
		status = "done"
	case running > 0:
		status = "running"
	}
	progress := 100
	if total > 0 {
		progress = done * 100 / total
	}
	msg := fmt.Sprintf("批量任务：%d/%d 完成", done, total)
	if failed > 0 {
		msg += fmt.Sprintf("，失败 %d", failed)
	}
	return taskItem{
		ID: st.JobID, Kind: "batch", Status: status,
		Progress: progress, Message: msg,
		Created: formatTaskTime(st.CreatedAt),
	}
}

// scanTaskItems 最近完成的扫描（store 历史，最新在前由 Store.List 保证）。
// tenant 非空时只返回该租户记录（BL-5）。
func (s *Server) scanTaskItems(limit int, tenant string) []taskItem {
	if s.st == nil {
		return nil
	}
	if limit <= 0 {
		limit = 50
	}
	scans := s.st.ListForTenant(limit, "", tenant)
	out := make([]taskItem, 0, len(scans))
	for _, rec := range scans {
		msg := "扫描完成：" + rec.URL
		if rec.VulnCount > 0 {
			msg += fmt.Sprintf("（情报关联 %d）", rec.VulnCount)
		}
		out = append(out, taskItem{
			ID: "scan-" + strconv.FormatInt(rec.ID, 10), Kind: "scan",
			Status: "done", Progress: 100, Message: msg,
			Created: formatTaskTime(rec.ScannedAt),
		})
	}
	return out
}

// liveJobTaskItems 聚合内存中的活跃作业（legacy 空租户；兼容既有调用）。
func (s *Server) liveJobTaskItems() []taskItem {
	return s.liveJobTaskItemsForTenant("")
}

// liveJobTaskItemsForTenant 同 liveJobTaskItems，但按租户过滤（BL-5）。
func (s *Server) liveJobTaskItemsForTenant(tenant string) []taskItem {
	l, ok := any(s.jobs).(taskJobLister)
	if !ok || s.jobs == nil {
		return nil
	}
	jobs := l.List()
	out := make([]taskItem, 0, len(jobs))
	for _, j := range jobs {
		if j == nil {
			continue
		}
		if tenant != "" && j.Tenant != tenant {
			continue
		}
		out = append(out, jobToTaskItem(j))
	}
	return out
}

// jobToTaskItem store.Job → 任务条目。Job 无 Created 字段：取首个事件时间戳
// （实时事件流按发生顺序追加），无事件时留空（排序时排最后）。
func jobToTaskItem(j *store.Job) taskItem {
	created := ""
	if len(j.Events) > 0 && j.Events[0].TS > 0 {
		created = time.Unix(j.Events[0].TS, 0).Format(time.RFC3339)
	}
	msg := j.Message
	if msg == "" {
		msg = j.Kind
	}
	return taskItem{
		ID: j.ID, Kind: j.Kind, Status: j.Status,
		Progress: j.Progress, Message: msg, Created: created,
	}
}

// loginBruteTaskItems 登录爆破任务：当前无数据来源——JobManager 无枚举接口、
// 爆破结果（hits）也不落盘，因此不产出条目。若后续 JobManager 提供 List()
// 或爆破结果入库，只需在此追加来源即可（对外契约不变）。
func (s *Server) loginBruteTaskItems() []taskItem {
	return nil
}

// sortTaskItems 按 created 倒序；时间不可解析排最后；同时间按 ID 倒序保证稳定。
func sortTaskItems(items []taskItem) {
	sort.SliceStable(items, func(i, j int) bool {
		ti, tj := parseTaskTime(items[i].Created), parseTaskTime(items[j].Created)
		switch {
		case ti.IsZero() && tj.IsZero():
			return items[i].ID > items[j].ID
		case ti.IsZero():
			return false
		case tj.IsZero():
			return true
		case ti.Equal(tj):
			return items[i].ID > items[j].ID
		default:
			return ti.After(tj)
		}
	})
}

// parseTaskTime 解析任务时间：批量状态用 RFC3339，扫描历史用
// "2006-01-02 15:04:05"（无时区，按本地时区解析，与写入侧一致）。
func parseTaskTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

// formatTaskTime 统一输出 RFC3339；不可解析时保留原始字符串（可读优先）。
func formatTaskTime(s string) string {
	if t := parseTaskTime(s); !t.IsZero() {
		return t.Format(time.RFC3339)
	}
	return strings.TrimSpace(s)
}
