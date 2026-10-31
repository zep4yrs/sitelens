package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// hBatchSchedulesList 列出全部定时批量任务。
func (s *Server) hBatchSchedulesList(w http.ResponseWriter, r *http.Request) {
	list, err := s.LoadSchedules()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "读取定时任务失败：" + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"schedules": list})
}

// hBatchScheduleCreate 新建定时批量（body 即 Schedule）。
func (s *Server) hBatchScheduleCreate(w http.ResponseWriter, r *http.Request) {
	var sc Schedule
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&sc); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体非法"})
		return
	}
	if len(sc.Entries) == 0 {
		writeJSON(w, 400, map[string]any{"error": "entries 不能为空"})
		return
	}
	out, err := s.UpsertSchedule(sc)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "保存失败：" + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"schedule": out})
}

// hBatchScheduleUpdate PATCH 局部更新：读取现有 → 覆盖提供的字段 → 保存。
func (s *Server) hBatchScheduleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, err := s.LoadSchedules()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	var cur *Schedule
	for i := range list {
		if list[i].ID == id {
			cur = &list[i]
			break
		}
	}
	if cur == nil {
		writeJSON(w, 404, map[string]any{"error": "定时任务不存在"})
		return
	}
	var patch map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&patch); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体非法"})
		return
	}
	base, _ := json.Marshal(cur)
	var merged map[string]any
	_ = json.Unmarshal(base, &merged)
	for k, v := range patch {
		merged[k] = v
	}
	var next Schedule
	data, _ := json.Marshal(merged)
	if err := json.Unmarshal(data, &next); err != nil {
		writeJSON(w, 400, map[string]any{"error": "字段非法"})
		return
	}
	next.ID = id
	out, err := s.UpsertSchedule(next)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "保存失败：" + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"schedule": out})
}

// hBatchScheduleDelete 删除定时批量。
func (s *Server) hBatchScheduleDelete(w http.ResponseWriter, r *http.Request) {
	ok, err := s.DeleteSchedule(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "定时任务不存在"})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}

// hBatchScheduleRun 立即执行一次定时任务（不影响下次排期）。
func (s *Server) hBatchScheduleRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, err := s.LoadSchedules()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	var sc *Schedule
	for i := range list {
		if list[i].ID == id {
			sc = &list[i]
			break
		}
	}
	if sc == nil {
		writeJSON(w, 404, map[string]any{"error": "定时任务不存在"})
		return
	}
	jobID, total := s.startBatchJob(scheduleEntries(*sc))
	if total == 0 {
		writeJSON(w, 400, map[string]any{"error": "定时任务没有可执行目标"})
		return
	}
	now := time.Now()
	sc.LastRunAt = now.Format(time.RFC3339)
	sc.NextRunAt = sc.nextRunAfter(now).Format(time.RFC3339)
	if _, err := s.UpsertSchedule(*sc); err != nil {
		writeJSON(w, 500, map[string]any{"error": "回写排期失败：" + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": jobID, "total": total, "schedule": sc})
}
