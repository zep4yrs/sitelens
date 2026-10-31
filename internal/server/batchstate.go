package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// batchStateItem 单条目标的持久化状态（断点续跑用）。
type batchStateItem struct {
	URL       string `json:"url"`
	Level     string `json:"level,omitempty"`
	Status    string `json:"status"` // queued|running|done|failed|skipped
	Attempts  int    `json:"attempts,omitempty"`
	Findings  int    `json:"findings,omitempty"`
	Techs     int    `json:"techs,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// batchState 一个批量任务的可恢复状态（落盘到 <dataDir>/batches/<job>.json）。
type batchState struct {
	JobID     string           `json:"job_id"`
	CreatedAt string           `json:"created_at"`
	UpdatedAt string           `json:"updated_at"`
	Finished  bool             `json:"finished"`
	Cancelled bool             `json:"cancelled"`
	Items     []batchStateItem `json:"items"`
}

// batchStateDir 批量状态目录（与 history.json 同级的 batches/）。
func (s *Server) batchStateDir() string {
	return filepath.Join(s.cfg.Store.DataDir, "batches")
}

func (s *Server) batchStatePath(jobID string) string {
	return filepath.Join(s.batchStateDir(), jobID+".json")
}

// saveBatchState 原子写状态文件（临时文件 + rename；Windows 目标存在时先删）。
func (s *Server) saveBatchState(st *batchState) error {
	if st == nil || st.JobID == "" {
		return nil
	}
	dir := s.batchStateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	st.UpdatedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, st.JobID+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
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
	dst := s.batchStatePath(st.JobID)
	_ = os.Remove(dst) // Windows rename 不覆盖已存在文件
	return os.Rename(tmpName, dst)
}

// loadBatchState 读取状态文件；不存在/损坏返回 nil。
func (s *Server) loadBatchState(jobID string) *batchState {
	if jobID == "" {
		return nil
	}
	data, err := os.ReadFile(s.batchStatePath(jobID))
	if err != nil {
		return nil
	}
	var st batchState
	if json.Unmarshal(data, &st) != nil || st.JobID == "" {
		return nil
	}
	return &st
}

// deleteBatchState 删除状态文件（完成/放弃后）。
func (s *Server) deleteBatchState(jobID string) {
	_ = os.Remove(s.batchStatePath(jobID))
}

// listBatchStates 列出未完成（可续跑）的批量状态，最新在前；顺带清理 7 天前的陈旧文件。
func (s *Server) listBatchStates() []*batchState {
	entries, err := os.ReadDir(s.batchStateDir())
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []*batchState
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		jobID := strings.TrimSuffix(name, ".json")
		st := s.loadBatchState(jobID)
		if st == nil {
			continue
		}
		if st.Finished {
			s.deleteBatchState(jobID)
			continue
		}
		if ts, err := time.Parse(time.RFC3339, st.UpdatedAt); err == nil && now.Sub(ts) > 7*24*time.Hour {
			s.deleteBatchState(jobID)
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

// pendingBatchItems 断点续跑选择：未完成的目标（done 跳过；failed 默认重试）。
func pendingBatchItems(st *batchState, retryFailed bool) []batchItem {
	if st == nil {
		return nil
	}
	var out []batchItem
	for _, it := range st.Items {
		switch it.Status {
		case "done":
			continue
		case "failed":
			if !retryFailed {
				continue
			}
		}
		if strings.TrimSpace(it.URL) == "" {
			continue
		}
		out = append(out, batchItem{URL: it.URL, Level: it.Level})
	}
	return out
}

// newBatchState 由目标列表构造初始状态。
func newBatchState(jobID string, items []batchItem) *batchState {
	st := &batchState{JobID: jobID, CreatedAt: time.Now().Format(time.RFC3339)}
	st.Items = make([]batchStateItem, len(items))
	for i, it := range items {
		st.Items[i] = batchStateItem{URL: it.URL, Level: it.Level, Status: "queued"}
	}
	return st
}

// hBatchJobs 列出可断点续跑的批量任务（未完成状态文件）。
func (s *Server) hBatchJobs(w http.ResponseWriter, r *http.Request) {
	sts := s.listBatchStates()
	writeJSON(w, 200, map[string]any{"jobs": sts})
}

// hBatchResume 从状态文件续跑：done 跳过，failed 默认重试（?retry_failed=0 可关）。
// 旧状态文件删除，新任务只包含待续跑目标（已完成结果已在历史里）。
func (s *Server) hBatchResume(w http.ResponseWriter, r *http.Request) {
	oldID := r.PathValue("id")
	st := s.loadBatchState(oldID)
	if st == nil {
		writeJSON(w, 404, map[string]any{"error": "批量状态不存在或已完成"})
		return
	}
	retryFailed := r.URL.Query().Get("retry_failed") != "0"
	items := pendingBatchItems(st, retryFailed)
	if len(items) == 0 {
		s.deleteBatchState(oldID)
		writeJSON(w, 400, map[string]any{"error": "没有待续跑目标"})
		return
	}
	newJobID := newID()
	nst := newBatchState(newJobID, items)
	if err := s.saveBatchState(nst); err != nil {
		writeJSON(w, 500, map[string]any{"error": "保存批量状态失败：" + err.Error()})
		return
	}
	s.deleteBatchState(oldID)
	urls := make([]string, len(items))
	for i, it := range items {
		urls[i] = it.URL
	}
	s.jobs.Create(newJobID, "batch", map[string]any{"urls": urls, "items": items, "resumed_from": oldID}, len(items))
	go s.runBatch(newJobID, items, nst)
	writeJSON(w, 200, map[string]any{"job_id": newJobID, "total": len(items), "resumed_from": oldID})
}
