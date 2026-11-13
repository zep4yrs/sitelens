package server

// 目标导向证明链 API（5.3 P1，设计稿 §4.1/§5）。
//
// 路由：
//
//	POST /api/proof/goals        创建验证目标（需授权目标 + allow_hosts）
//	GET  /api/proof/goals        列出目标
//	POST /api/proof/plan         对目标规划证明链（只读，返回 Chain[]）
//	GET  /api/proof/chains       列出证明链（可按 goal_id 过滤）
//	GET  /api/graph/paths        攻击图路径（最短/瓶颈/证据缺口）
//
// 设计纪律：
//   - 规划只读图数据，不触发扫描、不发任何请求；
//   - 目标创建与规划都不落敏感值；
//   - 目标/链保存在进程内存（重启清空），后续可迁移到 store（P2）。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/proof"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// proofGoalRequest 创建目标请求。
type proofGoalRequest struct {
	Title  string `json:"title"`
	Target string `json:"target"`
	Level  string `json:"level"`
}

// normalizeGoalTarget 把用户输入（URL 或 host）归一为 host，并过安全闸。
func normalizeGoalTarget(raw string, allowHosts []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errBadRequest("target 不能为空")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	_, host, _, err := target.Validate(raw, false)
	if err != nil {
		return "", err
	}
	if !target.Allowed(host, allowHosts) {
		return "", errForbidden("目标不在 allow_hosts 授权白名单：" + host)
	}
	return host, nil
}

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func errBadRequest(msg string) error { return &apiError{status: 400, msg: msg} }
func errForbidden(msg string) error  { return &apiError{status: 403, msg: msg} }

// hProofGoals POST 创建 / GET 列表。
func (s *Server) hProofGoals(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.proofMu.Lock()
		goals := append([]proof.Goal(nil), s.proofGoals...)
		s.proofMu.Unlock()
		writeJSON(w, 200, map[string]any{"goals": goals, "count": len(goals)})
		return
	}
	var req proofGoalRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体不是合法 JSON: " + err.Error()})
		return
	}
	cfg := s.cfgSnap()
	host, err := normalizeGoalTarget(req.Target, cfg.Scan.AllowHosts)
	if err != nil {
		var ae *apiError
		if e, ok := err.(*apiError); ok {
			ae = e
			writeJSON(w, ae.status, map[string]any{"error": ae.msg})
		} else {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
		}
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "验证 " + host
	}
	level := proof.NormalizeLevel(req.Level)
	now := time.Now()
	goal := proof.Goal{
		ID:        "goal-" + strconv.FormatInt(now.UnixNano(), 36),
		Title:     title,
		Target:    host,
		Level:     level,
		CreatedAt: now,
		Status:    "active",
	}
	s.proofMu.Lock()
	s.proofGoals = append(s.proofGoals, goal)
	s.proofMu.Unlock()
	writeJSON(w, 201, map[string]any{"goal": goal})
}

// hProofPlan POST 规划证明链（只读）。
func (s *Server) hProofPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GoalID string `json:"goal_id"`
		ScanID int64  `json:"scan_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体不是合法 JSON: " + err.Error()})
		return
	}
	s.proofMu.Lock()
	var goal *proof.Goal
	for i := range s.proofGoals {
		if s.proofGoals[i].ID == req.GoalID {
			g := s.proofGoals[i]
			goal = &g
			break
		}
	}
	s.proofMu.Unlock()
	if goal == nil {
		writeJSON(w, 404, map[string]any{"error": "目标不存在"})
		return
	}
	scanID := req.ScanID
	if scanID == 0 {
		scanID = s.latestScanIDForHost(goal.Target, tenantFromRequest(r))
	}
	if scanID == 0 {
		writeJSON(w, 404, map[string]any{"error": "该目标还没有扫描记录（先完成一次扫描）", "goal_id": goal.ID})
		return
	}
	g, status := s.st.GraphWithStatus(scanID)
	switch status {
	case "absent":
		writeJSON(w, 404, map[string]any{"error": "该扫描未收集结构化事实图（扫描时需开启 graph）", "scan_id": scanID})
		return
	case "corrupt":
		writeJSON(w, 500, map[string]any{"error": "图数据损坏（无法解析）", "scan_id": scanID})
		return
	}
	chains := proof.Plan(*goal, g, time.Now())
	s.proofMu.Lock()
	kept := s.proofChains[:0]
	for _, c := range s.proofChains {
		if c.GoalID != goal.ID {
			kept = append(kept, c)
		}
	}
	s.proofChains = append(kept, chains...)
	s.proofMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"goal_id": goal.ID, "scan_id": scanID,
		"chains": chains, "count": len(chains),
	})
}

// hProofChains GET 列出证明链。
func (s *Server) hProofChains(w http.ResponseWriter, r *http.Request) {
	goalID := strings.TrimSpace(r.URL.Query().Get("goal_id"))
	s.proofMu.Lock()
	out := make([]proof.Chain, 0, len(s.proofChains))
	for _, c := range s.proofChains {
		if goalID == "" || c.GoalID == goalID {
			out = append(out, c)
		}
	}
	s.proofMu.Unlock()
	writeJSON(w, 200, map[string]any{"chains": out, "count": len(out)})
}

// hGraphPaths GET 攻击图路径（最短/瓶颈/证据缺口）。
func (s *Server) hGraphPaths(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	idStr := strings.TrimSpace(q.Get("scan_id"))
	if idStr == "" {
		idStr = strings.TrimSpace(q.Get("id"))
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, 400, map[string]any{"error": "scan_id 必须是正整数"})
		return
	}
	if s.st.GetForTenant(id, tenantFromRequest(r)) == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	g, status := s.st.GraphWithStatus(id)
	switch status {
	case "absent":
		writeJSON(w, 404, map[string]any{"error": "该扫描未收集结构化事实图", "scan_id": id})
		return
	case "corrupt":
		writeJSON(w, 500, map[string]any{"error": "图数据损坏", "scan_id": id})
		return
	}
	limit := 16
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 && n <= 128 {
			limit = n
		}
	}
	from := strings.TrimSpace(q.Get("from"))
	to := strings.TrimSpace(q.Get("to"))
	if from != "" {
		if u, perr := url.Parse(from); perr == nil && u.Host != "" {
			from = u.Host
		}
	}
	view := g.ShortestPaths(from, to, limit)
	writeJSON(w, 200, map[string]any{
		"scan_id": id, "schema": g.Schema,
		"from": view.From, "to": view.To,
		"paths": view.Paths, "path_count": len(view.Paths),
		"bottlenecks": view.Bottlenecks, "evidence_gaps": view.EvidenceGaps,
		"truncated": view.Truncated,
	})
}

// latestScanIDForHost 找该 host 最近一次扫描（租户隔离）。
func (s *Server) latestScanIDForHost(host, tenant string) int64 {
	list := s.st.ListForTenant(200, "", tenant)
	for _, it := range list {
		if strings.EqualFold(strings.TrimSpace(it.Host), host) {
			return it.ID
		}
	}
	return 0
}
