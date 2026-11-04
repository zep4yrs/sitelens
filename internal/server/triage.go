// triage.go CP-08 UI triage 的 HTTP 适配层（路由由 Lead 在 server.Handler() 里接一行）。
//
// 本文件不改 server.go：路由集中在一个注册函数里，Lead 只需在 Handler() 的
// API 段加一行 ——
//
//	s.registerTriageRoutes(mux)
//
// 路由清单：
//
//	POST   /api/triage/{scanID}        body {"fingerprint","verdict","note"} → 标记/覆盖
//	GET    /api/triage/{scanID}        → {scan_id,host,entries,summary}
//	POST   /api/whitelist              body {"host","rule_id","reason"} → 新增/覆盖
//	DELETE /api/whitelist              body {"host","rule_id"} → {removed}
//	GET    /api/whitelist              → {entries}
//	GET    /api/whitelist/check?host=&rule= → {whitelisted}
//
// 契约：
//   - verdict ∈ false_positive / confirmed / ignored（非法 400）；
//   - 复核针对已有历史记录（scan 不存在 404），避免脏 scan_id 落盘；
//   - fingerprint 由前端从扫描结果取（服务端口径见 batchdiff.go 的
//     vulnerabilityFingerprint / verifiedFingerprint，与 SARIF
//     partialFingerprints 同源），这里只做不透明存储，不重算；
//   - 鉴权沿用 Handler() 的 guard 中间件（X-Token），本文件不重复实现；
//   - 存储未初始化（无 data_dir）→ 503，不 panic。
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// registerTriageRoutes 注册 CP-08 复核/白名单路由。
// Lead 接入：在 server.Handler() 的 API 段加一行 s.registerTriageRoutes(mux)。
func (s *Server) registerTriageRoutes(mux *http.ServeMux) {
	if s == nil || mux == nil {
		return
	}
	mux.HandleFunc("POST /api/triage/{scanID}", s.hTriageMark)
	mux.HandleFunc("GET /api/triage/{scanID}", s.hTriageList)
	mux.HandleFunc("POST /api/whitelist", s.hWhitelistAdd)
	mux.HandleFunc("DELETE /api/whitelist", s.hWhitelistRemove)
	mux.HandleFunc("GET /api/whitelist", s.hWhitelistList)
	mux.HandleFunc("GET /api/whitelist/check", s.hWhitelistCheck)
}

// ---- 复核标记 ----

// hTriageMark 标记/覆盖一条发现的复核结论。
func (s *Server) hTriageMark(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	scanID, ok := triageScanID(w, r)
	if !ok {
		return
	}
	var body struct {
		Fingerprint string `json:"fingerprint"`
		Verdict     string `json:"verdict"`
		Note        string `json:"note"`
	}
	if !decodeTriageBody(w, r, &body) {
		return
	}
	// BL-5：跨租户标记复核一律 404（不泄露存在性）。
	if st.GetForTenant(scanID, tenantFromRequest(r)) == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "扫描记录不存在"})
		return
	}
	if err := st.TriageMark(scanID, body.Fingerprint, body.Verdict, body.Note); err != nil {
		writeJSON(w, triageErrStatus(err, store.ErrInvalidTriage), map[string]any{"error": err.Error()})
		return
	}
	fp, confirmed, ignored := st.TriageSummary(scanID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "scan_id": scanID,
		"summary": triageSummaryJSON(fp, confirmed, ignored),
	})
}

// hTriageList 返回某次扫描的复核列表与汇总（结果页/批量复核用）。
func (s *Server) hTriageList(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	scanID, ok := triageScanID(w, r)
	if !ok {
		return
	}
	// BL-5：跨租户读复核列表一律 404。
	rec := st.GetForTenant(scanID, tenantFromRequest(r))
	if rec == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "扫描记录不存在"})
		return
	}
	fp, confirmed, ignored := st.TriageSummary(scanID)
	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": scanID,
		"host":    rec.Host,
		"entries": st.TriageList(scanID),
		"summary": triageSummaryJSON(fp, confirmed, ignored),
	})
}

// ---- 白名单 ----

// hWhitelistAdd 新增/覆盖一条白名单。
func (s *Server) hWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	var body struct {
		Host   string `json:"host"`
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	if !decodeTriageBody(w, r, &body) {
		return
	}
	if err := st.WhitelistAdd(body.Host, body.RuleID, body.Reason); err != nil {
		writeJSON(w, triageErrStatus(err, store.ErrInvalidWhitelist), map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// hWhitelistRemove 删除一条白名单（幂等：不存在返回 removed=false）。
func (s *Server) hWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	var body struct {
		Host   string `json:"host"`
		RuleID string `json:"rule_id"`
	}
	if !decodeTriageBody(w, r, &body) {
		return
	}
	removed, err := st.WhitelistRemove(body.Host, body.RuleID)
	if err != nil {
		writeJSON(w, triageErrStatus(err, store.ErrInvalidWhitelist), map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

// hWhitelistList 返回全部白名单。
func (s *Server) hWhitelistList(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": st.WhitelistList()})
}

// hWhitelistCheck 查询 host+rule 是否被白名单命中（前端扫描结果页抑制提示用）。
func (s *Server) hWhitelistCheck(w http.ResponseWriter, r *http.Request) {
	st := s.triageStore(w)
	if st == nil {
		return
	}
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	rule := strings.TrimSpace(q.Get("rule"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 host 参数"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": host, "rule_id": rule, "whitelisted": st.IsWhitelisted(host, rule),
	})
}

// ---- 内部工具 ----

// triageStore 取历史存储；未初始化时写 503 并返回 nil。
//
// C-09：复核/白名单已纳入 scanStore 接口（JSON/Tiered 与 SQL 后端均实现），
// 不再用类型断言探测具体后端；SQL 后端由 store.SQLStore 的迁移 004 表持久化。
func (s *Server) triageStore(w http.ResponseWriter) scanStore {
	if s == nil || s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "存储未初始化（缺少 data_dir），triage 不可用",
		})
		return nil
	}
	return s.st
}

// triageScanID 解析路径参数 {scanID}（正整数），失败写 400。
func triageScanID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(r.PathValue("scanID"))
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scan_id 必须为正整数"})
		return 0, false
	}
	return id, true
}

// decodeTriageBody 解 JSON 请求体（1MB 上限，与其它 POST 端点同口径）。
func decodeTriageBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON"})
		return false
	}
	return true
}

// triageSummaryJSON 汇总的 JSON 形态（含 total，前端直接渲染）。
func triageSummaryJSON(fp, confirmed, ignored int) map[string]any {
	return map[string]any{
		"false_positive": fp,
		"confirmed":      confirmed,
		"ignored":        ignored,
		"total":          fp + confirmed + ignored,
	}
}

// triageErrStatus 参数错误 → 400，落盘/内部错误 → 500。
func triageErrStatus(err, invalid error) int {
	if errors.Is(err, invalid) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}
