// FE-12 零丢失：取消/中断扫描的部分结果落库 + 续扫规划（新文件）。
//
// 背景：engine.Scan 被取消时仍返回已采集的部分结果（页面/技术/发现/证据），
// 但 server.runScanJob 的取消分支此前直接丢弃、只写 job.Status=cancelled。
// 本文件提供落库函数（不修改 server.go；Lead 只需在取消分支接线一行）：
//
//	if s.jobs.CancelRequested(jobID) {
//	    lastPhase := ""
//	    if j := s.jobs.Get(jobID); j != nil && j.Live != nil { lastPhase = j.Live.Phase }
//	    s.SavePartialJob(jobID, res, PartialOptions(opts), lastPhase)
//	    return
//	}
//
// 落库口径：
//   - 记录写入既有 store（history.json），Result.Partial=true、Options.status=
//     "partial"，页面/技术/发现/证据原样保留（"不再直接丢弃"）；
//   - 同时把 job 状态迁移到 partial（非法迁移拒绝并记录事件，数据仍落库）；
//   - ResumePlan 纯函数给出未完成阶段/页面，供上层续扫与前端提示。
package server

import (
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// partialStatusValue 落库/读取时使用的统一 status 值（Options["status"]）。
const partialStatusValue = "partial"

// PartialRecord 一次「部分结果」的可读视图（历史 + 续扫数据）。
// Result 不重复序列化（历史原记录经 store.Get 读取）；此处只放摘要与计划。
type PartialRecord struct {
	ScanID           int64           `json:"scan_id"`
	JobID            string          `json:"job_id,omitempty"`
	URL              string          `json:"url"`
	Host             string          `json:"host"`
	Status           engine.JobState `json:"status"` // 固定 partial
	Partial          bool            `json:"partial"`
	InterruptedPhase string          `json:"interrupted_phase,omitempty"`
	CompletedPhases  []string        `json:"completed_phases,omitempty"`
	RemainingPhases  []string        `json:"remaining_phases,omitempty"`
	Pages            []string        `json:"pages,omitempty"` // 已采集页面 URL（去重、保序）
	PageCount        int             `json:"page_count"`
	TechCount        int             `json:"tech_count"`
	FindingCount     int             `json:"finding_count"`
	EvidenceCount    int             `json:"evidence_count"`
	ResumeTargets    []string        `json:"resume_targets,omitempty"` // ResumePlan 结果
	ScannedAt        string          `json:"scanned_at,omitempty"`
	SavedAt          string          `json:"saved_at"`
	Options          map[string]any  `json:"options,omitempty"`
	Result           *engine.Result  `json:"-"`
}

// PartialSummary 部分结果的历史摘要（供 /api/scans 类列表过滤展示）。
type PartialSummary struct {
	ScanID           int64    `json:"scan_id"`
	URL              string   `json:"url"`
	Host             string   `json:"host"`
	Status           string   `json:"status"`
	ScannedAt        string   `json:"scanned_at,omitempty"`
	InterruptedPhase string   `json:"interrupted_phase,omitempty"`
	CompletedPhases  []string `json:"completed_phases,omitempty"`
	RemainingPhases  []string `json:"remaining_phases,omitempty"`
	ResumeTargets    []string `json:"resume_targets,omitempty"`
	PageCount        int      `json:"page_count"`
	TechCount        int      `json:"tech_count"`
	FindingCount     int      `json:"finding_count"`
	EvidenceCount    int      `json:"evidence_count"`
}

// PartialOptions 把引擎选项展开为与 scanOptions 一致的扁平 map（供落库与
// ResumePlan 判定阶段是否启用）。Lead 接线时直接传入即可。
func PartialOptions(opts engine.Options) map[string]any {
	m := map[string]any{
		"deep": opts.Deep, "checks": opts.Checks,
		"dast": opts.DAST, "passive": opts.Passive, "netsec": opts.Netsec,
		"js_map": opts.JSMap, "exploit": opts.Exploit,
		"subdomain": opts.Subdomain, "takeover": opts.Takeover,
		"dir_scan": opts.DirScan, "dir_bypass": opts.DirBypass,
		"webshell": opts.Webshell, "active_fp": opts.ActiveFP,
		"service_probe": opts.ServiceProbe, "netproto": opts.NetProto,
		"weak_audit": opts.WeakAudit, "graph": opts.Graph,
	}
	if opts.NucleiCap > 0 {
		m["nuclei_cap"] = opts.NucleiCap
	}
	return m
}

// SavePartial 把部分结果落库（无 job 上下文；等价于 SavePartialAt 空中断阶段）。
// 返回 scan ID 与可读记录；res/st 为空时返回 (0, nil)，绝不 panic。
func SavePartial(st scanStore, res *engine.Result, options map[string]any) (int64, *PartialRecord) {
	return SavePartialAt(st, res, options, "")
}

// SavePartialAt 落库部分结果并标记中断阶段。
//
// 行为：
//   - engine.MarkPartial 置 Result.Partial=true、CompletedPhases（诊断账本）；
//   - Options 副本写入 status=partial / partial=true / interrupted_phase；
//   - store.Save 原样保存页面/技术/发现/证据（Map 图走既有逻辑）；
//   - 返回的 PartialRecord 已带 ResumePlan（ResumeTargets/RemainingPhases）。
func SavePartialAt(st scanStore, res *engine.Result, options map[string]any, interruptedPhase string) (int64, *PartialRecord) {
	if st == nil || res == nil {
		return 0, nil
	}
	engine.MarkPartial(res, interruptedPhase)
	opts := copyAnyMap(options)
	opts["status"] = partialStatusValue
	opts["partial"] = true
	if interruptedPhase != "" {
		opts["interrupted_phase"] = interruptedPhase
	}
	scanID := st.Save(res, opts)
	rec := newPartialRecord(scanID, "", res, opts, interruptedPhase)
	return scanID, rec
}

// SavePartialJob server 侧接线入口：落库 + job 状态迁移到 partial。
//
// 状态迁移走 engine 状态机校验：合法则把 job.Status 置 partial 并写
// scan_id/resume_targets；非法（如 job 已 done）拒绝改状态、追加一条事件
// 说明，但「数据仍落库」——零丢失优先于状态一致性。
func (s *Server) SavePartialJob(jobID string, res *engine.Result, options map[string]any, interruptedPhase string) (int64, *PartialRecord) {
	if s == nil || s.st == nil {
		return 0, nil
	}
	scanID, rec := SavePartialAt(s.st, res, options, interruptedPhase)
	if rec != nil {
		rec.JobID = jobID
	}
	if s.jobs == nil || jobID == "" {
		return scanID, rec
	}
	var targets []string
	if rec != nil {
		targets = rec.ResumeTargets
	}
	// 先读快照再决定迁移（JobManager 的 RWMutex 不可重入，不能在 Update 回调里 Get）。
	cur := s.jobs.Get(jobID)
	if cur == nil {
		return scanID, rec
	}
	from, ok := engine.JobStateFromLegacy(cur.Status)
	if !ok {
		from = engine.StateRunning
	}
	if err := engine.ValidateTransition(from, engine.StatePartial); err != nil {
		s.jobs.AppendEvent(jobID, "info",
			"部分结果已保存（scan_id="+itoaServer(int(scanID))+"），但状态迁移被拒绝："+err.Error())
		return scanID, rec
	}
	msg := engine.PartialSummaryText(res)
	s.jobs.Update(jobID, func(j *store.Job) {
		j.Status = engine.StatePartial.LegacyJobStatus()
		j.Message = msg
		resPayload := map[string]any{"scan_id": scanID, "partial": true}
		if len(targets) > 0 {
			resPayload["resume_targets"] = targets
		}
		j.Result = resPayload
	})
	s.jobs.AppendEvent(jobID, "info", msg+"；可续扫目标 "+itoaServer(len(targets))+" 项")
	return scanID, rec
}

// LoadPartialRecord 从历史读回部分结果记录（历史可读）。
// 非部分记录（正常完成）返回 (nil,false)。
func LoadPartialRecord(st scanStore, scanID int64) (*PartialRecord, bool) {
	if st == nil {
		return nil, false
	}
	rec := st.Get(scanID)
	if rec == nil || rec.Result == nil {
		return nil, false
	}
	if !recordIsPartial(rec) {
		return nil, false
	}
	out := newPartialRecord(rec.ID, "", rec.Result, rec.Options, interruptedFromOptions(rec.Options))
	out.URL = firstNonEmptyStr(out.URL, rec.URL)
	out.Host = firstNonEmptyStr(out.Host, rec.Host)
	if out.ScannedAt == "" {
		out.ScannedAt = rec.ScannedAt
	}
	return out, true
}

// ListPartials 历史列表中的部分结果摘要（新→旧，最多 limit 条）。
// 走 store.List 的摘要顺序，再按需回读完整记录判定是否 partial。
func ListPartials(st scanStore, limit int) []PartialSummary {
	if st == nil || limit <= 0 {
		return nil
	}
	// 摘要窗口放大：List 只返回最近摘要，其中可能混有正常记录。
	window := limit * 4
	if window < limit {
		window = limit
	}
	if window > 500 {
		window = 500
	}
	summaries := st.List(window, "")
	out := make([]PartialSummary, 0, limit)
	for _, sum := range summaries {
		if len(out) >= limit {
			break
		}
		rec, ok := LoadPartialRecord(st, sum.ID)
		if !ok {
			continue
		}
		out = append(out, PartialSummary{
			ScanID: rec.ScanID, URL: rec.URL, Host: rec.Host,
			Status: string(rec.Status), ScannedAt: rec.ScannedAt,
			InterruptedPhase: rec.InterruptedPhase,
			CompletedPhases:  rec.CompletedPhases,
			RemainingPhases:  rec.RemainingPhases,
			ResumeTargets:    rec.ResumeTargets,
			PageCount:        rec.PageCount, TechCount: rec.TechCount,
			FindingCount: rec.FindingCount, EvidenceCount: rec.EvidenceCount,
		})
	}
	return out
}

// ResumePlan 续扫规划：返回未完成阶段/页面目标（形如 "phase:dast"、
// "page:https://host/path"）。纯函数，不读写存储。
//
// 口径：
//   - 阶段：引擎诊断账本名（home/jsmap/crawl/fingerprint/security/checks/
//     nuclei/passive/dast/modules/netsec/intel/ml），按扫描选项判断是否启用；
//     已完成阶段跳过，但「中断时所在阶段」强制重跑（该阶段可能只跑了一半）；
//   - 页面：已采集但状态为 0（未拿到响应）或 5xx 的页面给出重试目标，上限 20；
//   - 去重保序：中断阶段在前，其余按阶段顺序，最后页面。
func ResumePlan(rec *PartialRecord) []string {
	if rec == nil {
		return nil
	}
	return resumeTargets(rec.Result, rec.CompletedPhases, rec.InterruptedPhase, rec.Options)
}

// resumeTargets ResumePlan 的实现（便于测试纯数据输入）。
func resumeTargets(res *engine.Result, completed []string, interruptedPhase string, options map[string]any) []string {
	done := make(map[string]bool, len(completed))
	for _, p := range completed {
		if p != "" {
			done[p] = true
		}
	}
	interrupted := normalizeResumePhase(interruptedPhase)
	seen := map[string]bool{}
	add := func(targets []string, t string) []string {
		if t == "" || seen[t] {
			return targets
		}
		seen[t] = true
		return append(targets, t)
	}

	out := make([]string, 0, 4)
	// 1) 中断阶段优先（即使诊断账本误记完成也要重跑）。
	if interrupted != "" {
		// 中断阶段无需再判选项：它实际在跑，说明本次扫描已启用该阶段。
		out = add(out, "phase:"+interrupted)
	}
	// 2) 其余未完成且启用的阶段（按引擎阶段顺序）。
	for _, p := range resumePhaseOrder {
		if !p.enabled(options) || done[p.name] {
			continue
		}
		out = add(out, "phase:"+p.name)
	}
	// 3) 未成功采集的页面（status==0 或 5xx），最多 20 条。
	if res != nil {
		n := 0
		for _, page := range res.Pages {
			if n >= maxResumePages {
				break
			}
			if page.URL == "" {
				continue
			}
			if page.Status != 0 && page.Status < 500 {
				continue
			}
			before := len(out)
			out = add(out, "page:"+page.URL)
			if len(out) > before {
				n++
			}
		}
	}
	return out
}

// maxResumePages 续扫页面目标上限（避免大站点计划爆炸）。
const maxResumePages = 20

// resumePhase 一个可续扫阶段（启用判定依赖扫描选项）。
type resumePhase struct {
	name    string
	enabled func(map[string]any) bool
}

func alwaysPhase(map[string]any) bool { return true }

// resumePhaseOrder 引擎阶段顺序（与 engine.Scan 的诊断账本阶段对齐）。
var resumePhaseOrder = []resumePhase{
	{"home", alwaysPhase},
	{"jsmap", func(o map[string]any) bool { return optBool(o, "js_map") || optBool(o, "dast") }},
	{"crawl", alwaysPhase},
	{"fingerprint", alwaysPhase},
	{"security", alwaysPhase},
	{"checks", alwaysPhase},
	{"nuclei", func(o map[string]any) bool { return strings.EqualFold(optStr(o, "checks"), "all") }},
	{"passive", func(o map[string]any) bool { return optBool(o, "passive") }},
	{"dast", func(o map[string]any) bool { return optBool(o, "dast") }},
	{"modules", modulesEnabled},
	{"netsec", func(o map[string]any) bool { return optBool(o, "netsec") }},
	{"intel", alwaysPhase},
	{"ml", alwaysPhase},
}

// modulesEnabled 主动模块阶段是否启用（任一主动开关为真）。
func modulesEnabled(o map[string]any) bool {
	for _, key := range []string{
		"subdomain", "takeover", "dir_scan", "dir_bypass", "webshell",
		"active_fp", "service_probe", "weak_audit", "exploit",
	} {
		if optBool(o, key) {
			return true
		}
	}
	return false
}

// livePhaseToResume 引擎 live 阶段名 → 诊断账本阶段名（用于中断阶段归一）。
var livePhaseToResume = map[string]string{
	"prepare": "home", "home": "home", "jsmap": "jsmap", "crawl": "crawl",
	"fingerprint": "fingerprint", "security": "security", "checks": "checks",
	"nuclei": "nuclei", "passive": "passive", "dast": "dast", "exploit": "dast",
	"active": "modules", "modules": "modules",
	"netsec": "netsec", "intel": "intel", "ml": "ml",
}

// normalizeResumePhase live 阶段名归一为诊断账本阶段名（未知原样返回）。
func normalizeResumePhase(phase string) string {
	p := strings.ToLower(strings.TrimSpace(phase))
	if mapped, ok := livePhaseToResume[p]; ok {
		return mapped
	}
	return p
}

// newPartialRecord 由结果构造可读记录（内部统一出口，保证字段一致）。
func newPartialRecord(scanID int64, jobID string, res *engine.Result, opts map[string]any, interruptedPhase string) *PartialRecord {
	pages, techs, findings, evidence := engine.PartialCounts(res)
	pageURLs := pagesURLs(res)
	completed := engine.CompletedPhases(res)
	if len(completed) == 0 && res != nil {
		completed = append(completed, res.CompletedPhases...)
	}
	rec := &PartialRecord{
		ScanID: scanID, JobID: jobID,
		Status: engine.StatePartial, Partial: true,
		InterruptedPhase: interruptedPhase,
		CompletedPhases:  completed,
		Pages:            pageURLs,
		PageCount:        pages, TechCount: techs,
		FindingCount: findings, EvidenceCount: evidence,
		SavedAt: time.Now().Format(time.RFC3339),
		Options: copyAnyMap(opts),
		Result:  res,
	}
	if res != nil {
		rec.URL, rec.Host, rec.ScannedAt = res.URL, res.Host, res.ScannedAt
	}
	rec.RemainingPhases = remainingPhaseNames(rec.CompletedPhases, interruptedPhase, opts)
	rec.ResumeTargets = resumeTargets(res, rec.CompletedPhases, interruptedPhase, opts)
	return rec
}

// remainingPhaseNames 仅阶段部分（ResumePlan 去掉页面目标）。
func remainingPhaseNames(completed []string, interruptedPhase string, options map[string]any) []string {
	all := resumeTargets(&engine.Result{}, completed, interruptedPhase, options)
	out := make([]string, 0, len(all))
	for _, t := range all {
		if strings.HasPrefix(t, "phase:") {
			out = append(out, strings.TrimPrefix(t, "phase:"))
		}
	}
	return out
}

// pagesURLs 结果页面 URL（去重保序）。
func pagesURLs(res *engine.Result) []string {
	if res == nil || len(res.Pages) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(res.Pages))
	for _, p := range res.Pages {
		if p.URL == "" || seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		out = append(out, p.URL)
	}
	return out
}

// recordIsPartial 历史记录是否为部分结果（Result.Partial 或 Options.status）。
func recordIsPartial(rec *store.ScanRecord) bool {
	if rec == nil {
		return false
	}
	if rec.Result != nil && rec.Result.Partial {
		return true
	}
	if optStr(rec.Options, "status") == partialStatusValue {
		return true
	}
	if b, ok := rec.Options["partial"].(bool); ok && b {
		return true
	}
	return false
}

// interruptedFromOptions 从落库选项回读中断阶段。
func interruptedFromOptions(opts map[string]any) string {
	return optStr(opts, "interrupted_phase")
}

// ---- 小工具（避免为几个取值引入额外依赖噪音） ----

// optBool 取 map 布尔值（兼容 JSON float64=1/0 与字符串 "true"）。
func optBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true") || x == "1"
	}
	return false
}

// optStr 取 map 字符串值（其它类型返回 ""）。
func optStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// copyAnyMap 浅拷贝 map（nil 返回空 map，保证落库时可安全追加键）。
func copyAnyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+3)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// firstNonEmptyStr 取首个非空字符串。
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// itoaServer 整型转字符串（避免与 engine 包内部工具同名冲突）。
func itoaServer(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
