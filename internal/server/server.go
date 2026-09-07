// Package server 内置 Web 服务：嵌入前端 + 全量 REST API。
// 路由与响应契约对齐 python 分支 app.py（Flask），前端零改动迁移。
package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/headless"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/store"
	"cnb.cool/feng-qiao/sitelens/internal/target"
	"cnb.cool/feng-qiao/sitelens/web"
)

// Version 服务版本。
const Version = "0.0.1-preview"

// categoryNames 常见技术类别中文名（对齐 Wappalyzer 类别 id）。
var categoryNames = map[string]string{
	"cms": "内容管理系统", "web-framework": "Web 框架", "web-server": "Web 服务器",
	"database": "数据库", "js": "JavaScript 库", "js-library": "JavaScript 库",
	"os": "操作系统", "lang": "编程语言", "devops": "开发运维", "security": "安全",
	"blog": "博客", "ecommerce": "电子商务", "wiki": "Wiki", "cache": "缓存",
	"editor": "编辑器", "cdn": "CDN", "analytics": "统计分析", "misc": "其他",
	"static-site-generator": "静态站点生成器", "build-ci": "构建/CI",
	"font-script": "字体脚本", "payment": "支付", "hosting-panel": "主机面板",
	"message-board": "留言板", "photo-gallery": "相册", "documentation": "文档",
	"mobile-framework": "移动框架", "saas": "SaaS", "network-device": "网络设备",
	"reverse-proxy": "反向代理", "containers": "容器", "ci": "持续集成",
}

func categoryName(id string) string {
	if n, ok := categoryNames[id]; ok {
		return n
	}
	return id
}

// Server Web 服务。
type Server struct {
	cfg      *config.Config
	eng      *engine.Engine
	matcher  *sitelens.Matcher
	kb       atomic.Pointer[intel.KB] // 热替换安全：指向当前知识库快照
	st       *store.Store
	jobs     *store.JobManager
	sem      chan struct{}
	apiToken string
	techIDs  []string // 类别全集（CSV 宽表列序）
	techCnt  int

	dataMu   sync.Mutex
	lastData map[string]int64 // 数据文件路径 → 上次加载时的 mtime（热更新基线）
}

// New 装配服务（加载指纹库/知识库/历史存储/用户插件）。
func New(cfg *config.Config) (*Server, error) {
	s := &Server{cfg: cfg, jobs: store.NewJobManagerWithCap(200),
		sem:      make(chan struct{}, cfg.Scan.MaxConcurrent),
		lastData: map[string]int64{}}
	checks.ConfigurePlugins(cfg.Checks.PluginDir)
	s.apiToken = os.Getenv("SLENS_API_TOKEN")
	if s.apiToken == "" {
		s.apiToken = cfg.Web.APIToken
	}

	if m, err := loadTechMeta(cfg); err == nil {
		s.techIDs, s.techCnt = m.cats, m.count
	} else {
		log.Printf("指纹元数据读取失败（统计/CSV 降级）：%v", err)
	}
	if m, err := sitelens.LoadMatcher(cfg.Intel.TechnologiesPath); err == nil {
		s.matcher = m
	} else {
		log.Printf("指纹库加载失败（扫描将无指纹识别）：%v", err)
	}
	if kb, err := intel.Load(cfg.Intel.DumpPath, cfg.Intel.RangesPath); err == nil {
		s.kb.Store(kb)
	} else {
		log.Printf("知识库加载失败（情报关联降级）：%v", err)
	}
	st, err := store.New(cfg.Store.DataDir, cfg.Store.MaxRecords)
	if err != nil {
		return nil, err
	}
	s.st = st
	s.eng = engine.New(cfg, s.matcher, s.KB())
	if s.matcher == nil {
		s.matcher = &sitelens.Matcher{}
		s.eng.SetMatcher(s.matcher)
	}
	// 记录初始数据文件指纹（热更新基线）
	for _, p := range s.dataPaths() {
		if mt, ok := fileMTime(p); ok {
			s.lastData[p] = mt
		}
	}
	// KEV 本地缓存秒加载（网络拉取交给守护协程，不阻塞启动）
	if kb := s.KB(); kb != nil {
		if entries, err := intel.LoadKEVExtra(filepath.Join(cfg.Store.DataDir, "kev_extra.json")); err == nil {
			kb.MergeKEV(entries)
		}
	}
	return s, nil
}

// KB 返回当前知识库快照（热替换安全）。
func (s *Server) KB() *intel.KB { return s.kb.Load() }

// Handler 构建全部路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 页面
	pages := map[string]string{
		"/": "index.html", "/app": "app.html", "/batch": "batch.html",
		"/history": "history.html", "/api-docs": "api-docs.html",
		"/intel": "intel.html", "/audit": "audit.html", "/about": "about.html",
	}
	for route, file := range pages {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != route {
				http.NotFound(w, r)
				return
			}
			s.serveAsset(w, file)
		})
	}
	// 兼容旧路由：独立页已并入工作台标签
	mux.HandleFunc("/netsec", redirect("/app#netsec"))
	mux.HandleFunc("/loginbrute", redirect("/app#loginbrute"))
	mux.HandleFunc("/verified", redirect("/history#verified"))
	mux.HandleFunc("/js/", s.serveAssetPrefix)

	// API
	mux.HandleFunc("GET /api/version", s.hVersion)
	mux.HandleFunc("GET /api/stats", s.hStats)
	mux.HandleFunc("GET /api/categories", s.hCategories)
	mux.HandleFunc("POST /api/admin/reload", s.hAdminReload)
	mux.HandleFunc("POST /api/scan", s.hScan)
	mux.HandleFunc("GET /api/job/{id}", s.hJob)
	mux.HandleFunc("POST /api/job/{id}/cancel", s.hJobCancel)
	mux.HandleFunc("GET /api/job/{id}/results", s.hJobResults)
	mux.HandleFunc("POST /api/batch", s.hBatch)
	mux.HandleFunc("GET /api/history", s.hHistory)
	mux.HandleFunc("GET /api/history/{id}", s.hHistoryDetail)
	mux.HandleFunc("DELETE /api/history/{id}", s.hHistoryDelete)
	mux.HandleFunc("GET /api/export/{id}", s.hExport)
	mux.HandleFunc("GET /api/diff", s.hDiff)
	mux.HandleFunc("GET /api/vuln-search", s.hVulnSearch)
	mux.HandleFunc("GET /api/verified", s.hVerified)
	mux.HandleFunc("POST /api/netsec", s.hNetsec)
	mux.HandleFunc("POST /api/loginbrute", s.hLoginBrute)
	mux.HandleFunc("GET /api/captcha/capability", s.hCaptchaCapability)
	mux.HandleFunc("POST /api/audit", s.hAudit)
	mux.HandleFunc("GET /api/audit/demo", s.hAuditDemo)

	return s.guard(s.headers(mux))
}

// Run 启动 HTTP 服务（Ctrl+C 优雅关闭）。
func (s *Server) Run() error {
	s.startKEVDaemon()
	srv := &http.Server{
		Addr:              s.cfg.Web.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(s.cfg.Web.ShutdownSec)*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(done)
	}()
	log.Printf("SiteLens %s 监听 http://%s", Version, s.cfg.Web.Listen)
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

// startKEVDaemon 情报守护：立即拉取一次 KEV，此后按 update_hours 轮询。
// 失败仅记日志（离线环境降级为静态知识库）。
func (s *Server) startKEVDaemon() {
	if s.KB() == nil || s.cfg.Intel.UpdateHours <= 0 {
		return
	}
	dest := filepath.Join(s.cfg.Store.DataDir, "kev_extra.json")
	refresh := func() {
		// 固定 15s 超时：KEV 源为外部固定地址，不随 netsec 探测配置联动
		entries, err := intel.FetchKEV(intel.KEVFeedURL, 15*time.Second)
		if err != nil {
			log.Printf("KEV 更新失败（降级用本地缓存）：%v", err)
			return
		}
		added := s.KB().MergeKEV(entries)
		if err := intel.SaveKEVExtra(dest, entries); err != nil {
			log.Printf("KEV 缓存写入失败：%v", err)
			return
		}
		log.Printf("KEV 更新完成：%d 条，新增 %d", len(entries), added)
	}
	go func() {
		refresh()
		ticker := time.NewTicker(time.Duration(s.cfg.Intel.UpdateHours) * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()
}

// ---- 中间件 ----

// guard 可选 API 鉴权：设置 token 后 /api/* 需要 X-Token 头。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Token") != s.apiToken {
				writeJSON(w, 401, map[string]any{"error": "未授权：缺少或错误的 X-Token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// headers 安全响应头。
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "SiteLens")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// ---- 页面服务 ----

func (s *Server) serveAsset(w http.ResponseWriter, name string) {
	data, err := web.FS.ReadFile(name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) serveAssetPrefix(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	data, err := web.FS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(data)
}

func redirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}
}

// ---- 简单端点 ----

func (s *Server) hVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"name": "SiteLens", "version": Version, "engine": "go"})
}

func (s *Server) hStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]any{
		"categories": len(s.techIDs), "technologies": s.techCnt, "curated": s.techCnt,
		"vulns": 0, "tscan": 0, "vuln_by_severity": map[string]int{},
		"intel_sources": map[string]int{}, "intel_with_ranges": 0, "intel_with_cvss": 0,
	}
	if kb := s.KB(); kb != nil {
		for k, v := range kb.Stats() {
			stats[k] = v
		}
	}
	stats["history"] = s.st.HistoryStats()
	stats["top_techs"] = s.st.TopTechs(8)
	writeJSON(w, 200, stats)
}

func (s *Server) hCategories(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0, len(s.techIDs))
	for _, id := range s.techIDs {
		out = append(out, map[string]any{"id": id, "name": categoryName(id), "icon": ""})
	}
	writeJSON(w, 200, map[string]any{"categories": out})
}

func (s *Server) hVulnSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, 200, map[string]any{"results": []any{}})
		return
	}
	kb := s.KB()
	if kb == nil {
		writeJSON(w, 200, map[string]any{"results": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"results": kb.Search(q, s.cfg.Intel.SearchLimit)})
}

func (s *Server) hVerified(w http.ResponseWriter, r *http.Request) {
	limit := safeLimit(r.URL.Query().Get("limit"), s.cfg.Web.HistoryLimit, s.cfg.Web.HistoryCap)
	writeJSON(w, 200, map[string]any{"items": s.st.Verified(limit)})
}

// ---- 扫描 ----

func (s *Server) hScan(w http.ResponseWriter, r *http.Request) {
	s.reloadIfDataChanged()
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	urlStr, _ := body["url"].(string)
	urlStr = strings.TrimSpace(urlStr)

	opts := scanOptions(body)
	jobID := newID()
	s.jobs.Create(jobID, "scan", map[string]any{"url": urlStr, "options": opts}, 100)
	if _, _, _, verr := target.Validate(urlStr, s.cfg.Scan.Resolve); verr != nil {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = verr.Error() })
		writeJSON(w, 400, map[string]any{"job_id": jobID, "error": verr.Error()})
		return
	}
	go s.runScanJob(jobID, urlStr, opts)
	writeJSON(w, 200, map[string]any{"job_id": jobID})
}

// scanOptions 平铺 payload → 引擎选项（对齐 Python /api/scan）。
func scanOptions(body map[string]any) engine.Options {
	o := engine.DefaultOptions()
	o.Deep = boolOf(body["deep"], true)
	o.ActiveFP = boolOf(body["active_fp"], false)
	o.DirScan = boolOf(body["dir_scan"], false)
	o.DirBypass = boolOf(body["dir_bypass"], false)
	o.Subdomain = boolOf(body["subdomain"], false)
	o.ServiceProbe = boolOf(body["service_probe"], false)
	o.BrowserUA = boolOf(body["browser_ua"], false)
	o.WeakAudit = boolOf(body["weak_audit"], false)
	o.Webshell = boolOf(body["webshell"], false)
	o.Netsec = boolOf(body["netsec"], false)
	o.DAST = boolOf(body["dast"], false)
	o.Passive = boolOf(body["passive"], false)
	if v, ok := body["checks"].(string); ok && v != "" {
		o.Checks = v
	}
	if c, ok := body["auth_cookie"].(string); ok {
		o.AuthCookie = truncateStr(c, 1000)
	}
	return o
}

func (s *Server) runScanJob(jobID, urlStr string, opts engine.Options) {
	s.jobs.Update(jobID, func(j *store.Job) { j.Status = "running" })
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	res := s.eng.Scan(urlStr, opts, func(p int, msg string) {
		s.jobs.Update(jobID, func(j *store.Job) { j.Progress = p; j.Message = msg })
	}, func() bool { return s.jobs.CancelRequested(jobID) })

	if s.jobs.CancelRequested(jobID) {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "cancelled"; j.Message = "已取消" })
		return
	}
	if res.Error != "" {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = res.Error })
		return
	}
	scanID := s.st.Save(res, map[string]any{
		"deep": opts.Deep, "checks": opts.Checks, "netsec": opts.Netsec,
		"dast": opts.DAST, "passive": opts.Passive,
	})
	s.jobs.Update(jobID, func(j *store.Job) {
		j.Status = "done"
		j.Progress = 100
		j.Message = "完成"
		j.Result = map[string]any{"scan_id": scanID}
	})
}

func (s *Server) hJob(w http.ResponseWriter, r *http.Request) {
	s.jobOut(w, r.PathValue("id"), false)
}

func (s *Server) hJobResults(w http.ResponseWriter, r *http.Request) {
	s.jobOut(w, r.PathValue("id"), true)
}

func (s *Server) jobOut(w http.ResponseWriter, id string, withResults bool) {
	j := s.jobs.Get(id)
	if j == nil {
		writeJSON(w, 404, map[string]any{"error": "任务不存在"})
		return
	}
	out := map[string]any{
		"job_id": j.ID, "status": j.Status, "progress": j.Progress,
		"message": j.Message, "done": j.Done, "total": j.Total,
	}
	if j.Status == "done" && j.Result != nil {
		out["status"] = "done"
		if scanID, ok := j.Result["scan_id"]; ok {
			out["scan_id"] = scanID
		}
		if withResults {
			out["results"] = j.Result
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) hJobCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	j := s.jobs.Get(id)
	if j == nil {
		writeJSON(w, 404, map[string]any{"error": "任务不存在"})
		return
	}
	if j.Status == "done" || j.Status == "cancelled" || j.Status == "error" {
		writeJSON(w, 200, map[string]any{"cancelled": false, "reason": "任务已结束"})
		return
	}
	s.jobs.Update(id, func(x *store.Job) { x.Status = "cancelling"; x.Message = "取消中…" })
	writeJSON(w, 200, map[string]any{"cancelled": true})
}

// ---- 批量 ----

func (s *Server) hBatch(w http.ResponseWriter, r *http.Request) {
	s.reloadIfDataChanged()
	var body struct {
		URLs []string `json:"urls"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body)
	var urls []string
	for _, u := range body.URLs {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
		if len(urls) >= s.cfg.Batch.MaxURLs {
			break
		}
	}
	if len(urls) == 0 {
		writeJSON(w, 400, map[string]any{"error": "URL 列表为空"})
		return
	}
	jobID := newID()
	s.jobs.Create(jobID, "batch", map[string]any{"urls": urls}, len(urls))
	go s.runBatch(jobID, urls)
	writeJSON(w, 200, map[string]any{"job_id": jobID, "total": len(urls)})
}

func (s *Server) runBatch(jobID string, urls []string) {
	workers := s.cfg.Batch.Workers
	if workers <= 0 {
		workers = 3
	}
	var mu sync.Mutex
	done := 0
	var lines []string
	idx := atomic.Int64{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(idx.Add(1)) - 1
				if i >= len(urls) {
					return
				}
				u := urls[i]
				if s.jobs.CancelRequested(jobID) {
					mu.Lock()
					lines = append(lines, u+" -> 已跳过（任务取消）")
					mu.Unlock()
				} else {
					s.sem <- struct{}{}
					res := s.eng.Scan(u, engine.DefaultOptions(), nil,
						func() bool { return s.jobs.CancelRequested(jobID) })
					<-s.sem
					if res.Error != "" {
						mu.Lock()
						lines = append(lines, u+" -> 失败（"+res.Error+"）")
						mu.Unlock()
					} else {
						s.st.Save(res, map[string]any{"batch": true})
						mu.Lock()
						lines = append(lines, fmt.Sprintf("%s -> 完成（%d 项技术）", u, len(res.Technologies)))
						mu.Unlock()
					}
				}
				mu.Lock()
				done++
				d, ln := done, append([]string{}, lines...)
				mu.Unlock()
				s.jobs.Update(jobID, func(j *store.Job) {
					j.Done = d
					j.Progress = d * 100 / len(urls)
					if len(ln) > 0 {
						j.Message = ln[len(ln)-1]
					}
					j.Result = map[string]any{"lines": ln}
				})
			}
		}()
	}
	wg.Wait()
	// 注意：CancelRequested 不能放进 Update 回调——RWMutex 不可重入，
	// 持写锁再请求读锁会永久死锁（回调外先取状态）。
	wasCancelled := s.jobs.CancelRequested(jobID)
	s.jobs.Update(jobID, func(j *store.Job) {
		if wasCancelled {
			j.Status = "cancelled"
			j.Message = "批量已取消（未开始的 URL 已跳过）"
		} else {
			j.Status = "done"
			j.Message = "批量完成"
		}
	})
}

// ---- 历史 / 导出 / 差异 ----

func (s *Server) hHistory(w http.ResponseWriter, r *http.Request) {
	limit := safeLimit(r.URL.Query().Get("limit"), s.cfg.Web.HistoryLimit, s.cfg.Web.HistoryCap)
	tech := r.URL.Query().Get("tech")
	writeJSON(w, 200, map[string]any{"scans": s.st.List(limit, tech)})
}

func (s *Server) hHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	rec := s.st.Get(id)
	if rec == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) hHistoryDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": s.st.Delete(id)})
}

func (s *Server) hExport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	rec := s.st.Get(id)
	if rec == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	switch r.URL.Query().Get("fmt") {
	case "json", "":
		data, _ := json.MarshalIndent(rec.Result, "", "  ")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=sitelens-%d.json", id))
		_, _ = w.Write(data)
	case "csv":
		csvText := detailCSV(rec, s.techIDs)
		csvResponse(w, csvText, fmt.Sprintf("sitelens-%d.csv", id))
	case "wide":
		csvText := wideCSV([]*store.ScanRecord{rec}, s.techIDs)
		csvResponse(w, csvText, fmt.Sprintf("sitelens-wide-%d.csv", id))
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(htmlReport(rec)))
	default:
		writeJSON(w, 400, map[string]any{"error": "未知格式"})
	}
}

func (s *Server) hDiff(w http.ResponseWriter, r *http.Request) {
	aID, ea := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64)
	bID, eb := strconv.ParseInt(r.URL.Query().Get("b"), 10, 64)
	if ea != nil || eb != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	ra, rb := s.st.Get(aID), s.st.Get(bID)
	if ra == nil || rb == nil || ra.Result == nil || rb.Result == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	ma, mb := techMap(ra.Result), techMap(rb.Result)
	added, removed, changed := []map[string]any{}, []map[string]any{}, []map[string]any{}
	for name, tb := range mb {
		ta, ok := ma[name]
		if !ok {
			added = append(added, map[string]any{"name": name, "version": tb.Version})
			continue
		}
		if ta.Version != tb.Version {
			changed = append(changed, map[string]any{
				"name": name, "from": ta.Version, "to": tb.Version})
		}
	}
	for name, ta := range ma {
		if _, ok := mb[name]; !ok {
			removed = append(removed, map[string]any{"name": name, "version": ta.Version})
		}
	}
	writeJSON(w, 200, map[string]any{
		"a":     map[string]any{"id": aID, "host": ra.Host, "scanned_at": ra.ScannedAt},
		"b":     map[string]any{"id": bID, "host": rb.Host, "scanned_at": rb.ScannedAt},
		"added": added, "removed": removed, "version_changed": changed,
	})
}

// ---- 网络层 / 爆破 / 审计 ----

func (s *Server) hNetsec(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	host, _ := body["host"].(string)
	host = strings.TrimSpace(host)
	if host == "" {
		writeJSON(w, 400, map[string]any{"error": "请输入域名"})
		return
	}
	_, host, port, err := target.Validate(host, s.cfg.Scan.Resolve)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if port == 0 || port == 80 {
		port = 443
	}
	findings := netsec.CheckTLS(host, port)
	if s.cfg.Netsec.MailCheck {
		findings = append(findings, netsec.CheckDNSMail(host)...)
	}
	writeJSON(w, 200, map[string]any{"host": host, "findings": findings})
}

func (s *Server) hCaptchaCapability(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"available": false,
		"reason":    "验证码识别（ddddocr）未迁移至 Go 版，暂只能爆破无验证码表单",
	})
}

func (s *Server) hLoginBrute(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	urlStr, _ := body["url"].(string)
	urlStr = strings.TrimSpace(urlStr)
	if authorized, _ := body["authorized"].(bool); !authorized {
		writeJSON(w, 400, map[string]any{"error": "必须确认已获得目标授权"})
		return
	}
	captchaType, _ := body["captcha_type"].(string)
	jobID := newID()
	s.jobs.Create(jobID, "loginbrute", map[string]any{"url": urlStr}, 100)
	if _, _, _, verr := target.Validate(urlStr, s.cfg.Scan.Resolve); verr != nil {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = verr.Error() })
		writeJSON(w, 400, map[string]any{"job_id": jobID, "error": verr.Error()})
		return
	}
	go func() {
		f := &httpPoster{c: s.eng.ClientFor(scanOptions(body))}
		users := loginbrute.LoadList(
			filepath.Join(s.cfg.Active.WordlistDir, "weak_users.txt"), s.cfg.LoginBrute.MaxUsers)
		pwds := loginbrute.LoadList(
			filepath.Join(s.cfg.Active.WordlistDir, "weak_passwords.txt"), s.cfg.LoginBrute.MaxPasswords)
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "running" })

		// SPA 登录页支持：开启无头渲染时先渲染登录页，用渲染后的 DOM 解析表单
		rendered := ""
		if s.cfg.Crawler.Headless {
			r := headless.NewChrome(time.Duration(s.cfg.Crawler.HeadlessTimeoutSec) * time.Second)
			if html, rerr := r.Render(urlStr); rerr == nil {
				rendered = html
			}
		}
		hits, err := loginbrute.Brute(f, loginbrute.Options{
			PageURL:      urlStr,
			Users:        users,
			Passwords:    pwds,
			MaxTries:     s.cfg.LoginBrute.MaxTries,
			IntervalMS:   s.cfg.LoginBrute.IntervalMS,
			CaptchaType:  captchaType,
			RenderedBody: rendered,
		}, func(done, total int, msg string) {
			s.jobs.Update(jobID, func(j *store.Job) {
				j.Status = "running"
				j.Progress = done * 100 / max(1, total)
				j.Message = msg
			})
		})
		if err != nil {
			s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = err.Error() })
			return
		}
		s.jobs.Update(jobID, func(j *store.Job) {
			j.Status = "done"
			j.Progress = 100
			j.Message = fmt.Sprintf("完成，命中 %d 组", len(hits))
			j.Result = map[string]any{"hits": hits}
		})
	}()
	writeJSON(w, 200, map[string]any{"job_id": jobID})
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(int64(s.cfg.Audit.MaxArchiveMB) << 20); err != nil {
		writeJSON(w, 400, map[string]any{"error": "上传解析失败：" + err.Error()})
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "缺少 file 字段"})
		return
	}
	defer file.Close()
	dir, err := os.MkdirTemp("", "sitelens_audit_")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "创建临时目录失败"})
		return
	}
	defer os.RemoveAll(dir)

	name := hdr.Filename
	switch {
	case strings.HasSuffix(strings.ToLower(name), ".zip"):
		if err = extractZip(file, hdr.Size, dir, int64(s.cfg.Audit.MaxFileKB)*1024); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
	case strings.HasSuffix(strings.ToLower(name), ".py") ||
		strings.HasSuffix(strings.ToLower(name), ".js") ||
		strings.HasSuffix(strings.ToLower(name), ".php"):
		dst, cerr := os.Create(filepath.Join(dir, filepath.Base(name)))
		if cerr != nil {
			writeJSON(w, 500, map[string]any{"error": "写文件失败"})
			return
		}
		_, _ = io.Copy(dst, io.LimitReader(file, int64(s.cfg.Audit.MaxFileKB)*1024))
		dst.Close()
	default:
		writeJSON(w, 400, map[string]any{"error": "仅支持 .zip 压缩包或单个 .py/.js/.php 文件"})
		return
	}

	rep, err := audit.Run(dir, s.cfg.Audit, nil)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "审计失败：" + err.Error()})
		return
	}
	if rep.Files == 0 {
		writeJSON(w, 400, map[string]any{"error": "压缩包中没有可审计的文本源码"})
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) hAuditDemo(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp("", "sitelens_demo_")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "创建临时目录失败"})
		return
	}
	defer os.RemoveAll(dir)
	// 教学演示样本：运行时拼装的"故意漏洞"代码，仅作审计靶子文本，
	// 从不执行、审计后即删；源码中不出现完整危险调用字面量。
	q := `"`
	sample := strings.Join([]string{
		"import os, hashlib, yaml, pickle",
		"ADMIN_PASSWORD = " + q + "demo-pass-123456" + q,
		"",
		"def login(user, pwd):",
		"    if hashlib.md5(pwd).hexdigest() == ADMIN_PASSWORD:",
		"        return True",
		"",
		"def load_config(path):",
		"    return yaml." + "load(open(path))",
		"",
		"def run_cmd(user_input):",
		"    os." + "system" + "(" + q + "ping " + q + " + user_input)",
		"",
		"def get_user(uid):",
		"    cur." + "execute" + "(" + q + "SELECT * FROM us" + "ers WHERE id = " + q + " + uid)",
		"    return pickle." + "loads(data)",
		"",
		"def render(expr):",
		"    user_expr = request.args.get(" + q + "expr" + q + ")",
		"    eval(user_expr)",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "vulnerable_demo.py"),
		[]byte(sample), 0o644); err != nil {
		writeJSON(w, 500, map[string]any{"error": "写样本失败"})
		return
	}
	rep, err := audit.Run(dir, s.cfg.Audit, nil)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "审计失败"})
		return
	}
	writeJSON(w, 200, rep)
}

// ---- 工具 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func csvResponse(w http.ResponseWriter, text, filename string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	_, _ = w.Write([]byte("\ufeff" + text)) // BOM：Excel 直接打开不乱码
}

func safeLimit(raw string, def, cap int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > cap {
		return cap
	}
	return n
}

func boolOf(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func newID() string {
	return fmt.Sprintf("%08x%s", time.Now().UnixNano()&0xffffffff, randHex(4))
}

func randHex(n int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexDigits[time.Now().UnixNano()>>uint(i*3)&0xf]
	}
	return string(b)
}

func techMap(res *engine.Result) map[string]engine.Tech {
	m := map[string]engine.Tech{}
	for _, t := range res.Technologies {
		m[t.Name] = t
	}
	return m
}

// detailCSV 明细 CSV：每行一项技术（对齐 Python Exporter.detail_csv）。
func detailCSV(rec *store.ScanRecord, catOrder []string) string {
	buf := &strings.Builder{}
	w := csv.NewWriter(buf)
	_ = w.Write([]string{"技术", "类别", "置信度", "版本", "官网", "证据"})
	for _, t := range rec.Result.Technologies {
		cats := make([]string, 0, len(t.Categories))
		for _, c := range t.Categories {
			cats = append(cats, categoryName(c))
		}
		_ = w.Write([]string{
			t.Name, strings.Join(cats, " / "),
			fmt.Sprintf("%d%%", t.Confidence), t.Version, t.Website,
			strings.Join(t.Evidence, " | "),
		})
	}
	w.Flush()
	return buf.String()
}

// wideCSV 宽表 CSV：URL + 每类别一列（对齐 Python Exporter.wide_csv）。
func wideCSV(recs []*store.ScanRecord, catOrder []string) string {
	buf := &strings.Builder{}
	w := csv.NewWriter(buf)
	header := []string{"URL"}
	for _, c := range catOrder {
		header = append(header, categoryName(c))
	}
	_ = w.Write(header)
	for _, rec := range recs {
		cells := map[string][]string{}
		for _, t := range rec.Result.Technologies {
			for _, c := range t.Categories {
				cells[c] = append(cells[c], t.Name)
			}
		}
		line := []string{rec.URL}
		for _, c := range catOrder {
			line = append(line, strings.Join(cells[c], " ; "))
		}
		_ = w.Write(line)
	}
	w.Flush()
	return buf.String()
}
