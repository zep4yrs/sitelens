// Package server 内置 Web 服务：嵌入前端 + 全量 REST API。
// 路由与响应契约对齐 python 分支 app.py（Flask），前端零改动迁移。
package server

import (
	"context"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/beacon"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/headless"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/replay"
	"cnb.cool/feng-qiao/sitelens/internal/resource"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/store"
	"cnb.cool/feng-qiao/sitelens/internal/target"
	"cnb.cool/feng-qiao/sitelens/web"
)

// Version 服务版本。
const Version = "4.0.0"

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
	cfgPath  string // 用户配置文件路径（设置页保存目标）
	eng      *engine.Engine
	matcher  *sitelens.Matcher
	kb       atomic.Pointer[intel.KB] // 热替换安全：指向当前知识库快照
	st       *store.Store
	jobs     *store.JobManager
	sem      chan struct{}
	apiToken string
	techIDs  []string // 类别全集（CSV 宽表列序）
	techCnt  int

	cfgMu    sync.Mutex // 保护 cfg 与 apiToken 的设置页热更新
	dataMu   sync.Mutex
	lastData map[string]int64 // 数据文件路径 → 上次加载时的 mtime（热更新基线）

	osvMu       sync.Mutex // OSV 同步互斥（同时只允许一个同步任务）
	osvRunning  bool
	osvTotal    int
	osvLastTime string
	osvLastMsg  string
	osvLastN    int
}

// New 装配服务（加载指纹库/知识库/历史存储/用户插件）。
func New(cfg *config.Config, cfgPath string) (*Server, error) {
	if cfgPath == "" {
		cfgPath = ".sitelens.yml"
	}
	s := &Server{cfg: cfg, cfgPath: cfgPath, jobs: store.NewJobManagerWithCap(200),
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
	// A5 惰性：intel_dump 首次用到时才解码（空闲 RSS 再降 ~65MB）
	if kb := intel.LoadLazy(cfg.Intel.DumpPath, cfg.Intel.RangesPath); true {
		if n := intel.ApplyOverridesFile(kb, cfg.Intel.OverridesPath); n > 0 {
			log.Printf("情报覆盖合并：%d 条（%s）", n, cfg.Intel.OverridesPath)
		}
		// NVD 全量字典旁路挂载（update-nvd 产物）。A3 惰性：只记路径，
		// 首次真正用到（CVSS 补全 / CPE 检索 / CVE→CWE）时才解码——
		// 该索引实测占 HeapSys ≈1.7GB，指纹类场景不必付这笔钱。
		kb.AttachNVDPath(cfg.Intel.NVDPath)
		if tc, terr := intel.LoadTechCPE("data/go/tech_cpe.json"); terr == nil && tc != nil {
			kb.AttachTechCPE(tc)
		}
		if tr, rerr := intel.LoadTplIntel(cfg.Intel.TplIntelPath); rerr == nil && tr != nil {
			kb.AttachTplIntel(tr)
			log.Printf("模板情报行合并：%d 条", len(tr))
		}
		s.kb.Store(kb)
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

	// 页面（产品形态：无宣传首页与关于页，根路径即工作台）
	// "/" 不进表：由 hRoot 统一处理根路径、.html 直达与样式化 404
	pages := map[string]string{
		"/app": "app.html",
		"/history": "history.html", "/api-docs": "api-docs.html",
		"/intel": "intel.html",
		"/chain": "chain.html", "/settings": "settings.html",
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
	mux.HandleFunc("/", s.hRoot)
	// 兼容旧路由：独立页已并入工作台标签
	mux.HandleFunc("/netsec", redirect("/app#netsec"))
	mux.HandleFunc("/loginbrute", redirect("/app#loginbrute"))
	mux.HandleFunc("/audit", redirect("/app#audit"))
	mux.HandleFunc("/batch", redirect("/app#batch"))
	mux.HandleFunc("/verified", redirect("/history#verified"))
	mux.HandleFunc("/js/", s.serveAssetPrefix)
	mux.HandleFunc("/css/", s.serveAssetPrefix)
	mux.HandleFunc("/monaco/", s.hMonaco)
	mux.HandleFunc("/b/", s.hBeacon)

	// API
	mux.HandleFunc("GET /api/version", s.hVersion)
	mux.HandleFunc("GET /api/stats", s.hStats)
	mux.HandleFunc("GET /api/settings", s.hSettingsGet)
	mux.HandleFunc("PUT /api/settings", s.hSettingsPut)
	mux.HandleFunc("POST /api/osv-sync", s.hOsvSync)
	mux.HandleFunc("GET /api/osv-sync", s.hOsvStatus)
	mux.HandleFunc("GET /api/categories", s.hCategories)
	mux.HandleFunc("POST /api/admin/reload", s.hAdminReload)
	// A10 自适应：长空闲释放情报常驻（惰性路径保留，下次访问自动重载）
	mux.HandleFunc("POST /api/admin/release-intel", s.hAdminReleaseIntel)
	// 内置 SPA 靶页：JS 延迟注入登录表单，用于无头渲染/登录爆破链路自测
	mux.HandleFunc("GET /dev/spa-target", hSPATarget)
	mux.HandleFunc("POST /dev/spa-target/login", hSPATargetLogin)
	mux.HandleFunc("POST /api/scan", s.hScan)
	mux.HandleFunc("GET /api/job/{id}", s.hJob)
	mux.HandleFunc("POST /api/job/{id}/cancel", s.hJobCancel)
	mux.HandleFunc("GET /api/job/{id}/results", s.hJobResults)
	mux.HandleFunc("POST /api/batch", s.hBatch)
	mux.HandleFunc("GET /api/history", s.hHistory)
	mux.HandleFunc("GET /api/history/{id}", s.hHistoryDetail)
	mux.HandleFunc("DELETE /api/history/{id}", s.hHistoryDelete)
	mux.HandleFunc("POST /api/history/clear", s.hHistoryClear)
	mux.HandleFunc("GET /api/export/{id}", s.hExport)
	// 4.0 P8：结构化事实图（CWE/攻击链）查询、JSONL 导出、攻击链视图
	mux.HandleFunc("GET /api/graph/{id}", s.hGraph)
	mux.HandleFunc("GET /api/graph/{id}/jsonl", s.hGraphJSONL)
	mux.HandleFunc("GET /api/graph/{id}/chain", s.hGraphChain)
	mux.HandleFunc("GET /api/diff", s.hDiff)
	mux.HandleFunc("GET /api/vuln-search", s.hVulnSearch)
	mux.HandleFunc("GET /api/verified", s.hVerified)
	mux.HandleFunc("GET /api/replay/{id}", s.hReplay)
	mux.HandleFunc("POST /api/netsec", s.hNetsec)
	mux.HandleFunc("POST /api/loginbrute", s.hLoginBrute)
	mux.HandleFunc("GET /api/captcha/capability", s.hCaptchaCapability)
	mux.HandleFunc("POST /api/audit", s.hAudit)
	mux.HandleFunc("GET /api/audit/demo", s.hAuditDemo)

	return s.guard(s.headers(mux))
}

// Run 启动 HTTP 服务（Ctrl+C 优雅关闭）。
// hAdminReleaseIntel 释放情报知识库常驻内存（A10 自适应版；返回堆指标）。
func (s *Server) hAdminReleaseIntel(w http.ResponseWriter, r *http.Request) {
	before := resource.Snapshot()
	s.eng.ReleaseIntel()
	runtime.GC()
	after := resource.Snapshot()
	log.Printf("情报常驻已释放：%.1fMB → %.1fMB", before.HeapAllocMiB, after.HeapAllocMiB)
	writeJSON(w, 200, map[string]any{
		"released":       true,
		"heap_before_mb": before.HeapAllocMiB,
		"heap_after_mb":  after.HeapAllocMiB,
	})
}

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
	// SEC-8 加固：非回环监听且未设 Token 时给出醒目警告
	//（此时全部 /api/* 对所在网络开放，包括主动扫描与爆破能力）
	if !strings.HasPrefix(s.cfg.Web.Listen, "127.0.0.1") && !strings.HasPrefix(s.cfg.Web.Listen, "localhost") && s.apiToken == "" {
		log.Printf("警告：监听 %s 为非回环地址且未设置 API Token，全部 API 对所在网络开放（含主动扫描能力）。生产部署请设置 SLENS_API_TOKEN 或 web.api_token", s.cfg.Web.Listen)
	}
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
// 比较用常量时间实现（防时序侧信道逐字节猜 token）。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(s.apiToken)) != 1 {
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
	// 嵌入资源随二进制走：禁止启发式缓存，避免升级后浏览器拿旧页面/旧 JS
	//（旧 common.js + 新页面是白屏的经典组合）
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// hMonaco Monaco Editor 静态资源（25A）：读 web.MonacoFS（embed 根 monaco/），
// 经 /monaco/ 前缀服务；vendor 文件随二进制版本发布，给一天强缓存。
func (s *Server) hMonaco(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/monaco/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := web.MonacoFS.ReadFile("monaco/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := "application/javascript; charset=utf-8"
	switch {
	case strings.HasSuffix(name, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".json"):
		ct = "application/json; charset=utf-8"
	case strings.HasSuffix(name, ".ttf"):
		ct = "font/ttf"
	case strings.HasSuffix(name, ".woff"):
		ct = "font/woff"
	case strings.HasSuffix(name, ".woff2"):
		ct = "font/woff2"
	case strings.HasSuffix(name, ".svg"):
		ct = "image/svg+xml"
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(data)
}

func (s *Server) serveAssetPrefix(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	data, err := web.FS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// 按扩展名给 MIME（/js/ 与 /css/ 共用本处理器）。
	ct := "application/javascript; charset=utf-8"
	if strings.HasSuffix(name, ".css") {
		ct = "text/css; charset=utf-8"
	} else if strings.HasSuffix(name, ".json") {
		ct = "application/json; charset=utf-8"
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(data)
}

// hRoot 根路径与兜底路由："/" 出工作台；"/<page>.html" 直达对应页面
// （旧书签 / 历史链接兼容）；其余一律出样式化 404（带返回入口）。
func (s *Server) hRoot(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/" {
		s.serveAsset(w, "app.html")
		return
	}
	if strings.HasSuffix(p, ".html") {
		name := strings.TrimPrefix(p, "/")
		for _, known := range []string{"app.html", "history.html",
			"api-docs.html", "intel.html", "chain.html", "settings.html", "404.html"} {
			if name == known {
				s.serveAsset(w, name)
				return
			}
		}
	}
	s.serve404(w)
}

// serve404 样式化 404：与全站同壳同令牌，带返回工作台入口。
func (s *Server) serve404(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(404)
	if data, err := web.FS.ReadFile("404.html"); err == nil {
		_, _ = w.Write(data)
		return
	}
	_, _ = w.Write([]byte("404 page not found"))
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

// levelPresets 语义化扫描模式（level 参数）：先套预设，显式键仍可逐项覆盖。
// 与前端 web/app.html 的 LEVELS 表保持同一语义；毁天灭地为全模块+
// 全量模板验证，仅授权目标使用。
var levelPresets = map[string]map[string]any{
	"quick":      {"deep": false},
	"standard":   {"deep": true},
	"deep":       {"deep": true, "active_fp": true, "service_probe": true, "checks": "core", "dast": true},
	"full":       {"deep": true, "active_fp": true, "dir_scan": true, "dir_bypass": true, "subdomain": true, "webshell": true, "service_probe": true, "checks": "all", "dast": true, "netsec": true, "passive": true},
	"assets":     {"deep": true, "dir_scan": true, "subdomain": true, "takeover": true, "active_fp": true},
	"stealth":    {"deep": true, "browser_ua": true, "passive": true, "netsec": true},
	"apocalypse": {"deep": true, "active_fp": true, "dir_scan": true, "dir_bypass": true, "subdomain": true, "takeover": true, "webshell": true, "weak_audit": true, "service_probe": true, "checks": "all", "dast": true, "netsec": true, "passive": true, "browser_ua": true, "nuclei_cap": 6000},
}

// scanOptions 平铺 payload → 引擎选项（对齐 Python /api/scan）。
// 支持 level 语义化模式（预设先套、显式键覆盖），未识别 level 静默忽略。
func scanOptions(body map[string]any) engine.Options {
	if lv, _ := body["level"].(string); lv != "" {
		if preset, ok := levelPresets[strings.ToLower(strings.TrimSpace(lv))]; ok {
			merged := make(map[string]any, len(body)+len(preset))
			for k, v := range preset {
				merged[k] = v
			}
			for k, v := range body {
				merged[k] = v
			}
			body = merged
		}
	}
	o := engine.DefaultOptions()
	o.Deep = boolOf(body["deep"], true)
	o.ActiveFP = boolOf(body["active_fp"], false)
	o.DirScan = boolOf(body["dir_scan"], false)
	o.DirBypass = boolOf(body["dir_bypass"], false)
	o.Subdomain = boolOf(body["subdomain"], false)
	o.Takeover = boolOf(body["takeover"], false)
	o.ServiceProbe = boolOf(body["service_probe"], false)
	o.BrowserUA = boolOf(body["browser_ua"], false)
	o.WeakAudit = boolOf(body["weak_audit"], false)
	o.Webshell = boolOf(body["webshell"], false)
	o.Netsec = boolOf(body["netsec"], false)
	o.DAST = boolOf(body["dast"], false)
	o.Exploit = boolOf(body["exploit"], false) // config exploit.enabled 为总闸
	o.Passive = boolOf(body["passive"], false)
	o.JSMap = boolOf(body["js_map"], false)      // JS 攻击面提取（可独立于 DAST）
	o.NetProto = boolOf(body["netproto"], false) // 协议模板（可独立于端口识别）
	o.Graph = boolOf(body["graph"], false)       // 4.0 P8：结构化事实图（CWE/攻击链）
	// 强度档位的字典缩放与端口集（每扫描覆盖配置；0/缺省 = 沿用配置）
	if v, ok := body["dir_max_paths"].(float64); ok && v > 0 {
		o.DirMaxPaths = int(v)
	}
	if v, ok := body["shell_max_paths"].(float64); ok && v > 0 {
		o.ShellMaxPaths = int(v)
	}
	if v, ok := body["sub_max_words"].(float64); ok && v > 0 {
		o.SubMaxWords = int(v)
	}
	if v, ok := body["probe_ports"].(string); ok && v == "full" {
		o.ProbePorts = modules.FullProbePorts
	}
	if v, ok := body["checks"].(string); ok && v != "" {
		o.Checks = v
	}
	// 此前文档宣称支持 nuclei_cap 请求覆盖但从未解析（静默忽略）——补上
	//（JSON 数字为 float64，level 预设为 int，两形态都收）
	switch v := body["nuclei_cap"].(type) {
	case float64:
		if v > 0 {
			o.NucleiCap = int(v)
		}
	case int:
		if v > 0 {
			o.NucleiCap = v
		}
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

	// 实时事件流：引擎阶段/命中/认证事件写入 job 事件环，前端轮询消费
	opts.OnEvent = func(kind, text string) {
		s.jobs.AppendEvent(jobID, kind, text)
	}

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
	// 实时事件流：最多带最近 40 条（前端实时动态面板）
	if n := len(j.Events); n > 0 {
		evs := j.Events
		if n > 40 {
			evs = evs[n-40:]
		}
		out["events"] = evs
	}
	// 25B-B1：批量逐 URL 结构化状态（运行中即可取，驱动任务队列表格）
	if j.Result != nil {
		if rws, ok := j.Result["rows"]; ok {
			out["rows"] = rws
		}
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
	rows := make([]map[string]any, 0, len(urls)) // 25B-B1：逐 URL 结构化状态（任务队列表格数据源）
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
					rows = append(rows, map[string]any{"url": u, "status": "skipped"})
					mu.Unlock()
				} else {
					start := time.Now()
					s.sem <- struct{}{}
					res := s.eng.Scan(u, engine.DefaultOptions(), nil,
						func() bool { return s.jobs.CancelRequested(jobID) })
					<-s.sem
					elapsed := time.Since(start).Milliseconds()
					if res.Error != "" {
						mu.Lock()
						lines = append(lines, u+" -> 失败（"+res.Error+"）")
						rows = append(rows, map[string]any{"url": u, "status": "failed", "error": res.Error, "elapsed_ms": elapsed})
						mu.Unlock()
					} else {
						s.st.Save(res, map[string]any{"batch": true})
						mu.Lock()
						lines = append(lines, fmt.Sprintf("%s -> 完成（%d 项技术）", u, len(res.Technologies)))
						rows = append(rows, map[string]any{"url": u, "status": "done",
							"findings": len(res.Vulnerabilities) + len(res.Verified), "techs": len(res.Technologies), "elapsed_ms": elapsed})
						mu.Unlock()
					}
				}
				mu.Lock()
				done++
				d, ln := done, append([]string{}, lines...)
				rws := make([]map[string]any, len(rows))
				copy(rws, rows)
				mu.Unlock()
				s.jobs.Update(jobID, func(j *store.Job) {
					j.Done = d
					j.Progress = d * 100 / len(urls)
					if len(ln) > 0 {
						j.Message = ln[len(ln)-1]
					}
					j.Result = map[string]any{"lines": ln, "rows": rws}
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

// hReplay 验证回归（3.0）：重放一次历史扫描的全部 dast 类发现。
func (s *Server) hReplay(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	rec := s.st.Get(id)
	if rec == nil || rec.Result == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	timeoutMS := s.cfg.Active.ProbeTimeoutMS
	stats, details := replay.Batch(replay.NewFetcher(timeoutMS), rec.Result.Verified)
	writeJSON(w, 200, map[string]any{"scan_id": id, "stats": stats, "details": details})
}

func (s *Server) hHistoryDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": s.st.Delete(id)})
}

// hHistoryClear 清空全部扫描历史（设置页·数据管理；前端二次确认后调用）。
func (s *Server) hHistoryClear(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"cleared": s.st.ClearAll()})
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
	case "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=sitelens-%d.md", id))
		_, _ = w.Write([]byte(markdownReport(rec)))
	default:
		writeJSON(w, 400, map[string]any{"error": "未知格式"})
	}
}

// hBeacon SSRF 出带回调接收端：记录路径随机令牌（/b/<token>）。
// 无状态、无敏感数据；token 128 位随机不可预测，仅供 dast 出带判定。
func (s *Server) hBeacon(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/b/")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	// B5：只登记已预订 token，未预订回连忽略（Hit 内部校验）
	beacon.Hit(token)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
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
	available := s.cfg.LoginBrute.CaptchaOCRURL != ""
	reason := "已就绪（ddddocr sidecar）"
	if !available {
		reason = "未配置 loginbrute.captcha_ocr_url；启动 python tools/ocr_server.py 并配置后即可识别验证码"
	}
	// 契约与 api-docs / 前端对齐：ocr=数字与算术（ddddocr 已支持），
	// click/slider 为预留位（sidecar 尚未实现，恒 false）
	writeJSON(w, 200, map[string]any{
		"available": available, "ocr": available,
		"click": false, "slider": false, "reason": reason,
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
	captchaField, _ := body["captcha_field"].(string)
	loginMode, _ := body["login_mode"].(string)
	jsonEndpoint, _ := body["json_endpoint"].(string)
	jsonTemplate, _ := body["json_template"].(string)
	successContains, _ := body["success_contains"].(string)
	jobID := newID()
	s.jobs.Create(jobID, "loginbrute", map[string]any{"url": urlStr, "login_mode": loginMode}, 100)
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
			r := headless.NewChrome(time.Duration(s.cfg.Crawler.HeadlessTimeoutSec)*time.Second, s.cfg.Crawler.HeadlessExecPath)
			if html, rerr := r.Render(urlStr); rerr == nil {
				rendered = html
			}
		}
		progress := func(done, total int, msg string) {
			s.jobs.Update(jobID, func(j *store.Job) {
				j.Status = "running"
				j.Progress = done * 100 / max(1, total)
				j.Message = msg
			})
		}
		var hits []loginbrute.Hit
		var err error
		if strings.EqualFold(loginMode, "json") {
			hits, err = loginbrute.JSONBrute(f, loginbrute.Options{
				PageURL:         urlStr,
				JSONEndpoint:    jsonEndpoint,
				JSONTemplate:    jsonTemplate,
				Users:           users,
				Passwords:       pwds,
				MaxTries:        s.cfg.LoginBrute.MaxTries,
				IntervalMS:      s.cfg.LoginBrute.IntervalMS,
				SuccessContains: successContains,
				CaptchaField:    captchaField, // 用户显式指定优先于自动识别
			}, progress)
		} else {
			hits, err = loginbrute.Brute(f, loginbrute.Options{
				PageURL:      urlStr,
				Users:        users,
				Passwords:    pwds,
				MaxTries:     s.cfg.LoginBrute.MaxTries,
				IntervalMS:   s.cfg.LoginBrute.IntervalMS,
				CaptchaType:  captchaType,
				CaptchaField: captchaField, // 用户显式指定优先（空 = 自动识别）
				OCRURL:       s.cfg.LoginBrute.CaptchaOCRURL,
				FetchImage: func(rawURL string) ([]byte, error) {
					rr, rerr := s.eng.ClientFor(scanOptions(body)).GetDirect(rawURL)
					if rerr != nil || rr == nil {
						return nil, rerr
					}
					return []byte(rr.Body), nil
				},
				RenderedBody: rendered,
			}, progress)
		}
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
	// B23：上传体先加硬上限（multipart 解析会落盘 TempDir，无上限可耗尽磁盘）
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Audit.MaxArchiveMB+8)<<20)
	if err := r.ParseMultipartForm(int64(s.cfg.Audit.MaxArchiveMB) << 20); err != nil {
		writeJSON(w, 400, map[string]any{"error": "上传解析失败：" + err.Error()})
		return
	}
	// F1：兼容 files（多选）与 file（旧版单数）两种字段名，混用也收；
	// 单文件上限 MaxFileKB，文件个数上限 MaxFiles
	var headers []*multipart.FileHeader
	if r.MultipartForm != nil {
		headers = append(headers, r.MultipartForm.File["files"]...)
		headers = append(headers, r.MultipartForm.File["file"]...)
	}
	if len(headers) == 0 {
		writeJSON(w, 400, map[string]any{"error": "缺少 file/files 上传字段"})
		return
	}
	maxFiles := s.cfg.Audit.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 1
	}
	if len(headers) > maxFiles {
		headers = headers[:maxFiles]
	}
	dir, err := os.MkdirTemp("", "sitelens_audit_")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "创建临时目录失败"})
		return
	}
	defer os.RemoveAll(dir)

	var skipped []string
	for _, hdr := range headers {
		fh, err := hdr.Open()
		if err != nil {
			continue
		}
		name := hdr.Filename
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".zip"):
			// 解压单文件限额独立放大到 8MB（与审计读入上限一致）；
			// 512KB 只约束 CollectSources 的预览回传（截断），不再拦截文件入树
			if err = extractZip(fh, hdr.Size, dir, 8<<20); err != nil {
				fh.Close()
				writeJSON(w, 400, map[string]any{"error": name + "：" + err.Error()})
				return
			}
		case strings.HasSuffix(lower, ".py") ||
			strings.HasSuffix(lower, ".js") ||
			strings.HasSuffix(lower, ".php"):
			dst, cerr := os.Create(filepath.Join(dir, filepath.Base(name)))
			if cerr != nil {
				fh.Close()
				writeJSON(w, 500, map[string]any{"error": "写文件失败"})
				return
			}
			_, _ = io.Copy(dst, io.LimitReader(fh, 8<<20))
			dst.Close()
		default:
			skipped = append(skipped, name) // 不支持的格式：跳过不算失败
		}
		fh.Close()
	}
	if len(skipped) > 0 {
		writeJSON(w, 400, map[string]any{
			"error": "以下文件不是受支持格式（仅 .zip 压缩包或 .py/.js/.php 源码）：" +
				strings.Join(skipped, ", ")})
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
	// 25A 源码预览：文本路径 + ≤512KB 内容随响应回传（服务端即删，不落盘）
	rep.Sources, rep.Contents = audit.CollectSources(dir)
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
		"    return False",
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
	rep.Sources, rep.Contents = audit.CollectSources(dir)
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

// randHex 加密随机十六进制串（唯一性后缀；审计 STD-2：时间派生熵低且名不符实）。
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		// crypto/rand 失败极罕见；退化为时间戳派生并保留原语义
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> uint(i*3) & 0xf)
		}
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, n)
	for i := range out {
		out[i] = hexDigits[b[i]&0xf]
	}
	return string(out)
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
