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
	"runtime/debug"
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
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/headless"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
	"cnb.cool/feng-qiao/sitelens/internal/replay"
	"cnb.cool/feng-qiao/sitelens/internal/resource"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/store"
	"cnb.cool/feng-qiao/sitelens/internal/target"
	"cnb.cool/feng-qiao/sitelens/web"
)

// Version 服务版本。
const Version = "5.2.3"

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
	// cfgPtr 当前配置快照（A-09）：写侧只在设置页保存时经 applySettings
	// 深拷贝后原子换枪；读侧一律经 cfgSnap() 取指针。指向的 *config.Config
	// 一经发布不得原地修改（否则与正在读快照的请求/扫描构成数据竞争）。
	cfgPtr  atomic.Pointer[config.Config]
	cfgPath string // 用户配置文件路径（设置页保存目标）
	eng     *engine.Engine
	matcher *sitelens.Matcher
	kb      atomic.Pointer[intel.KB] // 热替换安全：指向当前知识库快照
	st      scanStore                // 历史存储：JSON/Tiered/SQL 统一接口（默认 JSON 分层归档）
	jobs    *store.JobManager        // 作业注册表（/api/tasks 经可选 List() 接口接入）
	sem     chan struct{}
	// apiToken / tech 均以原子快照整体换枪：热更新写侧与请求读侧
	// 不共享可变内存（此前 string / slice header 无锁换枪 → 撕裂）。
	apiToken atomic.Pointer[string]
	tech     atomic.Pointer[techMeta] // 类别全集 + 指纹条数（CSV 宽表列序）

	// cfgMu 串行化设置页写侧（持久化 + 深拷贝 + 原子换枪的读改写序列），
	// 读侧不取锁：一律经 cfgSnap() 读不加速快照。
	cfgMu    sync.Mutex
	dataMu   sync.Mutex
	lastData map[string]int64 // 数据文件路径 → 上次加载时的 mtime（热更新基线）

	osvMu       sync.Mutex // OSV 同步互斥（同时只允许一个同步任务）
	osvRunning  bool
	osvTotal    int
	osvLastTime string
	osvLastMsg  string
	osvLastN    int

	preflights *preflightCache // 扫描前预检缓存（TTL/上限/in-flight 去重）
	bgOnce     sync.Once       // 后台调度器启动一次
}

// New 装配服务（加载指纹库/知识库/历史存储/用户插件）。
func New(cfg *config.Config, cfgPath string) (*Server, error) {
	if cfgPath == "" {
		cfgPath = ".sitelens.yml"
	}
	// 企业化认证模式校验：none（默认，沿用 X-Token）| token（RBAC Bearer）。
	switch strings.ToLower(strings.TrimSpace(cfg.Web.AuthMode)) {
	case "", "none":
	case "token":
		if strings.TrimSpace(cfg.Web.AuthSecret) == "" {
			return nil, fmt.Errorf("web.auth_mode=token 需要配置 web.auth_secret（authz 令牌 HMAC 密钥）")
		}
	default:
		return nil, fmt.Errorf("web.auth_mode 非法：%q（可选 none/token）", cfg.Web.AuthMode)
	}
	s := &Server{cfgPath: cfgPath, jobs: store.NewJobManagerWithCap(200),
		sem:        make(chan struct{}, cfg.Scan.MaxConcurrent),
		preflights: newPreflightCache(),
		lastData:   map[string]int64{}}
	s.cfgPtr.Store(cfg)
	checks.ConfigurePlugins(cfg.Checks.PluginDir)
	tok := os.Getenv("SLENS_API_TOKEN")
	if tok == "" {
		tok = cfg.Web.APIToken
	}
	s.apiToken.Store(&tok)

	if m, err := loadTechMeta(cfg); err == nil {
		s.tech.Store(&m)
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
	// 企业化 6.x：历史存储后端可切换（json 默认 | sqlite | postgres）。
	// 非 JSON 后端不可用（driver 未注册/连接/迁移失败）时回退 JSON 并打日志。
	st, err := s.openScanStore(cfg)
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

// token 返回当前 API 令牌快照（空串 = 未启用鉴权）。
// 读侧无锁：令牌由设置页热更新，整体换枪避免字符串头撕裂。
func (s *Server) token() string {
	if p := s.apiToken.Load(); p != nil {
		return *p
	}
	return ""
}

// techMetaSnap 返回当前指纹元数据快照（类别全集 + 条数）。
// cats 一经发布不再改写，读侧可安全共享；未加载时为零值（统计降级为 0）。
func (s *Server) techMetaSnap() techMeta {
	if p := s.tech.Load(); p != nil {
		return *p
	}
	return techMeta{}
}

// Handler 构建全部路由。
func (s *Server) Handler() http.Handler {
	// 后台调度器：每 30s 检查定时批量任务（幂等，仅首次 Handler 调用启动）。
	s.bgOnce.Do(func() { go s.RunScheduler(context.Background()) })
	mux := http.NewServeMux()

	// 页面（产品形态：无宣传首页与关于页，根路径即工作台）
	// "/" 不进表：由 hRoot 统一处理根路径、.html 直达与样式化 404
	pages := map[string]string{
		"/app":     "app.html",
		"/history": "history.html", "/api-docs": "api-docs.html",
		"/intel": "intel.html",
		"/chain": "chain.html", "/settings": "settings.html",
		"/feedback": "feedback.html",
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
	// 设计系统页（FE-10）：仅当嵌入资源存在时注册（未发布 design.html 时不加路由）
	if _, derr := web.FS.ReadFile("design.html"); derr == nil {
		mux.HandleFunc("GET /design", func(w http.ResponseWriter, r *http.Request) {
			s.serveAsset(w, "design.html")
		})
	}
	// 产品介绍页：由引擎提供，内嵌真实工作台 /demo/app。
	// 页面里的 token 占位符只在本地引擎响应时替换；该路由不应对公网暴露。
	mux.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/welcome" {
			http.NotFound(w, r)
			return
		}
		data, err := web.FS.ReadFile("welcome.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(strings.ReplaceAll(string(data), "__SITELENS_TOKEN__", s.token())))
	})
	// 仅给 /welcome 内嵌用的 app 副本：放行同源 iframe，其余安全头不变。
	mux.HandleFunc("GET /demo/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'; base-uri 'self'; form-action 'self'")
		s.serveAsset(w, "app.html")
	})
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
	// 收尾接线：任务聚合（内存作业 + 可续跑批量 + 定时批量）、证书到期资产数据
	mux.HandleFunc("GET /api/tasks", s.hTasks)
	mux.HandleFunc("GET /api/assets/cert-expiry", s.hCertExpiry)
	mux.HandleFunc("GET /api/assets/ports", s.hAssetPorts)
	// 5.2 反馈与诊断：本机生成脱敏诊断包 + 可选提交到用户自建端点
	// （产品不做常驻埋点——见《用户服务协议》）。
	mux.HandleFunc("GET /api/diagnostics", s.hDiagnostics)
	mux.HandleFunc("POST /api/feedback", s.hFeedback)
	mux.HandleFunc("POST /api/admin/reload", s.hAdminReload)
	// A10 自适应：长空闲释放情报常驻（惰性路径保留，下次访问自动重载）
	mux.HandleFunc("POST /api/admin/release-intel", s.hAdminReleaseIntel)
	// 内置 SPA 靶页：JS 延迟注入登录表单，用于无头渲染/登录爆破链路自测。
	// V-18：该页含硬编码演示凭据（admin/admin123），默认不注册；只有自测/
	// 演示环境显式设置 SITELENS_DEV_SPA_TARGET=1 才暴露（生产/桌面壳零暴露）。
	if devSPATargetEnabled() {
		mux.HandleFunc("GET /dev/spa-target", hSPATarget)
		mux.HandleFunc("POST /dev/spa-target/login", hSPATargetLogin)
	}
	mux.HandleFunc("POST /api/scan", s.hScan)
	mux.HandleFunc("POST /api/preflight", s.hPreflight) // 扫描前只读预检（1 次 GET，供建议卡 + 首页复用）
	mux.HandleFunc("GET /api/job/{id}", s.hJob)
	mux.HandleFunc("POST /api/job/{id}/cancel", s.hJobCancel)
	mux.HandleFunc("GET /api/job/{id}/results", s.hJobResults)
	mux.HandleFunc("POST /api/batch", s.hBatch)
	mux.HandleFunc("GET /api/batch/jobs", s.hBatchJobs)           // 可断点续跑的批量任务
	mux.HandleFunc("POST /api/batch/{id}/resume", s.hBatchResume) // 从状态文件续跑
	// 定时批量（BT-03）
	mux.HandleFunc("GET /api/batch/schedules", s.hBatchSchedulesList)
	mux.HandleFunc("POST /api/batch/schedules", s.hBatchScheduleCreate)
	mux.HandleFunc("PATCH /api/batch/schedules/{id}", s.hBatchScheduleUpdate)
	mux.HandleFunc("DELETE /api/batch/schedules/{id}", s.hBatchScheduleDelete)
	mux.HandleFunc("POST /api/batch/schedules/{id}/run", s.hBatchScheduleRun)
	// API 描述解析（CP-03）：OpenAPI/Swagger JSON、HAR、GraphQL introspection
	mux.HandleFunc("POST /api/apispec", s.hAPISpec)
	mux.HandleFunc("POST /api/apispec/graphql", s.hAPISpecGraphQL)
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
	// V-06：重放会对外发起网络请求（有副作用），必须是 POST —— GET 可被
	// <img>/链接诱导触发，且违背 GET 幂等语义。
	mux.HandleFunc("POST /api/replay/{id}", s.hReplay)
	mux.HandleFunc("POST /api/netsec", s.hNetsec)
	mux.HandleFunc("POST /api/loginbrute", s.hLoginBrute)
	mux.HandleFunc("GET /api/captcha/capability", s.hCaptchaCapability)
	mux.HandleFunc("POST /api/audit", s.hAudit)
	mux.HandleFunc("GET /api/audit/demo", s.hAuditDemo)
	// CP-08 UI triage：误报标记 + 白名单（internal/server/triage.go）
	s.registerTriageRoutes(mux)

	// V-05/BL-1：originGuard 必须在最外层——Host/来源校验先于任何凭据判定，
	// 且能覆盖 none 模式（无凭据）的全部路径。
	return s.originGuard(s.guard(s.headers(mux)))
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	s.startKEVDaemon()
	srv := &http.Server{
		Addr:              cfg.Web.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// V-20：只设 ReadHeaderTimeout 时，慢速 body（Slowloris 变体）没有截止
		// 时间，可长期占用连接。扫描器是长任务程序：读超时 120s（覆盖
		// /api/audit 的 8MB 上传），空闲连接 60s 回收，头大小 64KB 封顶。
		// 写超时保持 0：导出/报告是同步长响应，由各 handler 自行控制。
		ReadTimeout:    120 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(cfg.Web.ShutdownSec)*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(done)
	}()
	// SEC-8 加固：非回环监听且未设 Token 时给出醒目警告
	//（此时全部 /api/* 对所在网络开放，包括主动扫描与爆破能力）
	if !strings.HasPrefix(cfg.Web.Listen, "127.0.0.1") && !strings.HasPrefix(cfg.Web.Listen, "localhost") && s.token() == "" {
		log.Printf("警告：监听 %s 为非回环地址且未设置 API Token，全部 API 对所在网络开放（含主动扫描能力）。生产部署请设置 SLENS_API_TOKEN 或 web.api_token", cfg.Web.Listen)
	}
	log.Printf("SiteLens %s 监听 http://%s", Version, cfg.Web.Listen)
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	if s.KB() == nil || cfg.Intel.UpdateHours <= 0 {
		return
	}
	dest := filepath.Join(cfg.Store.DataDir, "kev_extra.json")
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
		ticker := time.NewTicker(time.Duration(cfg.Intel.UpdateHours) * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()
}

// ---- 中间件 ----

// guard 可选 API 鉴权。
//
// 两种模式：
//   - token（企业化 RBAC）：/api/* 需 Authorization: Bearer <authz 令牌>，
//     按 角色×动作×资源 鉴权（写操作需写权限；租户头不匹配 403）；
//   - none（默认，兼容旧行为）：配置了 api_token 时 /api/* 需 X-Token 头。
//
// 比较用常量时间实现（防时序侧信道逐字节猜 token）。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authMode() == "token" && strings.HasPrefix(r.URL.Path, "/api/") {
			if !s.authorizeRBAC(w, r) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if tok := s.token(); tok != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(tok)) != 1 {
				writeJSON(w, 401, map[string]any{"error": "未授权：缺少或错误的 X-Token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// headers 安全响应头。
//
// V-15：补点击劫持 / 来源泄露 / 敏感设备权限的默认拒绝。CSP 只放
// frame-ancestors/base-uri/form-action 三个不影响脚本执行的指令——SPA 大量
// 使用内联 <script>、内联事件与 Monaco 的 blob worker，加 script-src 会白屏，
// 故本轮不加（后续做 nonce 化后可再收）。
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "SiteLens")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
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
			"api-docs.html", "intel.html", "chain.html", "settings.html",
			"feedback.html", "404.html"} {
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
	writeJSON(w, 200, versionBody())
}

func (s *Server) hStats(w http.ResponseWriter, r *http.Request) {
	tm := s.techMetaSnap()
	stats := map[string]any{
		"categories": len(tm.cats), "technologies": tm.count, "curated": tm.count,
		"vulns": 0, "tscan": 0, "vuln_by_severity": map[string]int{},
		"intel_sources": map[string]int{}, "intel_with_ranges": 0, "intel_with_cvss": 0,
	}
	if kb := s.KB(); kb != nil {
		for k, v := range kb.Stats() {
			stats[k] = v
		}
	}
	stats["history"] = s.st.HistoryStatsForTenant(tenantFromRequest(r))
	stats["top_techs"] = s.st.TopTechsForTenant(8, tenantFromRequest(r))
	writeJSON(w, 200, stats)
}

func (s *Server) hCategories(w http.ResponseWriter, r *http.Request) {
	ids := s.techMetaSnap().cats // 单次快照：避免换枪中途 len/range 错配
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "name": categoryName(id), "icon": ""})
	}
	writeJSON(w, 200, map[string]any{"categories": out})
}

func (s *Server) hVulnSearch(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
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
	writeJSON(w, 200, map[string]any{"results": kb.Search(q, cfg.Intel.SearchLimit)})
}

func (s *Server) hVerified(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	limit := safeLimit(r.URL.Query().Get("limit"), cfg.Web.HistoryLimit, cfg.Web.HistoryCap)
	// BL-5：只汇总本租户已验证漏洞（空租户=全局，auth 关闭行为不变）。
	writeJSON(w, 200, map[string]any{"items": s.st.VerifiedForTenant(limit, tenantFromRequest(r))})
}

// ---- 扫描 ----

func (s *Server) hScan(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	s.reloadIfDataChanged()
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	urlStr, _ := body["url"].(string)
	urlStr = strings.TrimSpace(urlStr)

	// URL 输入自动修正（只改格式、不改目标）：补协议/去标点/hxxp 还原等。
	// 修正在响应里回显，前端 toast + 结果 extras 留痕。
	inputURL := urlStr
	var urlCorrections []string
	if cfg.Target.AutoNormalize {
		if nr := target.Normalize(urlStr); len(nr.Changes) > 0 {
			urlStr = nr.URL
			urlCorrections = nr.Changes
		}
	}

	opts := scanOptions(body)
	// 预检结果注入：命中且未过期时，引擎首页复用该响应（总请求不增加）。
	if pid, _ := body["preflight_id"].(string); pid != "" {
		if pf := s.preflights.get(pid); pf != nil {
			opts.Preflight = pf
		}
	}
	jobID := newID()
	s.jobs.Create(jobID, "scan", map[string]any{"url": urlStr, "options": opts}, 100)
	// BL-5：作业归属租户（token 模式取令牌租户；none 模式为空 = legacy）。
	// 扫描是异步的，收尾时请求上下文已不在——租户必须随 job 一起捕获。
	tenant := tenantFromRequest(r)
	s.jobs.Update(jobID, func(j *store.Job) { j.Tenant = tenant })
	if _, vhost, _, verr := target.Validate(urlStr, cfg.Scan.Resolve); verr != nil {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = verr.Error() })
		writeJSON(w, 400, map[string]any{"job_id": jobID, "error": verr.Error()})
		return
	} else if !target.Allowed(vhost, cfg.Scan.AllowHosts) {
		msg := "目标不在 allow_hosts 授权白名单：" + vhost
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = msg })
		writeJSON(w, 400, map[string]any{"job_id": jobID, "error": msg})
		return
	}
	go s.runScanJob(jobID, urlStr, opts)
	resp := map[string]any{
		"job_id":         jobID,
		"input_url":      inputURL,
		"normalized_url": urlStr,
	}
	if len(urlCorrections) > 0 {
		resp["url_corrections"] = urlCorrections
	}
	writeJSON(w, 200, resp)
}

// levelPresets 语义化扫描模式（level 参数）：先套预设，显式键仍可逐项覆盖。
// 与前端 web/app.html 的 LEVELS 表保持同一语义；毁天灭地为全模块+
// 全量模板验证，仅授权目标使用。
var levelPresets = map[string]map[string]any{
	"quick":      {"deep": false},
	"standard":   {"deep": true},
	"deep":       {"deep": true, "active_fp": true, "service_probe": true, "checks": "core", "dast": true, "nuclei": true, "nuclei_cap": 3000},
	"full":       {"deep": true, "active_fp": true, "dir_scan": true, "dir_bypass": true, "dir_full_words": true, "subdomain": true, "webshell": true, "service_probe": true, "checks": "all", "dast": true, "netsec": true, "passive": true},
	"assets":     {"deep": true, "dir_scan": true, "subdomain": true, "takeover": true, "active_fp": true},
	"stealth":    {"deep": true, "browser_ua": true, "passive": true, "netsec": true},
	"apocalypse": {"deep": true, "active_fp": true, "dir_scan": true, "dir_bypass": true, "dir_full_words": true, "subdomain": true, "takeover": true, "webshell": true, "weak_audit": true, "service_probe": true, "checks": "all", "dast": true, "netsec": true, "passive": true, "browser_ua": true, "nuclei_cap": 6000},
	"exhaustive": {"deep": true, "active_fp": true, "dir_scan": true, "dir_bypass": true, "dir_full_words": true, "subdomain": true, "takeover": true, "webshell": true, "weak_audit": true, "service_probe": true, "checks": "all", "dast": true, "netsec": true, "passive": true, "browser_ua": true, "nuclei": true, "nuclei_cap": 12000},
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
	if v, ok := body["dast"].(map[string]any); ok {
		// 前端高级检测对象：{idor,logic,upload,deser,proto}（G09/G10 per-scan 覆盖）
		o.DAST = true
		o.AdvIDOR = boolOf(v["idor"], false)
		o.AdvLogic = boolOf(v["logic"], false)
		o.AdvUpload = boolOf(v["upload"], false)
		o.AdvDeser = boolOf(v["deser"], false)
		o.AdvProto = boolOf(v["proto"], false)
	} else {
		o.DAST = boolOf(body["dast"], false)
	}
	o.Exploit = boolOf(body["exploit"], false)     // config exploit.enabled 为总闸
	o.NucleiSubset = boolOf(body["nuclei"], false) // 5.3：显式开启社区模板池（深度/穷尽档）
	o.Passive = boolOf(body["passive"], false)
	o.JSMap = boolOf(body["js_map"], false)      // JS 攻击面提取（可独立于 DAST）
	o.NetProto = boolOf(body["netproto"], false) // 协议模板（可独立于端口识别）
	o.Graph = boolOf(body["graph"], false)       // 4.0 P8：结构化事实图（CWE/攻击链）
	// 强度档位的字典缩放与端口集（每扫描覆盖配置；0/缺省 = 沿用配置）
	if v, ok := body["dir_max_paths"].(float64); ok && v > 0 {
		o.DirMaxPaths = int(v)
	}
	o.DirFullWords = boolOf(body["dir_full_words"], false)
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
	// BL-5：租户随 job 捕获（请求上下文在异步收尾时已不可用）。
	tenant := s.jobTenant(jobID)
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	// V-09：后台 goroutine 拿不到 net/http 的 per-request recover——引擎在
	// 不可信输入（HTML/JSON/JS/协议模板）上 panic 会直接终止整个进程，正在
	// 跑的所有扫描与前端连接一起断。这里兜底恢复并落 job 错误。
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[panic] 扫描任务 %s 已恢复（进程继续运行）：%v\n%s", jobID, rec, debug.Stack())
			s.jobs.Update(jobID, func(j *store.Job) {
				j.Status = "error"
				j.Message = "内部错误（已恢复）：" + fmt.Sprint(rec)
			})
		}
	}()

	// 实时事件流：引擎阶段/命中/认证事件写入 job 事件环，前端轮询消费
	opts.OnEvent = func(kind, text string) {
		s.jobs.AppendEvent(jobID, kind, text)
	}
	// 实时统计：请求数/页面数/拦截数/瞬时速率（引擎节流 ~250ms 推送）。
	opts.OnLive = func(st engine.LiveStats) {
		s.jobs.Update(jobID, func(j *store.Job) {
			j.Live = &store.LiveStats{
				Phase: st.Phase, PhaseName: st.PhaseName, Requests: st.Requests,
				Pages: st.Pages, Blocked: st.Blocked, Rate: st.Rate, ElapsedMS: st.ElapsedMS,
			}
		})
	}

	res := s.eng.Scan(urlStr, opts, func(p int, msg string) {
		s.jobs.Update(jobID, func(j *store.Job) { j.Progress = p; j.Message = msg })
	}, func() bool { return s.jobs.CancelRequested(jobID) })

	if s.jobs.CancelRequested(jobID) {
		// 零丢失（FE-12）：取消时把已采集结果落库为 partial，可在历史中查看/续扫。
		lastPhase := ""
		if j := s.jobs.Get(jobID); j != nil && j.Live != nil {
			lastPhase = j.Live.Phase
		}
		s.SavePartialJob(jobID, res, PartialOptions(opts), lastPhase)
		return
	}
	if res.Error != "" {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = res.Error })
		return
	}
	scanID := s.st.SaveForTenant(res, map[string]any{
		"deep": opts.Deep, "checks": opts.Checks, "netsec": opts.Netsec,
		"dast": opts.DAST, "passive": opts.Passive,
	}, tenant)
	// C-03：Save 的 int64 签名无法表达错误，失败时后端返回 0。此时绝不能把 job
	// 标成 done——"结果没落库、任务却显示完成"是静默丢数据（SQL 断连/权限/磁盘满
	// 都可能触发）。失败要显式失败，并带上后端给出的原因。
	if scanID <= 0 {
		msg := "结果保存失败：存储后端未返回记录 ID"
		if rep, ok := s.st.(saveErrReporter); ok {
			if e := rep.LastSaveError(); e != "" {
				msg = "结果保存失败（已写入回退队列，可在诊断中查看）：" + e
			}
		}
		log.Printf("错误：扫描结果保存失败（job=%s url=%s）：%s", jobID, urlStr, msg)
		s.jobs.Update(jobID, func(j *store.Job) {
			j.Status = "error"
			j.Progress = 100
			j.Message = msg
		})
		return
	}
	s.jobs.Update(jobID, func(j *store.Job) {
		j.Status = "done"
		j.Progress = 100
		j.Message = "完成"
		j.Result = map[string]any{"scan_id": scanID}
	})
}

// jobTenant 读取作业归属租户（BL-5）。作业不存在/legacy 时返回空 = 全局。
func (s *Server) jobTenant(jobID string) string {
	if s == nil || s.jobs == nil || jobID == "" {
		return ""
	}
	if j := s.jobs.Get(jobID); j != nil {
		return strings.TrimSpace(j.Tenant)
	}
	return ""
}

func (s *Server) hJob(w http.ResponseWriter, r *http.Request) {
	s.jobOut(w, r.PathValue("id"), false, tenantFromRequest(r))
}

func (s *Server) hJobResults(w http.ResponseWriter, r *http.Request) {
	s.jobOut(w, r.PathValue("id"), true, tenantFromRequest(r))
}

func (s *Server) jobOut(w http.ResponseWriter, id string, withResults bool, tenant string) {
	j := s.jobs.Get(id)
	// BL-5：跨租户按 job id 读取一律 404（job payload 含目标 URL/结果）。
	if j == nil || (tenant != "" && j.Tenant != tenant) {
		writeJSON(w, 404, map[string]any{"error": "任务不存在"})
		return
	}
	out := map[string]any{
		"job_id": j.ID, "status": j.Status, "progress": j.Progress,
		"message": j.Message, "done": j.Done, "total": j.Total,
	}
	// 扫描实时统计（请求/页面/拦截/速率）——前端实时面板消费，additive。
	if j.Live != nil {
		out["live"] = j.Live
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
	// BL-5：跨租户按 job id 取消一律 404（不能取消别人的任务）。
	if j == nil || (tenantFromRequest(r) != "" && j.Tenant != tenantFromRequest(r)) {
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	s.reloadIfDataChanged()
	var body batchRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body)
	items := parseBatchItems(body, cfg.Batch.MaxURLs)
	jobID, total := s.startBatchJobForTenant(items, tenantFromRequest(r))
	if total == 0 {
		writeJSON(w, 400, map[string]any{"error": "URL 列表为空"})
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": jobID, "total": total})
}

// batchMaxAttempts 单条 URL 最大尝试次数（失败重试，指数退避）。
const batchMaxAttempts = 3

// runBatchLegacy 旧批量并发路径（Batch.UseWorkerPool=false，默认行为零变化）。
func (s *Server) runBatchLegacy(jobID string, items []batchItem, st *batchState) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	workers := cfg.Batch.Workers
	if workers <= 0 {
		workers = 3
	}
	var mu sync.Mutex
	done := 0
	var lines []string
	rows := make([]map[string]any, 0, len(items))
	idx := atomic.Int64{}
	// 同 host 串行：避免批量把同一站点并发打爆（不同 host 仍按 workers 并行）。
	hostLocks := map[string]*sync.Mutex{}
	var hostMu sync.Mutex
	lockFor := func(raw string) *sync.Mutex {
		h := batchHost(raw)
		hostMu.Lock()
		defer hostMu.Unlock()
		l, ok := hostLocks[h]
		if !ok {
			l = &sync.Mutex{}
			hostLocks[h] = l
		}
		return l
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(idx.Add(1)) - 1
				if i >= len(items) {
					return
				}
				it := items[i]
				if st != nil {
					mu.Lock()
					st.Items[i].Status = "running"
					_ = s.saveBatchState(st)
					mu.Unlock()
				}
				if s.jobs.CancelRequested(jobID) {
					mu.Lock()
					lines = append(lines, it.URL+" -> 已跳过（任务取消）")
					rows = append(rows, map[string]any{"url": it.URL, "status": "skipped", "level": it.Level})
					if st != nil {
						st.Items[i].Status = "skipped"
						_ = s.saveBatchState(st)
					}
					mu.Unlock()
				} else {
					res, attempts, elapsed := s.scanBatchURL(jobID, it, lockFor)
					if res.Error != "" {
						mu.Lock()
						lines = append(lines, it.URL+" -> 失败（"+res.Error+"，尝试 "+fmt.Sprint(attempts)+" 次）")
						rows = append(rows, map[string]any{"url": it.URL, "status": "failed", "error": res.Error,
							"level": it.Level, "attempts": attempts, "elapsed_ms": elapsed})
						if st != nil {
							st.Items[i].Status = "failed"
							st.Items[i].Attempts = attempts
							st.Items[i].Error = res.Error
							st.Items[i].ElapsedMS = elapsed
							_ = s.saveBatchState(st)
						}
						mu.Unlock()
					} else {
						batchTenant := s.jobTenant(jobID)
						s.st.SaveForTenant(res, map[string]any{"batch": true}, batchTenant)
						row := map[string]any{"url": it.URL, "status": "done",
							"level": it.Level, "attempts": attempts,
							"findings": len(res.Vulnerabilities) + len(res.Verified), "techs": len(res.Technologies), "elapsed_ms": elapsed}
						if n, fx, ok := s.DiffURLForTenant(it.URL, batchTenant); ok {
							row["new_findings"] = n
							row["fixed"] = fx
						}
						mu.Lock()
						lines = append(lines, fmt.Sprintf("%s -> 完成（%d 项技术）", it.URL, len(res.Technologies)))
						rows = append(rows, row)
						if st != nil {
							st.Items[i].Status = "done"
							st.Items[i].Attempts = attempts
							st.Items[i].Findings = len(res.Vulnerabilities) + len(res.Verified)
							st.Items[i].Techs = len(res.Technologies)
							st.Items[i].ElapsedMS = elapsed
							_ = s.saveBatchState(st)
						}
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
					j.Progress = d * 100 / len(items)
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
	if st != nil {
		if wasCancelled {
			// 取消：保留状态供断点续跑（未完成项 queued/skipped，失败项 failed 可重试）。
			st.Cancelled = true
			_ = s.saveBatchState(st)
		} else {
			st.Finished = true
			_ = s.saveBatchState(st)
			s.deleteBatchState(jobID)
		}
	}
	s.jobs.Update(jobID, func(j *store.Job) {
		if wasCancelled {
			j.Status = "cancelled"
			j.Message = "批量已取消（未开始的 URL 已跳过，可断点续跑）"
		} else {
			j.Status = "done"
			j.Message = "批量完成"
		}
	})
	// Webhook 通知（可选；配置 batch.webhook_url 后异步推送，不阻塞任务收尾）。
	if hook := cfg.Batch.WebhookURL; hook != "" {
		event := "batch.done"
		if wasCancelled {
			event = "batch.cancelled"
		}
		payload := map[string]any{
			"event": event, "job_id": jobID, "total": len(items), "done": done,
			"tag": batchTagOf(items), "rows": rows,
		}
		go func() {
			if err := NotifyBatch(hook, payload); err != nil {
				log.Printf("批量 webhook 通知失败：%v", err)
			}
		}()
	}
}

// ---- 历史 / 导出 / 差异 ----

func (s *Server) hHistory(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	limit := safeLimit(r.URL.Query().Get("limit"), cfg.Web.HistoryLimit, cfg.Web.HistoryCap)
	tech := r.URL.Query().Get("tech")
	// BL-5：token 模式只返回本租户记录（auth 关闭 tenant 空 → 全局，行为不变）。
	writeJSON(w, 200, map[string]any{"scans": s.st.ListForTenant(limit, tech, tenantFromRequest(r))})
}

func (s *Server) hHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	// BL-5：跨租户按 id 读取一律 404（不泄露存在性）。
	rec := s.st.GetForTenant(id, tenantFromRequest(r))
	if rec == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	writeJSON(w, 200, rec)
}

// hReplay 验证回归（3.0）：重放一次历史扫描的全部 dast 类发现。
//
// V-06：①只允许 POST（GET 会被 <img> 等无副作用语义触发，且违背幂等）；
// ②重放前对每条待请求 URL（含注入探针 URL）重新做 SSRF 校验 + allow_hosts，
// 历史记录里的 URL 可能来自被扫站点的可控内容，不可盲信。
func (s *Server) hReplay(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	// BL-5：跨租户按 id 重放一律 404。
	rec := s.st.GetForTenant(id, tenantFromRequest(r))
	if rec == nil || rec.Result == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	timeoutMS := cfg.Active.ProbeTimeoutMS
	entries, blocked := s.replayableEntries(rec.Result.Verified)
	stats, details := replay.Batch(replay.NewFetcher(timeoutMS), entries)
	writeJSON(w, 200, map[string]any{
		"scan_id": id, "stats": stats, "details": details, "blocked_targets": blocked,
	})
}

// replayableEntries 过滤可安全重放的条目。
//
// 不可信来源：历史 verified 里的 url/param/payload 可能源自被扫站点的可控
// 内容（跳转目标、JS 抽取等）。重放会真实发请求，故逐条重建探针 URL 后
// 重新走 target.Validate(resolve=true) + allow_hosts；不合规条目置空 url
// （replay.One 会判 unsupported，索引与前端列表保持一致），并统计条数。
func (s *Server) replayableEntries(verified []map[string]any) ([]map[string]any, int) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	out := make([]map[string]any, 0, len(verified))
	blocked := 0
	for _, v := range verified {
		src, _ := v["src"].(string)
		if src != "dast" {
			out = append(out, v)
			continue
		}
		rawURL, _ := v["url"].(string)
		param, _ := v["param"].(string)
		payload, _ := v["payload"].(string)
		urls := []string{rawURL}
		if rawURL != "" && param != "" && payload != "" {
			urls = append(urls, dast.SetParam(rawURL, param, payload))
		}
		ok := true
		for _, u := range urls {
			if u == "" {
				continue
			}
			_, host, _, verr := target.Validate(u, true)
			if verr != nil || !target.Allowed(host, cfg.Scan.AllowHosts) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, v)
			continue
		}
		blocked++
		cp := make(map[string]any, len(v))
		for k, val := range v {
			cp[k] = val
		}
		cp["url"] = ""
		out = append(out, cp)
	}
	return out, blocked
}

func (s *Server) hHistoryDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	tenant := tenantFromRequest(r)
	// BL-5：token 模式下跨租户删除一律 404（不泄露存在性）；auth 关闭保持
	// 既有语义（不存在返回 deleted:false，不改成 404）。
	if tenant != "" && s.st.GetForTenant(id, tenant) == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": s.st.DeleteForTenant(id, tenant)})
}

// hHistoryClear 清空扫描历史（设置页·数据管理；前端二次确认后调用）。
//
// BL-5：token 模式下只清空本租户历史（tenant 空 = 全局，auth 关闭时行为不变），
// 避免租户管理员跨租户销毁他人数据。
func (s *Server) hHistoryClear(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"cleared": s.st.ClearAllForTenant(tenantFromRequest(r))})
}

func (s *Server) hExport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return
	}
	// BL-5：跨租户导出一律 404。
	rec := s.st.GetForTenant(id, tenantFromRequest(r))
	if rec == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	switch r.URL.Query().Get("fmt") {
	case "json", "":
		// CP-10：报告 JSON 只增字段——check_runs 汇总为每来源 runs/pass/fail。
		// nil Result 保持既有 "null" 输出（导入迁移/写库中断形态）。
		payload := any(rec.Result)
		if rec.Result != nil {
			if stats := s.sourceStats(rec.Result.CheckRuns); len(stats) > 0 {
				payload = exportReport{Result: rec.Result, SourceStats: stats}
			}
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=sitelens-%d.json", id))
		_, _ = w.Write(data)
	case "csv":
		if rec.Result == nil {
			// result 为 null 的历史记录（导入迁移/写库中断都可能产生）：
			// 与 hReplay 同口径 404，不能解引用 nil panic 炸掉该连接
			writeJSON(w, 404, map[string]any{"error": "记录不存在（无详细结果数据）"})
			return
		}
		csvText := detailCSV(rec, s.techMetaSnap().cats)
		csvResponse(w, csvText, fmt.Sprintf("sitelens-%d.csv", id))
	case "wide":
		if rec.Result == nil {
			writeJSON(w, 404, map[string]any{"error": "记录不存在（无详细结果数据）"})
			return
		}
		csvText := wideCSV([]*store.ScanRecord{rec}, s.techMetaSnap().cats)
		csvResponse(w, csvText, fmt.Sprintf("sitelens-wide-%d.csv", id))
	case "sarif":
		data, serr := scanSARIF(rec)
		if serr != nil {
			writeJSON(w, 404, map[string]any{"error": serr.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=sitelens-%d.sarif", id))
		_, _ = w.Write(data)
	case "har":
		// HAR 1.2：把证据链重建为「扫描器实际发出了什么」，可直接导入
		// Chrome DevTools 或兼容 HAR 的工具复核；?raw=1 保留敏感头原值。
		data, herr := buildScanHAR(rec, r.URL.Query().Get("raw") == "1")
		if herr != nil {
			writeJSON(w, 404, map[string]any{"error": herr.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=sitelens-%d.har", id))
		_, _ = w.Write(data)
	case "mlps", "asvs", "compliance":
		fw := FrameworkMLPS
		if r.URL.Query().Get("fmt") == "asvs" {
			fw = FrameworkASVS
		}
		format := FormatMarkdown
		if r.URL.Query().Get("format") == "html" {
			format = FormatHTML
		}
		out, cerr := RenderCompliance(rec, fw, format)
		if cerr != nil {
			writeJSON(w, 400, map[string]any{"error": cerr.Error()})
			return
		}
		ct := "text/markdown; charset=utf-8"
		if format == FormatHTML {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=sitelens-%d-%s.%s", id, string(fw), string(format)))
		_, _ = w.Write([]byte(out))
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

// exportReport 报告 JSON 附加字段载体：内嵌 *engine.Result 保持既有字段原序，
// 仅追加 source_stats（CP-10；additive，omitempty 不改变无 runs 时的旧输出形态）。
type exportReport struct {
	*engine.Result
	SourceStats []checks.SourcePassRate `json:"source_stats,omitempty"`
}

// sourceStats 每来源 runs/pass/fail 统计（CP-10 报告链路）。
// 模板条目取本地索引缓存（热路径）；无 runs 时返回 nil（JSON 省略该字段）。
func (s *Server) sourceStats(runs []checks.CheckRun) []checks.SourcePassRate {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	if len(runs) == 0 || cfg == nil {
		return nil
	}
	entries := nuclei.IndexCached(filepath.Join(cfg.Store.DataDir, "nuclei_index.json"))
	return checks.AggregateCheckRuns(runs, nuclei.SourceResolver(entries))
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
	// BL-5：diff 两侧都必须归属当前租户（任一不匹配 → 404，不泄露另一侧存在性）。
	tenant := tenantFromRequest(r)
	ra, rb := s.st.GetForTenant(aID, tenant), s.st.GetForTenant(bID, tenant)
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	host, _ := body["host"].(string)
	host = strings.TrimSpace(host)
	if host == "" {
		writeJSON(w, 400, map[string]any{"error": "请输入域名"})
		return
	}
	scheme, host, port, err := target.Validate(host, cfg.Scan.Resolve)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !target.Allowed(host, cfg.Scan.AllowHosts) {
		writeJSON(w, 400, map[string]any{"error": "目标不在 allow_hosts 授权白名单：" + host})
		return
	}
	tlsPort := port
	if tlsPort == 0 || tlsPort == 80 {
		tlsPort = 443
	}
	findings := netsec.CheckTLS(host, tlsPort)
	if cfg.Netsec.MailCheck {
		findings = append(findings, netsec.CheckDNSMail(host)...)
	}
	// HSTS / HTTP→HTTPS 跳转：一次只读 GET（≤5s、丢弃正文）。
	probeURL := scheme + "://" + host
	if port > 0 && !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		probeURL = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	findings = append(findings, netsec.CheckHTTP(probeURL, cfg.Scan.AllowHosts)...)
	// 证书资产线索（SAN/颁发者/到期）+ 可选端口探测（?ports=1 或 ?ports=22,443）。
	resp := map[string]any{"host": host, "findings": findings}
	if sans, issuer, notAfter := netsec.CheckCertAssets(host, tlsPort); len(sans) > 0 || issuer != "" || !notAfter.IsZero() {
		assets := map[string]any{"sans": sans, "issuer": issuer}
		if !notAfter.IsZero() {
			assets["not_after"] = notAfter.Format(time.RFC3339)
			assets["days_left"] = int(time.Until(notAfter).Hours() / 24)
		}
		resp["assets"] = assets
	}
	if q := strings.TrimSpace(r.URL.Query().Get("ports")); q != "" {
		var ports []int
		if q == "1" || q == "common" || q == "true" {
			ports = netsec.DefaultPorts
		} else {
			// V-10：显式端口列表去重 + 硬上限。此前无上限：一个请求可列近
			// 6.5 万端口，8 并发 × 1.5s 超时 ≈ 3.4 小时挂起且响应体数万条。
			seen := make(map[int]bool, 32)
			for _, part := range strings.Split(q, ",") {
				if len(ports) >= maxNetsecPorts {
					break
				}
				n, perr := strconv.Atoi(strings.TrimSpace(part))
				if perr != nil || n <= 0 || n >= 65536 || seen[n] {
					continue
				}
				seen[n] = true
				ports = append(ports, n)
			}
		}
		resp["ports"] = netsec.CheckPorts(host, ports, 1500*time.Millisecond)
	}
	writeJSON(w, 200, resp)
}

// maxNetsecPorts 单次 /api/netsec 端口探测上限（V-10）。默认端口表远小于此值，
// 显式列表按序截断；配合去重防止重复探测。
const maxNetsecPorts = 1024

func (s *Server) hCaptchaCapability(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	available := cfg.LoginBrute.CaptchaOCRURL != ""
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
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
	multiStep, _ := body["multistep"].(bool)
	jobID := newID()
	s.jobs.Create(jobID, "loginbrute", map[string]any{"url": urlStr, "login_mode": loginMode}, 100)
	if _, _, _, verr := target.Validate(urlStr, cfg.Scan.Resolve); verr != nil {
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = verr.Error() })
		writeJSON(w, 400, map[string]any{"job_id": jobID, "error": verr.Error()})
		return
	}
	// V-10：爆破是重型任务（可选无头 Chrome + MaxTries 次登录尝试），此前
	// 完全无并发闸——单请求即可开无限作业。现复用扫描信号量（扫描/爆破共享
	// 并发上限），满则 429 快速失败，不把作业排进内存。
	select {
	case s.sem <- struct{}{}:
	default:
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "error"; j.Message = "并发已满" })
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"job_id": jobID,
			"error":  "并发任务已满（扫描/爆破共享并发闸），请稍后重试",
		})
		return
	}
	go func() {
		defer func() { <-s.sem }()
		// V-09：同扫描任务——后台 goroutine panic 必须兜住，否则整进程退出。
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[panic] 登录爆破任务 %s 已恢复：%v\n%s", jobID, rec, debug.Stack())
				s.jobs.Update(jobID, func(j *store.Job) {
					j.Status = "error"
					j.Message = "内部错误（已恢复）：" + fmt.Sprint(rec)
				})
			}
		}()
		f := &httpPoster{c: s.eng.ClientFor(scanOptions(body))}
		users := loginbrute.LoadList(
			filepath.Join(cfg.Active.WordlistDir, "weak_users.txt"), cfg.LoginBrute.MaxUsers)
		pwds := loginbrute.LoadList(
			filepath.Join(cfg.Active.WordlistDir, "weak_passwords.txt"), cfg.LoginBrute.MaxPasswords)
		s.jobs.Update(jobID, func(j *store.Job) { j.Status = "running" })

		// SPA 登录页支持：开启无头渲染时先渲染登录页，用渲染后的 DOM 解析表单
		rendered := ""
		if cfg.Crawler.Headless {
			r := headless.NewChrome(time.Duration(cfg.Crawler.HeadlessTimeoutSec)*time.Second, cfg.Crawler.HeadlessExecPath)
			if html, rerr := r.Render(urlStr); rerr == nil {
				rendered = html
			}
		}
		progress := func(done, total int, msg string) {
			s.jobs.Update(jobID, func(j *store.Job) {
				// 不写 j.Status：进度上报不得覆写 hJobCancel 置上的 cancelling
				j.Progress = done * 100 / max(1, total)
				j.Done, j.Total = done, total // 实时尝试计数（走查 Major）
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
				MaxTries:        cfg.LoginBrute.MaxTries,
				IntervalMS:      cfg.LoginBrute.IntervalMS,
				SuccessContains: successContains,
				CaptchaField:    captchaField, // 用户显式指定优先于自动识别
				MultiStep:       multiStep,
				AllowHosts:      cfg.Scan.AllowHosts,
				Cancel:          func() bool { return s.jobs.CancelRequested(jobID) },
			}, progress)
		} else {
			hits, err = loginbrute.Brute(f, loginbrute.Options{
				PageURL:      urlStr,
				Users:        users,
				Passwords:    pwds,
				MaxTries:     cfg.LoginBrute.MaxTries,
				IntervalMS:   cfg.LoginBrute.IntervalMS,
				CaptchaType:  captchaType,
				CaptchaField: captchaField, // 用户显式指定优先（空 = 自动识别）
				MultiStep:    multiStep,
				OCRURL:       cfg.LoginBrute.CaptchaOCRURL,
				AllowHosts:   cfg.Scan.AllowHosts,
				Cancel:       func() bool { return s.jobs.CancelRequested(jobID) },
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
		// 取消检查须在 Update 回调外（RWMutex 不可重入），且优先于 error/done 收尾
		if s.jobs.CancelRequested(jobID) {
			s.jobs.Update(jobID, func(j *store.Job) { j.Status = "cancelled"; j.Message = "已取消" })
			return
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	// B23：上传体先加硬上限（multipart 解析会落盘 TempDir，无上限可耗尽磁盘）
	r.Body = http.MaxBytesReader(w, r.Body, int64(cfg.Audit.MaxArchiveMB+8)<<20)
	if err := r.ParseMultipartForm(int64(cfg.Audit.MaxArchiveMB) << 20); err != nil {
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
	maxFiles := cfg.Audit.MaxFiles
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
			// 解压单文件限额独立放大到 8MB；审计读入上限由下方 acfg 对齐到
			// 同一 8MB（否则 512KB~8MB 文件入树、计入 rep.Files 却零规则扫描）。
			// CollectSources 预览为全量回传（不截断），总量同样由 8MB 闸门把守
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

	// 三闸门对齐：解压/直传单文件已放大到 8MB，规则扫描的读入上限一并抬到
	// 8MB，否则 512KB~8MB 源码计入「扫描文件」却一条规则都不跑（零发现）
	acfg := cfg.Audit
	if acfg.MaxFileKB < 8192 {
		acfg.MaxFileKB = 8192
	}
	rep, err := audit.Run(dir, acfg, nil)
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
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
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
	acfg := cfg.Audit
	if acfg.MaxFileKB < 8192 {
		acfg.MaxFileKB = 8192 // 与 hAudit 一致：审计读入上限对齐 8MB 上传闸门
	}
	rep, err := audit.Run(dir, acfg, nil)
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

// csvCellSafe CSV 公式注入转义（V-14）。
//
// 技术名/版本/官网/证据全部来自被扫页面（<meta generator>、响应头、JS 变量），
// 攻击者可控。Excel/WPS 会把以 = + - @ 或制表/回车开头的单元格当公式求值
// （=HYPERLINK(...) 外带、DDE 命令执行）。OWASP CSV Injection 的标准缓解是
// 前置单引号并保持字段整体被引号包裹——csv.Writer 只在必要时加引号，所以
// 这里既前置 ' 又强制包一层双引号（内容里的双引号转义为两个）。
func csvCellSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return `"'` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
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
			csvCellSafe(t.Name), csvCellSafe(strings.Join(cats, " / ")),
			fmt.Sprintf("%d%%", t.Confidence), csvCellSafe(t.Version), csvCellSafe(t.Website),
			csvCellSafe(strings.Join(t.Evidence, " | ")),
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
				cells[c] = append(cells[c], csvCellSafe(t.Name))
			}
		}
		line := []string{csvCellSafe(rec.URL)}
		for _, c := range catOrder {
			line = append(line, csvCellSafe(strings.Join(cells[c], " ; ")))
		}
		_ = w.Write(line)
	}
	w.Flush()
	return buf.String()
}
