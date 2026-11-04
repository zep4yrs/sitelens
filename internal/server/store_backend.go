// 企业化 6.x：历史存储后端抽象与 SQL 适配（G09/G10 基座接线）。
//
// server 只依赖 scanStore 接口，三种后端均满足：
//   - JSON 文件式（store.Tiered，默认；List/Get 跨归档透明）；
//   - sqlite / postgres（store.SQLStore 经 sqlScanStore 适配）。
//
// 切换规则（config.Store.Driver）：
//   - 空 / "json" → JSON 文件存储（默认行为零变化）；
//   - "sqlite" / "postgres" → sql.Open(driver, dsn) → ApplyMigrations →
//     NewSQLStoreDialect；driver 未注册 / 连接失败 / 迁移失败 → 明确日志 +
//     回退 JSON（不阻断启动，避免企业版因 DB 抖动完全不可用）。
package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/model"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// scanStore server 依赖的历史存储能力集（JSON/Tiered/SQL 适配器均满足）。
type scanStore interface {
	Save(res *engine.Result, options map[string]any) int64
	Import(rec store.ScanRecord) (int64, error)
	List(limit int, tech string) []store.ScanSummary
	Get(id int64) *store.ScanRecord
	Delete(id int64) bool
	ClearAll() int
	HistoryStats() map[string]any
	TopTechs(limit int) []map[string]any
	Verified(limit int) []map[string]any
	Graph(id int64) (*model.ScanGraph, bool)
	GraphWithStatus(id int64) (*model.ScanGraph, string)
	GraphJSONL(id int64) ([]byte, bool)
	GraphManifestOf(id int64) (*store.GraphManifest, bool)
	HasGraph(id int64) bool
	GraphIDs() []int64

	// ---- BL-5/A-04 多租户数据面隔离（Wave-3） ----
	// tenant 为空 = 全局（认证关闭/单机，保持既有语义）；非空 = 只操作该租户
	// 记录。Get/Delete 不匹配按「不存在」处理（nil/false），server 统一 404。
	SaveForTenant(res *engine.Result, options map[string]any, tenant string) int64
	ListForTenant(limit int, tech, tenant string) []store.ScanSummary
	GetForTenant(id int64, tenant string) *store.ScanRecord
	DeleteForTenant(id int64, tenant string) bool
	ClearAllForTenant(tenant string) int
	HistoryStatsForTenant(tenant string) map[string]any
	TopTechsForTenant(limit int, tenant string) []map[string]any
	VerifiedForTenant(limit int, tenant string) []map[string]any

	// ---- C-09 复核/白名单（JSON 与 SQL 后端统一能力） ----
	TriageMark(scanID int64, fingerprint, verdict, note string) error
	TriageList(scanID int64) []store.TriageEntry
	TriageSummary(scanID int64) (fp, confirmed, ignored int)
	WhitelistAdd(host, ruleID, reason string) error
	WhitelistRemove(host, ruleID string) (bool, error)
	WhitelistList() []store.WhitelistEntry
	IsWhitelisted(host, ruleID string) bool
}

// saveErrReporter 可选能力：存储后端能报告最近一次 Save 的失败原因（C-03）。
//
// scanStore.Save 的签名（返回 int64）无法表达错误，因此保存失败时只能返回 0；
// server 收尾据此把 job 从 done 纠正为 error。只有 SQL 后端实现该能力，
// JSON 后端 Save 失败会走自身错误路径（不返回 0），无需此接口。
type saveErrReporter interface{ LastSaveError() string }

// 编译期断言：JSON 分层视图直接满足。
var _ scanStore = (*store.Tiered)(nil)

// sqlScanStore 把 store.SQLStore 适配为 scanStore。
//
// SQL 后端不支持的能力（历史导入 / 图谱 / 来源聚合）明确降级：写日志后返回
// 空值，接口语义不 panic；JSON 后端仍是默认，能力完整。
//
// C-03：保存失败不再"只返回 0 + 一行日志"。失败时：
//  1. 计数 + 记录最后一次错误（HistoryStats → /api/stats.history 可观测）；
//  2. 把整条记录追加到回退 spool（<data_dir>/sql_unsaved.jsonl，NDJSON），
//     避免 SQL 抖动期间扫描结果彻底丢失，供人工/后续工具回灌。
//
// 注意：job 状态由 server.go 的扫描收尾逻辑决定（不在本文件写域内），
// 因此这里无法把 job 从 done 改成 error；可观测性经 /api/stats 暴露，
// 调用方（Lead）如需 job 级错误语义需再改 server.go:761-770。
type sqlScanStore struct {
	db           *store.SQLStore
	warned       atomic.Bool // 降级日志只打一次（避免每请求刷屏）
	fallbackPath string      // 保存失败的回退 spool（空 = 不写）
	saveErrors   atomic.Int64
	lastSaveErr  atomic.Pointer[string]
}

// 编译期断言：SQL 适配器满足统一接口。
var _ scanStore = (*sqlScanStore)(nil)

func newSQLScanStore(db *store.SQLStore) *sqlScanStore { return &sqlScanStore{db: db} }

// newSQLScanStoreWithFallback 带保存失败回退 spool 的适配器。
func newSQLScanStoreWithFallback(db *store.SQLStore, fallbackPath string) *sqlScanStore {
	return &sqlScanStore{db: db, fallbackPath: fallbackPath}
}

// warnOnce 降级能力只提示一次。
func (a *sqlScanStore) warnOnce(format string, args ...any) {
	if a.warned.Swap(true) {
		return
	}
	log.Printf(format, args...)
}

// sqlFallbackRecord 保存失败时写入回退 spool 的一条记录（NDJSON）。
type sqlFallbackRecord struct {
	SavedAt string         `json:"saved_at"`
	Reason  string         `json:"reason"`
	URL     string         `json:"url"`
	Host    string         `json:"host"`
	Result  *engine.Result `json:"result"`
	Options map[string]any `json:"options,omitempty"`
}

// Save 保存扫描结果（legacy 空租户；token 模式请用 SaveForTenant）。
//
// C-03：SQL 写失败时不再只是 log + 0——记录计数/最后错误，并把结果落到
// 回退 spool；返回值仍为 0（接口签名限制），降级状态由 HistoryStats 暴露。
func (a *sqlScanStore) Save(res *engine.Result, options map[string]any) int64 {
	return a.SaveForTenant(res, options, "")
}

// SaveForTenant 保存扫描结果并写入归属租户（BL-5）。
func (a *sqlScanStore) SaveForTenant(res *engine.Result, options map[string]any, tenant string) int64 {
	id, err := a.db.SaveScanForTenant(res, options, tenant)
	if err != nil {
		a.saveErrors.Add(1)
		msg := err.Error()
		a.lastSaveErr.Store(&msg)
		spoolErr := a.spoolFailed(res, options, err)
		if spoolErr != nil {
			log.Printf("错误：SQL 存储保存扫描结果失败，且回退 spool 写入失败（记录丢失）：%v；spool=%v", err, spoolErr)
		} else {
			log.Printf("错误：SQL 存储保存扫描结果失败（已写回退 spool %s）：%v", a.fallbackPath, err)
		}
		return 0
	}
	// 成功后清空"最后一次错误"，避免上一次失败影响后续 job 的收尾判定。
	a.lastSaveErr.Store(nil)
	return id
}

// LastSaveError 返回最近一次 Save 的失败原因（空 = 最近一次成功/尚未保存）。
//
// C-03：server 在 Save 返回 0 时用它把 job 置为 error 并给出可读原因，
// 避免"结果其实没落库，任务却显示完成"的静默失败。
func (a *sqlScanStore) LastSaveError() string {
	if p := a.lastSaveErr.Load(); p != nil {
		return *p
	}
	return ""
}

// spoolFailed 把没能写进 SQL 的记录追加到回退 spool（原子追加，0600）。
func (a *sqlScanStore) spoolFailed(res *engine.Result, options map[string]any, cause error) error {
	if a.fallbackPath == "" || res == nil {
		return errors.New("回退 spool 未配置")
	}
	rec := sqlFallbackRecord{
		SavedAt: time.Now().UTC().Format(time.RFC3339), Reason: cause.Error(),
		URL: res.URL, Host: res.Host, Result: res, Options: options,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.fallbackPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(a.fallbackPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// 历史遗留的宽权限文件同样收紧（与 history.json 的口径一致）。
	_ = f.Chmod(0o600)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// stats 保存失败诊断（供 HistoryStats 合并）。
func (a *sqlScanStore) saveHealth() (degraded bool, errors int64, last string, spool string, spoolBytes int64) {
	errors = a.saveErrors.Load()
	if p := a.lastSaveErr.Load(); p != nil {
		last = *p
	}
	spool = a.fallbackPath
	if spool != "" {
		if fi, err := os.Stat(spool); err == nil {
			spoolBytes = fi.Size()
		}
	}
	return errors > 0, errors, last, spool, spoolBytes
}

// Import SQL 后端不支持历史导入（JSON→SQL 请用 store.MigrateFromJSON）。
func (a *sqlScanStore) Import(rec store.ScanRecord) (int64, error) {
	return 0, errors.New("SQL 存储后端不支持历史导入（请使用 store.MigrateFromJSON 一次性迁移）")
}

// List 历史列表（legacy 空租户；token 模式请用 ListForTenant）。
func (a *sqlScanStore) List(limit int, tech string) []store.ScanSummary {
	return a.ListForTenant(limit, tech, "")
}

// ListForTenant 历史列表 + 租户过滤（BL-5）。
func (a *sqlScanStore) ListForTenant(limit int, tech, tenant string) []store.ScanSummary {
	sums, err := a.db.ListScansPageForTenant(0, limit, tech, tenant)
	if err != nil {
		log.Printf("警告：SQL 存储查询历史失败：%v", err)
		return nil
	}
	return sums
}

// Get 按 id 取记录（legacy 空租户；token 模式请用 GetForTenant）。
func (a *sqlScanStore) Get(id int64) *store.ScanRecord {
	return a.GetForTenant(id, "")
}

// GetForTenant 按 id 取记录并校验租户归属（BL-5，不匹配返回 nil → 404）。
func (a *sqlScanStore) GetForTenant(id int64, tenant string) *store.ScanRecord {
	rec, err := a.db.GetScanForTenant(id, tenant)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("警告：SQL 存储读取记录失败：%v", err)
		}
		return nil
	}
	return rec
}

// Delete 删除记录（legacy 空租户；token 模式请用 DeleteForTenant）。
func (a *sqlScanStore) Delete(id int64) bool {
	return a.DeleteForTenant(id, "")
}

// DeleteForTenant 删除记录并校验租户归属（BL-5）。
func (a *sqlScanStore) DeleteForTenant(id int64, tenant string) bool {
	ok, err := a.db.DeleteScanForTenant(id, tenant)
	if err != nil {
		log.Printf("警告：SQL 存储删除记录失败：%v", err)
		return false
	}
	return ok
}

// ClearAll 清空全部历史（SQL 后端直接 DELETE，返回删除前条数）。
func (a *sqlScanStore) ClearAll() int {
	return a.ClearAllForTenant("")
}

// ClearAllForTenant 清空指定租户历史（tenant 空 = 全局，同 ClearAll）。
func (a *sqlScanStore) ClearAllForTenant(tenant string) int {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		n, _ := a.db.CountScans()
		if _, err := a.db.DB().Exec("DELETE FROM " + store.ScansTable); err != nil {
			log.Printf("警告：SQL 存储清空历史失败：%v", err)
			return 0
		}
		return int(n)
	}
	n, err := a.db.DeleteScansForTenant(tenant)
	if err != nil {
		log.Printf("警告：SQL 存储清空租户历史失败（tenant=%s）：%v", tenant, err)
		return 0
	}
	return int(n)
}

// HistoryStats 历史统计：条数 / 站点数 / 平均技术数全部走 SQL 聚合（C-08）。
//
// 改造前这里是 `ListScans(10000, "")` 再在内存里累加——每次请求都可能拉
// 上万行并解码（PG 上可达数十 MB）。现在一条 COUNT/GROUP BY 聚合解决，
// 且旧行缺失的冗余汇总列由启动时的一次性 BackfillScanSummary 补齐。
//
// C-03：额外暴露后端类型与保存降级状态（backend/degraded/save_errors/
// last_save_error/fallback_spool...），经 /api/stats.history 可观测；
// 任何返回分支都带这些键，避免"出错时反而看不到降级"。
func (a *sqlScanStore) HistoryStats() map[string]any {
	degraded, saveErrs, lastErr, spool, spoolBytes := a.saveHealth()
	diag := func(m map[string]any) map[string]any {
		m["backend"] = a.db.Dialect().String()
		m["degraded"] = degraded
		m["save_errors"] = saveErrs
		if lastErr != "" {
			m["last_save_error"] = lastErr
		}
		if spool != "" {
			m["fallback_spool"] = spool
			m["fallback_spool_bytes"] = spoolBytes
		}
		return m
	}
	st, err := a.db.Stats()
	if err != nil {
		log.Printf("警告：SQL 存储统计聚合失败：%v", err)
		return diag(map[string]any{"scans": 0, "hosts": 0, "avg_techs": 0.0})
	}
	return diag(map[string]any{
		"scans":     st.Scans,
		"hosts":     st.Hosts,
		"avg_techs": math.Round(st.AvgTechs*10) / 10,
	})
}

// HistoryStatsForTenant 历史统计 + 租户过滤（BL-5；空租户 = 全局，同旧行为）。
func (a *sqlScanStore) HistoryStatsForTenant(tenant string) map[string]any {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return a.HistoryStats()
	}
	degraded, saveErrs, lastErr, spool, spoolBytes := a.saveHealth()
	diag := func(m map[string]any) map[string]any {
		m["backend"] = a.db.Dialect().String()
		m["degraded"] = degraded
		m["save_errors"] = saveErrs
		if lastErr != "" {
			m["last_save_error"] = lastErr
		}
		if spool != "" {
			m["fallback_spool"] = spool
			m["fallback_spool_bytes"] = spoolBytes
		}
		return m
	}
	st, err := a.db.StatsForTenant(tenant)
	if err != nil {
		log.Printf("警告：SQL 存储租户统计聚合失败：%v", err)
		return diag(map[string]any{"scans": 0, "hosts": 0, "avg_techs": 0.0})
	}
	return diag(map[string]any{
		"scans":     st.Scans,
		"hosts":     st.Hosts,
		"avg_techs": math.Round(st.AvgTechs*10) / 10,
	})
}

// ---- C-09 复核/白名单（SQL 后端持久化；JSON 后端由 store.Tiered 提供） ----

// TriageMark 写入/覆盖复核记录。
func (a *sqlScanStore) TriageMark(scanID int64, fingerprint, verdict, note string) error {
	return a.db.TriageMark(scanID, fingerprint, verdict, note)
}

// TriageList 某次扫描的复核记录。
func (a *sqlScanStore) TriageList(scanID int64) []store.TriageEntry {
	return a.db.TriageList(scanID)
}

// TriageSummary 复核结论汇总。
func (a *sqlScanStore) TriageSummary(scanID int64) (fp, confirmed, ignored int) {
	return a.db.TriageSummary(scanID)
}

// WhitelistAdd 新增/覆盖白名单。
func (a *sqlScanStore) WhitelistAdd(host, ruleID, reason string) error {
	return a.db.WhitelistAdd(host, ruleID, reason)
}

// WhitelistRemove 删除白名单（幂等）。
func (a *sqlScanStore) WhitelistRemove(host, ruleID string) (bool, error) {
	return a.db.WhitelistRemove(host, ruleID)
}

// WhitelistList 全部白名单。
func (a *sqlScanStore) WhitelistList() []store.WhitelistEntry {
	return a.db.WhitelistList()
}

// IsWhitelisted host+rule 是否命中白名单。
func (a *sqlScanStore) IsWhitelisted(host, ruleID string) bool {
	return a.db.IsWhitelisted(host, ruleID)
}

// TopTechs SQL 后端暂不提供（需全表聚合，后续用物化统计表实现）。
func (a *sqlScanStore) TopTechs(limit int) []map[string]any {
	a.warnOnce("提示：SQL 存储后端暂不支持 top_techs 聚合（/api/stats 返回空）")
	return nil
}

// TopTechsForTenant SQL 后端同样暂不提供（同上，返回空；空租户=全局）。
func (a *sqlScanStore) TopTechsForTenant(limit int, tenant string) []map[string]any {
	return a.TopTechs(limit)
}

// Verified SQL 后端暂不提供（需解析 result JSON 聚合）。
func (a *sqlScanStore) Verified(limit int) []map[string]any {
	a.warnOnce("提示：SQL 存储后端暂不支持 verified 聚合（/api/verified 返回空）")
	return nil
}

// VerifiedForTenant SQL 后端同样暂不提供（同上，返回空；空租户=全局）。
func (a *sqlScanStore) VerifiedForTenant(limit int, tenant string) []map[string]any {
	return a.Verified(limit)
}

// ---- 图谱能力（JSON 后端专属；SQL 后端降级为空） ----

func (a *sqlScanStore) Graph(id int64) (*model.ScanGraph, bool) { return nil, false }

func (a *sqlScanStore) GraphWithStatus(id int64) (*model.ScanGraph, string) {
	return nil, "unsupported"
}

func (a *sqlScanStore) GraphJSONL(id int64) ([]byte, bool) { return nil, false }

func (a *sqlScanStore) GraphManifestOf(id int64) (*store.GraphManifest, bool) {
	return nil, false
}

func (a *sqlScanStore) HasGraph(id int64) bool { return false }

func (a *sqlScanStore) GraphIDs() []int64 { return nil }

// ---- 后端装配 ----

// openScanStore 按 config.Store.Driver 装配历史存储；非 JSON 后端不可用时
// 回退 JSON 并打日志（启动不阻断）。JSON 存储自身打开失败才返回错误。
//
// C-03：回退时把原因写进 JSON 存储（SetFallbackReason），使 /api/stats
// 能区分"本来就是 JSON"与"配置要 SQL 但降级成 JSON"。
func (s *Server) openScanStore(cfg *config.Config) (scanStore, error) {
	jsonStore := func(reason string) (scanStore, error) {
		tv, err := store.NewTiered(cfg.Store.DataDir, cfg.Store.ArchiveKeep)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			tv.SetFallbackReason(reason)
		}
		return tv, nil
	}
	driver := strings.ToLower(strings.TrimSpace(cfg.Store.Driver))
	if driver == "" || driver == "json" {
		return jsonStore("")
	}
	dsn := strings.TrimSpace(cfg.Store.DSN)
	if dsn == "" {
		reason := fmt.Sprintf("store.driver=%s 但未配置 store.dsn", driver)
		log.Printf("警告：%s；回退 JSON 文件存储", reason)
		return jsonStore(reason)
	}
	// 保存失败的回退 spool 与 JSON 后端同目录（data_dir）：SQL 抖动期间
	// 扫描结果落 NDJSON，供人工/工具回灌，不再"只返回 0 就完事"。
	fallback := filepath.Join(cfg.Store.DataDir, "sql_unsaved.jsonl")
	st, err := openSQLScanStoreWithFallback(driver, dsn, fallback)
	if err != nil {
		// 明确报错并回退：driver 未注册（如未编译进 sqlite/postgres 驱动）也走这里
		reason := fmt.Sprintf("SQL 历史存储不可用（driver=%s）：%v", driver, err)
		log.Printf("警告：%s；回退 JSON 文件存储", reason)
		return jsonStore(reason)
	}
	log.Printf("历史存储：SQL 后端（driver=%s）", driver)
	return st, nil
}

// openSQLScanStore 打开 SQL 后端（无保存失败 spool）。
// 任一失败返回明确错误（调用方决定是否回退 JSON）。
func openSQLScanStore(driver, dsn string) (scanStore, error) {
	return openSQLScanStoreWithFallback(driver, dsn, "")
}

// openSQLScanStoreWithFallback 打开 SQL 后端：sql.Open → Ping →
// ApplyMigrations → NewSQLStore；fallbackPath 非空时 Save 失败会把记录
// 追加到该 NDJSON spool（C-03）。
func openSQLScanStoreWithFallback(driver, dsn, fallbackPath string) (scanStore, error) {
	var dialect store.Dialect
	sqlDriver := driver
	switch driver {
	case "sqlite", "sqlite3":
		dialect = store.DialectSQLite
		sqlDriver = "sqlite" // modernc.org/sqlite
	case "postgres", "postgresql":
		dialect = store.DialectPostgres
		sqlDriver = "pgx" // jackc/pgx/v5 stdlib
	default:
		return nil, fmt.Errorf("不支持的存储驱动 %q（可选 json/sqlite/postgres）", driver)
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open(%s)：%w", sqlDriver, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库连接失败：%w", err)
	}
	if err := store.ApplyMigrationsDialect(db, dialect); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库迁移失败：%w", err)
	}
	// C-08：升级前写入的旧行没有冗余汇总列（tech_count/vuln_count/…），
	// 列表页与 /api/stats 会把它们显示成 0。这里做一次幂等回填（只处理
	// result_json 非空且 tech_names 为空的行），失败不阻断启动——Get 单条
	// 仍会从 result 里补齐。
	if n, berr := store.BackfillScanSummary(db, dialect, 0); berr != nil {
		log.Printf("警告：SQL 历史汇总列回填失败（列表页旧记录计数可能为 0）：%v", berr)
	} else if n > 0 {
		log.Printf("SQL 历史汇总列回填：%d 条旧记录", n)
	}
	return newSQLScanStoreWithFallback(store.NewSQLStoreDialect(db, dialect), fallbackPath), nil
}
