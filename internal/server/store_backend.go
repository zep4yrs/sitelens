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
	"errors"
	"fmt"
	"log"
	"math"
	"strings"

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
}

// 编译期断言：JSON 分层视图直接满足。
var _ scanStore = (*store.Tiered)(nil)

// sqlScanStore 把 store.SQLStore 适配为 scanStore。
//
// SQL 后端不支持的能力（历史导入 / 图谱 / 来源聚合）明确降级：写日志后返回
// 空值，接口语义不 panic；JSON 后端仍是默认，能力完整。
type sqlScanStore struct {
	db     *store.SQLStore
	warned bool // 降级日志只打一次（避免每请求刷屏）
}

// 编译期断言：SQL 适配器满足统一接口。
var _ scanStore = (*sqlScanStore)(nil)

func newSQLScanStore(db *store.SQLStore) *sqlScanStore { return &sqlScanStore{db: db} }

// warnOnce 降级能力只提示一次。
func (a *sqlScanStore) warnOnce(format string, args ...any) {
	if a.warned {
		return
	}
	a.warned = true
	log.Printf(format, args...)
}

// Save 保存扫描结果（SQL 错误只记录并返回 0，不 panic 主链路）。
func (a *sqlScanStore) Save(res *engine.Result, options map[string]any) int64 {
	id, err := a.db.SaveScan(res, options)
	if err != nil {
		log.Printf("警告：SQL 存储保存扫描结果失败：%v", err)
		return 0
	}
	return id
}

// Import SQL 后端不支持历史导入（JSON→SQL 请用 store.MigrateFromJSON）。
func (a *sqlScanStore) Import(rec store.ScanRecord) (int64, error) {
	return 0, errors.New("SQL 存储后端不支持历史导入（请使用 store.MigrateFromJSON 一次性迁移）")
}

// List 历史列表。
func (a *sqlScanStore) List(limit int, tech string) []store.ScanSummary {
	sums, err := a.db.ListScans(limit, tech)
	if err != nil {
		log.Printf("警告：SQL 存储查询历史失败：%v", err)
		return nil
	}
	return sums
}

// Get 按 id 取记录。
func (a *sqlScanStore) Get(id int64) *store.ScanRecord {
	rec, err := a.db.GetScan(id)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("警告：SQL 存储读取记录失败：%v", err)
		}
		return nil
	}
	return rec
}

// Delete 删除记录。
func (a *sqlScanStore) Delete(id int64) bool {
	ok, err := a.db.DeleteScan(id)
	if err != nil {
		log.Printf("警告：SQL 存储删除记录失败：%v", err)
		return false
	}
	return ok
}

// ClearAll 清空全部历史（SQL 后端直接 DELETE，返回删除前条数）。
func (a *sqlScanStore) ClearAll() int {
	n, _ := a.db.CountScans()
	if _, err := a.db.DB().Exec("DELETE FROM " + store.ScansTable); err != nil {
		log.Printf("警告：SQL 存储清空历史失败：%v", err)
		return 0
	}
	return int(n)
}

// HistoryStats 历史统计：条数取 COUNT；hosts/avg_techs 由最近列表近似计算
// （SQL 后端无聚合索引，避免每请求全表扫描，最多取 10000 条）。
func (a *sqlScanStore) HistoryStats() map[string]any {
	n, _ := a.db.CountScans()
	sums, err := a.db.ListScans(10000, "")
	if err != nil {
		return map[string]any{"scans": n, "hosts": 0, "avg_techs": 0.0}
	}
	hosts := map[string]bool{}
	total := 0
	for _, s := range sums {
		hosts[s.Host] = true
		total += s.TechCount
	}
	avg := 0.0
	if len(sums) > 0 {
		avg = math.Round(float64(total)/float64(len(sums))*10) / 10
	}
	return map[string]any{"scans": n, "hosts": len(hosts), "avg_techs": avg}
}

// TopTechs SQL 后端暂不提供（需全表聚合，后续用物化统计表实现）。
func (a *sqlScanStore) TopTechs(limit int) []map[string]any {
	a.warnOnce("提示：SQL 存储后端暂不支持 top_techs 聚合（/api/stats 返回空）")
	return nil
}

// Verified SQL 后端暂不提供（需解析 result JSON 聚合）。
func (a *sqlScanStore) Verified(limit int) []map[string]any {
	a.warnOnce("提示：SQL 存储后端暂不支持 verified 聚合（/api/verified 返回空）")
	return nil
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
func (s *Server) openScanStore(cfg *config.Config) (scanStore, error) {
	jsonStore := func() (scanStore, error) {
		return store.NewTiered(cfg.Store.DataDir, cfg.Store.ArchiveKeep)
	}
	driver := strings.ToLower(strings.TrimSpace(cfg.Store.Driver))
	if driver == "" || driver == "json" {
		return jsonStore()
	}
	dsn := strings.TrimSpace(cfg.Store.DSN)
	if dsn == "" {
		log.Printf("警告：store.driver=%s 但未配置 store.dsn；回退 JSON 文件存储", driver)
		return jsonStore()
	}
	st, err := openSQLScanStore(driver, dsn)
	if err != nil {
		// 明确报错并回退：driver 未注册（如未编译进 sqlite/postgres 驱动）也走这里
		log.Printf("警告：SQL 历史存储不可用（driver=%s）：%v；回退 JSON 文件存储", driver, err)
		return jsonStore()
	}
	log.Printf("历史存储：SQL 后端（driver=%s）", driver)
	return st, nil
}

// openSQLScanStore 打开 SQL 后端：sql.Open → Ping → ApplyMigrations → NewSQLStore。
// 任一失败返回明确错误（调用方决定是否回退 JSON）。
func openSQLScanStore(driver, dsn string) (scanStore, error) {
	var dialect store.Dialect
	switch driver {
	case "sqlite", "sqlite3":
		dialect = store.DialectSQLite
	case "postgres", "postgresql":
		dialect = store.DialectPostgres
	default:
		return nil, fmt.Errorf("不支持的存储驱动 %q（可选 json/sqlite/postgres）", driver)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open(%s)：%w", driver, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库连接失败：%w", err)
	}
	if err := store.ApplyMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库迁移失败：%w", err)
	}
	return newSQLScanStore(store.NewSQLStoreDialect(db, dialect)), nil
}
