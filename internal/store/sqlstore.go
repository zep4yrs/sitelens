// sqlstore.go 企业版 6.x SQL 后端：DB 抽象 + SQLStore + 迁移工具（additive）。
//
// 设计边界：
//   - **不新增第三方依赖**：只用 database/sql 与标准库；driver 由调用方注入
//     （SQLite / MySQL / PostgreSQL 均可，方言见 Dialect）。
//   - **不改既有实现**：history.json 版 Store/Tiered 仍是默认路径；本文件只提供
//     新后端与一次性 JSON→SQL 迁移，切换与否由接线方决定（store.go/config/
//     server 均未改动）。
//   - 方法命名与语义对齐 store.Tiered 的公开方法：
//     Tiered.Save (int64)               → SQLStore.SaveScan  (int64, error)
//     Tiered.Get  (*ScanRecord)         → SQLStore.GetScan   (*ScanRecord, error)
//     Tiered.List (limit, tech)         → SQLStore.ListScans (limit, tech)
//     Tiered.Delete (bool)              → SQLStore.DeleteScan(bool, error)
//     另加 CountScans（分页 UI 需要总数；Tiered 无对应方法）。
//     error 是 SQL 后端的必要差异：JSON 版用日志兜底，SQL 版必须让上层感知失败。
//   - DB 接口只要求 database/sql 的四个方法（Exec/Query/QueryRow/Begin），
//     *sql.DB 直接满足；单元测试用自写 fake driver（database/sql/driver）验证
//     真实 SQL 往返（含事务回滚），不需要真实数据库。
//   - 事务内的写入用 *sql.Tx（Begin 返回），与 database/sql 原生语义一致。
//
// schema 见 migrations/001_init.sql（go:embed 打包，ApplyMigrations 幂等执行）。
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

// migrationsFS 打包 schema 迁移（只读，随二进制分发，不依赖外部 SQL 文件）。
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	// ScansTable scans 表名（迁移/查询共用，避免字面量散落）。
	ScansTable = "scans"
)

// DB 是 SQLStore 依赖的最小数据库能力集。
//
// *sql.DB 直接满足（Exec/Query/QueryRow/Begin 的签名与 database/sql 一致）；
// 调用方也可传入自己的包装（例如带重试/审计的实现）。注意 *sql.Tx 不满足
// （Tx 没有 Begin），事务内部由本文件自行用 Begin 返回的 *sql.Tx 操作。
type DB interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Begin() (*sql.Tx, error)
}

// Dialect 目标数据库方言：影响占位符与自增 id 的读回方式。
type Dialect int

const (
	// DialectSQLite ? 占位符 + LastInsertId（SQLite/MySQL 一致）。
	DialectSQLite Dialect = iota
	// DialectPostgres $N 占位符 + INSERT ... RETURNING id。
	DialectPostgres
)

// String 便于日志/诊断。
func (d Dialect) String() string {
	if d == DialectPostgres {
		return "postgres"
	}
	return "sqlite"
}

// placeholder 返回第 n 个（1-based）占位符。
func (d Dialect) placeholder(n int) string {
	if d == DialectPostgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// placeholders 返回 n 个逗号分隔占位符（拼 VALUES 用）。
func (d Dialect) placeholders(n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = d.placeholder(i + 1)
	}
	return strings.Join(parts, ",")
}

// SQLStore 关系库后端（并发安全由 database/sql 连接池保证；本结构体自身只读）。
type SQLStore struct {
	db      DB
	dialect Dialect
}

// NewSQLStore 用默认方言（SQLite 占位符 + LastInsertId）包装 db。
func NewSQLStore(db DB) *SQLStore {
	return &SQLStore{db: db, dialect: DialectSQLite}
}

// NewSQLStoreDialect 指定方言包装 db（PostgreSQL 用 DialectPostgres）。
func NewSQLStoreDialect(db DB, dialect Dialect) *SQLStore {
	return &SQLStore{db: db, dialect: dialect}
}

// DB 返回底层 DB（接线方复用连接/事务时用）。
func (s *SQLStore) DB() DB { return s.db }

// Dialect 返回当前方言。
func (s *SQLStore) Dialect() Dialect { return s.dialect }

// ready 校验可用性；所有公开方法先过这里，避免 nil 解引用。
func (s *SQLStore) ready() error {
	if s == nil || s.db == nil {
		return errors.New("SQLStore 未初始化（db 为空）")
	}
	return nil
}

// ---- 查询列（集中一处，fake driver/真实库共用同一 SQL 形态） ----

const (
	// scanSummaryCols 列表/摘要需要的列（C-08：不含 result_json/options_json；
	// 条数/时长/技术名由迁移 002 的冗余列提供，列表不再解码大 JSON）。
	// BL-5：tenant 列随摘要返回，供 server 侧租户归属校验（迁移 003）。
	scanSummaryCols = "id,url,host,title,status,grade,score,scanned_at," +
		"tech_count,vuln_count,duration_ms,tenant"
	// scanFullCols 单条完整记录（result_json 仅在 Get 单条时解码）。
	scanFullCols = scanSummaryCols + ",result_json,options_json"

	// MaxListLimit 列表单页上限（防止一次拉爆内存；接线方可传更小值）。
	MaxListLimit = 10000
	// defaultListLimit ListScans limit<=0 时的默认值（与 JSON 版列表惯例一致）。
	defaultListLimit = 100
)

// scanSummaryFields 由 engine.Result 派生列表冗余列（C-08）。
//
// techNames 用空格连接的**小写**技术名，供 SQL 子串过滤（语义对齐 JSON 版
// 「Technologies 名称包含」）；tech_count/vuln_count/duration_ms 避免列表解码。
func scanSummaryFields(res *engine.Result) (techCount, vulnCount, durationMs int64, techNames string) {
	if res == nil {
		return 0, 0, 0, ""
	}
	names := make([]string, 0, len(res.Technologies))
	for _, t := range res.Technologies {
		if n := strings.ToLower(strings.TrimSpace(t.Name)); n != "" {
			names = append(names, n)
		}
	}
	return int64(len(res.Technologies)), int64(len(res.Vulnerabilities)),
		int64(res.Duration * 1000), strings.Join(names, " ")
}

// SaveScan 保存一次扫描结果，返回新 id（语义对齐 Tiered.Save；legacy 空租户）。
func (s *SQLStore) SaveScan(res *engine.Result, options map[string]any) (int64, error) {
	return s.SaveScanForTenant(res, options, "")
}

// SaveScanForTenant 保存一次扫描结果并写入归属租户（BL-5/A-04）。
//
// tenant 为空保持既有行为（tenant 为空视为 legacy/单机）；非空时列表/Get/
// Delete 的租户过滤只返回本租户记录。
//
// result_json 保存完整 engine.Result；grade/score 冗余成列，列表页无需解 JSON
// 即可展示评分（与 JSON 版 ScanSummary 字段一致）。C-08 起同时写入
// tech_count/vuln_count/duration_ms/tech_names 冗余列，列表走纯 SQL 投影。
func (s *SQLStore) SaveScanForTenant(res *engine.Result, options map[string]any, tenant string) (int64, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	if res == nil {
		return 0, errors.New("SaveScan: res 为空")
	}
	resultJSON, err := json.Marshal(res)
	if err != nil {
		return 0, fmt.Errorf("SaveScan: 序列化 result 失败：%w", err)
	}
	optionsJSON, err := marshalNullable(options)
	if err != nil {
		return 0, fmt.Errorf("SaveScan: 序列化 options 失败：%w", err)
	}
	grade, score := "", 0
	if res.Security != nil {
		grade, score = res.Security.Grade, res.Security.Score
	}
	techCount, vulnCount, durationMs, techNames := scanSummaryFields(res)
	cols := "url,host,title,status,grade,score,scanned_at," +
		"tech_count,vuln_count,duration_ms,tech_names,tenant,result_json,options_json"
	args := []any{
		res.URL, res.Host, res.Title, res.Status, grade, score,
		res.ScannedAt, techCount, vulnCount, durationMs, techNames,
		strings.TrimSpace(tenant), string(resultJSON), optionsJSON,
	}
	if s.dialect == DialectPostgres {
		q := "INSERT INTO " + ScansTable + " (" + cols + ") VALUES (" +
			s.dialect.placeholders(len(args)) + ") RETURNING id"
		var id int64
		if err := s.db.QueryRow(q, args...).Scan(&id); err != nil {
			return 0, fmt.Errorf("SaveScan: 插入失败：%w", err)
		}
		return id, nil
	}
	r, err := s.db.Exec("INSERT INTO "+ScansTable+" ("+cols+") VALUES ("+
		s.dialect.placeholders(len(args))+")", args...)
	if err != nil {
		return 0, fmt.Errorf("SaveScan: 插入失败：%w", err)
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("SaveScan: 读取自增 id 失败：%w", err)
	}
	return id, nil
}

// GetScan 按 id 取完整记录；不存在返回 (nil, nil)（对齐 Tiered.Get）。
func (s *SQLStore) GetScan(id int64) (*ScanRecord, error) {
	return s.GetScanForTenant(id, "")
}

// GetScanForTenant 按 id 取记录并校验租户归属（不匹配返回 (nil,nil)，
// 与「不存在」同形，server 统一映射 404，不泄露存在性）。
func (s *SQLStore) GetScanForTenant(id int64, tenant string) (*ScanRecord, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	q := "SELECT " + scanFullCols + " FROM " + ScansTable + " WHERE id = " + s.dialect.placeholder(1)
	args := []any{id}
	if tenant = strings.TrimSpace(tenant); tenant != "" {
		q += " AND tenant = " + s.dialect.placeholder(2)
		args = append(args, tenant)
	}
	rec, err := scanFullRow(s.db.QueryRow(q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetScan(%d): %w", id, err)
	}
	return rec, nil
}

// ListScans 历史列表（新→旧），tech 非空时按技术名子串过滤（语义对齐 Tiered.List）。
//
// C-08：纯 SQL 投影，**不解码 result_json**；tech 过滤走迁移 002 的
// `tech_names` 冗余列（SQL LIKE，转义通配符）并带 LIMIT，不再全表拉进 Go。
// 保留原签名供既有接线使用；分页请用 ListScansPage。
func (s *SQLStore) ListScans(limit int, tech string) ([]ScanSummary, error) {
	return s.ListScansPage(0, limit, tech)
}

// ListScansPage 分页列表：offset 起始偏移（>=0），limit 单页条数（<=0 用默认，
// 上限 MaxListLimit）；tech 非空时按技术名子串过滤（legacy 空租户路径）。
func (s *SQLStore) ListScansPage(offset, limit int, tech string) ([]ScanSummary, error) {
	return s.ListScansPageForTenant(offset, limit, tech, "")
}

// ListScansPageForTenant 分页列表 + 租户过滤（BL-5）。
//
// tenant 为空 = 不过滤（保持既有调用方语义）；非空 = WHERE tenant = ?，
// legacy（tenant 为空）记录不会返回给具体租户。
func (s *SQLStore) ListScansPageForTenant(offset, limit int, tech, tenant string) ([]ScanSummary, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	tech = strings.ToLower(strings.TrimSpace(tech))
	tenant = strings.TrimSpace(tenant)
	q := "SELECT " + scanSummaryCols + " FROM " + ScansTable
	var args []any
	var where []string
	if tech != "" {
		where = append(where, "tech_names LIKE "+s.dialect.placeholder(len(args)+1)+" ESCAPE '\\'")
		args = append(args, "%"+escapeLike(tech)+"%")
	}
	if tenant != "" {
		where = append(where, "tenant = "+s.dialect.placeholder(len(args)+1))
		args = append(args, tenant)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT " + s.dialect.placeholder(len(args)+1) +
		" OFFSET " + s.dialect.placeholder(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("ListScans: 查询失败：%w", err)
	}
	defer rows.Close()

	capHint := limit
	if capHint > 64 {
		capHint = 64
	}
	out := make([]ScanSummary, 0, capHint)
	for rows.Next() {
		sm, err := scanSummaryRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListScans: 读取行失败：%w", err)
		}
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListScans: 遍历失败：%w", err)
	}
	return out, nil
}

// escapeLike 转义 LIKE 通配符（tech 是用户输入，参数化 + 转义缺一不可）。
func escapeLike(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SQLStoreStats SQL 后端的轻量聚合结果（C-08：COUNT/GROUP BY，不拉列表）。
type SQLStoreStats struct {
	Scans     int64   `json:"scans"`
	Hosts     int64   `json:"hosts"`
	TechTotal int64   `json:"tech_total"`
	AvgTechs  float64 `json:"avg_techs"`
}

// Stats 轻量聚合：条数 / 站点数 / 技术总数 / 平均技术数。
//
// 对应 server 侧 HistoryStats 的 hosts/avg_techs：原实现拉 10000 条列表再
// 在 Go 里聚合（每请求解码大量 result_json），改为一条聚合 SQL。
func (s *SQLStore) Stats() (SQLStoreStats, error) {
	return s.StatsForTenant("")
}

// StatsForTenant 轻量聚合 + 租户过滤（tenant 为空 = 全局，保持既有语义）。
func (s *SQLStore) StatsForTenant(tenant string) (SQLStoreStats, error) {
	if err := s.ready(); err != nil {
		return SQLStoreStats{}, err
	}
	q := "SELECT COUNT(*), COUNT(DISTINCT host), " +
		"COALESCE(SUM(tech_count),0), COALESCE(AVG(tech_count),0) FROM " + ScansTable
	var args []any
	if tenant = strings.TrimSpace(tenant); tenant != "" {
		q += " WHERE tenant = " + s.dialect.placeholder(1)
		args = append(args, tenant)
	}
	var st SQLStoreStats
	if err := s.db.QueryRow(q, args...).Scan(&st.Scans, &st.Hosts, &st.TechTotal, &st.AvgTechs); err != nil {
		return SQLStoreStats{}, fmt.Errorf("Stats: %w", err)
	}
	return st, nil
}

// BackfillScanSummary 回填列表冗余列（C-08，一次性/按批）。
//
// 只处理「result_json 非 NULL 且 tech_names 仍为空」的旧行（升级前由旧版本
// 写入的记录）：解码 result_json 后 UPDATE 冗余列。可重复执行（幂等，已回填
// 的行不再被选中）；batch<=0 用 1000。返回本次回填条数。
//
// 接线建议：启动 ApplyMigrations 后调用一次；未调用时 List 对旧行展示
// tech_count/vuln_count/duration=0（Get 单条仍从 result_json 回填，不受影响）。
func BackfillScanSummary(db *sql.DB, dialect Dialect, batch int) (int, error) {
	if db == nil {
		return 0, errors.New("BackfillScanSummary: db 为空")
	}
	if batch <= 0 {
		batch = 1000
	}
	total := 0
	for {
		q := "SELECT id, result_json FROM " + ScansTable +
			" WHERE result_json IS NOT NULL AND tech_names = ''" +
			" ORDER BY id LIMIT " + dialect.placeholder(1)
		rows, err := db.Query(q, batch)
		if err != nil {
			return total, fmt.Errorf("BackfillScanSummary: 查询失败：%w", err)
		}
		type job struct {
			id  int64
			raw sql.NullString
		}
		var jobs []job
		for rows.Next() {
			var j job
			if err := rows.Scan(&j.id, &j.raw); err != nil {
				rows.Close()
				return total, fmt.Errorf("BackfillScanSummary: 读行失败：%w", err)
			}
			jobs = append(jobs, j)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("BackfillScanSummary: 遍历失败：%w", err)
		}
		rows.Close()
		if len(jobs) == 0 {
			return total, nil
		}
		upd := "UPDATE " + ScansTable +
			" SET tech_count = " + dialect.placeholder(1) +
			", vuln_count = " + dialect.placeholder(2) +
			", duration_ms = " + dialect.placeholder(3) +
			", tech_names = " + dialect.placeholder(4) +
			" WHERE id = " + dialect.placeholder(5)
		for _, j := range jobs {
			res, derr := decodeResultJSON(j.raw)
			if derr != nil {
				return total, fmt.Errorf("BackfillScanSummary: id=%d result_json 损坏：%w", j.id, derr)
			}
			tc, vc, dm, names := scanSummaryFields(res)
			if _, uerr := db.Exec(upd, tc, vc, dm, names, j.id); uerr != nil {
				return total, fmt.Errorf("BackfillScanSummary: id=%d 更新失败：%w", j.id, uerr)
			}
			total++
		}
		if len(jobs) < batch {
			return total, nil
		}
	}
}

// CountScans 记录总数（分页 UI / 统计用；Tiered 无对应方法）。
func (s *SQLStore) CountScans() (int64, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	var n int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM " + ScansTable).Scan(&n); err != nil {
		return 0, fmt.Errorf("CountScans: %w", err)
	}
	return n, nil
}

// DeleteScan 删除一条记录；返回是否真的删到了（语义对齐 Tiered.Delete）。
func (s *SQLStore) DeleteScan(id int64) (bool, error) {
	return s.DeleteScanForTenant(id, "")
}

// DeleteScanForTenant 删除记录 + 租户归属校验（BL-5）。
//
// tenant 非空时只删除归属本租户的记录；不匹配返回 (false,nil)（与不存在
// 同形，server 统一 404）。删除成功同时清理该扫描的复核记录（C-09 一致性）。
func (s *SQLStore) DeleteScanForTenant(id int64, tenant string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	q := "DELETE FROM " + ScansTable + " WHERE id = " + s.dialect.placeholder(1)
	args := []any{id}
	if tenant = strings.TrimSpace(tenant); tenant != "" {
		q += " AND tenant = " + s.dialect.placeholder(2)
		args = append(args, tenant)
	}
	r, err := s.db.Exec(q, args...)
	if err != nil {
		return false, fmt.Errorf("DeleteScan(%d): %w", id, err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("DeleteScan(%d): 读取影响行数失败：%w", id, err)
	}
	if n > 0 {
		if _, terr := s.db.Exec("DELETE FROM "+TriageTable+" WHERE scan_id = "+s.dialect.placeholder(1), id); terr != nil {
			// 复核记录清理失败不影响删除结果（孤儿复核记录不会被列表读取），
			// 但记录日志便于排查。
			log.Printf("警告：删除扫描 %d 后清理复核记录失败：%v", id, terr)
		}
	}
	return n > 0, nil
}

// DeleteScansForTenant 删除某租户全部扫描记录，返回删除条数（BL-5 清空）。
func (s *SQLStore) DeleteScansForTenant(tenant string) (int64, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return 0, errors.New("DeleteScansForTenant: tenant 不能为空")
	}
	q := "DELETE FROM " + ScansTable + " WHERE tenant = " + s.dialect.placeholder(1)
	r, err := s.db.Exec(q, tenant)
	if err != nil {
		return 0, fmt.Errorf("DeleteScansForTenant(%q): %w", tenant, err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("DeleteScansForTenant(%q): 读取影响行数失败：%w", tenant, err)
	}
	return n, nil
}

// ---- 行扫描 ----

// rowScanner *sql.Row 与 *sql.Rows 的公共扫描入口。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanFullRow 读完整记录（result_json/options_json 仅在单条 Get 时解码）。
func scanFullRow(sc rowScanner) (*ScanRecord, error) {
	var (
		rec                     ScanRecord
		durationMs              int64
		resultJSON, optionsJSON sql.NullString
	)
	if err := sc.Scan(
		&rec.ID, &rec.URL, &rec.Host, &rec.Title, &rec.Status,
		&rec.SecurityGrade, &rec.SecurityScore, &rec.ScannedAt,
		&rec.TechCount, &rec.VulnCount, &durationMs, &rec.Tenant,
		&resultJSON, &optionsJSON,
	); err != nil {
		return nil, err
	}
	rec.Duration = float64(durationMs) / 1000.0
	res, err := decodeResultJSON(resultJSON)
	if err != nil {
		return nil, err
	}
	rec.Result = res
	// 旧行（迁移 002 之前写入、尚未 Backfill）冗余列为 0：Get 单条时用
	// result_json 的计数补齐（列表页不享受该回填，需跑 BackfillScanSummary）。
	if res != nil {
		if rec.TechCount == 0 && len(res.Technologies) > 0 {
			rec.TechCount = len(res.Technologies)
		}
		if rec.VulnCount == 0 && len(res.Vulnerabilities) > 0 {
			rec.VulnCount = len(res.Vulnerabilities)
		}
		if rec.Duration == 0 && res.Duration != 0 {
			rec.Duration = res.Duration
		}
		if rec.SecurityGrade == "" && res.Security != nil {
			rec.SecurityGrade = res.Security.Grade
			rec.SecurityScore = res.Security.Score
		}
	}
	if optionsJSON.Valid && strings.TrimSpace(optionsJSON.String) != "" && optionsJSON.String != "null" {
		if err := json.Unmarshal([]byte(optionsJSON.String), &rec.Options); err != nil {
			return nil, fmt.Errorf("options_json 解码失败：%w", err)
		}
	}
	return &rec, nil
}

// scanSummaryRow 读列表行（C-08：纯列投影，无 result_json 解码）。
func scanSummaryRow(sc rowScanner) (ScanSummary, error) {
	var (
		sm         ScanSummary
		durationMs int64
	)
	if err := sc.Scan(
		&sm.ID, &sm.URL, &sm.Host, &sm.Title, &sm.Status,
		&sm.SecurityGrade, &sm.SecurityScore, &sm.ScannedAt,
		&sm.TechCount, &sm.VulnCount, &durationMs, &sm.Tenant,
	); err != nil {
		return ScanSummary{}, err
	}
	sm.Duration = float64(durationMs) / 1000.0
	return sm, nil
}

// decodeResultJSON 解码 result_json：NULL/空/"null" 均视为「无结果」（对齐
// JSON 版 result:null 的记录，Get/List 不 panic，历史降级可继续展示摘要）。
func decodeResultJSON(ns sql.NullString) (*engine.Result, error) {
	if !ns.Valid {
		return nil, nil
	}
	raw := strings.TrimSpace(ns.String)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, fmt.Errorf("result_json 解码失败：%w", err)
	}
	return &res, nil
}

// marshalNullable map 为 nil 时返回 nil（数据库写 NULL），否则 JSON 字节。
func marshalNullable(m map[string]any) (any, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// ---- schema 迁移（apply） ----

// MigrationFile 一个已解析的迁移文件。
type MigrationFile struct {
	Version    int      // 文件名前缀（001 → 1）
	Name       string   // 文件名（含扩展名）
	Statements []string // 按行解析出的可执行语句（已去注释/分号）
}

// MigrationFiles 解析内嵌 migrations/ 目录（按版本号升序）。
//
// 解析规则（简单解析，够 DDL 用）：逐行读；跳过空行与 `--` 注释行；语句以
// 行尾分号结束；去分号后按出现顺序收集。文件末尾残留未闭合语句视为错误
// （schema 不完整会让运行期报错，宁可启动期失败）。
func MigrationFiles() ([]MigrationFile, error) {
	return migrationFilesFromFS()
}

func migrationFilesFromFS() ([]MigrationFile, error) {
	names, err := fsGlob()
	if err != nil {
		return nil, err
	}
	out := make([]MigrationFile, 0, len(names))
	for _, name := range names {
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("读取迁移 %s 失败：%w", name, err)
		}
		version, err := parseMigrationVersion(name)
		if err != nil {
			return nil, err
		}
		stmts, err := splitSQLStatements(string(data))
		if err != nil {
			return nil, fmt.Errorf("迁移 %s 解析失败：%w", name, err)
		}
		out = append(out, MigrationFile{Version: version, Name: name, Statements: stmts})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// fsGlob 列出 embed 中的 migration 文件名（升序）。
func fsGlob() ([]string, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("读取内嵌 migrations 目录失败：%w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return nil, errors.New("未找到任何 migrations/*.sql（go:embed 未打包？）")
	}
	sort.Strings(names)
	return names, nil
}

// parseMigrationVersion 从文件名前缀解析版本号（001_init.sql → 1）。
func parseMigrationVersion(name string) (int, error) {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("迁移文件名缺少版本前缀：%s（应形如 001_init.sql）", name)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("迁移文件名版本前缀非法：%s", name)
	}
	return v, nil
}

// splitSQLStatements 拆分迁移 SQL 语句（C-12）。
//
// 旧实现按行判断"行首 -- 注释 + 行尾分号"，一旦语句里出现字符串字面量
// （如 DEFAULT ';'、CHECK (x = '--')）或行内注释，就会切错语句且难以定位。
// 现改为最小状态机：识别单引号/双引号字符串（单引号内部以双写单引号转义）、
// -- 行注释、/* */ 块注释，仅在"代码态"遇到 ; 才断句；未闭合引号/块注释直接
// 报错。仍不支持 PostgreSQL 的 $$ dollar-quoting——当前迁移不需要，出现时请扩展。
func splitSQLStatements(src string) ([]string, error) {
	rs := []rune(strings.ReplaceAll(src, "\r\n", "\n"))
	var (
		stmts []string
		cur   strings.Builder
	)
	flush := func() {
		s := strings.TrimSpace(cur.String())
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
		if s != "" {
			stmts = append(stmts, s)
		}
		cur.Reset()
	}
	var (
		inSingle, inDouble bool
		inLine, inBlock    bool
	)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				cur.WriteRune('\n') // 保留换行，语句可读性不变
			}
		case inBlock:
			if c == '*' && i+1 < len(rs) && rs[i+1] == '/' {
				inBlock = false
				i++
			}
		case inSingle:
			cur.WriteRune(c)
			if c == '\'' {
				if i+1 < len(rs) && rs[i+1] == '\'' { // 双写单引号 = 转义
					cur.WriteRune('\'')
					i++
				} else {
					inSingle = false
				}
			}
		case inDouble:
			cur.WriteRune(c)
			if c == '"' {
				inDouble = false
			}
		default:
			switch {
			case c == '-' && i+1 < len(rs) && rs[i+1] == '-':
				inLine = true
				i++
			case c == '/' && i+1 < len(rs) && rs[i+1] == '*':
				inBlock = true
				i++
			case c == '\'':
				inSingle = true
				cur.WriteRune(c)
			case c == '"':
				inDouble = true
				cur.WriteRune(c)
			case c == ';':
				flush()
			default:
				cur.WriteRune(c)
			}
		}
	}
	if inSingle || inDouble || inBlock {
		return nil, fmt.Errorf("迁移 SQL 存在未闭合的字符串或块注释")
	}
	if strings.TrimSpace(cur.String()) != "" {
		return nil, fmt.Errorf("末尾语句未以分号结尾：%q", strings.TrimSpace(cur.String()))
	}
	return stmts, nil
}

// ApplyMigrations 幂等应用全部内嵌迁移（DDL 均 IF NOT EXISTS，可重复执行）。
//
// 接线点：企业版启动时在 sql.Open 之后、NewSQLStore 之前调用一次；
// 失败必须中止启动（schema 不完整时继续跑会在运行期报错，且可能写坏数据）。
// ApplyMigrations 应用内嵌迁移（SQLite 方言，保持既有行为）。
func ApplyMigrations(db DB) error {
	return ApplyMigrationsDialect(db, DialectSQLite)
}

// postgresAutoIncRE SQLite 的自增主键在 PostgreSQL 的等价替换。
// 迁移文件按 SQLite 语法书写，仅此一处方言差异（TEXT/INTEGER/IF NOT EXISTS 通用）。
var postgresAutoIncRE = regexp.MustCompile(`(?i)\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b`)

// migrationStatementForDialect 把一条 SQLite 迁移语句转成目标方言；
// SQLite 原样返回，PostgreSQL 只替换自增主键写法。
func migrationStatementForDialect(stmt string, dialect Dialect) string {
	if dialect != DialectPostgres {
		return stmt
	}
	return postgresAutoIncRE.ReplaceAllString(stmt, "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY")
}

// ApplyMigrationsDialect 按方言应用内嵌迁移（幂等 DDL）。
//
// 接线点：企业版启动时在 sql.Open 之后、NewSQLStore 之前调用一次；
// 失败必须中止启动（schema 不完整时继续跑会在运行期报错，且可能写坏数据）。
func ApplyMigrationsDialect(db DB, dialect Dialect) error {
	if db == nil {
		return errors.New("ApplyMigrations: db 为空")
	}
	files, err := migrationFilesFromFS()
	if err != nil {
		return err
	}
	for _, f := range files {
		for i, stmt := range f.Statements {
			if _, err := db.Exec(migrationStatementForDialect(stmt, dialect)); err != nil {
				// 002 起有 ALTER TABLE ADD COLUMN（SQLite/PG 均无 IF NOT EXISTS）：
				// 已存在的列视为"该迁移已应用"，跳过以保证重复启动幂等。
				// 只对 ALTER TABLE 容忍，其它错误照常中止。
				if isDuplicateColumnStmt(stmt, err) {
					continue
				}
				return fmt.Errorf("应用迁移 %s 第 %d 条语句失败：%w", f.Name, i+1, err)
			}
		}
	}
	return nil
}

// isDuplicateColumnStmt 判断 ALTER TABLE ADD COLUMN 是否因列已存在而失败
// （SQLite: "duplicate column name"；PostgreSQL: SQLSTATE 42701 / 文本
// "column \"x\" of relation \"scans\" already exists"）。
func isDuplicateColumnStmt(stmt string, err error) bool {
	if err == nil {
		return false
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "ALTER TABLE") {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "42701")
}

// ---- JSON → SQL 一次性迁移 ----

// MigrateFromJSON 把 srcDir/history.json 批量导入 SQL（SQLite 方言）。
//
// 语义：
//   - 保留原记录 id（深链 /history?id=N、图表 scan_id 不断链）；
//   - 单事务：任一条失败整体回滚（返回已成功条数 0），不留半套数据；
//   - 幂等：INSERT ... ON CONFLICT(id) DO NOTHING，重复执行不重复插入，
//     第二次调用返回新增 0 条（已存在记录不会被覆盖——迁移不静默改历史）；
//   - history.json 不存在返回 (0, nil)（旧安装未产生历史是正常态）；
//   - 文件损坏返回错误（不跳过，避免"迁移完成但少了数据"的静默事故）。
//
// 调用前需先 ApplyMigrations 建表。返回值为实际新增条数。
func MigrateFromJSON(srcDir string, db *sql.DB) (int, error) {
	return MigrateFromJSONDialect(srcDir, db, DialectSQLite)
}

// MigrateFromJSONDialect 指定方言版本的 JSON→SQL 迁移（PostgreSQL 接线用）。
func MigrateFromJSONDialect(srcDir string, db *sql.DB, dialect Dialect) (int, error) {
	if db == nil {
		return 0, errors.New("MigrateFromJSON: db 为空")
	}
	if strings.TrimSpace(srcDir) == "" {
		return 0, errors.New("MigrateFromJSON: srcDir 为空")
	}
	path := filepath.Join(srcDir, "history.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("MigrateFromJSON: 读取 %s 失败：%w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return 0, nil // 空文件视作空库
	}
	var h history
	if err := json.Unmarshal(data, &h); err != nil {
		return 0, fmt.Errorf("MigrateFromJSON: %s 损坏：%w", path, err)
	}
	if len(h.Scans) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("MigrateFromJSON: 开启事务失败：%w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// C-08：迁移同样写入列表冗余列（tech_count/vuln_count/duration_ms/
	// tech_names），迁移后列表无需解码 result_json。
	// BL-5：tenant 一并迁移（旧 JSON 记录缺省 "" = legacy）。
	cols := "id,url,host,title,status,grade,score,scanned_at," +
		"tech_count,vuln_count,duration_ms,tech_names,tenant,result_json,options_json"
	q := "INSERT INTO " + ScansTable + " (" + cols + ") VALUES (" +
		dialect.placeholders(15) + ") ON CONFLICT(id) DO NOTHING"

	inserted := 0
	for _, rec := range h.Scans {
		if rec.ID <= 0 {
			continue // 与 Import 同语义：非法 id 跳过（不阻断整批迁移）
		}
		args, err := scanInsertArgs(rec)
		if err != nil {
			return 0, fmt.Errorf("MigrateFromJSON: 记录 %d 序列化失败：%w", rec.ID, err)
		}
		r, err := tx.Exec(q, args...)
		if err != nil {
			return 0, fmt.Errorf("MigrateFromJSON: 插入记录 %d 失败（已回滚）：%w", rec.ID, err)
		}
		if n, err := r.RowsAffected(); err == nil && n > 0 {
			inserted++
		}
	}
	// C-02：PostgreSQL 的 GENERATED BY DEFAULT AS IDENTITY 允许显式写 id，
	// 但**不会**把序列抬到已插入的最大值（与 SQLite AUTOINCREMENT 不同——
	// SQLite 在显式插入更大 rowid 时会更新 sqlite_sequence）。不补这一步，
	// 迁移后序列仍从 1 开始，第一次 SaveScan 就 duplicate key 撞主键。
	// 在事务内 setval：要么一起提交、要么一起回滚。
	if dialect == DialectPostgres {
		if err := resetPostgresIdentitySeq(tx); err != nil {
			return 0, fmt.Errorf("MigrateFromJSON: 重置 PostgreSQL 自增序列失败（已回滚）：%w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("MigrateFromJSON: 提交事务失败：%w", err)
	}
	committed = true
	return inserted, nil
}

// postgresIdentitySeqResetSQL 把 scans.id 的 identity 序列推进到 MAX(id)+1。
//
// 3 参 setval(seq, v, false)：下次 nextval 返回 v（is_called=false），即
// MAX(id)+1；空表时 v=1。pg_get_serial_sequence 对 IDENTITY 列同样适用。
// 全部是常量 SQL（无用户输入拼接）。
const postgresIdentitySeqResetSQL = `SELECT setval(pg_get_serial_sequence('scans','id'), ` +
	`COALESCE((SELECT MAX(id) FROM ` + ScansTable + `), 0) + 1, false)`

// rowQuerier *sql.Tx / *sql.DB 的 QueryRow 子集（便于单测替换）。
type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// resetPostgresIdentitySeq 在迁移事务内推进 scans.id 的序列（C-02）。
func resetPostgresIdentitySeq(q rowQuerier) error {
	var next int64
	if err := q.QueryRow(postgresIdentitySeqResetSQL).Scan(&next); err != nil {
		return err
	}
	return nil
}

// scanInsertArgs 把 ScanRecord 转成 scans 表的 14 个列值
// （id + 8 摘要列 + 4 冗余汇总列 + result_json + options_json）。
func scanInsertArgs(rec ScanRecord) ([]any, error) {
	var resultJSON any // nil → SQL NULL（无结果记录保持 result:null 语义）
	if rec.Result != nil {
		b, err := json.Marshal(rec.Result)
		if err != nil {
			return nil, err
		}
		resultJSON = string(b)
	}
	optionsJSON, err := marshalNullable(rec.Options)
	if err != nil {
		return nil, err
	}
	techCount, vulnCount, durationMs, techNames := scanSummaryFields(rec.Result)
	return []any{
		rec.ID, rec.URL, rec.Host, rec.Title, rec.Status,
		rec.SecurityGrade, rec.SecurityScore, rec.ScannedAt,
		techCount, vulnCount, durationMs, techNames, strings.TrimSpace(rec.Tenant),
		resultJSON, optionsJSON,
	}, nil
}
