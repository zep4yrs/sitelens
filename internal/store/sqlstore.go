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
	// scanSummaryCols 列表/摘要需要的列（不含 options_json，减少大字段传输）。
	scanSummaryCols = "id,url,host,title,status,grade,score,scanned_at,result_json"
	// scanFullCols 单条完整记录（含 options_json）。
	scanFullCols = scanSummaryCols + ",options_json"
)

// SaveScan 保存一次扫描结果，返回新 id（语义对齐 Tiered.Save）。
//
// result_json 保存完整 engine.Result；grade/score 冗余成列，列表页无需解 JSON
// 即可展示评分（与 JSON 版 ScanSummary 字段一致）。
func (s *SQLStore) SaveScan(res *engine.Result, options map[string]any) (int64, error) {
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
	cols := "url,host,title,status,grade,score,scanned_at,result_json,options_json"
	args := []any{
		res.URL, res.Host, res.Title, res.Status, grade, score,
		res.ScannedAt, string(resultJSON), optionsJSON,
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
	if err := s.ready(); err != nil {
		return nil, err
	}
	q := "SELECT " + scanFullCols + " FROM " + ScansTable + " WHERE id = " + s.dialect.placeholder(1)
	rec, err := scanFullRow(s.db.QueryRow(q, id))
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
// tech 过滤在 Go 侧做：技术名保存在 result_json 里，SQL 直接 LIKE 会误命中
// 证据/URL 文本（JSON 版语义是「Technologies 名称包含」）。代价是带 tech 过滤
// 时多读 result_json；列表页默认 limit 100 内可接受，大历史场景建议接线方
// 加 tech 冗余列（另开迁移 002）。
func (s *SQLStore) ListScans(limit int, tech string) ([]ScanSummary, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	tech = strings.ToLower(strings.TrimSpace(tech))
	var (
		rows *sql.Rows
		err  error
	)
	if tech == "" {
		q := "SELECT " + scanSummaryCols + " FROM " + ScansTable +
			" ORDER BY id DESC LIMIT " + s.dialect.placeholder(1)
		rows, err = s.db.Query(q, limit)
	} else {
		// 过滤在 Go 侧，SQL 不设 LIMIT：避免「先截断再过滤」丢结果。
		q := "SELECT " + scanSummaryCols + " FROM " + ScansTable + " ORDER BY id DESC"
		rows, err = s.db.Query(q)
	}
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
		sm, res, err := scanSummaryRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListScans: 读取行失败：%w", err)
		}
		if tech != "" {
			rec := ScanRecord{Result: res}
			if !scanHasTech(&rec, tech) {
				continue
			}
		}
		out = append(out, sm)
		if len(out) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListScans: 遍历失败：%w", err)
	}
	return out, nil
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
	if err := s.ready(); err != nil {
		return false, err
	}
	q := "DELETE FROM " + ScansTable + " WHERE id = " + s.dialect.placeholder(1)
	r, err := s.db.Exec(q, id)
	if err != nil {
		return false, fmt.Errorf("DeleteScan(%d): %w", id, err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("DeleteScan(%d): 读取影响行数失败：%w", id, err)
	}
	return n > 0, nil
}

// ---- 行扫描 ----

// rowScanner *sql.Row 与 *sql.Rows 的公共扫描入口。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanFullRow 读完整记录（含 options_json → Options）。
func scanFullRow(sc rowScanner) (*ScanRecord, error) {
	var (
		rec                     ScanRecord
		resultJSON, optionsJSON sql.NullString
	)
	if err := sc.Scan(
		&rec.ID, &rec.URL, &rec.Host, &rec.Title, &rec.Status,
		&rec.SecurityGrade, &rec.SecurityScore, &rec.ScannedAt,
		&resultJSON, &optionsJSON,
	); err != nil {
		return nil, err
	}
	res, err := decodeResultJSON(resultJSON)
	if err != nil {
		return nil, err
	}
	rec.Result = res
	if optionsJSON.Valid && strings.TrimSpace(optionsJSON.String) != "" && optionsJSON.String != "null" {
		if err := json.Unmarshal([]byte(optionsJSON.String), &rec.Options); err != nil {
			return nil, fmt.Errorf("options_json 解码失败：%w", err)
		}
	}
	return &rec, nil
}

// scanSummaryRow 读列表行（result_json 只用于计数/时长/tech 过滤）。
func scanSummaryRow(sc rowScanner) (ScanSummary, *engine.Result, error) {
	var (
		sm         ScanSummary
		resultJSON sql.NullString
	)
	if err := sc.Scan(
		&sm.ID, &sm.URL, &sm.Host, &sm.Title, &sm.Status,
		&sm.SecurityGrade, &sm.SecurityScore, &sm.ScannedAt, &resultJSON,
	); err != nil {
		return ScanSummary{}, nil, err
	}
	res, err := decodeResultJSON(resultJSON)
	if err != nil {
		return ScanSummary{}, nil, err
	}
	if res != nil {
		sm.TechCount = len(res.Technologies)
		sm.VulnCount = len(res.Vulnerabilities)
		sm.Duration = res.Duration // duration 没有独立列：从 result_json 取（与 JSON 版一致）
		if sm.SecurityGrade == "" && res.Security != nil {
			sm.SecurityGrade = res.Security.Grade
			sm.SecurityScore = res.Security.Score
		}
	}
	return sm, res, nil
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

// splitSQLStatements 简单的 SQL 语句拆分：跳过 `--` 注释行与空行，按行尾
// 分号断句。不处理字符串字面量里的分号（schema 不用字符串字面量，够用且
// 可自检；未来出现数据回填语句时请升级为真正的 tokenizer）。
func splitSQLStatements(src string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var (
		stmts []string
		cur   []string
	)
	flush := func() {
		s := strings.TrimSpace(strings.Join(cur, "\n"))
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
		if s != "" {
			stmts = append(stmts, s)
		}
		cur = cur[:0]
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		cur = append(cur, line)
		if strings.HasSuffix(trimmed, ";") {
			flush()
		}
	}
	if strings.TrimSpace(strings.Join(cur, "\n")) != "" {
		return nil, fmt.Errorf("末尾语句未以分号结尾：%q", strings.TrimSpace(strings.Join(cur, "\n")))
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
				return fmt.Errorf("应用迁移 %s 第 %d 条语句失败：%w", f.Name, i+1, err)
			}
		}
	}
	return nil
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

	cols := "id,url,host,title,status,grade,score,scanned_at,result_json,options_json"
	q := "INSERT INTO " + ScansTable + " (" + cols + ") VALUES (" +
		dialect.placeholders(10) + ") ON CONFLICT(id) DO NOTHING"

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
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("MigrateFromJSON: 提交事务失败：%w", err)
	}
	committed = true
	return inserted, nil
}

// scanInsertArgs 把 ScanRecord 转成 scans 表的 10 个列值（id + 9 列）。
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
	return []any{
		rec.ID, rec.URL, rec.Host, rec.Title, rec.Status,
		rec.SecurityGrade, rec.SecurityScore, rec.ScannedAt,
		resultJSON, optionsJSON,
	}, nil
}
