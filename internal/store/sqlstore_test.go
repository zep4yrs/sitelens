// sqlstore_test.go 企业版 6.x SQL 后端单测。
//
// 不依赖真实数据库/第三方 driver：这里实现一个最小 database/sql driver
// （driver.Conn/Stmt/Tx/Rows），用内存表承载 sqlstore.go 发出的真实 SQL，
// 从而验证 CRUD / 分页 / tech 过滤 / 方言分支 / JSON 迁移幂等 / 事务回滚。
//
// fake driver 的能力边界（诚实声明）：
//   - 只实现本包实际发出的 SQL 形态（INSERT/SELECT/COUNT/DELETE + DDL 空操作）；
//   - 事务 = 写入暂存 + Commit 应用 / Rollback 丢弃（单连接单事务模型，
//     不支持并发事务与真实 MVCC；测试均为顺序执行）；
//   - 不校验 DDL 语义（schema 自检靠 MigrationFiles 解析 + 必需片段断言）。
package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

/* ============================ fake driver ============================ */

var fakeDriverSeq atomic.Int64

// fakeScan 内存表 scans 的一行（列对齐 migrations/001_init.sql + 002 冗余列 + 003 tenant）。
type fakeScan struct {
	id                   int64
	url, host, title     string
	status, score        int
	grade, scannedAt     string
	techCount, vulnCount int
	durationMs           int64
	techNames            string
	tenant               string
	resultJSON           *string // nil = SQL NULL
	optionsJSON          *string
}

// finishRow 由 result_json 派生列表冗余列（C-08；与 SaveScan 的写入口径一致）。
func (row *fakeScan) finishRow() {
	if row.resultJSON == nil {
		return
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(*row.resultJSON), &res); err != nil {
		return
	}
	names := make([]string, 0, len(res.Technologies))
	for _, t := range res.Technologies {
		if n := strings.ToLower(strings.TrimSpace(t.Name)); n != "" {
			names = append(names, n)
		}
	}
	row.techCount = len(res.Technologies)
	row.vulnCount = len(res.Vulnerabilities)
	row.durationMs = int64(res.Duration * 1000)
	row.techNames = strings.Join(names, " ")
}

// fakeDB 一个 fake driver 实例的后端存储。
type fakeDB struct {
	mu         sync.Mutex
	scans      map[int64]*fakeScan
	nextID     int64
	lastID     int64 // 最近一次插入的 id（供 LastInsertId 读回）
	execCount  int   // 数据写语句计数（DDL 不计数）
	failOnExec int   // 第 N 条数据写语句失败（0 = 不注入失败）
	begins     int
	commits    int
	rollbacks  int
	inTx       bool
	pending    []*fakeScan
	seqResets  int // PG identity 序列重置（SELECT setval(...)）次数（C-02 断言用）
}

func newFakeDB() *fakeDB {
	return &fakeDB{scans: map[int64]*fakeScan{}, nextID: 1}
}

// fakeDriver 每次 openFake 注册唯一名字，避免 sql.Register 重复 panic。
type fakeDriver struct{ db *fakeDB }

func (d *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{db: d.db}, nil }

type fakeConn struct{ db *fakeDB }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeStmt{db: c.db, query: query}, nil
}
func (c *fakeConn) Close() error { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	c.db.begins++
	c.db.inTx = true
	c.db.pending = nil
	return &fakeTx{db: c.db}, nil
}

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	return c.db.execLocked(query, args)
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	return c.db.queryLocked(query, args)
}

type fakeStmt struct {
	db    *fakeDB
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	return s.db.execLocked(s.query, valuesToNamed(args))
}
func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	return s.db.queryLocked(s.query, valuesToNamed(args))
}

type fakeTx struct{ db *fakeDB }

func (t *fakeTx) Commit() error {
	t.db.mu.Lock()
	defer t.db.mu.Unlock()
	for _, p := range t.db.pending {
		if _, exists := t.db.scans[p.id]; exists {
			continue // 事务内已判过冲突；提交时以已提交行为准（ON CONFLICT 语义）
		}
		t.db.applyLocked(p)
	}
	t.db.pending = nil
	t.db.inTx = false
	t.db.commits++
	return nil
}

func (t *fakeTx) Rollback() error {
	t.db.mu.Lock()
	defer t.db.mu.Unlock()
	t.db.pending = nil
	t.db.inTx = false
	t.db.rollbacks++
	return nil
}

type fakeResult struct{ lastID, affected int64 }

func (r fakeResult) LastInsertId() (int64, error) { return r.lastID, nil }
func (r fakeResult) RowsAffected() (int64, error) { return r.affected, nil }

type fakeRows struct {
	cols []string
	data [][]driver.Value
	pos  int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.pos])
	r.pos++
	return nil
}

// openFake 注册一个独立 fake driver 并返回 *sql.DB + 后端（便于断言/注入失败）。
func openFake(t *testing.T, opts ...func(*fakeDB)) (*sql.DB, *fakeDB) {
	t.Helper()
	f := newFakeDB()
	for _, o := range opts {
		o(f)
	}
	name := fmt.Sprintf("sitelens-fake-%d", fakeDriverSeq.Add(1))
	sql.Register(name, &fakeDriver{db: f})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open(fake): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, f
}

// ---- fake 内部 SQL 解析/执行 ----

func normalizeSQL(q string) string {
	return strings.ToUpper(strings.Join(strings.Fields(q), " "))
}

func valuesToNamed(vals []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(vals))
	for i, v := range vals {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}

func argValue(vals []driver.NamedValue, i int) driver.Value {
	if i < 0 || i >= len(vals) {
		return nil
	}
	return vals[i].Value
}

func valueInt64(v driver.Value) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case nil:
		return 0
	default:
		return 0
	}
}

func valueString(v driver.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func valueNullableString(v driver.Value) *string {
	if v == nil {
		return nil
	}
	s := valueString(v)
	return &s
}

// parseColumns 取 INSERT INTO t (a,b,c) 的列名列表。
func parseColumns(q string) []string {
	start := strings.Index(q, "(")
	if start < 0 {
		return nil
	}
	end := strings.Index(q[start:], ")")
	if end < 0 {
		return nil
	}
	body := q[start+1 : start+end]
	return splitColumnList(body)
}

// parseSelectColumns 取 SELECT a,b,c FROM t 的列名列表。
func parseSelectColumns(q string) []string {
	up := strings.ToUpper(q)
	start := strings.Index(up, "SELECT ")
	if start < 0 {
		return nil
	}
	from := strings.Index(up, " FROM ")
	if from <= start {
		return nil
	}
	return splitColumnList(q[start+len("SELECT ") : from])
}

func splitColumnList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// applyScanLocked 由列名/参数构造一行并写入（含冲突判定）。
// 返回插入条数（ON CONFLICT 命中时为 0）。
func (b *fakeDB) applyScanLocked(cols []string, args []driver.NamedValue) int64 {
	row := &fakeScan{}
	hasID := false
	for i, col := range cols {
		v := argValue(args, i)
		switch col {
		case "id":
			row.id = valueInt64(v)
			hasID = true
		case "url":
			row.url = valueString(v)
		case "host":
			row.host = valueString(v)
		case "title":
			row.title = valueString(v)
		case "status":
			row.status = int(valueInt64(v))
		case "score":
			row.score = int(valueInt64(v))
		case "grade":
			row.grade = valueString(v)
		case "scanned_at":
			row.scannedAt = valueString(v)
		case "tech_count":
			row.techCount = int(valueInt64(v))
		case "vuln_count":
			row.vulnCount = int(valueInt64(v))
		case "duration_ms":
			row.durationMs = valueInt64(v)
		case "tech_names":
			row.techNames = valueString(v)
		case "tenant":
			row.tenant = valueString(v)
		case "result_json":
			row.resultJSON = valueNullableString(v)
		case "options_json":
			row.optionsJSON = valueNullableString(v)
		}
	}
	row.finishRow() // 由 result_json 派生冗余列（与生产写入口径一致）
	if !hasID || row.id == 0 {
		row.id = b.allocIDLocked()
	}
	// 冲突：已提交行或当前事务 pending 行
	if _, exists := b.scans[row.id]; exists {
		return 0
	}
	for _, p := range b.pending {
		if p.id == row.id {
			return 0
		}
	}
	b.lastID = row.id
	if b.inTx {
		b.pending = append(b.pending, row)
	} else {
		b.applyLocked(row)
	}
	return 1
}

func (b *fakeDB) allocIDLocked() int64 {
	id := b.nextID
	b.nextID++
	return id
}

func (b *fakeDB) applyLocked(row *fakeScan) {
	b.scans[row.id] = row
	if row.id >= b.nextID {
		b.nextID = row.id + 1
	}
}

// execLocked 执行写语句（DDL 空操作）。
func (b *fakeDB) execLocked(query string, args []driver.NamedValue) (driver.Result, error) {
	q := normalizeSQL(query)
	switch {
	case strings.HasPrefix(q, "CREATE"), strings.HasPrefix(q, "PRAGMA"),
		strings.HasPrefix(q, "BEGIN"), strings.HasPrefix(q, "ALTER"):
		return fakeResult{}, nil
	case strings.HasPrefix(q, "INSERT INTO SCANS"):
		b.execCount++
		if b.failOnExec > 0 && b.execCount == b.failOnExec {
			return nil, errors.New("fake: 注入的写入失败")
		}
		cols := parseColumns(query)
		n := b.applyScanLocked(cols, args)
		return fakeResult{lastID: b.lastID, affected: n}, nil
	case strings.HasPrefix(q, "DELETE FROM SCANS"):
		b.execCount++
		if b.failOnExec > 0 && b.execCount == b.failOnExec {
			return nil, errors.New("fake: 注入的写入失败")
		}
		// BL-5：WHERE id=? [AND tenant=?] —— 末位参数可能是 tenant。
		id := valueInt64(argValue(args, 0))
		tenant := ""
		hasTenant := strings.Contains(q, "AND TENANT =") || strings.Contains(q, "WHERE TENANT =")
		if hasTenant && len(args) > 1 {
			tenant = valueString(argValue(args, 1))
		}
		row, ok := b.scans[id]
		if ok && hasTenant && row.tenant != tenant {
			return fakeResult{}, nil // 跨租户：不删
		}
		if ok {
			delete(b.scans, id)
			return fakeResult{affected: 1}, nil
		}
		return fakeResult{}, nil
	case strings.HasPrefix(q, "DELETE FROM SCAN_TRIAGE"):
		// C-09：删除扫描后清理复核记录（fake 无复核表，空操作）。
		return fakeResult{}, nil
	default:
		return nil, fmt.Errorf("fake driver 不支持的写语句：%s", query)
	}
}

// queryLocked 执行读语句（含 PostgreSQL RETURNING id 的插入）。
func (b *fakeDB) queryLocked(query string, args []driver.NamedValue) (driver.Rows, error) {
	q := normalizeSQL(query)
	switch {
	case strings.HasPrefix(q, "SELECT SETVAL("):
		// C-02：PostgreSQL 迁移后推进 identity 序列（fake 只记录次数）。
		b.seqResets++
		return &fakeRows{cols: []string{"setval"}, data: [][]driver.Value{{int64(1)}}}, nil
	case strings.HasPrefix(q, "SELECT COUNT(*) FROM SCANS"):
		return &fakeRows{cols: []string{"count"}, data: [][]driver.Value{{int64(len(b.scans))}}}, nil
	case strings.HasPrefix(q, "SELECT COUNT(*),") && strings.Contains(q, "AVG(TECH_COUNT)"):
		// C-08：轻量聚合（COUNT / COUNT(DISTINCT host) / SUM / AVG）。
		// BL-5：可带 WHERE tenant = ?。
		tenantFilter := ""
		if strings.Contains(q, "AND TENANT =") || strings.Contains(q, "WHERE TENANT =") && len(args) > 0 {
			tenantFilter = valueString(args[0].Value)
		}
		hosts := map[string]bool{}
		var sum int64
		n := 0
		for _, r := range b.scans {
			if tenantFilter != "" && r.tenant != tenantFilter {
				continue
			}
			hosts[r.host] = true
			sum += int64(r.techCount)
			n++
		}
		avg := 0.0
		if n > 0 {
			avg = float64(sum) / float64(n)
		}
		return &fakeRows{cols: []string{"count", "hosts", "sum", "avg"},
			data: [][]driver.Value{{int64(n), int64(len(hosts)), sum, avg}}}, nil
	case strings.HasPrefix(q, "INSERT INTO SCANS") && strings.Contains(q, "RETURNING"):
		b.execCount++
		if b.failOnExec > 0 && b.execCount == b.failOnExec {
			return nil, errors.New("fake: 注入的写入失败")
		}
		cols := parseColumns(query)
		row := &fakeScan{}
		for i, col := range cols {
			v := argValue(args, i)
			switch col {
			case "url":
				row.url = valueString(v)
			case "host":
				row.host = valueString(v)
			case "title":
				row.title = valueString(v)
			case "status":
				row.status = int(valueInt64(v))
			case "score":
				row.score = int(valueInt64(v))
			case "grade":
				row.grade = valueString(v)
			case "scanned_at":
				row.scannedAt = valueString(v)
			case "tech_count":
				row.techCount = int(valueInt64(v))
			case "vuln_count":
				row.vulnCount = int(valueInt64(v))
			case "duration_ms":
				row.durationMs = valueInt64(v)
			case "tech_names":
				row.techNames = valueString(v)
			case "tenant":
				row.tenant = valueString(v)
			case "result_json":
				row.resultJSON = valueNullableString(v)
			case "options_json":
				row.optionsJSON = valueNullableString(v)
			}
		}
		row.finishRow()
		if row.id == 0 {
			row.id = b.allocIDLocked()
		}
		b.applyLocked(row)
		return &fakeRows{cols: []string{"id"}, data: [][]driver.Value{{row.id}}}, nil
	case strings.HasPrefix(q, "SELECT") && strings.Contains(q, "FROM SCANS WHERE ID"):
		cols := parseSelectColumns(query)
		id := valueInt64(argValue(args, 0))
		if row, ok := b.scans[id]; ok {
			// BL-5：GetScanForTenant 附带 AND tenant=?（不匹配按不存在返回空行集）。
			if strings.Contains(q, "AND TENANT =") || strings.Contains(q, "WHERE TENANT =") && len(args) > 1 && row.tenant != valueString(argValue(args, 1)) {
				return &fakeRows{cols: cols}, nil
			}
			return &fakeRows{cols: cols, data: [][]driver.Value{projectRow(row, cols)}}, nil
		}
		return &fakeRows{cols: cols}, nil
	case strings.HasPrefix(q, "SELECT") && strings.Contains(q, "FROM SCANS"):
		cols := parseSelectColumns(query)
		ids := make([]int64, 0, len(b.scans))
		for id := range b.scans {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] }) // ORDER BY id DESC
		// tech 过滤（tech_names LIKE ? ESCAPE '\'）
		needle := ""
		hasLike := strings.Contains(q, "LIKE")
		if hasLike && len(args) > 0 {
			needle = strings.ToLower(strings.Trim(valueString(args[0].Value), "%"))
		}
		// BL-5：租户过滤（WHERE tenant = ?），占位符在 LIMIT/OFFSET 之前。
		tenantFilter := ""
		hasTenant := strings.Contains(q, "AND TENANT =") || strings.Contains(q, "WHERE TENANT =")
		if hasTenant && len(args) >= 3 {
			tenantFilter = valueString(args[len(args)-3].Value)
		}
		// LIMIT/OFFSET 占位符位于参数尾部。
		limit, offset := -1, 0
		if strings.Contains(q, "LIMIT") && len(args) > 0 {
			if strings.Contains(q, "OFFSET") && len(args) >= 2 {
				limit = int(valueInt64(args[len(args)-2].Value))
				offset = int(valueInt64(args[len(args)-1].Value))
			} else {
				limit = int(valueInt64(args[len(args)-1].Value))
			}
		}
		data := make([][]driver.Value, 0, len(ids))
		skipped := 0
		for _, id := range ids {
			row := b.scans[id]
			if hasTenant && row.tenant != tenantFilter {
				continue
			}
			if hasLike && !strings.Contains(strings.ToLower(row.techNames), needle) {
				continue
			}
			if skipped < offset {
				skipped++
				continue
			}
			if limit >= 0 && len(data) >= limit {
				break
			}
			data = append(data, projectRow(row, cols))
		}
		return &fakeRows{cols: cols, data: data}, nil
	default:
		return nil, fmt.Errorf("fake driver 不支持的读语句：%s", query)
	}
}

// projectRow 按列名投影一行（NULL 列返回 nil）。
func projectRow(row *fakeScan, cols []string) []driver.Value {
	out := make([]driver.Value, len(cols))
	for i, col := range cols {
		switch col {
		case "id":
			out[i] = row.id
		case "url":
			out[i] = row.url
		case "host":
			out[i] = row.host
		case "title":
			out[i] = row.title
		case "status":
			out[i] = int64(row.status)
		case "score":
			out[i] = int64(row.score)
		case "grade":
			out[i] = row.grade
		case "scanned_at":
			out[i] = row.scannedAt
		case "tech_count":
			out[i] = int64(row.techCount)
		case "vuln_count":
			out[i] = int64(row.vulnCount)
		case "duration_ms":
			out[i] = row.durationMs
		case "tech_names":
			out[i] = row.techNames
		case "tenant":
			out[i] = row.tenant
		case "result_json":
			if row.resultJSON == nil {
				out[i] = nil
			} else {
				out[i] = *row.resultJSON
			}
		case "options_json":
			if row.optionsJSON == nil {
				out[i] = nil
			} else {
				out[i] = *row.optionsJSON
			}
		default:
			out[i] = nil
		}
	}
	return out
}

/* ============================ 测试辅助 ============================ */

// sqlTestResult 构造典型 engine.Result（覆盖摘要字段 + JSON 往返字段）。
func sqlTestResult(host string, techs ...string) *engine.Result {
	res := &engine.Result{
		URL: "https://" + host, Host: host, Title: "标题 " + host,
		Status: 200, ScannedAt: "2026-11-01 09:00:00", Duration: 1.5,
		Technologies: make([]engine.Tech, 0, len(techs)),
		Extras:       map[string]any{"note": "roundtrip"},
	}
	for _, name := range techs {
		res.Technologies = append(res.Technologies, engine.Tech{Name: name})
	}
	return res
}

/* ============================ 测试 ============================ */

// TestMigrationFilesSelfCheck 迁移文件可被解析，且包含 6.x 要求的三张表与索引。
func TestMigrationFilesSelfCheck(t *testing.T) {
	files, err := MigrationFiles()
	if err != nil {
		t.Fatalf("MigrationFiles: %v", err)
	}
	if len(files) == 0 || files[0].Name != "001_init.sql" || files[0].Version != 1 {
		t.Fatalf("首个迁移应为 001_init.sql(v1)，实得 %+v", files)
	}
	var all []string
	for _, f := range files {
		if len(f.Statements) == 0 {
			t.Fatalf("%s 未解析出语句", f.Name)
		}
		for _, st := range f.Statements {
			if strings.Contains(st, ";") {
				t.Fatalf("%s 语句残留分号：%q", f.Name, st)
			}
			all = append(all, st)
		}
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS scans",
		"CREATE TABLE IF NOT EXISTS triage",
		"CREATE TABLE IF NOT EXISTS whitelist",
		"idx_scans_host", "idx_scans_scanned_at",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("迁移缺少 %q", want)
		}
	}
	for _, col := range []string{
		"id ", "url", "host", "title", "status", "grade", "score",
		"scanned_at", "result_json", "options_json",
	} {
		if !strings.Contains(joined, col) {
			t.Errorf("scans 表缺少列 %q", col)
		}
	}
	// 注释剥离：迁移文件里 `--` 注释（含 001 文末的"未来版本示例"）不得被解析成语句。
	// 注意 002 起有真实的 ALTER TABLE（C-08 冗余列），因此不再断言"joined 无 ALTER"，
	// 改为断言：① 注释文本未泄露进语句；② 语句本身不含 "--" 注释残留；
	// ③ 002 的 ALTER 确实被解析出来（防止拆分器把 ALTER 吞掉）。
	for _, st := range all {
		if strings.Contains(st, "--") {
			t.Errorf("语句残留注释：%q", st)
		}
	}
	if strings.Contains(joined, "002 计划") || strings.Contains(joined, "未来版本（示例") {
		t.Errorf("注释被解析成语句：%s", joined)
	}
	for _, want := range []string{
		"ALTER TABLE scans ADD COLUMN tech_count",
		"ALTER TABLE scans ADD COLUMN vuln_count",
		"ALTER TABLE scans ADD COLUMN duration_ms",
		"ALTER TABLE scans ADD COLUMN tech_names",
		// BL-5：迁移 003 的租户列 + 索引；C-09：迁移 004 的复核/白名单表
		"ALTER TABLE scans ADD COLUMN tenant",
		"idx_scans_tenant",
		"CREATE TABLE IF NOT EXISTS scan_triage",
		"CREATE TABLE IF NOT EXISTS whitelist",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("迁移缺少 %q", want)
		}
	}
	if len(files) < 4 || files[3].Name != "004_triage_whitelist.sql" || files[3].Version != 4 {
		t.Fatalf("迁移文件应按版本升序包含 004，实得 %+v", files)
	}

	db, _ := openFake(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if err := ApplyMigrations(db); err != nil { // 幂等 DDL：可重复执行
		t.Fatalf("重复 ApplyMigrations 应成功：%v", err)
	}
}

// TestSQLStoreCRUD 保存/读取/计数/删除往返，含 NULL result 与 options。
func TestSQLStoreCRUD(t *testing.T) {
	db, _ := openFake(t)
	st := NewSQLStore(db)

	if rec, err := st.GetScan(1); err != nil || rec != nil {
		t.Fatalf("空库 GetScan 应 (nil,nil)，实得 %+v err=%v", rec, err)
	}
	id1, err := st.SaveScan(sqlTestResult("a.com", "Nginx"), map[string]any{"deep": true})
	if err != nil || id1 != 1 {
		t.Fatalf("SaveScan#1 = %d err=%v want 1", id1, err)
	}
	id2, err := st.SaveScan(sqlTestResult("b.com", "Apache"), nil)
	if err != nil || id2 != 2 {
		t.Fatalf("SaveScan#2 = %d err=%v want 2", id2, err)
	}

	rec, err := st.GetScan(id1)
	if err != nil || rec == nil {
		t.Fatalf("GetScan(%d): %+v err=%v", id1, rec, err)
	}
	if rec.ID != 1 || rec.URL != "https://a.com" || rec.Host != "a.com" ||
		rec.Title != "标题 a.com" || rec.Status != 200 || rec.ScannedAt != "2026-11-01 09:00:00" {
		t.Fatalf("摘要列往返不符: %+v", rec.ScanSummary)
	}
	if rec.Result == nil || rec.Result.Host != "a.com" || len(rec.Result.Technologies) != 1 {
		t.Fatalf("result_json 往返不符: %+v", rec.Result)
	}
	if rec.Result.Duration != 1.5 || rec.Result.Extras["note"] != "roundtrip" {
		t.Fatalf("result_json 字段丢失: %+v", rec.Result)
	}
	if !rec.Options["deep"].(bool) {
		t.Fatalf("options_json 往返不符: %+v", rec.Options)
	}

	// 无 result / 无 options 的记录：GetScan 返回摘要，Result/Options 为 nil。
	rec2, err := st.GetScan(id2)
	if err != nil || rec2 == nil {
		t.Fatalf("GetScan(%d): %+v err=%v", id2, rec2, err)
	}
	if rec2.Options != nil || rec2.Result == nil {
		t.Fatalf("options 应为 nil、result 应存在：%+v", rec2)
	}

	if n, err := st.CountScans(); err != nil || n != 2 {
		t.Fatalf("CountScans = %d err=%v want 2", n, err)
	}
	if ok, err := st.DeleteScan(id2); err != nil || !ok {
		t.Fatalf("DeleteScan(%d) = %v err=%v want true", id2, ok, err)
	}
	if ok, err := st.DeleteScan(id2); err != nil || ok {
		t.Fatalf("重复 DeleteScan 应 (false,nil)，实得 %v err=%v", ok, err)
	}
	if n, err := st.CountScans(); err != nil || n != 1 {
		t.Fatalf("删除后 CountScans = %d err=%v want 1", n, err)
	}
	if _, err := st.SaveScan(nil, nil); err == nil {
		t.Fatal("SaveScan(nil) 应报错")
	}
	if rec, err := st.GetScan(999); err != nil || rec != nil {
		t.Fatalf("缺失 id 应 (nil,nil)，实得 %+v err=%v", rec, err)
	}
}

// TestSQLStoreListPagingAndTechFilter 列表新→旧、LIMIT 分页、tech 子串过滤。
func TestSQLStoreListPagingAndTechFilter(t *testing.T) {
	db, _ := openFake(t)
	st := NewSQLStore(db)
	specs := []struct {
		host  string
		techs []string
	}{
		{"h1.com", []string{"Nginx"}},
		{"h2.com", []string{"Apache"}},
		{"h3.com", []string{"Nginx", "PHP"}},
		{"h4.com", []string{"IIS"}},
		{"h5.com", []string{"Nginx"}},
	}
	for _, sp := range specs {
		if _, err := st.SaveScan(sqlTestResult(sp.host, sp.techs...), nil); err != nil {
			t.Fatalf("SaveScan(%s): %v", sp.host, err)
		}
	}

	list, err := st.ListScans(2, "")
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(list) != 2 || list[0].ID != 5 || list[1].ID != 4 {
		t.Fatalf("分页应新→旧取 5,4，实得 %+v", list)
	}
	if list[0].Host != "h5.com" || list[0].TechCount != 1 || list[0].Duration != 1.5 {
		t.Fatalf("摘要字段不符: %+v", list[0])
	}

	all, err := st.ListScans(0, "") // limit<=0 → 默认 100
	if err != nil || len(all) != 5 {
		t.Fatalf("默认 limit 应返回 5 条，实得 %d err=%v", len(all), err)
	}

	nginx, err := st.ListScans(10, "nginx")
	if err != nil {
		t.Fatalf("tech 过滤: %v", err)
	}
	ids := make([]int64, 0, len(nginx))
	for _, sm := range nginx {
		ids = append(ids, sm.ID)
	}
	if fmt.Sprint(ids) != "[5 3 1]" {
		t.Fatalf("tech=nginx 应命中 5,3,1，实得 %v", ids)
	}
	php, err := st.ListScans(10, "php")
	if err != nil || len(php) != 1 || php[0].ID != 3 {
		t.Fatalf("tech=php 应只命中 3，实得 %+v err=%v", php, err)
	}
	// 过滤后仍受 limit 约束。
	nginx2, err := st.ListScans(1, "nginx")
	if err != nil || len(nginx2) != 1 || nginx2[0].ID != 5 {
		t.Fatalf("带 tech 过滤的 limit 失效: %+v err=%v", nginx2, err)
	}
	if empty, err := st.ListScans(10, "cobol"); err != nil || len(empty) != 0 {
		t.Fatalf("未命中应返回空列表，实得 %d err=%v", len(empty), err)
	}
}

// TestSQLStoreDialect 占位符与 PostgreSQL RETURNING 分支。
func TestSQLStoreDialect(t *testing.T) {
	if got := DialectSQLite.placeholder(1); got != "?" {
		t.Fatalf("sqlite 占位符 = %q want ?", got)
	}
	if got := DialectSQLite.placeholders(3); got != "?,?,?" {
		t.Fatalf("sqlite 占位符列表 = %q", got)
	}
	if got := DialectPostgres.placeholder(2); got != "$2" {
		t.Fatalf("postgres 占位符 = %q want $2", got)
	}
	if got := DialectPostgres.placeholders(2); got != "$1,$2" {
		t.Fatalf("postgres 占位符列表 = %q", got)
	}
	if DialectSQLite.String() != "sqlite" || DialectPostgres.String() != "postgres" {
		t.Fatalf("方言名不符: %s/%s", DialectSQLite, DialectPostgres)
	}

	db, _ := openFake(t)
	pg := NewSQLStoreDialect(db, DialectPostgres)
	if pg.Dialect() != DialectPostgres || pg.DB() != db {
		t.Fatal("NewSQLStoreDialect 未保存方言/DB")
	}
	id, err := pg.SaveScan(sqlTestResult("pg.com"), nil)
	if err != nil || id != 1 {
		t.Fatalf("PostgreSQL 分支 SaveScan = %d err=%v", id, err)
	}
	if rec, err := pg.GetScan(id); err != nil || rec == nil || rec.Host != "pg.com" {
		t.Fatalf("PostgreSQL 分支 GetScan: %+v err=%v", rec, err)
	}
}

// TestSQLStoreUninitialized 零值/空 DB：所有入口返回明确错误而不是 panic。
func TestSQLStoreUninitialized(t *testing.T) {
	var zero SQLStore
	if _, err := zero.SaveScan(sqlTestResult("a.com"), nil); err == nil {
		t.Fatal("零值 SaveScan 应报错")
	}
	if _, err := zero.GetScan(1); err == nil {
		t.Fatal("零值 GetScan 应报错")
	}
	if _, err := zero.ListScans(10, ""); err == nil {
		t.Fatal("零值 ListScans 应报错")
	}
	if _, err := zero.CountScans(); err == nil {
		t.Fatal("零值 CountScans 应报错")
	}
	if _, err := zero.DeleteScan(1); err == nil {
		t.Fatal("零值 DeleteScan 应报错")
	}
	if err := ApplyMigrations(nil); err == nil {
		t.Fatal("ApplyMigrations(nil) 应报错")
	}
	if _, err := MigrateFromJSON("x", nil); err == nil {
		t.Fatal("MigrateFromJSON(nil db) 应报错")
	}
	if _, err := MigrateFromJSON("  ", nil); err == nil {
		t.Fatal("MigrateFromJSON 空 srcDir 应报错")
	}
}

// writeHistoryJSON 构造 srcDir/history.json 测试数据。
func writeHistoryJSON(t *testing.T, dir string, h history) {
	t.Helper()
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal history: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history.json"), data, 0o600); err != nil {
		t.Fatalf("write history.json: %v", err)
	}
}

// TestMigrateFromJSONRoundTripAndIdempotent 迁移保留 id/result/options，二次执行零新增。
func TestMigrateFromJSONRoundTripAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	h := history{NextID: 3, Scans: []ScanRecord{
		{
			ScanSummary: ScanSummary{
				ID: 1, URL: "https://a.com", Host: "a.com", Title: "A",
				Status: 200, SecurityGrade: "B", SecurityScore: 80,
				ScannedAt: "2026-10-01 10:00:00",
			},
			Options: map[string]any{"deep": true, "level": "standard"},
			Result:  sqlTestResult("a.com", "Nginx"),
		},
		{
			ScanSummary: ScanSummary{ID: 2, URL: "https://b.com", Host: "b.com", Title: "B"},
			// Result/Options 均为 nil：迁移后应为 NULL（与 JSON 版 result:null 一致）
		},
	}}
	writeHistoryJSON(t, dir, h)

	db, f := openFake(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	n, err := MigrateFromJSON(dir, db)
	if err != nil {
		t.Fatalf("MigrateFromJSON: %v", err)
	}
	if n != 2 {
		t.Fatalf("首次迁移应插入 2 条，实得 %d", n)
	}
	st := NewSQLStore(db)
	rec, err := st.GetScan(1)
	if err != nil || rec == nil {
		t.Fatalf("迁移后 GetScan(1): %+v err=%v", rec, err)
	}
	if rec.URL != "https://a.com" || rec.SecurityGrade != "B" || rec.SecurityScore != 80 {
		t.Fatalf("迁移摘要不符: %+v", rec.ScanSummary)
	}
	if rec.Result == nil || len(rec.Result.Technologies) != 1 {
		t.Fatalf("迁移 result 丢失: %+v", rec.Result)
	}
	if rec.Options["level"] != "standard" {
		t.Fatalf("迁移 options 丢失: %+v", rec.Options)
	}
	rec2, err := st.GetScan(2)
	if err != nil || rec2 == nil {
		t.Fatalf("迁移后 GetScan(2): %+v err=%v", rec2, err)
	}
	if rec2.Result != nil || rec2.Options != nil {
		t.Fatalf("result/options 应保持 NULL: %+v", rec2)
	}

	// 幂等：重复迁移不重复插入、不覆盖已有记录。
	before := f.scans[1].title
	n2, err := MigrateFromJSON(dir, db)
	if err != nil {
		t.Fatalf("二次迁移: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("二次迁移应新增 0 条，实得 %d", n2)
	}
	if got, _ := st.CountScans(); got != 2 {
		t.Fatalf("二次迁移后总数应仍为 2，实得 %d", got)
	}
	if f.scans[1].title != before {
		t.Fatal("幂等迁移不应改写已存在记录")
	}

	// 不存在的 history.json：0, nil（旧安装正常态）。
	emptyDir := t.TempDir()
	if n, err := MigrateFromJSON(emptyDir, db); err != nil || n != 0 {
		t.Fatalf("无 history.json 应 (0,nil)，实得 %d err=%v", n, err)
	}
	// 损坏的 history.json：返回错误，不静默跳过。
	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, "history.json"), []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateFromJSON(corruptDir, db); err == nil {
		t.Fatal("损坏 history.json 应报错")
	}
}

// TestMigrateFromJSONRollback 事务内第 2 条插入失败 → 整体回滚，库里 0 条。
func TestMigrateFromJSONRollback(t *testing.T) {
	dir := t.TempDir()
	h := history{NextID: 3, Scans: []ScanRecord{
		{ScanSummary: ScanSummary{ID: 1, Host: "a.com"}, Result: sqlTestResult("a.com")},
		{ScanSummary: ScanSummary{ID: 2, Host: "b.com"}, Result: sqlTestResult("b.com")},
	}}
	writeHistoryJSON(t, dir, h)

	db, f := openFake(t, func(b *fakeDB) { b.failOnExec = 2 })
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if _, err := MigrateFromJSON(dir, db); err == nil {
		t.Fatal("第 2 条写入失败时应返回错误")
	}
	st := NewSQLStore(db)
	if n, err := st.CountScans(); err != nil || n != 0 {
		t.Fatalf("回滚后应 0 条，实得 %d err=%v", n, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rollbacks != 1 || f.commits != 0 {
		t.Fatalf("应回滚 1 次、提交 0 次，实得 rollback=%d commit=%d", f.rollbacks, f.commits)
	}
}

// TestMigrateFromJSONDialect PostgreSQL 方言占位符路径（$N）。
func TestMigrateFromJSONDialect(t *testing.T) {
	dir := t.TempDir()
	h := history{NextID: 2, Scans: []ScanRecord{
		{ScanSummary: ScanSummary{ID: 1, Host: "pg.com"}, Result: sqlTestResult("pg.com")},
	}}
	writeHistoryJSON(t, dir, h)
	db, _ := openFake(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatal(err)
	}
	n, err := MigrateFromJSONDialect(dir, db, DialectPostgres)
	if err != nil || n != 1 {
		t.Fatalf("PostgreSQL 迁移 = %d err=%v want 1", n, err)
	}
}
