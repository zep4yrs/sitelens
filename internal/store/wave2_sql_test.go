// wave2_sql_test.go C-08（Wave-2）：SQL 后端列表投影 / 分页 / 轻量聚合 / 回填。
//
// 关键断言：列表路径**不读 result_json**（即使该列是非法 JSON 也能出列表），
// 只有 Get 单条才解码；tech 过滤走冗余列且带 LIMIT；Stats 走聚合 SQL。
package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

// openSQLiteTestDB 打开一个真实 modernc sqlite 测试库（driver 由 drivers.go 注册）。
func openSQLiteTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "wave2.db") + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestSQLListDoesNotDecodeResultJSON 列表只做列投影：result_json 即使是非法
// JSON，List 也必须正常返回；Get 单条才解码并如实报错。
func TestSQLListDoesNotDecodeResultJSON(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	st := NewSQLStore(db)
	// 直接插入一行：摘要/冗余列有效，result_json 故意写成非法 JSON。
	if _, err := db.Exec(
		"INSERT INTO scans (url,host,title,status,grade,score,scanned_at,"+
			"tech_count,vuln_count,duration_ms,tech_names,result_json,options_json)"+
			" VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
		"https://bad.example", "bad.example", "坏 result", 200, "A", 90,
		"2026-01-01 00:00:00", 2, 1, 1500, "nginx php", "{not-json"); err != nil {
		t.Fatalf("插入非法 result_json 行: %v", err)
	}

	list, err := st.ListScans(10, "") // C-08：不得解码 result_json
	if err != nil {
		t.Fatalf("List 不应因 result_json 损坏而失败（仍应解码=%v）", err)
	}
	if len(list) != 1 {
		t.Fatalf("List 应返回 1 条，实际 %d", len(list))
	}
	if list[0].TechCount != 2 || list[0].VulnCount != 1 || list[0].Duration != 1.5 {
		t.Fatalf("列表冗余列投影不符: %+v", list[0])
	}
	// tech 过滤走 tech_names 冗余列
	if hit, err := st.ListScans(10, "nginx"); err != nil || len(hit) != 1 {
		t.Fatalf("tech 过滤应命中冗余列: %v err=%v", hit, err)
	}
	// Get 单条才解码 result_json → 如实报错（不吞）
	if _, err := st.GetScan(1); err == nil {
		t.Fatal("GetScan 应因 result_json 损坏而报错（单条解码路径）")
	}
}

// TestSQLPagingProjectionAndStats 分页 / tech 过滤 / LIKE 转义 / 轻量聚合。
func TestSQLPagingProjectionAndStats(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	st := NewSQLStore(db)
	specs := []struct {
		host  string
		techs []string
	}{
		{"h1.com", []string{"Nginx"}},
		{"h2.com", []string{"Apache"}},
		{"h3.com", []string{"Nginx", "PHP"}},
		{"h4.com", []string{"IIS"}},
		{"h5.com", []string{"100%"}},
	}
	for _, sp := range specs {
		if _, err := st.SaveScan(sqlTestResult(sp.host, sp.techs...), nil); err != nil {
			t.Fatalf("SaveScan(%s): %v", sp.host, err)
		}
	}
	// 分页：offset=1 limit=2 → id 4,3
	page, err := st.ListScansPage(1, 2, "")
	if err != nil {
		t.Fatalf("ListScansPage: %v", err)
	}
	if len(page) != 2 || page[0].ID != 4 || page[1].ID != 3 {
		t.Fatalf("分页异常: %+v", page)
	}
	// 默认/上限：limit<=0 → 100；limit>MaxListLimit 被截断（不报错）
	if all, err := st.ListScans(0, ""); err != nil || len(all) != 5 {
		t.Fatalf("默认 limit 应返回 5 条: %d err=%v", len(all), err)
	}
	if _, err := st.ListScansPage(0, MaxListLimit+1, ""); err != nil {
		t.Fatalf("超大 limit 应被截断而非报错: %v", err)
	}
	// tech 过滤 + 分页
	nginx, err := st.ListScans(10, "nginx")
	if err != nil || len(nginx) != 2 || nginx[0].ID != 3 || nginx[1].ID != 1 {
		t.Fatalf("tech=nginx 应命中 3,1: %+v err=%v", nginx, err)
	}
	if got, err := st.ListScansPage(1, 10, "nginx"); err != nil || len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("tech 过滤 + offset 异常: %+v err=%v", got, err)
	}
	// LIKE 通配符转义：查询 "%" 只应命中名字里含字面量 % 的记录（不能全表命中）
	onlyPct, err := st.ListScans(10, "%")
	if err != nil {
		t.Fatalf("LIKE 转义: %v", err)
	}
	if len(onlyPct) != 1 || onlyPct[0].Host != "h5.com" {
		t.Fatalf("LIKE 通配符未被转义（%% 命中过多/过少）: %+v", onlyPct)
	}
	// 空格分隔的技术名：多词技术按子串匹配
	if _, err := st.SaveScan(sqlTestResult("h6.com", "Microsoft IIS"), nil); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ListScans(10, "microsoft"); err != nil || len(got) != 1 || got[0].Host != "h6.com" {
		t.Fatalf("多词技术名子串过滤异常: %+v err=%v", got, err)
	}
	// 轻量聚合（COUNT/GROUP BY，不拉列表）
	stats, err := st.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Scans != 6 || stats.Hosts != 6 {
		t.Fatalf("聚合计数不符: %+v", stats)
	}
	if stats.TechTotal != 7 { // 1+1+2+1+1+1
		t.Fatalf("技术总数不符: %+v", stats)
	}
	if stats.AvgTechs < 1.16 || stats.AvgTechs > 1.17 {
		t.Fatalf("平均技术数不符: %+v", stats)
	}
}

// TestBackfillScanSummary 旧行（冗余列未填）回填：一次扫描后列表/过滤正确，
// 且函数幂等（二次调用回填 0 条）。
func TestBackfillScanSummary(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	res := sqlTestResult("legacy.com", "Nginx", "PHP")
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟迁移 002 之前的旧行：只有 result_json，冗余列取默认值
	if _, err := db.Exec(
		"INSERT INTO scans (url,host,title,status,grade,score,scanned_at,result_json)"+
			" VALUES (?,?,?,?,?,?,?,?)",
		res.URL, res.Host, res.Title, res.Status, "B", 80, res.ScannedAt, string(raw)); err != nil {
		t.Fatalf("插入旧行: %v", err)
	}
	st := NewSQLStore(db)
	// 回填前：列表 tech_count 为 0、tech 过滤不命中（文档已说明）
	before, err := st.ListScans(10, "php")
	if err != nil || len(before) != 0 {
		t.Fatalf("回填前 tech 过滤不应命中: %+v err=%v", before, err)
	}
	n, err := BackfillScanSummary(db, DialectSQLite, 100)
	if err != nil || n != 1 {
		t.Fatalf("BackfillScanSummary = %d err=%v want 1", n, err)
	}
	if n2, err := BackfillScanSummary(db, DialectSQLite, 100); err != nil || n2 != 0 {
		t.Fatalf("回填应幂等（二次 0 条）: %d err=%v", n2, err)
	}
	after, err := st.ListScans(10, "php")
	if err != nil || len(after) != 1 {
		t.Fatalf("回填后 tech 过滤应命中: %+v err=%v", after, err)
	}
	if after[0].TechCount != 2 || after[0].Duration != 1.5 {
		t.Fatalf("回填后冗余列不符: %+v", after[0])
	}
}

// TestMigration002IdempotentOnRealSQLite 002 的 ALTER 无 IF NOT EXISTS：
// 重复应用必须被容忍（列已存在错误），且不影响后续读写。
func TestMigration002IdempotentOnRealSQLite(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("首次 ApplyMigrations: %v", err)
	}
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("重复 ApplyMigrations 应成功（ALTER 已存在列需容忍）: %v", err)
	}
	st := NewSQLStore(db)
	id, err := st.SaveScan(sqlTestResult("after.com", "Nginx"), nil)
	if err != nil || id != 1 {
		t.Fatalf("迁移后 SaveScan: id=%d err=%v", id, err)
	}
	list, err := st.ListScans(10, "nginx")
	if err != nil || len(list) != 1 || list[0].Host != "after.com" {
		t.Fatalf("迁移后列表/过滤异常: %+v err=%v", list, err)
	}
}

// TestSQLPostgresDialectProjectionListPG 分支也应走投影/聚合（占位符 $N）。
func TestSQLPostgresDialectProjectionListPG(t *testing.T) {
	db, _ := openFake(t)
	pg := NewSQLStoreDialect(db, DialectPostgres)
	if _, err := pg.SaveScan(sqlTestResult("pg1.com", "Nginx"), nil); err != nil {
		t.Fatalf("PG SaveScan: %v", err)
	}
	if _, err := pg.SaveScan(sqlTestResult("pg2.com", "PHP"), nil); err != nil {
		t.Fatalf("PG SaveScan: %v", err)
	}
	list, err := pg.ListScansPage(0, 10, "")
	if err != nil || len(list) != 2 {
		t.Fatalf("PG ListScansPage: %+v err=%v", list, err)
	}
	if list[0].TechCount != 1 || list[0].Duration != 1.5 {
		t.Fatalf("PG 列表投影不符: %+v", list[0])
	}
	if hit, err := pg.ListScans(10, "nginx"); err != nil || len(hit) != 1 || hit[0].Host != "pg1.com" {
		t.Fatalf("PG tech 过滤: %+v err=%v", hit, err)
	}
	st, err := pg.Stats()
	if err != nil || st.Scans != 2 || st.Hosts != 2 {
		t.Fatalf("PG Stats: %+v err=%v", st, err)
	}
	rec, err := pg.GetScan(1)
	if err != nil || rec == nil || rec.Host != "pg1.com" || rec.Result == nil {
		t.Fatalf("PG GetScan: %+v err=%v", rec, err)
	}
}
