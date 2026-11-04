// wave1_fixes_test.go Wave-1 F3 回归测试（C-02/C-04/C-05/C-06/C-12/C-18/C-20）。
//
// 覆盖范围刻意落在"可观测的内部行为"上：
//   - store.New 读错误不得按空库继续（否则后续 flush 覆盖原 history.json）；
//   - 裁剪归档失败不得裁剪主库（保留原记录 + 显式报错）；
//   - 归档层/List 按 id 去重（Import/回灌/崩溃窗口不再产生重复行）；
//   - JobManager.Get 深拷贝（不能通过返回值篡改内部状态）；
//   - Save 不改写调用方 res.Graph.ScanID；
//   - PostgreSQL 迁移会推进 identity 序列（fake driver 断言语句下发）；
//   - SQLite 迁移后新插入 id 连续（真实 modernc sqlite E2E）；
//   - 迁移语句拆分器不被字符串字面量/注释里的分号切断。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// ---------------------------------------------------------------------------
// C-04：history.json 存在但读不出来时，New 必须返回错误（不得按空库启动）
// ---------------------------------------------------------------------------

func TestNewUnreadableHistoryReturnsError(t *testing.T) {
	dir := t.TempDir()
	// 用同名目录制造非 NotExist 的读取错误（任何非 NotExist 错误走同一分支）
	if err := os.MkdirAll(filepath.Join(dir, "history.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, 10)
	if err == nil {
		t.Fatalf("history.json 不可读时 New 必须报错；实际返回 store=%+v（后续 flush 会覆盖原文件）", s)
	}
	if s != nil {
		t.Fatalf("出错时不应返回可用 store: %+v", s)
	}

	// 不存在 = 首次启动正常态，仍可正常打开
	if _, err := New(t.TempDir(), 10); err != nil {
		t.Fatalf("history.json 不存在应正常首启: %v", err)
	}
}

// ---------------------------------------------------------------------------
// C-05：裁剪归档失败时保留主库原记录并报错（不能静默丢记录）
// ---------------------------------------------------------------------------

func TestArchiveFailureKeepsMainRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	// 让归档路径不可写：history.archive.jsonl 位置放一个目录
	if err := os.Mkdir(filepath.Join(dir, "history.archive.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := captureStderr(t, func() {
		for i := 0; i < 4; i++ {
			s.Save(sampleResult(fmt.Sprintf("h%d.com", i), "x", 1), nil)
		}
	})
	if n := len(s.List(10, "")); n != 4 {
		t.Fatalf("归档失败时不应裁剪主库（应保留 4 条），实际 %d", n)
	}
	if !strings.Contains(out, "归档失败") {
		t.Fatalf("归档失败应显式告警到 stderr，实际 %q", out)
	}
	if s.ArchiveError() == "" {
		t.Fatal("ArchiveError 应记录最近一次归档失败原因")
	}
	if stats := s.ArchiveStats(); stats["archive_error"] == nil {
		t.Fatalf("ArchiveStats 应暴露 archive_error: %+v", stats)
	}

	// 恢复可写路径：下一次 Save 重新归档成功，主库回落到 max=2
	if err := os.Remove(filepath.Join(dir, "history.archive.jsonl")); err != nil {
		t.Fatal(err)
	}
	s.Save(sampleResult("h5.com", "x", 1), nil)
	if n := len(s.List(10, "")); n != 2 {
		t.Fatalf("归档恢复后应裁剪到 max=2，实际 %d", n)
	}
	if s.ArchiveError() != "" {
		t.Fatalf("归档成功后 ArchiveError 应清空，实际 %q", s.ArchiveError())
	}
}

// ---------------------------------------------------------------------------
// C-06：归档层按 id 去重（Import 已归档记录后再次归档不写重复）
// ---------------------------------------------------------------------------

func TestArchiveDedupesByIDOnReimport(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	if _, err := tv.ArchiveNowKeep(1); err != nil { // 归档 id 1,2
		t.Fatalf("首次归档: %v", err)
	}
	// 模拟回灌/迁移：把已归档记录重新 Import 进主库（Tiered.Import 是公开路径）
	for id := int64(1); id <= 2; id++ {
		rec := tv.Get(id)
		if rec == nil {
			t.Fatalf("跨档取不到 id=%d", id)
		}
		if _, err := tv.Import(*rec); err != nil {
			t.Fatalf("Import id=%d: %v", id, err)
		}
	}
	// 再次归档：主库 victims 含已在年度文件里的 id
	if _, err := tv.ArchiveNowKeep(1); err != nil {
		t.Fatalf("二次归档: %v", err)
	}
	yf := loadYearDoc(t, dir, 2025)
	seen := map[int64]int{}
	for _, r := range yf.Scans {
		seen[r.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Fatalf("年度归档 id=%d 重复 %d 份（归档层应按 id 去重）: %v", id, n, seen)
		}
	}
	if _, ok := seen[1]; !ok {
		t.Fatalf("年度归档应保留 id=1: %v", seen)
	}
}

// TestTieredListDedupesCrashWindow 模拟「年度文件已写、主库 trim 未落盘」的
// 崩溃窗口：重启后同一 id 同时存在于主库与归档，List 必须只输出一次。
func TestTieredListDedupesCrashWindow(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // keep=2 → 第 3 条触发归档 id=1
		tv.Save(resultAt(fmt.Sprintf("h%d.com", i+1), "2025-05-01 10:00:00"), nil)
	}
	arch := tv.Get(1)
	if arch == nil {
		t.Fatal("id=1 应已归档")
	}
	// 把归档记录写回 history.json（模拟 trim 前崩溃）
	raw, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h history
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	h.Scans = append(h.Scans, *arch)
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	tv2, err := NewTiered(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]int{}
	for _, s := range tv2.List(20, "") {
		ids[s.ID]++
	}
	for id, n := range ids {
		if n > 1 {
			t.Fatalf("Tiered.List 输出重复 id=%d（%d 次）: %v", id, n, ids)
		}
	}
}

// ---------------------------------------------------------------------------
// C-20：Save 不得改写调用方 res.Graph.ScanID
// ---------------------------------------------------------------------------

func TestSaveDoesNotMutateCallerGraphScanID(t *testing.T) {
	s, err := New(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	res := sampleResult("graph.example", "G", 1)
	res.Graph = model.NewGraph("")
	id := s.Save(res, nil)
	if res.Graph == nil || res.Graph.ScanID != "" {
		t.Fatalf("Save 不应改写调用方 res.Graph.ScanID，实际 %q", res.Graph.ScanID)
	}
	man, ok := s.GraphManifestOf(id)
	if !ok {
		t.Fatal("应落盘图清单")
	}
	if man.ScanID != id {
		t.Fatalf("落盘图 scan_id 应回填为记录 id=%d，实际 %d", id, man.ScanID)
	}
	// 二次保存同一 *Result：调用方对象仍不应被改（旧实现会钉在首个 id）
	res2 := sampleResult("graph2.example", "G2", 1)
	res2.Graph = model.NewGraph("")
	id2 := s.Save(res2, nil)
	if res2.Graph.ScanID != "" {
		t.Fatalf("二次保存不应改写调用方图: %q", res2.Graph.ScanID)
	}
	if man2, ok := s.GraphManifestOf(id2); !ok || man2.ScanID != id2 {
		t.Fatalf("第二条图 scan_id 应为 %d: %+v", id2, man2)
	}
}

// ---------------------------------------------------------------------------
// C-18：JobManager.Get 深拷贝，返回值不能篡改内部状态
// ---------------------------------------------------------------------------

func TestJobGetDeepCopy(t *testing.T) {
	m := NewJobManager()
	m.Create("j1", "batch", map[string]any{"url": "https://a.com"}, 2)
	m.Update("j1", func(j *Job) {
		j.Result = map[string]any{"rows": []map[string]any{{"url": "a.com", "status": "done"}}}
		j.Live = &LiveStats{Phase: "scan", Requests: 1}
		j.Events = []JobEvent{{TS: 1, Kind: "stage", Text: "开始"}}
	})

	got := m.Get("j1")
	if got == nil {
		t.Fatal("Get 返回 nil")
	}
	// 通过返回值做 in-place 篡改
	got.Payload["url"] = "https://evil.example"
	got.Result["extra"] = 1
	rows, ok := got.Result["rows"].([]map[string]any)
	if !ok {
		t.Fatalf("rows 类型应保持 []map[string]any: %T", got.Result["rows"])
	}
	rows[0]["status"] = "hacked"
	got.Events[0].Text = "hacked"
	got.Live.Phase = "hacked"

	again := m.Get("j1")
	if again.Payload["url"] != "https://a.com" {
		t.Fatalf("Payload 被外部篡改: %v", again.Payload)
	}
	if _, exists := again.Result["extra"]; exists {
		t.Fatalf("Result 被外部新增键: %v", again.Result)
	}
	rows2 := again.Result["rows"].([]map[string]any)
	if rows2[0]["status"] != "done" {
		t.Fatalf("Result.rows 被外部篡改: %v", rows2)
	}
	if again.Events[0].Text != "开始" || again.Live.Phase != "scan" {
		t.Fatalf("Events/Live 被外部篡改: %+v %+v", again.Events, again.Live)
	}
}

// ---------------------------------------------------------------------------
// C-02：PostgreSQL 迁移后必须推进 identity 序列（fake driver 断言语句下发）
// ---------------------------------------------------------------------------

func TestMigrateFromJSONPostgresResetsSequence(t *testing.T) {
	if !strings.Contains(postgresIdentitySeqResetSQL, "setval") ||
		!strings.Contains(postgresIdentitySeqResetSQL, "pg_get_serial_sequence") {
		t.Fatalf("序列重置语句形态异常: %s", postgresIdentitySeqResetSQL)
	}
	dir := t.TempDir()
	writeHistoryJSON(t, dir, history{NextID: 4, Scans: []ScanRecord{
		{ScanSummary: ScanSummary{ID: 1, Host: "a.com"}, Result: sqlTestResult("a.com")},
		{ScanSummary: ScanSummary{ID: 2, Host: "b.com"}, Result: sqlTestResult("b.com")},
		{ScanSummary: ScanSummary{ID: 3, Host: "c.com"}, Result: sqlTestResult("c.com")},
	}})
	db, f := openFake(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatal(err)
	}
	n, err := MigrateFromJSONDialect(dir, db, DialectPostgres)
	if err != nil || n != 3 {
		t.Fatalf("PG 迁移 = %d, err=%v, want 3", n, err)
	}
	f.mu.Lock()
	resets := f.seqResets
	f.mu.Unlock()
	if resets != 1 {
		t.Fatalf("迁移后应执行 1 次序列重置（setval），实际 %d 次", resets)
	}
	// SQLite 方言不应发 PG 专属语句
	dir2 := t.TempDir()
	writeHistoryJSON(t, dir2, history{NextID: 2, Scans: []ScanRecord{
		{ScanSummary: ScanSummary{ID: 1, Host: "s.com"}, Result: sqlTestResult("s.com")},
	}})
	db2, f2 := openFake(t)
	if err := ApplyMigrations(db2); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateFromJSON(dir2, db2); err != nil {
		t.Fatal(err)
	}
	f2.mu.Lock()
	resets2 := f2.seqResets
	f2.mu.Unlock()
	if resets2 != 0 {
		t.Fatalf("SQLite 方言不应执行 setval，实际 %d 次", resets2)
	}
}

// TestSQLiteMigrationThenSaveScanContinuesIDs 真实 modernc sqlite E2E：
// JSON 迁移保留 id 1..3 后，新 SaveScan 必须拿到 4（SQLite AUTOINCREMENT
// 在显式插入更大 rowid 时会推进 sqlite_sequence，本用例把该保证钉住）。
func TestSQLiteMigrationThenSaveScanContinuesIDs(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "mig.db") + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open(sqlite): %v", err)
	}
	defer db.Close()
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	writeHistoryJSON(t, dir, history{NextID: 4, Scans: []ScanRecord{
		{ScanSummary: ScanSummary{ID: 1, Host: "a.com"}, Result: sqlTestResult("a.com")},
		{ScanSummary: ScanSummary{ID: 2, Host: "b.com"}, Result: sqlTestResult("b.com")},
		{ScanSummary: ScanSummary{ID: 3, Host: "c.com"}, Result: sqlTestResult("c.com")},
	}})
	n, err := MigrateFromJSON(dir, db)
	if err != nil || n != 3 {
		t.Fatalf("SQLite 迁移 = %d, err=%v, want 3", n, err)
	}
	st := NewSQLStore(db)
	id, err := st.SaveScan(sqlTestResult("new.com"), nil)
	if err != nil {
		t.Fatalf("迁移后 SaveScan（序列应已推进）: %v", err)
	}
	if id != 4 {
		t.Fatalf("迁移后新记录 id 应为 4（sqlite_sequence 已推进），实际 %d", id)
	}
	// 二次迁移幂等且不影响序列
	if n2, err := MigrateFromJSON(dir, db); err != nil || n2 != 0 {
		t.Fatalf("二次迁移应 0 条: %d err=%v", n2, err)
	}
	next, err := st.SaveScan(sqlTestResult("new2.com"), nil)
	if err != nil || next != 5 {
		t.Fatalf("二次迁移后继续插入应为 5: id=%d err=%v", next, err)
	}
}

// ---------------------------------------------------------------------------
// C-12：迁移语句拆分器（字符串字面量/行内注释里的分号不误切）
// ---------------------------------------------------------------------------

func TestSplitSQLStatementsLiteralSafe(t *testing.T) {
	src := "-- 头部注释 ; 不是语句\n" +
		"CREATE TABLE t (a TEXT DEFAULT ';', b TEXT DEFAULT 'x;y'); -- 行尾注释 ;\n" +
		"CREATE TABLE u (c TEXT DEFAULT '--not-comment');\n" +
		"/* 块注释 ;\n   多行 */ CREATE INDEX i ON t(a);\n"
	stmts, err := splitSQLStatements(src)
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(stmts) != 3 {
		t.Fatalf("应拆出 3 条语句，实际 %d: %#v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0], "DEFAULT ';'") || !strings.Contains(stmts[0], "x;y") {
		t.Fatalf("字符串字面量被切断: %q", stmts[0])
	}
	if strings.Contains(stmts[0], "行尾注释") || strings.Contains(stmts[0], "头部注释") {
		t.Fatalf("注释应被剥离: %q", stmts[0])
	}
	if !strings.Contains(stmts[1], "'--not-comment'") {
		t.Fatalf("字符串里的 -- 不应触发注释: %q", stmts[1])
	}
	if !strings.HasPrefix(strings.TrimSpace(stmts[2]), "CREATE INDEX") {
		t.Fatalf("块注释后的语句不正确: %q", stmts[2])
	}
	// 未闭合字符串：明确报错（不能静默切错）
	if _, err := splitSQLStatements("CREATE TABLE t (a TEXT DEFAULT ';);"); err == nil {
		t.Fatal("未闭合字符串应返回错误")
	}
	// 末尾缺分号：明确报错（既有契约）
	if _, err := splitSQLStatements("CREATE TABLE t (a INT)"); err == nil {
		t.Fatal("末尾语句未以分号结尾应返回错误")
	}
}
