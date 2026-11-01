// 企业化 6.x 历史存储后端接线回归：JSON 默认、SQL 不可用回退、fake driver
// 走通 SQL 适配器（sqlite 方言）。
package server

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"io"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// captureLog 捕获 log 输出（回退告警断言用）。
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// TestOpenScanStoreJSONDefault 默认配置 → JSON 分层归档后端（行为零变化）。
func TestOpenScanStoreJSONDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	st, err := (&Server{}).openScanStore(cfg)
	if err != nil {
		t.Fatalf("openScanStore(json): %v", err)
	}
	if _, ok := st.(*store.Tiered); !ok {
		t.Fatalf("默认应为 JSON/Tiered 后端，实际 %T", st)
	}
}

// TestOpenScanStoreUnsupportedDriverFallsBack 不支持的 driver → 明确告警 + 回退 JSON。
func TestOpenScanStoreUnsupportedDriverFallsBack(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "mysql"
	cfg.Store.DSN = "user:pass@/db"
	var st scanStore
	var err error
	out := captureLog(t, func() { st, err = (&Server{}).openScanStore(cfg) })
	if err != nil {
		t.Fatalf("不支持 driver 应回退而非报错: %v", err)
	}
	if _, ok := st.(*store.Tiered); !ok {
		t.Fatalf("回退后应为 JSON 后端，实际 %T", st)
	}
	if !strings.Contains(out, "回退 JSON") {
		t.Fatalf("回退应有明确日志: %q", out)
	}
}

// TestOpenScanStoreUnregisteredDriverFallsBack driver 未注册（sql.Open 报错）
// → 明确告警 + 回退 JSON。
func TestOpenScanStoreUnregisteredDriverFallsBack(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "postgres" // 测试进程未注册该驱动
	cfg.Store.DSN = "host=127.0.0.1 port=1 user=x"
	var st scanStore
	var err error
	out := captureLog(t, func() { st, err = (&Server{}).openScanStore(cfg) })
	if err != nil {
		t.Fatalf("driver 未注册应回退而非报错: %v", err)
	}
	if _, ok := st.(*store.Tiered); !ok {
		t.Fatalf("回退后应为 JSON 后端，实际 %T", st)
	}
	if !strings.Contains(out, "回退 JSON") {
		t.Fatalf("回退应有明确日志: %q", out)
	}
}

// TestOpenScanStoreMissingDSNFallsBack 非 json 但缺 DSN → 告警 + 回退。
func TestOpenScanStoreMissingDSNFallsBack(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "sqlite"
	var st scanStore
	var err error
	out := captureLog(t, func() { st, err = (&Server{}).openScanStore(cfg) })
	if err != nil {
		t.Fatalf("缺 DSN 应回退而非报错: %v", err)
	}
	if _, ok := st.(*store.Tiered); !ok || !strings.Contains(out, "回退 JSON") {
		t.Fatalf("缺 DSN 回退异常: type=%T log=%q", st, out)
	}
}

// ---- fake database/sql driver（不依赖真实数据库/第三方驱动） ----

var registerFakeSQLiteOnce sync.Once

// registerFakeSQLiteDriver 注册最小 fake sqlite 驱动（幂等；已被注册时忽略）。
func registerFakeSQLiteDriver() {
	registerFakeSQLiteOnce.Do(func() {
		defer func() { _ = recover() }()
		sql.Register("sqlite", fakeSQLDriver{})
	})
}

type fakeSQLDriver struct{}

func (fakeSQLDriver) Open(string) (driver.Conn, error) { return &fakeConn{}, nil }

type fakeConn struct{}

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return &fakeStmt{}, nil }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeStmt struct{}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }

func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) { return fakeResult{}, nil }
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error)  { return &fakeRows{}, nil }

type fakeResult struct{}

func (fakeResult) LastInsertId() (int64, error) { return 1, nil }
func (fakeResult) RowsAffected() (int64, error) { return 1, nil }

type fakeRows struct{}

func (r *fakeRows) Columns() []string         { return nil }
func (r *fakeRows) Close() error              { return nil }
func (r *fakeRows) Next([]driver.Value) error { return io.EOF }

// TestOpenSQLScanStoreFakeDriver fake driver 走通 SQL 后端装配与 scanStore 适配。
func TestOpenSQLScanStoreFakeDriver(t *testing.T) {
	registerFakeSQLiteDriver()
	st, err := openSQLScanStore("sqlite", "fake-dsn")
	if err != nil {
		t.Fatalf("openSQLScanStore: %v", err)
	}
	if _, ok := st.(*sqlScanStore); !ok {
		t.Fatalf("SQL 后端应为 sqlScanStore，实际 %T", st)
	}
	// Save：INSERT + LastInsertId（fake 返回 1）
	id := st.Save(&engine.Result{URL: "https://x.example", Host: "x.example",
		ScannedAt: "2026-01-01 00:00:00"}, nil)
	if id != 1 {
		t.Fatalf("SQL Save 应返回自增 id=1，实际 %d", id)
	}
	// 读路径：fake 空结果集 → 空列表/nil，不 panic
	if sums := st.List(10, ""); len(sums) != 0 {
		t.Fatalf("fake 空结果集应返回空列表: %v", sums)
	}
	if rec := st.Get(1); rec != nil {
		t.Fatalf("fake 空结果集 Get 应返回 nil: %+v", rec)
	}
	// fake driver 的 DELETE 影响行数恒为 1；这里只验证不 panic/不误报错误
	_ = st.Delete(1)
	// 不支持能力明确降级（不 panic、不阻塞接口）
	if _, ierr := st.Import(store.ScanRecord{}); ierr == nil {
		t.Fatal("SQL 后端 Import 应明确报错")
	}
	if st.TopTechs(1) != nil || st.Verified(1) != nil {
		t.Fatal("SQL 后端 TopTechs/Verified 应降级为空")
	}
	if _, ok := st.Graph(1); ok {
		t.Fatal("SQL 后端不应有图谱")
	}
	if st.HasGraph(1) || st.GraphIDs() != nil {
		t.Fatal("SQL 后端图谱能力应降级")
	}
	// 统计/清空不 panic
	if stats := st.HistoryStats(); stats == nil {
		t.Fatal("HistoryStats 不应为 nil")
	}
	_ = st.ClearAll()
}

// TestSQLScanStoreUnsupportedDriver openSQLScanStore 对未知 driver 明确报错。
func TestSQLScanStoreUnsupportedDriver(t *testing.T) {
	if _, err := openSQLScanStore("mysql", "dsn"); err == nil {
		t.Fatal("不支持的 driver 应返回明确错误")
	}
}

// TestNewWithSQLFallback 全量 New：SQL 不可用时启动成功且回退 JSON 存储。
func TestNewWithSQLFallback(t *testing.T) {
	t.Chdir("../..")
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "postgres"
	cfg.Store.DSN = "host=127.0.0.1 port=1"
	var s *Server
	var err error
	out := captureLog(t, func() { s, err = New(cfg, filepath.Join(t.TempDir(), "cfg.yml")) })
	if err != nil {
		t.Fatalf("New 应回退而非失败: %v", err)
	}
	if s.st == nil {
		t.Fatal("回退后 st 不应为空")
	}
	if _, ok := s.st.(*store.Tiered); !ok {
		t.Fatalf("回退后应为 JSON 后端，实际 %T", s.st)
	}
	if !strings.Contains(out, "回退 JSON") {
		t.Fatalf("回退应有明确日志: %q", out)
	}
}
