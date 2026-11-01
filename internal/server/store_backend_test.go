// 企业化 6.x 历史存储后端接线回归：JSON 默认、SQL 不可用回退、fake driver
// 走通 SQL 适配器（sqlite 方言）。
package server

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
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

// TestOpenScanStorePostgresUnreachableFallsBack PostgreSQL 驱动已注册但目标不可达
// （Ping 失败）→ 明确告警 + 回退 JSON，不阻断启动。
func TestOpenScanStorePostgresUnreachableFallsBack(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "postgres"
	cfg.Store.DSN = "host=127.0.0.1 port=1 user=x connect_timeout=1"
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

// TestOpenSQLScanStoreRealSQLite 真实 sqlite 驱动（modernc，纯 Go）走通 SQL 后端：
// 建表迁移 → Save/List/Get/Delete/HistoryStats；不再依赖测试专用 fake driver。
func TestOpenSQLScanStoreRealSQLite(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "scan.db") + "?_pragma=busy_timeout(5000)"
	st, err := openSQLScanStore("sqlite", dsn)
	if err != nil {
		t.Fatalf("openSQLScanStore(sqlite): %v", err)
	}
	// 测试结束前关掉底层连接，否则 Windows 上 TempDir 清理会报“文件被占用”。
	defer func() {
		if a, ok := st.(*sqlScanStore); ok {
			if c, ok := a.db.DB().(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	}()
	if _, ok := st.(*sqlScanStore); !ok {
		t.Fatalf("SQL 后端应为 sqlScanStore，实际 %T", st)
	}
	id := st.Save(&engine.Result{
		URL: "https://x.example", Host: "x.example", ScannedAt: "2026-01-01 00:00:00",
	}, nil)
	if id != 1 {
		t.Fatalf("SQL Save 应返回自增 id=1，实际 %d", id)
	}
	sums := st.List(10, "")
	if len(sums) != 1 || sums[0].Host != "x.example" {
		t.Fatalf("SQL List 结果异常: %+v", sums)
	}
	rec := st.Get(id)
	if rec == nil || rec.Host != "x.example" {
		t.Fatalf("SQL Get 结果异常: %+v", rec)
	}
	if !st.Delete(id) {
		t.Fatal("SQL Delete 应返回 true")
	}
	if rec := st.Get(id); rec != nil {
		t.Fatalf("删除后 Get 应为 nil: %+v", rec)
	}
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
