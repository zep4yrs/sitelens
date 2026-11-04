// store_backend_wave1_test.go Wave-1 F3 回归：SQL 后端保存失败/回退的可观测性（C-03）。
//
// 独立文件（不改 store_backend_test.go 既有用例）：本任务只允许改
// internal/server/store_backend.go 一个既有文件，新增用例集中在这里，
// 复用同包的 captureLog 与 config/engine 依赖。
package server

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestFallbackBackendObservable C-03：SQL 不可用回退 JSON 时，
// /api/stats.history（HistoryStats）必须能看出"降级 + 原因 + 后端类型"，
// 不能只留一行启动日志。
func TestFallbackBackendObservable(t *testing.T) {
	cfg := config.Default()
	cfg.Store.DataDir = t.TempDir()
	cfg.Store.Driver = "mysql" // 不支持的 driver → 回退 JSON
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
	hs := st.HistoryStats()
	if hs["degraded"] != true {
		t.Fatalf("回退后端 degraded 应为 true: %+v", hs)
	}
	if reason, _ := hs["fallback_reason"].(string); reason == "" {
		t.Fatalf("回退后端应暴露 fallback_reason: %+v", hs)
	}
	if hs["backend"] != "json" {
		t.Fatalf("JSON 回退后端 backend 应为 json: %+v", hs)
	}

	// 正常 JSON 后端（未降级）不应误报 degraded / fallback_reason
	cfg2 := config.Default()
	cfg2.Store.DataDir = t.TempDir()
	st2, err := (&Server{}).openScanStore(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	hs2 := st2.HistoryStats()
	if hs2["degraded"] != false {
		t.Fatalf("默认 JSON 后端不应 degraded: %+v", hs2)
	}
	if _, ok := hs2["fallback_reason"]; ok {
		t.Fatalf("未回退时不应有 fallback_reason: %+v", hs2)
	}
}

// TestSQLScanStoreSaveFailureObservable C-03：SQL 保存失败时：
//  1. 不丢记录——整条记录写进回退 spool（NDJSON，可人工/工具回灌）；
//  2. 降级状态可经 HistoryStats 观测（save_errors/last_save_error/spool 路径）。
func TestSQLScanStoreSaveFailureObservable(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "dead.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_ = db.Close() // 连接已关闭 → SaveScan 必然失败
	spool := filepath.Join(t.TempDir(), "sql_unsaved.jsonl")
	a := newSQLScanStoreWithFallback(store.NewSQLStore(db), spool)

	res := &engine.Result{URL: "https://spool.example", Host: "spool.example", Status: 200}
	if id := a.Save(res, map[string]any{"deep": true}); id != 0 {
		t.Fatalf("失败时 Save 应返回 0，实际 %d", id)
	}
	// 回退 spool：整条记录可回灌（含 URL / result / options）
	data, rerr := os.ReadFile(spool)
	if rerr != nil {
		t.Fatalf("保存失败应写回退 spool（不能只返回 0 就丢记录）: %v", rerr)
	}
	if !bytes.Contains(data, []byte("https://spool.example")) ||
		!bytes.Contains(data, []byte(`"deep":true`)) {
		t.Fatalf("spool 内容不完整（应含 result 与 options）: %s", data)
	}
	// 可观测性：/api/stats.history 对应的 map 必须带降级诊断
	hs := a.HistoryStats()
	if hs["degraded"] != true {
		t.Fatalf("保存失败后 degraded 应为 true: %+v", hs)
	}
	if n, _ := hs["save_errors"].(int64); n != 1 {
		t.Fatalf("save_errors 应为 1，实际 %v", hs["save_errors"])
	}
	if msg, _ := hs["last_save_error"].(string); msg == "" {
		t.Fatalf("应记录 last_save_error: %+v", hs)
	}
	if sp, _ := hs["fallback_spool"].(string); sp != spool {
		t.Fatalf("应暴露 fallback_spool 路径: %+v", hs)
	}
	if sz, _ := hs["fallback_spool_bytes"].(int64); sz <= 0 {
		t.Fatalf("应暴露 spool 字节数: %+v", hs)
	}
	if hs["backend"] != "sqlite" {
		t.Fatalf("backend 应为 sqlite: %+v", hs)
	}
	// C-03 收尾契约：Save 返回 0 时 server 需要用 LastSaveError() 把 job
	// 从 done 纠正为 error；因此失败原因必须能从这个可选接口读到。
	if msg := a.LastSaveError(); msg == "" {
		t.Fatalf("保存失败后 LastSaveError() 必须非空（否则 server 只能报通用错误）")
	}
}
