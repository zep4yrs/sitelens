package intel

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gzBytes 把 JSON 文本压成 feed 形态的 gzip 字节。
func gzBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b strings.Builder
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(b.String())
}

// TestSyncNVDFeed：年度 feed 下载 → 解析 → 合并写出（含 CWE）。
func TestSyncNVDFeed(t *testing.T) {
	// 两个年份各一页；2017 含 CWE，2018 为 Rejected（应跳过）。
	y2017 := `{"totalResults":1,"vulnerabilities":[` + nvdCVE1 + `]}`
	y2018 := `{"totalResults":1,"vulnerabilities":[` + nvdCVE2 + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "2017"):
			_, _ = w.Write(gzBytes(t, y2017))
		case strings.Contains(r.URL.Path, "2018"):
			_, _ = w.Write(gzBytes(t, y2018))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	oldURL := nvdFeedURL
	nvdFeedURL = srv.URL + "/nvdcve-2.0-%d.json.gz"
	defer func() { nvdFeedURL = oldURL }()

	out := filepath.Join(t.TempDir(), "feed.json.gz")
	var lastDone, lastTotal int
	if err := SyncNVDFeed(out, 2017, 2018, func(done, total, skipped int) {
		lastDone, lastTotal = done, total
	}); err != nil {
		t.Fatalf("SyncNVDFeed: %v", err)
	}
	if lastDone != 2 || lastTotal != 2 {
		t.Errorf("进度回调 = %d/%d，期望 2/2", lastDone, lastTotal)
	}

	store, err := LoadNVD(out)
	if err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatalf("Rejected 应跳过，实得 %d 条", store.Len())
	}
	e, ok := store.ByCVE("CVE-2099-0001")
	if !ok {
		t.Fatal("条目应在库")
	}
	if len(e.CWEs) == 0 || e.CWEs[0] != "CWE-22" {
		t.Errorf("feed 模式应保留 CWE：%v", e.CWEs)
	}
}

// TestSyncNVDFeedPartialFailure：单年失败不中断，但返回明确错误（不静默）。
func TestSyncNVDFeedPartialFailure(t *testing.T) {
	y2019 := `{"totalResults":1,"vulnerabilities":[` + nvdCVE1 + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "2019") {
			_, _ = w.Write(gzBytes(t, y2019))
			return
		}
		w.WriteHeader(500) // 2020 失败
	}))
	defer srv.Close()
	oldURL := nvdFeedURL
	nvdFeedURL = srv.URL + "/nvdcve-2.0-%d.json.gz"
	defer func() { nvdFeedURL = oldURL }()

	out := filepath.Join(t.TempDir(), "f.json.gz")
	err := SyncNVDFeed(out, 2019, 2020, nil)
	if err == nil {
		t.Fatal("单年失败应返回错误（不静默）")
	}
	// 但成功年份的数据应已写出。
	store, lerr := LoadNVD(out)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if store == nil || store.Len() != 1 {
		t.Errorf("成功年份数据应写出，实得 %v", store)
	}
}

// TestSyncNVDFeedAllFail：全部失败 → 返回错误且不产出文件。
func TestSyncNVDFeedAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	oldURL := nvdFeedURL
	nvdFeedURL = srv.URL + "/x-%d.json.gz"
	defer func() { nvdFeedURL = oldURL }()

	out := filepath.Join(t.TempDir(), "none.json.gz")
	if err := SyncNVDFeed(out, 2021, 2022, nil); err == nil {
		t.Fatal("全失败应返回错误")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("全失败不应产出数据文件")
	}
}

// TestFeedYearOf：meta 解析（辅助）。
func TestFeedYearOf(t *testing.T) {
	got := feedYearOf([]byte(`{"lastModifiedDate":"2026-09-14T00:00:00Z"}`))
	if got != "2026-09-14T00:00:00Z" {
		t.Errorf("feedYearOf = %q", got)
	}
}

// TestParseNVDPageShared：API 与 feed 共用解析（同格式验证）。
func TestParseNVDPageShared(t *testing.T) {
	page := `{"totalResults":2,"vulnerabilities":[` + nvdCVE1 + `,` + nvdCVE2 + `]}`
	entries, meta, err := parseNVDPage([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("应产出 1 条（Rejected 跳过），实得 %d", len(entries))
	}
	if meta.skipped != 1 || meta.total != 2 {
		t.Errorf("meta = %+v，期望 skipped=1 total=2", meta)
	}
	var _ = json.Marshal // keep json import used
}
