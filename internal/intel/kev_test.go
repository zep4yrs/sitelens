package intel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFetchKEVParsesFeed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"title":"CISA KEV","vulnerabilities":[
			{"cveID":"CVE-2024-1234","dateAdded":"2024-01-15"},
			{"cveID":"CVE-2024-5678","dateAdded":"2024-02-01"},
			{"cveID":"","dateAdded":"2024-02-02"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entries, err := FetchKEV(srv.URL+"/kev.json", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("应解析 3 条（含空 CVE 过滤前）: %d", len(entries))
	}
	kb := &KB{}
	added := kb.MergeKEV(entries)
	if added != 2 { // 空 CVE 不计
		t.Fatalf("合并应新增 2 条: %d", added)
	}
	if !kb.kev["CVE-2024-1234"] {
		t.Fatal("CVE-2024-1234 应在索引")
	}
	// 重复合并不重复计数
	if added := kb.MergeKEV(entries); added != 0 {
		t.Fatalf("重复合并应新增 0: %d", added)
	}
}

func TestKEVExtraRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kev_extra.json")
	entries := []KevEntry{{CVE: "CVE-2024-9999", DateAdded: "2024-03-01"}}
	if err := SaveKEVExtra(path, entries); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKEVExtra(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].CVE != "CVE-2024-9999" {
		t.Fatalf("缓存往返失败: %+v", loaded)
	}
}

func TestFetchKEVBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	if _, err := FetchKEV(srv.URL, time.Second); err == nil {
		t.Fatal("非 200 应报错")
	}
}

// TestIsKEVAndCVSSFor：4.0 P10 新增的公开查询入口（供 impact 先验标注）。
func TestIsKEVAndCVSSFor(t *testing.T) {
	kb := &KB{}
	if n := kb.MergeKEV([]KevEntry{{CVE: "CVE-2021-44228"}, {CVE: "cve-2019-0708"}}); n != 2 {
		t.Fatalf("MergeKEV 新增 = %d，期望 2", n)
	}
	// 大小写不敏感。
	if !kb.IsKEV("CVE-2021-44228") || !kb.IsKEV("cve-2021-44228") {
		t.Error("IsKEV 应命中且大小写不敏感")
	}
	if kb.IsKEV("CVE-0000-0000") {
		t.Error("未知 CVE 不应命中")
	}
	if kb.IsKEV("") {
		t.Error("空 CVE 不应命中")
	}
	// nil 安全。
	var nilKB *KB
	if nilKB.IsKEV("CVE-2021-44228") || nilKB.CVSSFor("CVE-2021-44228") != 0 {
		t.Error("nil KB 应安全返回 false/0")
	}
	// 未挂 NVD 时 CVSSFor 返回 0（不臆造）。
	if kb.CVSSFor("CVE-2021-44228") != 0 {
		t.Error("未挂 NVD 时 CVSS 应为 0")
	}
}

// TestMergeKEVIsKEVConcurrentSafe BUG-004 回归：KEV 守护 goroutine 的写
// （MergeKEV）与扫描线程的读（IsKEV / kevCount）并发。旧实现 map 无锁，
// 并发读写是 Go fatal error（不可 recover，整个 serve 进程崩溃）；本用例
// 必须在 -race 下干净，且写完的条目对读侧可见。
//
// 注：本机 CGO_ENABLED=0 且无 C 编译器，-race 无法运行（-race requires
// cgo）；用例按 -race 友好设计（读线程只读、写线程独占 MergeKEV），需在
// 带 CGO 的环境用 `CGO_ENABLED=1 go test -race ./internal/intel` 复核。
func TestMergeKEVIsKEVConcurrentSafe(t *testing.T) {
	kb := &KB{}
	const iters = 500
	var wg sync.WaitGroup
	// 写：模拟 KEV 守护 goroutine 周期轮询合并
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			kb.MergeKEV([]KevEntry{
				{CVE: fmt.Sprintf("CVE-2024-%04d", i)},
				{CVE: fmt.Sprintf("CVE-2025-%04d", i)},
			})
		}
	}()
	// 读：模拟扫描线程逐条查 KEV / 情报行镶嵌 KEV 标注
	wg.Add(2)
	for r := 0; r < 2; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = kb.IsKEV(fmt.Sprintf("CVE-2024-%04d", i))
				_ = kb.IsKEV(fmt.Sprintf("cve-2025-%04d", i))
				_ = kb.kevCount()
			}
		}()
	}
	wg.Wait()
	if n := kb.kevCount(); n != 2*iters {
		t.Fatalf("并发合并后 KEV 条数 = %d，期望 %d", n, 2*iters)
	}
	if !kb.IsKEV("CVE-2024-0499") || !kb.IsKEV("cve-2025-0000") {
		t.Fatal("并发合并后的条目应对读侧可见")
	}
}
