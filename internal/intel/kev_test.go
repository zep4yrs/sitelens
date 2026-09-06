package intel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
