package intel

// C2-09 回归：NVD API 分页同步失败必须保留已抓页，并支持下次从断点续传。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSyncNVDResumeAfterPageFailure(t *testing.T) {
	const (
		cve1 = `{"cve":{"id":"CVE-2099-1001","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"first"}]}}`
		cve2 = `{"cve":{"id":"CVE-2099-1002","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"second"}]}}`
	)
	var mu sync.Mutex
	failPage2 := true
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		fail := failPage2
		mu.Unlock()
		switch {
		case strings.Contains(r.URL.RawQuery, "startIndex=0"):
			_, _ = w.Write([]byte(nvdPage(4001, cve1)))
		case strings.Contains(r.URL.RawQuery, "startIndex=2000"):
			if fail {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(nvdPage(4001, cve2)))
		default:
			// 越过末页：空 vulnerabilities（模拟 NVD API 尾部）
			_, _ = w.Write([]byte(`{"totalResults":4001,"resultsPerPage":1,"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()

	oldURL, oldKeyWait, oldRetry := nvdAPIURL, nvdKeyWait, nvdRetryWait
	nvdAPIURL = srv.URL
	nvdKeyWait = time.Millisecond
	nvdRetryWait = time.Millisecond
	defer func() { nvdAPIURL, nvdKeyWait, nvdRetryWait = oldURL, oldKeyWait, oldRetry }()

	out := filepath.Join(t.TempDir(), "nvd.json.gz")
	progPath := nvdProgressPath(out)

	// 第一轮：page2 恒失败 → 必须返回错误，并把已抓的 page1 写入断点文件。
	if err := SyncNVD(out, "k", nil); err == nil {
		t.Fatal("page2 失败应返回错误")
	} else if !strings.Contains(err.Error(), "断点") {
		t.Errorf("错误信息应提示断点可续传: %v", err)
	}
	if _, err := os.Stat(progPath); err != nil {
		t.Fatalf("失败后应保留断点文件: %v", err)
	}
	p, err := loadNVDProgress(progPath)
	if err != nil || p == nil {
		t.Fatalf("断点文件不可读: %v", err)
	}
	if len(p.Entries) != 1 || p.StartIndex != 2000 || p.Entries[0].CVE != "CVE-2099-1001" {
		t.Fatalf("断点内容异常: start=%d entries=%+v", p.StartIndex, p.Entries)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("失败时不应写出正式产物（避免半成品被当作完整镜像）: %v", err)
	}

	// 第二轮：page2 恢复 → 自动从 startIndex=2000 续传，不再重抓 page1。
	mu.Lock()
	failPage2 = false
	queries = nil
	mu.Unlock()
	if err := SyncNVD(out, "k", nil); err != nil {
		t.Fatalf("续传应成功: %v", err)
	}
	mu.Lock()
	gotQueries := append([]string(nil), queries...)
	mu.Unlock()
	if len(gotQueries) == 0 || !strings.Contains(gotQueries[0], "startIndex=2000") {
		t.Fatalf("续传应从断点 startIndex=2000 开始，实得请求序列 %v", gotQueries)
	}
	for _, q := range gotQueries {
		if strings.Contains(q, "startIndex=0") {
			t.Fatalf("续传不应重抓第一页: %v", gotQueries)
		}
	}
	s, err := LoadNVD(out)
	if err != nil || s == nil {
		t.Fatalf("续传产物不可读: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("续传后应合并两页共 2 条，实得 %d", s.Len())
	}
	if _, err := os.Stat(progPath); !os.IsNotExist(err) {
		t.Fatalf("成功后应删除断点文件: %v", err)
	}
}

// TestParseNVDPageAllRejectedKeepsPaging C2-09 附属修复：整页都是 Rejected
// 时不能把 len(entries)==0 当成"没有下一页"而提前结束全量同步。
func TestParseNVDPageAllRejectedKeepsPaging(t *testing.T) {
	rejected := `{"cve":{"id":"CVE-2099-1999","vulnStatus":"Rejected"}}`
	entries, meta, err := parseNVDPage([]byte(nvdPage(4002, rejected)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || meta.skipped != 1 {
		t.Fatalf("Rejected 应被跳过: entries=%d skipped=%d", len(entries), meta.skipped)
	}
	if meta.raw != 1 || meta.total != 4002 {
		t.Fatalf("原始条数/total 元信息异常: %+v", meta)
	}
}
