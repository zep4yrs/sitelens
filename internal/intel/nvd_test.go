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
	"time"
)

// 测试页数据：两页各 1 条（覆盖 v3.1 评分 / Rejected 跳过 / CPE 边界解析）。
func nvdPage(total int, cveJSON string) string {
	return `{"totalResults":` + itoa(total) + `,"resultsPerPage":1,"vulnerabilities":[` + cveJSON + `]}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

const nvdCVE1 = `{"cve":{
  "id":"CVE-2099-0001","published":"2099-01-01T00:00:00.000",
  "lastModified":"2099-01-02T00:00:00.000","vulnStatus":"Analyzed",
  "descriptions":[{"lang":"en","value":"A test vulnerability in ExampleApp allows reading files."}],
  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseSeverity":"CRITICAL"}}]},
  "configurations":[{"nodes":[{"cpeMatch":[
    {"criteria":"cpe:2.3:a:example:example_app:1.0:*:*:*:*:*:*:*","versionEndExcluding":"1.2.3"},
    {"criteria":"cpe:2.3:a:example:example_pro:2.0:beta:*:*:*:*:*:*:*"}
  ]}]}]
}}`

const nvdCVE2 = `{"cve":{
  "id":"CVE-2099-0002","vulnStatus":"Rejected",
  "descriptions":[{"lang":"en","value":"Rejected reason."}]}
}`

func TestSyncNVDRoundtrip(t *testing.T) {
	page1 := nvdPage(2001, nvdCVE1) // totalResults=2001 逼出第二页
	page2 := nvdPage(2001, nvdCVE2)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "resultsPerPage=2000") {
			t.Errorf("应按 resultsPerPage=2000 翻页，得到 %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 0 {
			_, _ = w.Write([]byte(page1))
		} else {
			_, _ = w.Write([]byte(page2))
		}
		calls++
	}))
	defer srv.Close()

	oldURL, oldWait := nvdAPIURL, nvdKeyWait
	nvdAPIURL = srv.URL
	nvdKeyWait = time.Millisecond
	defer func() { nvdAPIURL, nvdKeyWait = oldURL, oldWait }()

	out := filepath.Join(t.TempDir(), "nvd.json.gz")
	if err := SyncNVD(out, "test-key", nil); err != nil {
		t.Fatalf("SyncNVD: %v", err)
	}
	if calls != 2 {
		t.Fatalf("应请求 2 页，实际 %d", calls)
	}

	store, err := LoadNVD(out)
	if err != nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("Rejected 条目应跳过，实际 %d 条", store.Len())
	}
	e, ok := store.ByCVE("cve-2099-0001")
	if !ok {
		t.Fatal("CVE-2099-0001 应在库")
	}
	if e.Score != 9.8 || e.Sev != "critical" ||
		!strings.HasPrefix(e.Vector, "CVSS:3.1/") {
		t.Errorf("评分投影不完整: %+v", e)
	}
	if len(e.Prods) != 2 || e.Prods[0].VP != "example/example_app" ||
		e.Prods[0].EE != "1.2.3" {
		t.Errorf("CPE 约束解析不对: %+v", e.Prods)
	}
	if e.Prods[1].V != "2.0" {
		t.Errorf("cpe 第 6 段应取版本: %+v", e.Prods[1])
	}
	// 产品检索
	if hits := store.ByProduct("example_app", 10); len(hits) != 1 {
		t.Errorf("ByProduct(example_app) 应命中 1 条，得到 %d", len(hits))
	}
}

func TestLoadNVDMissingFile(t *testing.T) {
	s, err := LoadNVD(filepath.Join(os.TempDir(), "no-such-nvd-file.json.gz"))
	if err != nil || s != nil {
		t.Fatalf("缺失文件应返回 (nil, nil)，得到 (%v, %v)", s, err)
	}
}

func TestNVDFillEnrichesMissingCVSS(t *testing.T) {
	kb := &KB{}
	data, _ := json.Marshal([]NVDEntry{{
		CVE: "CVE-2099-0001", Score: 9.8, Sev: "critical",
	}})
	dir := t.TempDir()
	p := filepath.Join(dir, "nvd.json.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	_ = json.NewEncoder(gz).Encode(map[string]any{"cves": json.RawMessage(data)})
	_ = gz.Close()
	_ = f.Close()
	store, err2 := LoadNVD(p)
	if err2 != nil {
		t.Fatal(err2)
	}
	kb.AttachNVD(store)
	fv := Finding{CVE: "CVE-2099-0001"}
	kb.nvdFill(&fv)
	if fv.CVSSScore != 9.8 || fv.CVSSSev != "critical" {
		t.Errorf("nvdFill 未补全: %+v", fv)
	}
	// 已有评分不被覆盖
	f2 := Finding{CVE: "CVE-2099-0001", CVSSScore: 5.0, CVSSSev: "medium"}
	kb.nvdFill(&f2)
	if f2.CVSSScore != 5.0 {
		t.Errorf("已有评分不应被覆盖: %+v", f2)
	}
	// 未挂载时安全
	kb2 := &KB{}
	f3 := Finding{CVE: "CVE-2099-0001"}
	kb2.nvdFill(&f3)
	if f3.CVSSScore != 0 {
		t.Errorf("未挂载不应填充: %+v", f3)
	}
}
