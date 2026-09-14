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
  "weaknesses":[
    {"type":"Primary","description":[{"lang":"en","value":"CWE-89"}]},
    {"type":"Secondary","description":[{"lang":"en","value":"CWE-22"},{"lang":"en","value":"NVD-CWE-noinfo"}]},
    {"type":"Secondary","description":[{"lang":"en","value":"CWE-89"}]}
  ],
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
	// A2 瘦身后 NVDProd 只保留 VP（版本边界无消费方，已核实）。
	if len(e.Prods) != 2 || e.Prods[0].VP != "example/example_app" ||
		e.Prods[1].VP != "example/example_pro" {
		t.Errorf("CPE 产品解析不对（应只留 vendor/product）: %+v", e.Prods)
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

// TestSyncNVDParsesCWEs：NVD weaknesses → NVDEntry.CWEs（去重升序、过滤占位值）。
func TestSyncNVDParsesCWEs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdPage(1, nvdCVE1)))
	}))
	defer srv.Close()
	oldURL, oldWait := nvdAPIURL, nvdKeyWait
	nvdAPIURL, nvdKeyWait = srv.URL, time.Millisecond
	defer func() { nvdAPIURL, nvdKeyWait = oldURL, oldWait }()

	out := filepath.Join(t.TempDir(), "nvd.json.gz")
	if err := SyncNVD(out, "k", nil); err != nil {
		t.Fatal(err)
	}
	store, err := LoadNVD(out)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := store.ByCVE("CVE-2099-0001")
	if !ok {
		t.Fatal("条目应在库")
	}
	// CWE-89 重复一次、CWE-22 一次、NVD-CWE-noinfo 应被过滤 → [CWE-22 CWE-89]
	got := e.CWEs
	if len(got) != 2 || got[0] != "CWE-22" || got[1] != "CWE-89" {
		t.Fatalf("CWEs = %v，期望 [CWE-22 CWE-89]（去重升序且过滤占位值）", got)
	}
	// 访问器返回副本。
	c := store.CWEsFor("cve-2099-0001")
	if len(c) != 2 {
		t.Fatalf("CWEsFor = %v", c)
	}
	c[0] = "MUTATED"
	if store.CWEsFor("CVE-2099-0001")[0] != "CWE-22" {
		t.Error("CWEsFor 应返回副本")
	}
	// 未知 CVE → nil。
	if store.CWEsFor("CVE-9999-0000") != nil {
		t.Error("未知 CVE 应返回 nil")
	}
}

// TestIsCWENumber：编号与占位值区分。
func TestIsCWENumber(t *testing.T) {
	yes := []string{"CWE-89", "CWE-1", "CWE-1336"}
	no := []string{"NVD-CWE-noinfo", "NVD-CWE-Other", "CWE-", "CWE-79x", "", "cwe-79"}
	for _, s := range yes {
		if !isCWENumber(s) {
			t.Errorf("%q 应判为编号", s)
		}
	}
	for _, s := range no {
		if isCWENumber(s) {
			t.Errorf("%q 不应判为编号", s)
		}
	}
}

// TestNVDVersion2：写出文件版本为 3（A2 瘦身 prods 后；v1/v2 数据仍可读）。
func TestNVDVersion2(t *testing.T) {
	// 通过一次真实写出验证版本号。
	dir := t.TempDir()
	out := filepath.Join(dir, "n.json.gz")
	if err := writeNVDFile(out, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var box struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		t.Fatal(err)
	}
	if box.Version != 3 {
		t.Errorf("写出版本 = %d，期望 3（A2 瘦身后）", box.Version)
	}
}

// TestLoadNVDUnsortedInput 回归测试：文件非全局有序时，索引仍必须指向正确条目。
//
// 背景（真实 bug）：byCVE/byProd 存 *NVDEntry 指针，早期实现「先建索引、后排序」，
// sort 移动元素会让指针悬空指向错位条目——表现为查到其它 CVE 的 CWE/CVSS。
// 旧数据文件恰好有序（sort 为 no-op）掩盖了问题；feed 按年拼接的文件非有序才暴露。
func TestLoadNVDUnsortedInput(t *testing.T) {
	// 故意逆序写入三条，且各带不同的 CWEs 与 Score 以检测错位。
	entries := []NVDEntry{
		{CVE: "CVE-3000-0003", Score: 3.3, CWEs: []string{"CWE-3"}},
		{CVE: "CVE-3000-0001", Score: 1.1, CWEs: []string{"CWE-1"}},
		{CVE: "CVE-3000-0002", Score: 2.2, CWEs: []string{"CWE-2"}},
	}
	out := filepath.Join(t.TempDir(), "u.json.gz")
	if err := writeNVDFile(out, entries); err != nil {
		t.Fatal(err)
	}
	store, err := LoadNVD(out)
	if err != nil {
		t.Fatal(err)
	}
	// 每条都必须查到自己的 CWE 与分数。
	want := map[string]struct {
		cwe   string
		score float64
	}{
		"CVE-3000-0001": {"CWE-1", 1.1},
		"CVE-3000-0002": {"CWE-2", 2.2},
		"CVE-3000-0003": {"CWE-3", 3.3},
	}
	for cve, w := range want {
		e, ok := store.ByCVE(cve)
		if !ok {
			t.Fatalf("%s 未找到", cve)
		}
		if len(e.CWEs) == 0 || e.CWEs[0] != w.cwe {
			t.Errorf("%s CWEs = %v，期望 [%s]（指针错位会查到他人数据）", cve, e.CWEs, w.cwe)
		}
		if e.Score != w.score {
			t.Errorf("%s Score = %.1f，期望 %.1f", cve, e.Score, w.score)
		}
	}
	// list 应已按 CVE 升序。
	if store.list[0].CVE != "CVE-3000-0001" {
		t.Errorf("list 未排序：首条 %s", store.list[0].CVE)
	}
}

// TestNVDPathLazyLoading：A3 惰性加载——只挂路径不加载；HasNVD/NVDCount
// 不触发；首次真正取数（NVD()）才解码，且只解码一次（sync.Once）。
func TestNVDPathLazyLoading(t *testing.T) {
	// 造一个小 NVD 文件。
	entries := []NVDEntry{
		{CVE: "CVE-3000-0001", Score: 9.9, CWEs: []string{"CWE-89"}},
	}
	out := filepath.Join(t.TempDir(), "n.json.gz")
	if err := writeNVDFile(out, entries); err != nil {
		t.Fatal(err)
	}

	kb := &KB{}
	kb.AttachNVDPath(out)

	// 1) 挂路径后：HasNVD=true，但**未加载**（NVDCount 仍 0）。
	if !kb.HasNVD() {
		t.Error("AttachNVDPath 后 HasNVD 应为 true")
	}
	if n := kb.NVDCount(); n != 0 {
		t.Errorf("仅挂路径时 NVDCount 应为 0（未加载），实得 %d", n)
	}
	if kb.nvd != nil {
		t.Error("仅挂路径时不应已解码索引")
	}

	// 2) 存在性判断不得触发加载（关键：避免判断本身拉起 1.7GB）。
	_ = kb.HasNVD()
	_ = kb.NVDCount()
	if kb.nvd != nil {
		t.Error("HasNVD/NVDCount 不应触发惰性加载")
	}

	// 3) 真正取数才加载。
	s := kb.NVD()
	if s == nil {
		t.Fatal("NVD() 应触发加载并返回索引")
	}
	if e, ok := s.ByCVE("CVE-3000-0001"); !ok || e.Score != 9.9 {
		t.Errorf("加载后应能查到条目：%+v", e)
	}
	if kb.NVDCount() != 1 {
		t.Errorf("加载后 NVDCount 应为 1，实得 %d", kb.NVDCount())
	}
	// 4) 幂等：再次取数返回同一实例（未重复解码）。
	if kb.NVD() != s {
		t.Error("重复取数应返回同一实例")
	}
}

// TestNVDFillTriggersLazyLoad：CVSS/CWE 补全路径自动触发惰性加载。
func TestNVDFillTriggersLazyLoad(t *testing.T) {
	entries := []NVDEntry{{CVE: "CVE-3000-0002", Score: 7.5, Sev: "high", CWEs: []string{"CWE-79"}}}
	out := filepath.Join(t.TempDir(), "n.json.gz")
	if err := writeNVDFile(out, entries); err != nil {
		t.Fatal(err)
	}
	kb := &KB{}
	kb.AttachNVDPath(out)
	if kb.nvd != nil {
		t.Fatal("前置：不应已加载")
	}
	f := Finding{CVE: "CVE-3000-0002"}
	kb.nvdFill(&f) // 应触发加载并补全
	if f.CVSSScore != 7.5 {
		t.Errorf("CVSS 应被补全为 7.5，实得 %v", f.CVSSScore)
	}
	if len(f.CWEs) == 0 || f.CWEs[0] != "CWE-79" {
		t.Errorf("CWE 应被补全，实得 %v", f.CWEs)
	}
}
