package server

// BT-03 结果 diff 测试：指纹稳定性（易变字段不入指纹）、集合差、URL 归一化、
// 只取同 URL 最近两条历史。

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// newDiffTestServer 构造带历史存储的 Server（不启动 HTTP 服务）。
func newDiffTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir, 100)
	if err != nil {
		t.Fatalf("打开历史存储失败: %v", err)
	}
	cfg := &config.Config{
		Store: config.StoreConfig{DataDir: dir},
		Web:   config.WebConfig{HistoryCap: 100},
	}
	s := &Server{st: store.WrapTiered(st, 0)}
	s.cfgPtr.Store(cfg)
	return s, st
}

// saveTestScan 直接落一条历史扫描结果（只填 diff 相关字段）。
func saveTestScan(t *testing.T, st *store.Store, rawURL string, vulns []intel.Finding, verified []map[string]any) int64 {
	t.Helper()
	res := &engine.Result{
		URL:             rawURL,
		Host:            "example.com",
		Title:           "t",
		Status:          200,
		ScannedAt:       "2026-01-01T00:00:00Z",
		Vulnerabilities: vulns,
		Verified:        verified,
		Extras:          map[string]any{},
		Pages:           []engine.PageInfo{},
	}
	return st.Save(res, map[string]any{"test": true})
}

func TestDiffURLNewAndFixed(t *testing.T) {
	s, st := newDiffTestServer(t)
	const base = "https://example.com/app"

	vulnOld := intel.Finding{CVE: "CVE-2024-1111", Tech: "nginx", Severity: "high", Desc: "旧措辞"}
	plain := intel.Finding{Product: "acme", Name: "bad-config", Tech: "acme", Type: "config"}
	csp := map[string]any{"check": "csp-missing", "src": "passive", "url": base, "evidence": "旧证据"}

	// 第一次：CVE-2024-1111 + 无 CVE 的配置项 + csp-missing。
	saveTestScan(t, st, base, []intel.Finding{vulnOld, plain}, []map[string]any{csp})

	// 第二次：同 CVE（描述/评分/严重度变化不应算新增）、新增 CVE-2024-2222、
	// plain 消失（=已修复）、csp-missing 仍在、新增 x-frame-options-missing。
	vulnSame := intel.Finding{CVE: "cve-2024-1111", Tech: "nginx", Severity: "critical",
		Desc: "新措辞", CVSSScore: 9.8}
	vulnNew := intel.Finding{CVE: "CVE-2024-2222"}
	xfo := map[string]any{"check": "x-frame-options-missing", "src": "passive", "url": base}
	saveTestScan(t, st, base, []intel.Finding{vulnSame, vulnNew}, []map[string]any{csp, xfo})

	newN, fixedN, ok := s.DiffURL(base)
	if !ok {
		t.Fatal("两次历史应可 diff")
	}
	if newN != 2 || fixedN != 1 {
		t.Fatalf("期望 新增=2（CVE-2222 + x-frame）修复=1（bad-config），实得 新增=%d 修复=%d",
			newN, fixedN)
	}
}

func TestDiffURLRequiresTwoScans(t *testing.T) {
	s, st := newDiffTestServer(t)
	if _, _, ok := s.DiffURL("https://example.com"); ok {
		t.Fatal("无历史时 ok 应为 false")
	}
	saveTestScan(t, st, "https://example.com", []intel.Finding{{CVE: "CVE-1"}}, nil)
	if _, _, ok := s.DiffURL("https://example.com"); ok {
		t.Fatal("只有一条历史时 ok 应为 false")
	}
	if _, _, ok := s.DiffURL("  "); ok {
		t.Fatal("空 URL 应 ok=false")
	}
	if _, _, ok := s.DiffURL("https://other.example.com"); ok {
		t.Fatal("不同 URL 应 ok=false")
	}
	var bare Server // st == nil
	if _, _, ok := bare.DiffURL("https://example.com"); ok {
		t.Fatal("无历史存储时 ok 应为 false")
	}
}

func TestDiffURLUsesLatestTwoScans(t *testing.T) {
	s, st := newDiffTestServer(t)
	const base = "https://example.com/x"
	a := intel.Finding{CVE: "CVE-2024-0001"}
	b := intel.Finding{CVE: "CVE-2024-0002"}
	saveTestScan(t, st, base, []intel.Finding{a}, nil)    // 第 1 次
	saveTestScan(t, st, base, []intel.Finding{a, b}, nil) // 第 2 次
	saveTestScan(t, st, base, []intel.Finding{a}, nil)    // 第 3 次
	newN, fixedN, ok := s.DiffURL(base)
	if !ok {
		t.Fatal("应可 diff")
	}
	// 只应比较最近两次（第 2 次 → 第 3 次）：b 被修复，无新增。
	if newN != 0 || fixedN != 1 {
		t.Fatalf("期望 新增=0 修复=1（只比较最近两次），实得 新增=%d 修复=%d", newN, fixedN)
	}
}

func TestDiffURLKeyNormalization(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:443/a/": "https://example.com/a",
		"http://example.com:80":      "http://example.com/",
		"https://example.com/a?x=1":  "https://example.com/a?x=1",
		"https://example.com":        "https://example.com/",
		"  ":                         "",
		"not a url":                  "not a url",
	}
	for in, want := range cases {
		if got := diffURLKey(in); got != want {
			t.Fatalf("diffURLKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDiffURLMatchesNormalizedForms(t *testing.T) {
	s, st := newDiffTestServer(t)
	a := intel.Finding{CVE: "CVE-2024-3333"}
	b := intel.Finding{CVE: "CVE-2024-4444"}
	// 两个写法指向同一目标：默认端口/大小写/尾斜杠差异。
	saveTestScan(t, st, "https://Example.com:443/page/", []intel.Finding{a}, nil)
	saveTestScan(t, st, "https://example.com/page", []intel.Finding{a, b}, nil)
	newN, fixedN, ok := s.DiffURL("https://example.com/page/")
	if !ok || newN != 1 || fixedN != 0 {
		t.Fatalf("不同写法应视为同一 URL：ok=%v 新增=%d 修复=%d", ok, newN, fixedN)
	}
}

func TestVulnerabilityFingerprintStability(t *testing.T) {
	a := intel.Finding{CVE: "CVE-2024-1111", Severity: "high", Desc: "d1", CVSSScore: 7.5}
	b := intel.Finding{CVE: "cve-2024-1111", Severity: "low", Desc: "d2", CVSSScore: 3.1, Version: "1.2"}
	if vulnerabilityFingerprint(a) != vulnerabilityFingerprint(b) {
		t.Fatal("同一 CVE 的易变字段变化不应改变指纹")
	}
	c := intel.Finding{CVE: "CVE-2024-2222"}
	if vulnerabilityFingerprint(a) == vulnerabilityFingerprint(c) {
		t.Fatal("不同 CVE 指纹应不同")
	}
	// 无 CVE：用 Product|Name|Tech|Type，大小写归一。
	d := intel.Finding{Product: "acme", Name: "n", Tech: "t", Type: "ty"}
	d2 := intel.Finding{Product: "ACME", Name: "N", Tech: "T", Type: "TY", Severity: "x"}
	if vulnerabilityFingerprint(d) != vulnerabilityFingerprint(d2) {
		t.Fatal("无 CVE 条目的身份字段应大小写归一")
	}
	if vulnerabilityFingerprint(intel.Finding{}) != "" {
		t.Fatal("全空条目应无指纹")
	}
}

func TestVerifiedFingerprintStability(t *testing.T) {
	v1 := map[string]any{"check": "csp-missing", "src": "passive", "url": "https://example.com/a", "evidence": "e1"}
	v2 := map[string]any{"check": "csp-missing", "src": "passive", "url": "https://EXAMPLE.com/a/", "evidence": "e2", "severity": "high"}
	if verifiedFingerprint(v1) != verifiedFingerprint(v2) {
		t.Fatal("同一 check/url 的证据/严重度变化不应改变指纹")
	}
	v3 := map[string]any{"check": "csp-missing", "src": "passive", "url": "https://example.com/b"}
	if verifiedFingerprint(v1) == verifiedFingerprint(v3) {
		t.Fatal("不同 url 指纹应不同")
	}
	// check 缺失时退回 title。
	t1 := map[string]any{"title": "缺 CSP", "src": "passive", "url": "https://example.com/a"}
	t2 := map[string]any{"check": "缺 CSP", "src": "passive", "url": "https://example.com/a"}
	if verifiedFingerprint(t1) != verifiedFingerprint(t2) {
		t.Fatal("check 缺失应退回 title 作为身份")
	}
	if verifiedFingerprint(nil) != "" {
		t.Fatal("nil map 应无指纹")
	}
}

func TestDiffFingerprintsSets(t *testing.T) {
	prev := map[string]struct{}{"a": {}, "b": {}, "c": {}}
	cur := map[string]struct{}{"b": {}, "c": {}, "d": {}}
	newN, fixedN := diffFingerprints(prev, cur)
	if newN != 1 || fixedN != 1 {
		t.Fatalf("期望 新增=1 修复=1，实得 %d/%d", newN, fixedN)
	}
	if n, f := diffFingerprints(nil, nil); n != 0 || f != 0 {
		t.Fatalf("空集合应为 0/0，实得 %d/%d", n, f)
	}
}

func TestFindingFingerprintsSources(t *testing.T) {
	res := &engine.Result{
		Vulnerabilities: []intel.Finding{
			{CVE: "CVE-1"},
			{CVE: "CVE-1"}, // 同一次扫描内重复，按集合去重
			{},             // 无身份：忽略
		},
		Verified: []map[string]any{
			{"check": "c1", "src": "s"},
			{"check": ""}, // 无身份：忽略
			nil,
		},
	}
	if got := len(findingFingerprints(res)); got != 2 {
		t.Fatalf("应得到 2 个去重指纹（CVE-1 + c1），实得 %d", got)
	}
	if got := len(findingFingerprints(nil)); got != 0 {
		t.Fatalf("nil 结果应为空集合，实得 %d", got)
	}
}
