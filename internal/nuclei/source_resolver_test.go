package nuclei

// CP-10 接线单测：check id → 模板来源解析 + 每来源通过率。

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// TestTemplateIDFromCheckID check id 前缀/分组后缀解析。
func TestTemplateIDFromCheckID(t *testing.T) {
	cases := []struct {
		in     string
		wantID string
		wantOK bool
	}{
		{"nuclei-CVE-2024-1234", "CVE-2024-1234", true},
		{"nuclei-CVE-2024-1234~g2", "CVE-2024-1234", true},
		{"nuclei-CVE-2024-1234~p1", "CVE-2024-1234", true},
		{"nuclei-", "", false},
		{"nuclei-~g1", "", false},
		{"csrf-form", "", false}, // 原生 check
		{"", "", false},
	}
	for _, c := range cases {
		id, ok := TemplateIDFromCheckID(c.in)
		if id != c.wantID || ok != c.wantOK {
			t.Fatalf("TemplateIDFromCheckID(%q)=(%q,%v), want (%q,%v)",
				c.in, id, ok, c.wantID, c.wantOK)
		}
	}
}

// TestSourceResolver check id → 来源：模板文件名对齐 / native / unknown。
func TestSourceResolver(t *testing.T) {
	entries := []Entry{
		{Path: "http/cves/2024/CVE-2024-1234.yaml", Source: "cves"},
		{Path: "afrog/CNVD/2018/CNVD-2018-0001.yaml", Source: "afrog"},
		{Path: "legacy/old.yaml", Source: "legacy"}, // 文件名 old.yaml → 模板 id old
		{Path: "network/redis-detect.yaml"},         // Source 空 → 路径归一 network
	}
	resolve := SourceResolver(entries)
	cases := []struct{ checkID, want string }{
		{"nuclei-CVE-2024-1234", "cves"},
		{"nuclei-CVE-2024-1234~g3", "cves"},
		{"nuclei-CNVD-2018-0001", "afrog"},
		{"nuclei-old", "legacy"},
		{"nuclei-redis-detect", "network"},
		{"nuclei-nonexistent", UnknownCheckSource},
		{"csrf-form", NativeCheckSource},
	}
	for _, c := range cases {
		if got := resolve(c.checkID); got != c.want {
			t.Fatalf("resolve(%q)=%q, want %q", c.checkID, got, c.want)
		}
	}

	// 空索引：模板 check 全 unknown，原生仍 native
	empty := SourceResolver(nil)
	if got := empty("nuclei-anything"); got != UnknownCheckSource {
		t.Fatalf("空索引导致 %q, want unknown", got)
	}
	if got := empty("csrf-form"); got != NativeCheckSource {
		t.Fatalf("空索引下原生 check=%q, want native", got)
	}
}

// TestSourcePassRates 端到端：索引 + CheckRun → 每来源 runs/pass/fail/命中率。
func TestSourcePassRates(t *testing.T) {
	entries := []Entry{
		{Path: "http/cves/2024/CVE-2024-1234.yaml", Source: "cves"},
		{Path: "afrog/CNVD/CNVD-2018-0001.yaml", Source: "afrog"},
	}
	runs := []checks.CheckRun{
		{Check: "nuclei-CVE-2024-1234", Status: checks.RunStatusExecuted, Hit: true},
		{Check: "nuclei-CVE-2024-1234~g2", Status: checks.RunStatusExecuted},
		{Check: "nuclei-CVE-2024-1234~p1", Status: checks.RunStatusNotExecuted, Reason: "timeout"},
		{Check: "nuclei-CNVD-2018-0001", Status: checks.RunStatusExecuted},
		{Check: "csrf-form", Status: checks.RunStatusExecuted},
		{Check: "nuclei-unknown-x", Status: checks.RunStatusNotExecuted},
	}
	got := SourcePassRates(entries, runs)
	if len(got) != 4 {
		t.Fatalf("来源数=%d, want 4: %+v", len(got), got)
	}
	want := []checks.SourcePassRate{
		{Source: "afrog", Runs: 1, Pass: 1, Fail: 0, PassRate: 1, Hits: 0, HitRate: 0},
		{Source: "cves", Runs: 3, Pass: 2, Fail: 1, PassRate: 2.0 / 3.0, Hits: 1, HitRate: 0.5},
		{Source: "native", Runs: 1, Pass: 1, Fail: 0, PassRate: 1, Hits: 0, HitRate: 0},
		{Source: "unknown", Runs: 1, Pass: 0, Fail: 1, PassRate: 0, Hits: 0, HitRate: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("来源数不符: got=%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 行不符\n got=%+v\nwant=%+v", i, got[i], want[i])
		}
	}
	// 空输入
	if got := SourcePassRates(nil, nil); got != nil {
		t.Fatalf("空输入应返回 nil: %+v", got)
	}
}
