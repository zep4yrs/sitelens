package nuclei

import "testing"

// CVE 通道优先级：声明目标受影响 CVE 的模板优先于 tag 命中，且不论其
// severity（「这台机器真的中的」 > 「tag 词面对得上」）。
func TestSelectCVEPriority(t *testing.T) {
	entries := []Entry{
		{Path: "sev-crit.yaml", Tags: []string{"nginx"}, Sev: "critical"},
		{Path: "cve-hit.yaml", Tags: []string{"misc"}, Sev: "info", CVEs: []string{"CVE-2021-1234"}},
		{Path: "other.yaml", Tags: []string{"misc"}, Sev: "low"},
	}
	cveSet := map[string]bool{"CVE-2021-1234": true}
	sel := SelectWithCVE(entries, map[string]bool{"nginx": true}, cveSet, "", 2, map[string]int64{})
	if len(sel) == 0 || sel[0].Path != "cve-hit.yaml" {
		t.Fatalf("CVE 命中应置顶（优先于 tag/severity）: %+v", sel)
	}
}

// cveSet 为空时行为与 Select 完全一致（零回归）。
func TestSelectWithCVENilEqualsSelect(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", Tags: []string{"wordpress"}, Sev: "high"},
		{Path: "b.yaml", Tags: []string{"misc"}, Sev: "low", CVEs: []string{"CVE-2020-1"}},
		{Path: "c.yaml", Tags: []string{"misc"}, Sev: "info"},
	}
	lr := map[string]int64{}
	got := SelectWithCVE(entries, map[string]bool{"wordpress": true}, nil, "x", 2, lr)
	want := Select(entries, map[string]bool{"wordpress": true}, "x", 2, lr)
	if len(got) != len(want) {
		t.Fatalf("条数不一致: %d vs %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Path != want[i].Path {
			t.Fatalf("顺序不一致 @%d: %q vs %q", i, got[i].Path, want[i].Path)
		}
	}
}

// CVE 通道不能破坏「全池迟早跑完一遍」：命中集本身有 2/3 预算上限，
// 且被截断的命中退回轮转池——连续多轮必须能覆盖到非命中模板。
func TestSelectCVEChannelRotationNotStarved(t *testing.T) {
	var entries []Entry
	for i := 0; i < 12; i++ {
		entries = append(entries, Entry{Path: "cve" + string(rune('a'+i)) + ".yaml", Sev: "info", CVEs: []string{"CVE-1"}})
	}
	for i := 0; i < 8; i++ {
		entries = append(entries, Entry{Path: "rest" + string(rune('a'+i)) + ".yaml", Sev: "info"})
	}
	lastRun := map[string]int64{}
	seenRest := false
	for round := 0; round < 6; round++ {
		sel := SelectWithCVE(entries, nil, map[string]bool{"CVE-1": true}, "", 6, lastRun)
		if len(sel) != 6 {
			t.Fatalf("每轮应选 6 条: %+v", sel)
		}
		now := int64(round + 1)
		for _, e := range sel {
			lastRun[e.Path] = now
			if len(e.CVEs) == 0 {
				seenRest = true
			}
		}
	}
	if !seenRest {
		t.Fatal("轮转被 CVE 命中集饿死：非命中模板一条都没跑到")
	}
}

func TestCountCVEHits(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", CVEs: []string{"cve-2020-1"}},
		{Path: "b.yaml", CVEs: []string{"CVE-2021-2"}},
		{Path: "c.yaml"},
	}
	if got := CountCVEHits(entries, map[string]bool{"CVE-2020-1": true}); got != 1 {
		t.Fatalf("CountCVEHits 大小写不敏感应有 1 条，实得 %d", got)
	}
	if got := CountCVEHits(entries, nil); got != 0 {
		t.Fatalf("空集合应为 0，实得 %d", got)
	}
}
