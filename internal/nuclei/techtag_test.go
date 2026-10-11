package nuclei

import "testing"

// TestTechTagsNormalization 技术名 → 模板 tag 归一：
// 显示名与 slug 之间的机械变换，必须两侧都对得上。
func TestTechTagsNormalization(t *testing.T) {
	cases := map[string][]string{
		"Microsoft IIS":             {"iis"},
		"Apache Tomcat":             {"tomcat"},
		"Oracle WebLogic Server":    {"weblogic"},
		"Microsoft Exchange Server": {"exchange"},
		"Spring Boot":               {"springboot", "spring-boot"},
		"jQuery":                    {"jquery"},
	}
	for name, want := range cases {
		got := map[string]bool{}
		for _, tg := range TechTags(name) {
			got[tg] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("TechTags(%q) 缺 %q，实得 %v", name, w, TechTags(name))
			}
		}
	}
	// 全名小写形态必须始终在（保持既有行为，不因归一丢命中）
	if got := TechTags("Some Product"); got[0] != "some product" {
		t.Fatalf("全名小写形态缺失：%v", got)
	}
	if len(TechTags("")) != 0 {
		t.Fatal("空技术名应返回空")
	}
}

// TestSelectTagHitBudget 命中集不得吃光预算：LRU 轮转的"全池迟早跑一遍"
// 是硬保证，tag 匹配变强不能把轮转饿死。
func TestSelectTagHitBudget(t *testing.T) {
	entries := []Entry{}
	for i := 0; i < 30; i++ {
		entries = append(entries, Entry{
			Path: string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".yaml",
			Tags: []string{"wordpress"}, Sev: "info",
		})
	}
	// 全部命中 tag：预算 9 → 命中集最多 9*2/3=6，至少 3 条留给轮转
	sel := Select(entries, map[string]bool{"wordpress": true}, "", 9, map[string]int64{})
	if len(sel) != 9 {
		t.Fatalf("应选满预算 9 条，实得 %d", len(sel))
	}
	seen := map[string]bool{}
	for _, e := range sel {
		seen[e.Path] = true
	}
	if len(seen) != 9 {
		t.Fatalf("同一次选择不应重复条目：%d", len(seen))
	}
}

// TestSelectRotationNotStarved 命中集的截断不能改变"选不出重复"的语义：
// 连续多轮必须能覆盖到非命中集里的模板。
func TestSelectRotationNotStarved(t *testing.T) {
	var entries []Entry
	for i := 0; i < 12; i++ {
		entries = append(entries, Entry{Path: "hit" + string(rune('a'+i)) + ".yaml", Tags: []string{"wordpress"}, Sev: "info"})
	}
	for i := 0; i < 8; i++ {
		entries = append(entries, Entry{Path: "rest" + string(rune('a'+i)) + ".yaml", Tags: []string{"misc"}, Sev: "info"})
	}
	lastRun := map[string]int64{}
	seenRest := false
	for round := 0; round < 6; round++ {
		sel := Select(entries, map[string]bool{"wordpress": true}, "", 6, lastRun)
		now := int64(round + 1)
		for _, e := range sel {
			lastRun[e.Path] = now
			if e.Tags[0] == "misc" {
				seenRest = true
			}
		}
	}
	if !seenRest {
		t.Fatal("轮转被命中集饿死：非 tag 命中的模板一条都没跑到")
	}
}

// TestSourceCounts 来源统计：官方 http/ 目录取类别名，协议根取首段。
func TestSourceCounts(t *testing.T) {
	entries := []Entry{
		{Path: "http/exposures/a.yaml"},
		{Path: "http/exposures/b.yaml"},
		{Path: "http/cves/c.yaml"},
		{Path: "legacy/d.yaml"},
		{Path: "network/e.yaml"},
	}
	got := SourceCounts(entries)
	want := map[string]int{"exposures": 2, "cves": 1, "legacy": 1, "network": 1}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("SourceCounts[%s]=%d want %d（全量 %v）", k, got[k], v, got)
		}
	}
}

// TestCountTagHits 匹配条数统计（调度可见性）。
func TestCountTagHits(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", Tags: []string{"nginx", "exposure"}},
		{Path: "b.yaml", Tags: []string{"tomcat"}},
		{Path: "c.yaml", Tags: []string{"misc"}},
	}
	if n := CountTagHits(entries, map[string]bool{"nginx": true}); n != 1 {
		t.Fatalf("CountTagHits=%d want 1", n)
	}
	if n := CountTagHits(entries, map[string]bool{}); n != 0 {
		t.Fatalf("空 tag 集应返回 0，实得 %d", n)
	}
	if n := CountTagHits(entries, map[string]bool{"nginx": true, "tomcat": true}); n != 2 {
		t.Fatalf("CountTagHits=%d want 2", n)
	}
}
