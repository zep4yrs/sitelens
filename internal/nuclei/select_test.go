package nuclei

import (
	"testing"
)

func TestSelectTagPriorityAndLRU(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", Tags: []string{"wordpress"}, Sev: "high"},
		{Path: "b.yaml", Tags: []string{"nginx"}, Sev: "critical"},
		{Path: "c.yaml", Tags: []string{"misc"}, Sev: "low"},
		{Path: "d.yaml", Tags: []string{"misc"}, Sev: "info"},
	}
	lastRun := map[string]int64{}
	// tag 命中置顶：a.yaml（wordpress）+ 其余 LRU 两条（c/d 从未运行优先于 b）
	sel := Select(entries, map[string]bool{"wordpress": true}, "", 3, lastRun)
	if len(sel) != 3 || sel[0].Path != "a.yaml" {
		t.Fatalf("tag 置顶失败: %+v", sel)
	}
	// 第二轮：a 刚跑过应排最后，其余按 LRU 升序
	sel2 := Select(entries, map[string]bool{"wordpress": true}, "", 3, lastRun)
	if len(sel2) != 3 || sel2[0].Path != "a.yaml" {
		t.Fatalf("第二轮 tag 仍应置顶: %+v", sel2)
	}
}

func TestSelectLRUFairness(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", Tags: []string{"misc"}, Sev: "low"},
		{Path: "b.yaml", Tags: []string{"misc"}, Sev: "low"},
		{Path: "c.yaml", Tags: []string{"misc"}, Sev: "low"},
		{Path: "d.yaml", Tags: []string{"misc"}, Sev: "low"},
	}
	lastRun := map[string]int64{}
	// 容量 2：三次选择应覆盖全部 4 条中的前几名且不重复同一批
	seen := map[string]bool{}
	for round := 0; round < 2; round++ {
		sel := Select(entries, map[string]bool{}, "", 2, lastRun)
		if len(sel) != 2 {
			t.Fatalf("每轮应选 2 条: %+v", sel)
		}
		for _, e := range sel {
			if seen[e.Path] {
				t.Fatalf("LRU 调度不应在未轮完一遍前重复: %s", e.Path)
			}
			seen[e.Path] = true
			lastRun[e.Path] = int64(round*1000 + 100)
		}
	}
	// 两轮覆盖 4 条中 4 条的不同条目（LRU 保证不重不漏推进）
	if len(seen) != 4 {
		t.Fatalf("两轮应覆盖 4 条: %v", seen)
	}
}

func TestSelectRelevanceRanking(t *testing.T) {
	entries := []Entry{
		{Path: "z-unrelated.yaml", Name: "Something Else", Tags: []string{"misc"}, Sev: "low"},
		{Path: "m-wp-firewall.yaml", Name: "WordPress Firewall Detect", Tags: []string{"wp-plugin"}, Sev: "medium"},
		{Path: "k-wp-backup.yaml", Name: "WordPress Backup Exposure", Tags: []string{"wp-plugin"}, Sev: "high"},
		{Path: "a-other.yaml", Name: "Other Thing", Tags: []string{"misc"}, Sev: "info"},
	}
	lastRun := map[string]int64{}
	// 无 tag 硬命中，但查询词 "wordpress backup" 与两条 wp 模板词面重合，
	// 在 LRU 同层（都从未运行）内应按相关度排前
	sel := Select(entries, map[string]bool{}, "wordpress backup 泄露", 2, lastRun)
	if len(sel) < 2 || sel[0].Path != "k-wp-backup.yaml" || sel[1].Path != "m-wp-firewall.yaml" {
		t.Fatalf("相关度排序失败: %+v", sel)
	}
}
