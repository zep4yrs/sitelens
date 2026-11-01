package checks

// CP-10 每来源通过率统计单测：语义 / 归一 / 排序 / 适配器。

import (
	"reflect"
	"testing"
)

// TestAggregateBySource 基础聚合：pass=executed、fail=not_executed、hit 单列。
func TestAggregateBySource(t *testing.T) {
	stats := []RunStat{
		{Source: "cves", Status: RunStatusExecuted, Hit: true},
		{Source: "cves", Status: RunStatusExecuted, Hit: false},
		{Source: "cves", Status: RunStatusNotExecuted, Hit: true}, // 未执行即使 Hit 也不算
		{Source: "afrog", Status: RunStatusExecuted, Hit: true},
		{Source: "afrog", Status: RunStatusExecuted, Hit: false},
		{Source: "", Status: RunStatusNotExecuted}, // 空来源 → unknown
	}
	got := AggregateBySource(stats)
	if len(got) != 3 {
		t.Fatalf("来源数=%d, want 3: %+v", len(got), got)
	}
	want := []SourcePassRate{
		{Source: "afrog", Runs: 2, Pass: 2, Fail: 0, PassRate: 1, Hits: 1, HitRate: 0.5},
		{Source: "cves", Runs: 3, Pass: 2, Fail: 1, PassRate: 2.0 / 3.0, Hits: 1, HitRate: 0.5},
		{Source: "unknown", Runs: 1, Pass: 0, Fail: 1, PassRate: 0, Hits: 0, HitRate: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("聚合结果不符\n got=%+v\nwant=%+v", got, want)
	}
}

// TestAggregateBySourceNormalize 来源大小写/空白归一、状态大小写归一、
// 未知状态按 fail 处理（保守）。
func TestAggregateBySourceNormalize(t *testing.T) {
	got := AggregateBySource([]RunStat{
		{Source: " CVES ", Status: " EXECUTED ", Hit: true},
		{Source: "cves", Status: "skipped", Hit: true}, // 未知状态 → fail，hit 不计
	})
	if len(got) != 1 {
		t.Fatalf("归一后应合并为 1 个来源: %+v", got)
	}
	row := got[0]
	if row.Source != "cves" || row.Runs != 2 || row.Pass != 1 || row.Fail != 1 ||
		row.Hits != 1 || row.PassRate != 0.5 || row.HitRate != 1 {
		t.Fatalf("归一/状态语义不符: %+v", row)
	}
}

// TestAggregateBySourceEmpty 空输入返回 nil；无记录来源不出现。
func TestAggregateBySourceEmpty(t *testing.T) {
	if got := AggregateBySource(nil); got != nil {
		t.Fatalf("nil 输入应返回 nil: %+v", got)
	}
	if got := AggregateBySource([]RunStat{}); got != nil {
		t.Fatalf("空切片应返回 nil: %+v", got)
	}
}

// TestRunStatsFromCheckRuns resolver nil/空返回都归 unknown。
func TestRunStatsFromCheckRuns(t *testing.T) {
	runs := []CheckRun{
		{Check: "nuclei-CVE-2024-1", Status: RunStatusExecuted, Hit: true},
		{Check: "nuclei-CVE-2024-2", Status: RunStatusNotExecuted, Reason: "timeout"},
		{Check: "csrf-form", Status: RunStatusExecuted, Hit: false},
	}
	resolve := func(id string) string {
		switch id {
		case "nuclei-CVE-2024-1":
			return "cves"
		case "nuclei-CVE-2024-2":
			return "cves"
		}
		return "native"
	}
	stats := RunStatsFromCheckRuns(runs, resolve)
	if len(stats) != 3 {
		t.Fatalf("RunStat 数=%d, want 3", len(stats))
	}
	if stats[0].Source != "cves" || !stats[0].Hit || stats[0].Status != RunStatusExecuted {
		t.Fatalf("resolver 映射不符: %+v", stats[0])
	}
	// nil resolver → 全部 unknown
	for _, st := range RunStatsFromCheckRuns(runs, nil) {
		if st.Source != "" {
			t.Fatalf("nil resolver 应返回空来源: %+v", st)
		}
	}
	if got := RunStatsFromCheckRuns(nil, resolve); got != nil {
		t.Fatalf("nil 输入应返回 nil: %+v", got)
	}
}

// TestAggregateCheckRuns 组合入口与分步调用一致。
func TestAggregateCheckRuns(t *testing.T) {
	runs := []CheckRun{
		{Check: "nuclei-a", Status: RunStatusExecuted, Hit: true},
		{Check: "nuclei-b", Status: RunStatusExecuted},
		{Check: "native-x", Status: RunStatusNotExecuted},
	}
	resolve := func(id string) string {
		if id == "nuclei-a" || id == "nuclei-b" {
			return "afrog"
		}
		return "native"
	}
	got := AggregateCheckRuns(runs, resolve)
	want := []SourcePassRate{
		{Source: "afrog", Runs: 2, Pass: 2, Fail: 0, PassRate: 1, Hits: 1, HitRate: 0.5},
		{Source: "native", Runs: 1, Pass: 0, Fail: 1, PassRate: 0, Hits: 0, HitRate: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("组合入口结果不符\n got=%+v\nwant=%+v", got, want)
	}
}
