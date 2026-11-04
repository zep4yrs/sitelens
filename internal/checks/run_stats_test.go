package checks

// CP-10 每来源通过率统计单测：语义 / 归一 / 排序 / 适配器。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// TestCancelledGroupsRecorded B-09 回归：取消时已领取的组必须留下
// not_executed 执行证据，不得从 runs 中整组消失。
//
// 旧实现在 processGroup 开头 `if cancelCheck() { return }` 直接返回，既不
// 记命中也不记 outcome，于是 runs 里整组条目消失——下游会把「已调度但没
// 执行」误当成「不在执行集」，破坏 CheckRun 的三值语义（not_executed
// 永远不作负样本）。
func TestCancelledGroupsRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	var calls atomic.Int64
	// 首次 false（让 worker 领到一个组），之后 true（让 processGroup 走取消分支）。
	cancel := func() bool { return calls.Add(1) > 1 }

	list := []Check{
		{ID: "c1", Path: "/a", Match: Match{Status: 200}, Title: "a", Sev: "low"},
		{ID: "c2", Path: "/b", Match: Match{Status: 200}, Title: "b", Sev: "low"},
	}
	_, runs := RunListWithLog(httpx.New(0), srv.URL, list, 1, cancel, nil, nil)

	if len(runs) == 0 {
		t.Fatal("取消后 runs 为空：已领取的组从执行证据中消失了（B-09 回归）")
	}
	sawCancelled := false
	for _, r := range runs {
		if r.Reason == "cancelled" {
			sawCancelled = true
			if r.Status != RunStatusNotExecuted {
				t.Fatalf("取消组的 status = %q, 期望 %q", r.Status, RunStatusNotExecuted)
			}
			if r.Hit {
				t.Fatalf("取消组不得标记为命中: %+v", r)
			}
		}
	}
	if !sawCancelled {
		t.Fatalf("未记录到 reason=cancelled 的执行证据: %+v", runs)
	}
}

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
