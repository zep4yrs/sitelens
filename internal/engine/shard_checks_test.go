// CP-05 模板批次分片回归：默认路径不变、分片结果一致、checkpoint 续扫、
// 取消语义。
package engine

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// newNucleiLikeServer 起一个模板命中测试服务：/hit 命中，其余不命中。
func newNucleiLikeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hit" {
			_, _ = w.Write([]byte("hello hit marker"))
			return
		}
		_, _ = w.Write([]byte("nothing here"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// templateChecks 构造 4 条模板：1 条命中，3 条不命中。
func templateChecks() []checks.Check {
	hit := checks.Check{ID: "c-hit", Path: "/hit", Title: "命中模板", Sev: "high",
		Match: checks.Match{Status: 200, Contains: []string{"hit marker"}}}
	mk := func(id, path string) checks.Check {
		return checks.Check{ID: id, Path: path, Title: "普通模板", Sev: "low",
			Match: checks.Match{Status: 200, Contains: []string{"hit marker"}}}
	}
	return []checks.Check{hit, mk("c-a", "/a"), mk("c-b", "/b"), mk("c-c", "/c")}
}

// hitIDs 命中 Check ID 集合（顺序无关）。
func hitIDs(hits []checks.Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Check)
	}
	sort.Strings(out)
	return out
}

// TestRunCheckListDefaultUnchanged 默认路径（ShardWorkers=0）与既有
// checks.RunListWithLog 完全一致：无分片摘要、命中/执行证据一致。
func TestRunCheckListDefaultUnchanged(t *testing.T) {
	srv := newNucleiLikeServer(t)
	c := httpx.NewWithOptions(httpx.ClientOptions{})
	list := templateChecks()

	var progress int32
	var hitsCalled int32
	hits, runs, info := runCheckList(c, srv.URL, list, 4, func() bool { return false },
		func(int, int, string) { atomic.AddInt32(&progress, 1) },
		func(checks.Hit) { atomic.AddInt32(&hitsCalled, 1) },
		0, nil)
	if info != nil {
		t.Fatalf("默认路径不应返回分片摘要：%+v", info)
	}
	if runs == nil && len(list) > 0 {
		// RunListWithLog 总会返回执行证据切片（可为空非 nil）
		t.Logf("runs = %v", runs)
	}
	if len(runs) != len(list) {
		t.Fatalf("执行证据 = %d，期望 %d", len(runs), len(list))
	}
	if got := hitIDs(hits); len(got) != 1 || got[0] != "c-hit" {
		t.Fatalf("默认路径命中异常：%v", got)
	}
	if atomic.LoadInt32(&hitsCalled) != 1 {
		t.Errorf("onHit 回调次数 = %d，期望 1", hitsCalled)
	}
	if atomic.LoadInt32(&progress) == 0 {
		t.Error("默认路径应回调进度")
	}
}

// TestRunCheckListShardedMatchesDefault 分片路径命中集合/执行证据数量与
// 默认路径一致，且返回分片摘要（并发由 RunShards 夹到 ≤4）。
func TestRunCheckListShardedMatchesDefault(t *testing.T) {
	srv := newNucleiLikeServer(t)
	list := templateChecks()

	defHits, defRuns, _ := runCheckList(httpx.NewWithOptions(httpx.ClientOptions{}),
		srv.URL, list, 4, func() bool { return false }, nil, nil, 0, nil)

	var hitsCalled int32
	shHits, shRuns, info := runCheckList(httpx.NewWithOptions(httpx.ClientOptions{}),
		srv.URL, list, 4, func() bool { return false }, nil,
		func(checks.Hit) { atomic.AddInt32(&hitsCalled, 1) }, 2, nil)
	if info == nil || !info.Enabled {
		t.Fatalf("分片路径应返回摘要：%+v", info)
	}
	if info.Shards != 2 || info.Stats.Total != 2 || info.Stats.Completed != 2 {
		t.Fatalf("分片统计异常：%+v", info.Stats)
	}
	if got, want := hitIDs(shHits), hitIDs(defHits); len(got) != len(want) ||
		(len(got) > 0 && got[0] != want[0]) {
		t.Fatalf("分片命中集合 = %v，默认 = %v", got, want)
	}
	if len(shRuns) != len(defRuns) {
		t.Fatalf("分片执行证据 = %d，默认 = %d", len(shRuns), len(defRuns))
	}
	if atomic.LoadInt32(&hitsCalled) != 1 {
		t.Errorf("分片 onHit 回调次数 = %d，期望 1（合并后串行回调）", hitsCalled)
	}
}

// TestRunCheckListCheckpoint 传入 checkpoint 时回传更新计划；全部分片完成后
// 再次执行只跳过、不重跑。
func TestRunCheckListCheckpoint(t *testing.T) {
	srv := newNucleiLikeServer(t)
	list := templateChecks()
	c := httpx.NewWithOptions(httpx.ClientOptions{})

	_, _, first := runCheckList(c, srv.URL, list, 4, func() bool { return false },
		nil, nil, 2, []byte("[]"))
	if first == nil || len(first.Checkpoint) == 0 {
		t.Fatalf("首次执行应回传 checkpoint：%+v", first)
	}
	if first.Pending != 0 {
		t.Fatalf("首次执行后应无待跑分片：%d", first.Pending)
	}

	hits, runs, second := runCheckList(c, srv.URL, list, 4, func() bool { return false },
		nil, nil, 2, first.Checkpoint)
	if second == nil {
		t.Fatal("checkpoint 续扫应返回摘要")
	}
	if len(hits) != 0 || len(runs) != 0 {
		t.Fatalf("checkpoint 全 Done 时应跳过全部：hits=%d runs=%d", len(hits), len(runs))
	}
	if second.Stats.Skipped != second.Stats.Total || second.Stats.Completed != 0 {
		t.Fatalf("续扫统计异常：%+v", second.Stats)
	}
}

// TestRunCheckListShardedCancel 取消时不再继续发请求（片内取消检查生效）。
func TestRunCheckListShardedCancel(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte("nothing"))
	}))
	defer srv.Close()
	c := httpx.NewWithOptions(httpx.ClientOptions{})
	hits, runs, info := runCheckList(c, srv.URL, templateChecks(), 4,
		func() bool { return true }, nil, nil, 2, nil)
	if len(hits) != 0 || len(runs) != 0 {
		t.Fatalf("取消后不应有命中/执行证据：%d/%d", len(hits), len(runs))
	}
	if info == nil || !info.Enabled {
		t.Fatalf("取消路径仍应返回摘要：%+v", info)
	}
	if atomic.LoadInt32(&requests) != 0 {
		t.Errorf("取消后不应发请求，实际 %d", requests)
	}
}
