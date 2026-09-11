package checks

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// TestRunListPathClustering 同路径 check 共享请求：3 条同路径 check
// 只应产生 1（无命中）或 2（命中+组级二次确认）次请求，而非 3 次。
func TestRunListPathClustering(t *testing.T) {
	var hitsReq, totalReq atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 只统计测试路径的请求；soft404Baseline 的随机路径探测不计
		switch r.URL.Path {
		case "/hit", "/p1", "/p2", "/p3":
			totalReq.Add(1)
		}
		switch r.URL.Path {
		case "/hit":
			hitsReq.Add(1)
			w.Write([]byte("secret admin panel marker"))
		default:
			w.Write([]byte("benign page"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := httpx.New(0)

	list := []Check{
		{ID: "a", Lv: 1, Path: "/hit", Match: Match{Status: 200, Contains: []string{"admin panel"}}, Title: "A", Sev: "high"},
		{ID: "b", Lv: 1, Path: "/hit", Match: Match{Status: 200, ContainsAny: []string{"nope", "marker"}}, Title: "B", Sev: "medium"},
		{ID: "c", Lv: 1, Path: "/hit", Match: Match{Status: 200, Contains: []string{"missing-keyword"}}, Title: "C", Sev: "low"},
	}
	hits := RunList(client, srv.URL, list, nil, nil, nil)

	if totalReq.Load() != 2 {
		t.Fatalf("同路径 3 条 check 应只发 2 次请求（1 首轮 + 1 组级确认）: %d", totalReq.Load())
	}
	if hitsReq.Load() != 2 {
		t.Fatalf("命中路径首轮+确认各 1 次: %d", hitsReq.Load())
	}
	if len(hits) != 2 {
		t.Fatalf("应命中 a/b 两条: %+v", hits)
	}
	for _, h := range hits {
		if h.Check != "a" && h.Check != "b" {
			t.Fatalf("不应有 c 的命中: %+v", h)
		}
	}

	// 不同路径不共享：三条不同路径各自请求
	totalReq.Store(0)
	list2 := []Check{
		{ID: "x", Lv: 1, Path: "/p1", Match: Match{Status: 200}, Title: "X", Sev: "info"},
		{ID: "y", Lv: 1, Path: "/p2", Match: Match{Status: 200}, Title: "Y", Sev: "info"},
		{ID: "z", Lv: 1, Path: "/p3", Match: Match{Status: 200}, Title: "Z", Sev: "info"},
	}
	RunList(client, srv.URL, list2, nil, nil, nil)
	if totalReq.Load() != 3 {
		t.Fatalf("不同路径应各自请求 3 次: %d", totalReq.Load())
	}
}
