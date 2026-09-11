package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// TestEvidenceChain 验证证据链四件套：请求文本/响应快照/信号明细/复现命令。
func TestEvidenceChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>dashboard <b>admin-panel</b> config db_password=secret tail</html>")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found page")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	chk := Check{
		ID: "ev-test", Lv: 0, Path: "/admin/config",
		Match: c(200, "admin-panel", "db_password"),
		Title: "配置面板暴露", Sev: "medium",
		Advice: "限制访问",
	}
	hits := RunList(httpx.New(0), srv.URL, []Check{chk}, nil, nil, nil)
	if len(hits) != 1 {
		t.Fatalf("应命中 1 条, got %d", len(hits))
	}
	h := hits[0]

	if !h.Confirmed {
		t.Error("命中应标记二次确认")
	}
	if h.Request == "" || !strings.Contains(h.Request, "GET /admin/config HTTP/1.1") ||
		!strings.Contains(h.Request, "Host: 127.0.0.1") {
		t.Errorf("请求文本不符: %q", h.Request)
	}
	if h.Response == nil || h.Response.Status != 200 || h.Response.Size == 0 {
		t.Errorf("响应快照缺失: %+v", h.Response)
	}
	if !strings.Contains(h.Response.Snippet, "admin-panel") {
		t.Errorf("响应摘要应含命中内容: %q", h.Response.Snippet)
	}
	if len(h.Signals) == 0 {
		t.Error("信号明细缺失")
	}
	for _, s := range h.Signals {
		if s == "" || strings.Contains(s, "\n") {
			t.Errorf("信号应为单行非空: %q", s)
		}
	}
	if !strings.HasPrefix(h.Replay, "curl -sk --path-as-is") ||
		!strings.Contains(h.Replay, srv.URL+"/admin/config") {
		t.Errorf("复现命令不符: %q", h.Replay)
	}
}

// TestCurlReplayEscaping 单引号体内的引号按 POSIX 规则转义。
func TestCurlReplayEscaping(t *testing.T) {
	m := Match{Method: "POST", ContentType: "application/json", Body: `{"u":"ad'min"}`}
	got := curlReplay("http://x/y", m)
	if !strings.Contains(got, `'{"u":"ad'\''min"}'`) {
		t.Errorf("单引号转义不符: %s", got)
	}
	if !strings.Contains(got, `-H 'Content-Type: application/json'`) {
		t.Errorf("Content-Type 头缺失: %s", got)
	}
}
