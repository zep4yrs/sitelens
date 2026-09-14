package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGraphAPIEndToEnd：真实扫描（graph=true）→ 图 API 三个端点。
func TestGraphAPIEndToEnd(t *testing.T) {
	_, api := newServer(t)

	// 目标假站：带参链接，让扫描有入口点。
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><head><title>G</title></head>
<body><a href="/?id=1">x</a></body></html>`)
	})
	site := newLocalSite(t, mux)

	code, body := postJSON(t, api.URL+"/api/scan",
		`{"url":"`+site+`","graph":true,"passive":true,"checks":"core"}`)
	if code != 200 {
		t.Fatalf("scan %d: %v", code, body)
	}
	jobID, _ := body["job_id"].(string)
	if jobID == "" {
		t.Fatalf("缺 job_id: %v", body)
	}
	var job map[string]any
	deadline := time.Now().Add(40 * time.Second)
	for {
		_, job = getJSON(t, api.URL+"/api/job/"+jobID)
		if st, _ := job["status"].(string); st == "done" || st == "error" || st == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("扫描超时: %v", job)
		}
		time.Sleep(150 * time.Millisecond)
	}
	if job["status"] != "done" {
		t.Fatalf("扫描未完成: %v", job)
	}
	scanID := idOf(job)
	if scanID == 0 {
		t.Fatalf("缺 scan_id: %v", job)
	}

	// 1) 摘要 API
	code, g := getJSON(t, api.URL+"/api/graph/"+itoa64(scanID))
	if code != 200 {
		t.Fatalf("graph API %d: %v", code, g)
	}
	if g["schema"] != "sitelens.graph/v1" {
		t.Errorf("schema = %v", g["schema"])
	}
	if g["counts"] == nil {
		t.Error("应返回 counts")
	}

	// 2) 链视图 API
	code, ch := getJSON(t, api.URL+"/api/graph/"+itoa64(scanID)+"/chain")
	if code != 200 {
		t.Fatalf("chain API %d: %v", code, ch)
	}
	if ch["nodes"] == nil || ch["edges"] == nil {
		t.Error("链视图应含 nodes/edges")
	}

	// 3) JSONL 导出（校验 Content-Type 与首行 header）
	resp, err := http.Get(api.URL + "/api/graph/" + itoa64(scanID) + "/jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("jsonl %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "ndjson") {
		t.Errorf("Content-Type = %q，期望 ndjson", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), `"kind":"header"`) {
		t.Error("JSONL 首行应为 header")
	}
}

// TestGraphAPINotCollected：未开 graph 的扫描 → 404 且提示未收集。
func TestGraphAPINotCollected(t *testing.T) {
	_, api := newServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><body>plain</body></html>`)
	})
	site := newLocalSite(t, mux)

	code, body := postJSON(t, api.URL+"/api/scan", `{"url":"`+site+`","passive":true}`)
	if code != 200 {
		t.Fatalf("scan %d", code)
	}
	jobID, _ := body["job_id"].(string)
	var job map[string]any
	deadline := time.Now().Add(40 * time.Second)
	for {
		_, job = getJSON(t, api.URL+"/api/job/"+jobID)
		if st, _ := job["status"].(string); st == "done" || st == "error" || st == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("超时")
		}
		time.Sleep(150 * time.Millisecond)
	}
	scanID := idOf(job)
	if scanID == 0 {
		t.Skipf("扫描未产出 scan_id（可能目标不可达）：%v", job)
	}
	code, g := getJSON(t, api.URL+"/api/graph/"+itoa64(scanID))
	if code != 404 {
		t.Errorf("未收集图应 404，实得 %d: %v", code, g)
	}
	if msg, _ := g["error"].(string); !strings.Contains(msg, "未收集") {
		t.Errorf("错误信息应说明未收集：%v", g)
	}
}

// TestGraphAPIBadID：非法 id → 400。
func TestGraphAPIBadID(t *testing.T) {
	_, api := newServer(t)
	code, _ := getJSON(t, api.URL+"/api/graph/abc")
	if code != 400 {
		t.Errorf("非法 id 应 400，实得 %d", code)
	}
}

// TestGraphAPIUnknownID：不存在的 scan_id → 404 记录不存在。
func TestGraphAPIUnknownID(t *testing.T) {
	_, api := newServer(t)
	code, body := getJSON(t, api.URL+"/api/graph/999999")
	if code != 404 {
		t.Errorf("未知 id 应 404，实得 %d", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "不存在") {
		t.Errorf("错误信息应说明不存在：%v", body)
	}
}

// newLocalSite 起一个本地假站并返回 URL（测试辅助）。
func newLocalSite(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// itoa64 十进制（避免与 store 测试辅助重名冲突的独立实现）。
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// idOf 从 job 响应里取 scan_id（服务端把 scan_id 放在 job 顶层）。
func idOf(job map[string]any) int64 {
	switch v := job["scan_id"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}
