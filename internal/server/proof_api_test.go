package server

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// TestProofAPIPlanEndToEnd：真实扫描（graph=true）→ 创建目标 → 只读规划 → 链/路径查询。
func TestProofAPIPlanEndToEnd(t *testing.T) {
	_, api := newServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><head><title>P</title></head>
<body><a href="/?id=1">x</a></body></html>`)
	})
	site := newLocalSite(t, mux)
	code, body := postJSON(t, api.URL+"/api/scan",
		`{"url":"`+site+`","graph":true,"passive":true,"checks":"core"}`)
	if code != 200 {
		t.Fatalf("scan %d: %v", code, body)
	}
	jobID, _ := body["job_id"].(string)
	var job map[string]any
	deadline := time.Now().Add(scanFlowTimeout())
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

	// 1) 创建目标（target 用扫描 URL 的 host）
	code, created := postJSON(t, api.URL+"/api/proof/goals",
		`{"title":"证明入口可达","target":"`+site+`","level":"reach"}`)
	if code != 201 {
		t.Fatalf("创建目标 %d: %v", code, created)
	}
	goal, _ := created["goal"].(map[string]any)
	goalID, _ := goal["id"].(string)
	if goalID == "" {
		t.Fatalf("缺 goal id: %v", created)
	}

	// 2) 只读规划
	code, plan := postJSON(t, api.URL+"/api/proof/plan", `{"goal_id":"`+goalID+`"}`)
	if code != 200 {
		t.Fatalf("规划 %d: %v", code, plan)
	}
	chains, _ := plan["chains"].([]any)
	if len(chains) == 0 {
		t.Fatalf("规划应至少返回一条链: %v", plan)
	}

	// 3) 链查询
	code, ch := getJSON(t, api.URL+"/api/proof/chains?goal_id="+goalID)
	if code != 200 {
		t.Fatalf("链查询 %d: %v", code, ch)
	}
	if n, _ := ch["count"].(float64); n <= 0 {
		t.Fatalf("链查询应返回记录: %v", ch)
	}

	// 4) 图路径查询（只读）
	code, paths := getJSON(t, api.URL+"/api/graph/paths?scan_id="+itoa64(scanID))
	if code != 200 {
		t.Fatalf("路径查询 %d: %v", code, paths)
	}
	if _, ok := paths["paths"]; !ok {
		t.Fatalf("路径查询缺少 paths 字段: %v", paths)
	}

	// 5) 目标列表
	code, goals := getJSON(t, api.URL+"/api/proof/goals")
	if code != 200 {
		t.Fatalf("目标列表 %d: %v", code, goals)
	}
	if n, _ := goals["count"].(float64); n != 1 {
		t.Fatalf("目标列表应有 1 条: %v", goals)
	}
}

// TestProofGoalRejectsBadTarget 目标创建必须过 target.Validate。
func TestProofGoalRejectsBadTarget(t *testing.T) {
	_, api := newServer(t)
	code, body := postJSON(t, api.URL+"/api/proof/goals", `{"target":"gov.cn"}`)
	if code == 201 {
		t.Fatalf("gov.cn 必须被拒绝: %v", body)
	}
}
