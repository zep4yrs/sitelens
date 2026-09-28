package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestExportNilResultCSVWide 回归：fmt=csv/wide 分支此前直接解引用
// rec.Result（detailCSV/wideCSV 里 rec.Result.Technologies），result 为
// null 的历史记录会 nil 指针 panic——net/http 按连接 recover 不死进程，
// 但该请求连接被重置而非返回 JSON 错误。同文件 hReplay 对同一形态做了
// rec.Result==nil 防护，说明该形态被视为可达（导入迁移/写库中断均可产生）。
func TestExportNilResultCSVWide(t *testing.T) {
	s, api := newServer(t)
	id, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{
			ID: 4242, URL: "http://nil-result.example", Host: "nil-result.example",
			ScannedAt: "2026-01-01T00:00:00Z",
		},
		Options: map[string]any{},
		Result:  nil,
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	idStr := strconv.FormatInt(id, 10)

	// csv/wide：404 + JSON 错误体，绝不能 panic 炸连接
	for _, fmtev := range []string{"csv", "wide"} {
		resp, err := http.Get(api.URL + "/api/export/" + idStr + "?fmt=" + fmtev)
		if err != nil {
			t.Fatalf("fmt=%s 请求被重置（panic 炸连接）: %v", fmtev, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("fmt=%s 应 404, got %d", fmtev, resp.StatusCode)
		}
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Errorf("fmt=%s 错误响应应为 JSON: %v", fmtev, err)
		} else if m["error"] == nil {
			t.Errorf("fmt=%s 应带 error 字段: %v", fmtev, m)
		}
	}

	// html/md/json 对 nil Result 自带处理（report.go nil 分支 / Marshal nil
	// 输出 null），应保持 200 不回归
	for _, fmtev := range []string{"html", "md", "json"} {
		resp, err := http.Get(api.URL + "/api/export/" + idStr + "?fmt=" + fmtev)
		if err != nil {
			t.Fatalf("fmt=%s 请求失败: %v", fmtev, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("fmt=%s 对 nil Result 应 200（自带 nil 处理）, got %d", fmtev, resp.StatusCode)
		}
	}

	// 对照：正常记录的 csv/wide 不受影响
	if _, err := s.st.Import(store.ScanRecord{
		ScanSummary: store.ScanSummary{
			ID: 4243, URL: "http://good.example", Host: "good.example",
			ScannedAt: "2026-01-01T00:00:00Z",
		},
		Options: map[string]any{},
		Result:  &engine.Result{URL: "http://good.example"},
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(api.URL + "/api/export/4243?fmt=csv")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("正常记录 fmt=csv 应 200, got %d", resp.StatusCode)
	}
}
