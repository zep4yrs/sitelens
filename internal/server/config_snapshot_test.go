package server

// A-09 回归：设置页配置快照语义与并发热更新。
//
// 背景：settings.applySettings 曾在 cfgMu 下原地写 s.cfg.*，而 handler 全程
// 无锁裸读 s.cfg.* → Wave-1 用 -race 复现（applySettings × hBatch）。
// 现改为「深拷贝 → 改拷贝 → 原子换枪 + 同步引擎快照」，读侧一律 cfgSnap()。

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// testServer 只构造最小 Server 并注入配置快照（A-09 后 cfg 为
// atomic.Pointer，测试不能再以复合字面量 &Server{cfg: ...} 直接写入）。
func testServer(cfg *config.Config) *Server {
	s := &Server{}
	s.cfgPtr.Store(cfg)
	return s
}

// setTestConfig 用 mutator 改配置并换枪（测试用：模拟设置页写侧的
// copy-on-write，不原地改旧快照）。
func setTestConfig(s *Server, mutate func(*config.Config)) {
	snap := cloneConfig(s.cfgSnap())
	if snap == nil {
		snap = config.Default()
	}
	mutate(snap)
	s.cfgPtr.Store(snap)
	if s.eng != nil {
		s.eng.SetConfig(snap)
	}
}

// TestSettingsSnapshotSemantics 写侧换枪语义：设置页保存后
//   - 旧快照（= 进行中扫描/请求持有的那份）保持原值、不被原地修改；
//   - 下一次读取（cfgSnap / HTTP GET /api/settings）拿到新值；
//   - 引擎快照同步换枪。
func TestSettingsSnapshotSemantics(t *testing.T) {
	s, api := newServer(t)

	old := s.cfgSnap()
	if old == nil {
		t.Fatal("New 后应能取到配置快照")
	}
	if old.Batch.MaxURLs != 50 || old.Crawler.MaxPages != 4 || old.Scan.TimeoutSec != 15 {
		t.Fatalf("默认值前提不成立：batch=%d crawler=%d timeout=%d",
			old.Batch.MaxURLs, old.Crawler.MaxPages, old.Scan.TimeoutSec)
	}

	code, body := putJSONReq(t, api.URL+"/api/settings", settingsBody(""))
	if code != 200 {
		t.Fatalf("保存设置失败: %d %v", code, body)
	}

	// 1) 旧快照必须原封不动（进行中的扫描/请求全程读它）。
	if old.Batch.MaxURLs != 50 || old.Crawler.MaxPages != 4 || old.Scan.TimeoutSec != 15 {
		t.Fatalf("旧配置快照被原地修改（数据竞争的根因复发）：batch=%d crawler=%d timeout=%d",
			old.Batch.MaxURLs, old.Crawler.MaxPages, old.Scan.TimeoutSec)
	}

	// 2) 换枪：新读取拿到新快照与新值。
	snap := s.cfgSnap()
	if snap == nil || snap == old {
		t.Fatal("设置保存应原子换枪为新配置快照")
	}
	if snap.Batch.MaxURLs != 10 || snap.Crawler.MaxPages != 200 ||
		snap.Scan.TimeoutSec != 10 || snap.Checks.NucleiCap != 100 || snap.ML.Predict {
		t.Fatalf("新快照值错误：batch=%d crawler=%d timeout=%d nuclei_cap=%d predict=%v",
			snap.Batch.MaxURLs, snap.Crawler.MaxPages, snap.Scan.TimeoutSec,
			snap.Checks.NucleiCap, snap.ML.Predict)
	}

	// 3) 引擎必须同步持有同一份新快照（下一次扫描从引擎侧读到新值）。
	if got := s.eng.Config(); got != snap {
		t.Fatal("引擎未同步设置页写入的新快照")
	}

	// 4) 下一次请求（settings 读路径）读到新值。
	code, body = getJSON(t, api.URL+"/api/settings")
	if code != 200 {
		t.Fatalf("GET /api/settings = %d", code)
	}
	crawler, _ := body["crawler"].(map[string]any)
	if crawler["max_pages"] != float64(200) {
		t.Fatalf("GET /api/settings 未反映新值: %v", body["crawler"])
	}
	batch, _ := body["batch"].(map[string]any)
	if batch["max_urls"] != float64(10) {
		t.Fatalf("GET /api/settings 未反映新值: %v", body["batch"])
	}

	// 5) 旧快照与引擎新快照彼此独立：改新快照的切片不影响旧快照。
	snap.Scan.AllowHosts = append(snap.Scan.AllowHosts, "late.example.com")
	if len(old.Scan.AllowHosts) != 0 {
		t.Fatalf("新旧快照共享切片底层数组: %v", old.Scan.AllowHosts)
	}
}

// TestSettingsHotReloadConcurrentRace 并发「设置页热更新 × API 请求 × 批量扫描」。
// 在 -race 下运行：任何 handler/扫描对配置的裸读都会在此暴露。
func TestSettingsHotReloadConcurrentRace(t *testing.T) {
	s, api := newServer(t)

	// 本地靶站（批量扫描目标；Resolve=false 的夹具旁路 IP 校验）。
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>race-site</title></head><body>ok</body></html>`)
	}))
	defer site.Close()

	client := &http.Client{Timeout: 30 * time.Second}
	do := func(method, path, body string) (int, error) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, api.URL+path, rd)
		if err != nil {
			return 0, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var problems []string
	record := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(problems) < 8 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	// 写侧：设置页反复保存（交替翻转 sev_onnx，覆盖引擎 ML 状态无效化路径）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			body := settingsBody("")
			if i%2 == 1 {
				body = strings.Replace(body, `"sev_onnx":false`, `"sev_onnx":true`, 1)
			}
			code, err := do(http.MethodPut, "/api/settings", body)
			if err != nil {
				record("PUT /api/settings 失败: %v", err)
				return
			}
			if code != 200 {
				record("PUT /api/settings = %d（期望 200）", code)
			}
		}
	}()

	// 读侧：各 handler 并发读配置快照。
	reads := []string{"/api/version", "/api/settings", "/api/history", "/api/verified", "/api/diagnostics"}
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, p := range reads {
					code, err := do(http.MethodGet, p, "")
					if err != nil {
						record("GET %s 失败: %v", p, err)
						return
					}
					if code != 200 {
						record("GET %s = %d（期望 200）", p, code)
					}
				}
			}
		}()
	}

	// 扫描侧：批量提交真实扫描（引擎侧读配置快照）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 4; i++ {
			select {
			case <-stop:
				return
			case <-time.After(150 * time.Millisecond):
			}
			code, err := do(http.MethodPost, "/api/batch",
				`{"urls":["`+site.URL+`"]}`)
			if err != nil {
				record("POST /api/batch 失败: %v", err)
				return
			}
			if code != 200 {
				record("POST /api/batch = %d（期望 200）", code)
			}
		}
	}()

	time.Sleep(900 * time.Millisecond)
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(problems) > 0 {
		t.Fatalf("并发热更新期间出现问题 %d 条（前几条）：%v", len(problems), problems)
	}
	// 稳态不变量：服务端与引擎持有的快照是同一个（applySettings 原子换枪）。
	if got, want := s.eng.Config(), s.cfgSnap(); got != want {
		t.Fatal("服务端与引擎配置快照不一致（换枪未同步）")
	}
}
