package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// writeTestTechFile 写一份最小 technologies.json（类别全集由 cats 决定）。
func writeTestTechFile(t *testing.T, path string) {
	t.Helper()
	box := map[string]any{"technologies": []map[string]any{
		{"name": "TechA", "cats": []string{"cms"}},
		{"name": "TechB", "cats": []string{"web-server"}},
		{"name": "TechC", "cats": []string{"cms"}},
	}}
	data, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// newReloadTestServer 构造热更新可触发的服务：数据文件指向临时目录，
// 缺失的情报库/插件目录按「加载失败保留旧快照」降级。
func newReloadTestServer(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	techPath := filepath.Join(dir, "technologies.json")
	writeTestTechFile(t, techPath)

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Store.DataDir = t.TempDir()
	cfg.Intel.TechnologiesPath = techPath
	cfg.Intel.DumpPath = filepath.Join(dir, "missing_dump.json.gz")
	cfg.Intel.RangesPath = filepath.Join(dir, "missing_ranges.json")
	cfg.Checks.PluginDir = filepath.Join(dir, "missing_plugins")
	s, err := New(cfg, filepath.Join(dir, "cfg.yml"))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return s, api, techPath
}

// TestConcurrentReloadAndCategories BUG-010 回归：reloadData 此前无锁换枪
// （s.techIDs, s.techCnt = ...）而 /api/categories 无锁 len/range，
// slice header 撕裂会越界 panic。现以 atomic 快照整体换枪：
// 本用例在 -race 下跑，两个方向都必须无竞态、无 5xx/连接重置。
func TestConcurrentReloadAndCategories(t *testing.T) {
	s, api, techPath := newReloadTestServer(t)
	// 初始快照必须可用（2 个类别：cms / web-server）
	if got := len(s.techMetaSnap().cats); got != 2 {
		t.Fatalf("初始类别快照应为 2，实际 %d", got)
	}

	const reloads = 40
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		base := time.Now()
		for i := 0; i < reloads; i++ {
			mt := base.Add(time.Duration(i+1) * time.Second)
			if err := os.Chtimes(techPath, mt, mt); err != nil {
				t.Errorf("Chtimes: %v", err)
				return
			}
			s.reloadIfDataChanged()
		}
	}()

	var readWG sync.WaitGroup
	var mu sync.Mutex
	var seen []int
	for r := 0; r < 4; r++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				resp, err := http.Get(api.URL + "/api/categories")
				if err != nil {
					t.Errorf("categories 请求失败（可能 panic 炸连接）: %v", err)
					return
				}
				var body map[string]any
				derr := json.NewDecoder(resp.Body).Decode(&body)
				resp.Body.Close()
				if derr != nil || resp.StatusCode != 200 {
					t.Errorf("categories 应 200+JSON: %d %v", resp.StatusCode, derr)
					return
				}
				cats, ok := body["categories"].([]any)
				if !ok {
					t.Errorf("categories 响应缺 categories 数组: %v", body)
					return
				}
				mu.Lock()
				seen = append(seen, len(cats))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	readWG.Wait()

	if len(seen) == 0 {
		t.Fatal("并发读未拿到任何成功响应")
	}
	for _, n := range seen {
		if n != 2 {
			t.Fatalf("类别数应恒为 2（换枪不得产生半截快照），实际 %d", n)
		}
	}
}

// settingsBodyToken 在标准设置体上覆盖 api_token。
func settingsBodyToken(overridesPath, token string) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(settingsBody(overridesPath)), &m)
	if web, ok := m["web"].(map[string]any); ok {
		web["api_token"] = token
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// TestConcurrentSettingsSaveAndAPIGuard BUG-011 回归：apiToken 写侧持 cfgMu、
// 读侧（guard）无锁 → string 头撕裂可致鉴权旁路或 panic。现读写都走
// atomic.Pointer[string]：设置页反复切换 token 与 /api/* 请求并发，
// 全程无竞态、请求不被重置。
func TestConcurrentSettingsSaveAndAPIGuard(t *testing.T) {
	_, api := newServer(t)
	const flips = 20
	client := &http.Client{Timeout: 30 * time.Second}
	do := func(method, path, body string) (int, error) {
		var r *http.Request
		var err error
		if body == "" {
			r, err = http.NewRequest(method, api.URL+path, nil)
		} else {
			r, err = http.NewRequest(method, api.URL+path, strings.NewReader(body))
		}
		if err != nil {
			return 0, err
		}
		// token 只会在 "" 与 "tok" 之间切换，带上 "tok" 两种态都通过
		r.Header.Set("X-Token", "tok")
		resp, err := client.Do(r)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var codes []int
	var reqErrs []error
	record := func(code int, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			reqErrs = append(reqErrs, err)
			return
		}
		codes = append(codes, code)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < flips; i++ {
			token := ""
			if i%2 == 1 {
				token = "tok"
			}
			code, err := do(http.MethodPut, "/api/settings", settingsBodyToken("", token))
			record(code, err)
		}
	}()

	var readWG sync.WaitGroup
	for r := 0; r < 3; r++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// /api/version 走 guard 读 token；/api/settings 还读 settingsCfg
				code, err := do(http.MethodGet, "/api/version", "")
				record(code, err)
				code, err = do(http.MethodGet, "/api/settings", "")
				record(code, err)
			}
		}()
	}
	wg.Wait()
	readWG.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(reqErrs) > 0 {
		t.Fatalf("%d 个并发请求被重置/失败: %v", len(reqErrs), reqErrs[0])
	}
	if len(codes) == 0 {
		t.Fatal("并发请求未产生任何响应")
	}
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("并发期间所有请求都应 200（token 切换不影响已带正确头），实际 %d", c)
		}
	}
}
