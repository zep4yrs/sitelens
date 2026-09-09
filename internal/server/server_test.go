package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

const targetHTML = `<html><head><title>契约测试站</title>
<meta name="generator" content="WordPress 6.4"></head>
<body><a href="/about">关于</a></body></html>`

func newServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	t.Chdir("../..") // 数据路径按「从项目根启动」约定解析
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Store.DataDir = t.TempDir()

	s, err := New(cfg, filepath.Join(t.TempDir(), "cfg.yml"))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)

	// 目标假站
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		strings.NewReader(targetHTML).WriteTo(w)
	})
	site := httptest.NewServer(mux)
	t.Cleanup(site.Close)
	return s, api
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func postJSON(t *testing.T, url string, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestVersionAndStats(t *testing.T) {
	_, api := newServer(t)
	code, v := getJSON(t, api.URL+"/api/version")
	if code != 200 || v["name"] != "SiteLens" {
		t.Fatalf("version 端点异常: %v", v)
	}
	code, st := getJSON(t, api.URL+"/api/stats")
	if code != 200 {
		t.Fatalf("stats %d", code)
	}
	for _, key := range []string{"categories", "technologies", "vulns", "intel_sources", "history", "top_techs"} {
		if _, ok := st[key]; !ok {
			t.Fatalf("stats 缺键 %s: %v", key, st)
		}
	}
	code, c := getJSON(t, api.URL+"/api/categories")
	if code != 200 {
		t.Fatalf("categories %d", code)
	}
	if _, ok := c["categories"]; !ok {
		t.Fatalf("categories 缺键: %v", c)
	}
}

func TestScanJobFlow(t *testing.T) {
	s, api := newServer(t)
	// 找目标假站地址：起一个
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		strings.NewReader(targetHTML).WriteTo(w)
	})
	site := httptest.NewServer(mux)
	defer site.Close()

	code, body := postJSON(t, api.URL+"/api/scan", `{"url":"`+site.URL+`","passive":true}`)
	if code != 200 {
		t.Fatalf("scan %d: %v", code, body)
	}
	jobID, _ := body["job_id"].(string)
	if jobID == "" {
		t.Fatalf("缺 job_id: %v", body)
	}

	// 轮询直到完成（最长 30s）
	var job map[string]any
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, job = getJSON(t, api.URL+"/api/job/"+jobID)
		if job["status"] == "done" || job["status"] == "error" || job["status"] == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("扫描超时: %v", job)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if job["status"] != "done" {
		t.Fatalf("扫描失败: %v", job)
	}
	scanID, ok := job["scan_id"].(float64)
	if !ok || scanID < 1 {
		t.Fatalf("done 任务应带 scan_id: %v", job)
	}

	// 历史
	code, h := getJSON(t, api.URL+"/api/history?limit=10")
	if code != 200 || len(h["scans"].([]any)) != 1 {
		t.Fatalf("历史异常: %v", h)
	}
	code, detail := getJSON(t, api.URL+"/api/history/1")
	if code != 200 || detail["result"] == nil {
		t.Fatalf("详情异常: %v", detail)
	}

	// 导出（含 HTML 报告）
	for _, fmtK := range []string{"json", "csv", "wide", "html"} {
		resp, err := http.Get(api.URL + "/api/export/1?fmt=" + fmtK)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("导出 %s 失败: %d", fmtK, resp.StatusCode)
		}
	}

	// 差异：把同一条和自己比
	code, d := getJSON(t, api.URL+"/api/diff?a=1&b=1")
	if code != 200 {
		t.Fatalf("diff 异常: %v", d)
	}

	// 已验证汇总（被动检测可能有发现，也可能为空）
	code, v := getJSON(t, api.URL+"/api/verified")
	if code != 200 {
		t.Fatalf("verified %d", code)
	}
	if _, ok := v["items"]; !ok {
		t.Fatalf("verified 缺 items 键: %v", v)
	}

	// 删除
	delReq, _ := http.NewRequest("DELETE", api.URL+"/api/history/1", nil)
	resp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("删除失败: %d", resp.StatusCode)
	}
	_ = s
}

func TestBatchFlow(t *testing.T) {
	_, api := newServer(t)
	// 两个目标：自身 API 站点（存活）+ 一个必然失败的保留域名
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strings.NewReader(targetHTML).WriteTo(w)
	}))
	defer site.Close()

	body := `{"urls":["` + site.URL + `","http://127.0.0.1:1"]}`
	code, resp := postJSON(t, api.URL+"/api/batch", body)
	if code != 200 {
		t.Fatalf("batch %d: %v", code, resp)
	}
	jobID, _ := resp["job_id"].(string)
	if jobID == "" {
		t.Fatalf("缺 job_id: %v", resp)
	}
	deadline := time.Now().Add(60 * time.Second)
	var job map[string]any
	for {
		_, job = getJSON(t, api.URL+"/api/job/"+jobID+"/results")
		st, _ := job["status"].(string)
		if st == "done" || st == "cancelled" || st == "error" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("批量超时: %v", job)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if job["status"] != "done" {
		t.Fatalf("批量未完成: %v", job)
	}
	if int(job["done"].(float64)) != 2 {
		t.Fatalf("应处理 2 个 URL: %v", job)
	}
	// 一条历史入库（存活的那个）
	_, h := getJSON(t, api.URL+"/api/history?limit=10")
	if n := len(h["scans"].([]any)); n != 1 {
		t.Fatalf("批量应入库 1 条: %d", n)
	}
}

func TestScanRejectsBadTarget(t *testing.T) {
	_, api := newServer(t)
	code, body := postJSON(t, api.URL+"/api/scan", `{"url":"ftp://x"}`)
	if code != 400 || body["error"] == "" {
		t.Fatalf("非法目标应 400: %d %v", code, body)
	}
}

// TestScanOptionsLevels 语义化模式预设：预设生效、显式键覆盖、
// 未知 level 忽略、nuclei_cap 请求覆盖（此前文档宣称支持但从未解析）。
func TestScanOptionsLevels(t *testing.T) {
	// quick：只关 deep，其余默认关
	o := scanOptions(map[string]any{"level": "quick"})
	if o.Deep {
		t.Fatal("quick 预设 deep 应为 false")
	}
	// apocalypse：全开 + 全量模板
	o = scanOptions(map[string]any{"level": "apocalypse"})
	if !o.Deep || !o.DirScan || !o.DirBypass || !o.Subdomain || !o.Takeover ||
		!o.Webshell || !o.WeakAudit || !o.ActiveFP || !o.ServiceProbe ||
		!o.DAST || !o.Netsec || !o.Passive || !o.BrowserUA {
		t.Fatalf("apocalypse 应全模块开启: %+v", o)
	}
	if o.Checks != "all" || o.NucleiCap != 6000 {
		t.Fatalf("apocalypse 应 checks=all 且 nuclei_cap=6000: %+v", o)
	}
	// 显式键覆盖预设：apocalypse 但单关目录探测
	o = scanOptions(map[string]any{"level": "apocalypse", "dir_scan": false})
	if o.DirScan {
		t.Fatal("显式 dir_scan=false 应覆盖预设")
	}
	// 大小写与空白规范化
	o = scanOptions(map[string]any{"level": "  Full "})
	if !o.Subdomain || !o.Netsec {
		t.Fatalf("level 规范化失败: %+v", o)
	}
	// 未知 level：静默忽略，保持默认
	o = scanOptions(map[string]any{"level": "nope"})
	if !o.Deep || o.DirScan {
		t.Fatalf("未知 level 应走默认: %+v", o)
	}
	// nuclei_cap 请求覆盖（独立于 level）
	o = scanOptions(map[string]any{"nuclei_cap": 1234.0})
	if o.NucleiCap != 1234 {
		t.Fatalf("nuclei_cap 请求覆盖未生效: %+v", o)
	}
	o = scanOptions(map[string]any{})
	if o.NucleiCap != 0 {
		t.Fatalf("默认应走配置 nuclei_cap（0）: %+v", o)
	}
}

func TestNetsecContract(t *testing.T) {
	_, api := newServer(t)
	code, body := postJSON(t, api.URL+"/api/netsec", `{"host":""}`)
	if code != 400 {
		t.Fatalf("空域名应 400: %d %v", code, body)
	}
}

func TestLoginBruteRequiresAuthorization(t *testing.T) {
	_, api := newServer(t)
	code, body := postJSON(t, api.URL+"/api/loginbrute", `{"url":"https://x.com"}`)
	if code != 400 || !strings.Contains(body["error"].(string), "授权") {
		t.Fatalf("未勾授权应拒绝: %d %v", code, body)
	}
}

func TestAuditDemo(t *testing.T) {
	_, api := newServer(t)
	code, rep := getJSON(t, api.URL+"/api/audit/demo")
	if code != 200 {
		t.Fatalf("审计演示 %d: %v", code, rep)
	}
	if rep["files"].(float64) < 1 || rep["findings"] == nil {
		t.Fatalf("演示报告不完整: %v", rep)
	}
}

func TestTokenGuard(t *testing.T) {
	t.Setenv("SLENS_API_TOKEN", "secret-token")
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Store.DataDir = t.TempDir()
	s, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(s.Handler())
	defer api.Close()

	resp, _ := http.Get(api.URL + "/api/version")
	if resp.StatusCode != 401 {
		t.Fatalf("无 token 应 401: %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest("GET", api.URL+"/api/version", nil)
	req.Header.Set("X-Token", "secret-token")
	resp2, _ := http.DefaultClient.Do(req)
	if resp2.StatusCode != 200 {
		t.Fatalf("正确 token 应 200: %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestLegacyRedirects(t *testing.T) {
	_, api := newServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for path, want := range map[string]string{
		"/netsec": "/app#netsec", "/loginbrute": "/app#loginbrute", "/verified": "/history#verified",
	} {
		resp, err := client.Get(api.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), want) {
			t.Fatalf("%s 重定向异常: %d %s", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestPagesServe(t *testing.T) {
	_, api := newServer(t)
	for _, p := range []string{"/", "/app", "/batch", "/history", "/intel", "/audit", "/api-docs", "/about", "/js/common.js"} {
		resp, err := http.Get(api.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("页面 %s 状态 %d", p, resp.StatusCode)
		}
		resp.Body.Close()
	}
}
