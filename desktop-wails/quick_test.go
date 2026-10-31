// quick_test.go FE-08 壳侧逻辑单测（不启动 Wails/GUI）。
//
// 覆盖范围按「出问题会静默」排序：URL 提取、API 交互（含鉴权头与错误路径）、
// 历史 id 解析、通知 HTML 转义、通知定位、窗口材质逃生阀。窗口/快捷键本身
// 是 Wails 原生行为，只能靠真机验证——这里只测我们自己的决策逻辑。
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func TestExtractURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"裸 URL", "https://example.com/a?b=1", "https://example.com/a?b=1", true},
		{"首尾空白换行", "  \n https://example.com/path \r\n ", "https://example.com/path", true},
		{"中文句子夹 URL", "看看这个 https://vuln.example/x 页面，挺有意思", "https://vuln.example/x", true},
		{"尾随中文句号", "https://example.com/a。", "https://example.com/a", true},
		{"尾随英文句点", "https://example.com/a.", "https://example.com/a", true},
		{"大写 HTTPS", "HTTPS://Example.COM/X", "HTTPS://Example.COM/X", true},
		{"http 也接受", "http://127.0.0.1:8080/", "http://127.0.0.1:8080/", true},
		{"ftp 拒绝", "ftp://example.com/file", "", false},
		{"无 scheme 拒绝", "example.com/path", "", false},
		{"空文本", "   \n\t ", "", false},
		{"纯中文", "这是一段没有链接的描述", "", false},
		{"javascript 伪协议拒绝", "javascript:alert(1)", "", false},
		{"缺 host 拒绝", "https:///path", "", false},
		{"超长拒绝", "https://example.com/" + strings.Repeat("a", 2100), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractURL(c.in)
			if ok != c.ok {
				t.Fatalf("extractURL(%q) ok=%v want %v", c.in, ok, c.ok)
			}
			if got != c.want {
				t.Fatalf("extractURL(%q) = %q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestScanIDString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`42`, "42"},
		{`"abc"`, "abc"},
		{`null`, ""},
		{``, ""},
		{`12.0`, "12"},
	}
	for _, c := range cases {
		if got := scanIDString(json.RawMessage(c.in)); got != c.want {
			t.Errorf("scanIDString(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestPostScan(t *testing.T) {
	var gotPath, gotMethod, gotToken string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotToken = r.URL.Path, r.Method, r.Header.Get("X-Token")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-1"}`))
	}))
	defer srv.Close()

	id, err := postScan(srv.Client(), srv.URL, "tok-1", "https://example.com/x")
	if err != nil {
		t.Fatalf("postScan: %v", err)
	}
	if id != "job-1" {
		t.Fatalf("job_id = %q want job-1", id)
	}
	if gotPath != "/api/scan" || gotMethod != http.MethodPost {
		t.Fatalf("请求 = %s %s want POST /api/scan", gotMethod, gotPath)
	}
	if gotToken != "tok-1" {
		t.Fatalf("X-Token = %q want tok-1", gotToken)
	}
	if gotBody["url"] != "https://example.com/x" || gotBody["level"] != "quick" {
		t.Fatalf("请求体 = %v want url+level=quick", gotBody)
	}
}

func TestPostScanEngineRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"URL 协议不支持"}`))
	}))
	defer srv.Close()
	_, err := postScan(srv.Client(), srv.URL, "", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "URL 协议不支持") {
		t.Fatalf("期望透出引擎错误，实际 %v", err)
	}
}

func TestPostScanMissingJobID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	_, err := postScan(srv.Client(), srv.URL, "", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "job_id") {
		t.Fatalf("期望报缺 job_id，实际 %v", err)
	}
}

// 轮询：running → running → done，且数字 scan_id 要能转成历史 id。
func TestPollScanDone(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "/api/job/job-9") {
			if calls < 3 {
				_, _ = w.Write([]byte(`{"status":"running","message":"扫描中"}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"done","message":"完成","scan_id":42}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	out, err := pollScan(context.Background(), srv.Client(), srv.URL, "", "job-9",
		time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("pollScan: %v", err)
	}
	if out.Status != "done" || out.ScanID != "42" || out.Msg != "完成" {
		t.Fatalf("outcome = %+v want done/42/完成", out)
	}
}

func TestPollScanErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","message":"目标不可达"}`))
	}))
	defer srv.Close()
	out, err := pollScan(context.Background(), srv.Client(), srv.URL, "", "job-2",
		time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("pollScan: %v", err)
	}
	if out.Status != "error" || out.Msg != "目标不可达" {
		t.Fatalf("outcome = %+v want error/目标不可达", out)
	}
}

func TestPollScanTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"running"}`))
	}))
	defer srv.Close()
	_, err := pollScan(context.Background(), srv.Client(), srv.URL, "", "job-3",
		time.Millisecond, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("期望超时错误，实际 %v", err)
	}
}

func TestPollScanContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pollScan(ctx, &http.Client{Timeout: time.Second}, "http://127.0.0.1:1", "", "job-4",
		time.Millisecond, time.Second)
	if err == nil || !strings.Contains(err.Error(), "取消") {
		t.Fatalf("期望取消错误，实际 %v", err)
	}
}

func TestReadAPIToken(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("web:\n  listen: 127.0.0.1:5087\n  api_token: from-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 环境变量优先（与引擎 guard 同优先级）
	t.Setenv("SLENS_API_TOKEN", "from-env")
	if got := readAPIToken(cfg); got != "from-env" {
		t.Fatalf("readAPIToken = %q want from-env", got)
	}
	// 环境变量为空 → 读配置文件
	t.Setenv("SLENS_API_TOKEN", "")
	if got := readAPIToken(cfg); got != "from-file" {
		t.Fatalf("readAPIToken = %q want from-file", got)
	}
	// 配置缺失/损坏 → 空 token（不阻断）
	if got := readAPIToken(filepath.Join(dir, "nope.yml")); got != "" {
		t.Fatalf("缺失配置应返回空 token，实际 %q", got)
	}
	if got := readAPIToken(""); got != "" {
		t.Fatalf("空路径应返回空 token，实际 %q", got)
	}
}

func TestBottomRight(t *testing.T) {
	cases := []struct {
		name                    string
		ax, ay, aw, ah, w, h, m int
		wantX, wantY            int
	}{
		{"标准 1080p", 0, 0, 1920, 1080, 380, 132, 18, 1522, 930},
		{"副屏偏移", 1920, 0, 2560, 1440, 380, 132, 18, 4082, 1290},
		{"工作区小于通知窗时夹住", 0, 0, 200, 100, 380, 132, 18, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x, y := bottomRight(c.ax, c.ay, c.aw, c.ah, c.w, c.h, c.m)
			if x != c.wantX || y != c.wantY {
				t.Fatalf("bottomRight = (%d,%d) want (%d,%d)", x, y, c.wantX, c.wantY)
			}
		})
	}
}

func TestToastHTML(t *testing.T) {
	h := toastHTML(toastOK, "快速扫描完成", `https://a.example/<script>alert(1)</script>`)
	if strings.Contains(h, "<script>") {
		t.Fatal("通知正文未转义：出现原始 <script>")
	}
	if !strings.Contains(h, "&lt;script&gt;") {
		t.Fatal("通知正文应转义为实体")
	}
	if !strings.Contains(h, "card ok") || !strings.Contains(h, "✓") {
		t.Fatal("ok 通知应带 ok 样式与对勾角标")
	}
	if !strings.Contains(h, `content="light dark"`) {
		t.Fatal("通知应声明跟随系统深浅色")
	}
	errHTML := toastHTML(toastErr, "失败", "boom")
	if !strings.Contains(errHTML, "card err") {
		t.Fatal("err 通知应带 err 样式")
	}
	infoHTML := toastHTML(toastInfo, "提示", "hi")
	if !strings.Contains(infoHTML, "card info") {
		t.Fatal("info 通知应带 info 样式")
	}
}

func TestWindowMaterial(t *testing.T) {
	t.Setenv("SITLENS_WIN_MATERIAL", "")
	bg, win := windowMaterial()
	if bg != application.BackgroundTypeTranslucent {
		t.Fatalf("默认应为半透明（Mica 前提），实际 %v", bg)
	}
	if win.BackdropType != application.Mica {
		t.Fatalf("默认材质应为 Mica，实际 %v", win.BackdropType)
	}
	if win.Theme != application.SystemDefault {
		t.Fatalf("标题栏主题应跟随系统，实际 %v", win.Theme)
	}
	// 逃生阀：off → 纯色 + Auto（无材质），保证观感异常时可回滚
	t.Setenv("SITLENS_WIN_MATERIAL", "off")
	bg2, win2 := windowMaterial()
	if bg2 != application.BackgroundTypeSolid || win2.BackdropType != application.Auto {
		t.Fatalf("off 应回退纯色+Auto，实际 bg=%v backdrop=%v", bg2, win2.BackdropType)
	}
}

func TestDiffURL(t *testing.T) {
	cases := []struct{ base, want string }{
		{"http://127.0.0.1:5087", "http://127.0.0.1:5087/history?diff=1"},
		{"http://127.0.0.1:5087/", "http://127.0.0.1:5087/history?diff=1"},
	}
	for _, c := range cases {
		if got := diffURL(c.base); got != c.want {
			t.Errorf("diffURL(%q) = %q want %q", c.base, got, c.want)
		}
	}
}

func TestInjectedJSSanity(t *testing.T) { // 前端结构变化不该让快捷键报错：脚本必须自带 try/catch 且不引用外部变量。
	for name, js := range map[string]string{
		"focusURLInput": focusURLInputJS,
		"diffHint":      diffHintJS,
	} {
		if !strings.Contains(js, "try") || !strings.Contains(js, "catch") {
			t.Errorf("%s 缺少 try/catch 兜底", name)
		}
	}
	if !strings.Contains(focusURLInputJS, "#url") {
		t.Error("聚焦脚本应首选 #url（引擎工作台 URL 输入框 id）")
	}
	if !strings.Contains(diffHintJS, "diff=1") {
		t.Error("对比提示脚本应校验 ?diff=1")
	}
}

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog("短文本", 10); got != "短文本" {
		t.Fatalf("短文本不应截断，实际 %q", got)
	}
	long := strings.Repeat("中文", 100)
	if got := truncateForLog(long, 5); got != "中文中文中…" {
		t.Fatalf("截断结果 = %q", got)
	}
}
