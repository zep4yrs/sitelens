package main

// Wave-1/3 修复（D-01/D-12/D-16 + 窗口图标 + D-07 nonce + D-06 桥）的回归测试：
// 只测纯逻辑/可注入 IO，不启动 Wails。
//
// 这些用例是「安全约束不被悄悄改回去」的闸：
//   - 摘要校验必须 fail-closed（缺摘要不得放行）；
//   - CDP 调试端口只接受 1-65535 且必须回环；
//   - 壳日志超限必须轮转（旧实现无限追加）；
//   - 应用图标必须是 ICO 字节（否则 Windows 窗口回落成 IDI_APPLICATION 通用图标）；
//   - 引擎就绪判定必须校验 nonce（端口被抢占时拒绝启动）；
//   - 壳 nonce 必须是 64 hex 随机串。

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"sitelens-wails/internal/usercfg"
)

// icoMagic ICONDIR 魔数：00 00 01 00。
var icoMagic = []byte{0x00, 0x00, 0x01, 0x00}

// pngMagic 用来反向断言：CreateLargeHIconFromImage 解析的是 ICONDIR，PNG 会失败。
var pngMagic = []byte{0x89, 'P', 'N', 'G'}

func TestVerifySHA512FailClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pkg.exe")
	content := []byte("site-lens-installer-bytes")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(content)
	good := base64.StdEncoding.EncodeToString(sum[:])

	if err := verifySHA512(p, good); err != nil {
		t.Fatalf("摘要匹配时应通过：%v", err)
	}

	bad := map[string]string{
		"缺摘要":       "",
		"仅空白":       "   ",
		"非 base64":   "abc==",
		"长度不对":      base64.StdEncoding.EncodeToString([]byte("short")),
		"摘要不匹配":     base64.StdEncoding.EncodeToString(make([]byte, sha512.Size)),
	}
	for name, want := range bad {
		if err := verifySHA512(p, want); err == nil {
			t.Errorf("%s：必须返回错误（fail-closed），实际 nil", name)
		}
	}
}

func TestCDPBrowserArgs(t *testing.T) {
	t.Setenv("SITLENS_CDP_PORT", "")
	if args := cdpBrowserArgs(); args != nil {
		t.Errorf("未设置时不应产生调试参数：%v", args)
	}

	t.Setenv("SITLENS_CDP_PORT", "9223")
	args := cdpBrowserArgs()
	if len(args) != 2 {
		t.Fatalf("应产生 2 个参数，实际 %v", args)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--remote-debugging-address=127.0.0.1") {
		t.Errorf("必须显式绑回环：%v", args)
	}
	if !strings.Contains(joined, "--remote-debugging-port=9223") {
		t.Errorf("端口应原样下发：%v", args)
	}

	for _, bad := range []string{"0", "65536", "-1", "abc", "9223 --disable-web-security", "80x", " "} {
		t.Setenv("SITLENS_CDP_PORT", bad)
		if got := cdpBrowserArgs(); got != nil {
			t.Errorf("非法取值 %q 必须被拒绝，实际 %v", bad, got)
		}
	}
}

func TestOpenShellLogRotates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "SiteLens-Wails")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "shell.log")
	// 造一个超限文件
	if err := os.WriteFile(p, make([]byte, shellLogMaxBytes+16), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openShellLogAt(dir)
	if err != nil {
		t.Fatalf("openShellLogAt 失败：%v", err)
	}
	defer f.Close()
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Errorf("超限后应轮转出 shell.log.1：%v", err)
	}
	if st, err := os.Stat(p); err != nil || st.Size() != 0 {
		t.Errorf("轮转后新日志应为空文件，实际 size=%v err=%v", st.Size(), err)
	}
	// 未超限时不轮转
	if err := os.WriteFile(p, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	f2, err := openShellLogAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()
	if st, err := os.Stat(p); err != nil || st.Size() != 5 {
		t.Errorf("未超限不应轮转，实际 size=%v err=%v", st.Size(), err)
	}
}

// TestAppOptionsIcon 回归：应用图标必须显式给出 ICO 字节。
//
// 根因（Wails v3 beta.22 webview_window_windows.go:585-600）：
//  1. 窗口初始化先找 exe 资源里 ID=3 的 RT_GROUP_ICON —— go-winres 生成的是 ID=1，
//     所以这一步必然失败；
//  2. 失败后回退 application.Options.Icon；旧实现没设 → 回退 nil；
//  3. 两步都拿不到 → 窗口类沿用 IDI_APPLICATION（Windows 通用图标），
//     即用户截图里「左上角图标是坏的」。
//
// 这条用例锁死：Icon 非空 + 是 ICONDIR（不是 PNG，CreateLargeHIconFromImage
// 解析 ICONDIR 而不是 PNG）+ 帧数 > 0；顺带锁住 Options 里其余不能丢的装配。
func TestAppOptionsIcon(t *testing.T) {
	args := []string{"--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9223"}
	var rawHandlerCalled bool
	opts := newAppOptions(args, func(application.Window, string, *application.OriginInfo) {
		rawHandlerCalled = true
	})
	if opts.RawMessageHandler == nil {
		t.Fatal("RawMessageHandler 为空：D-06 桥收不到页面 postMessage")
	}
	opts.RawMessageHandler(nil, "x", nil)
	if !rawHandlerCalled {
		t.Error("RawMessageHandler 未把消息转给注入的处理器")
	}

	if len(opts.Icon) == 0 {
		t.Fatal("application.Options.Icon 为空：exe 资源 ID=3 不存在时窗口会回落成 IDI_APPLICATION 通用图标")
	}
	if !bytes.HasPrefix(opts.Icon, icoMagic) {
		t.Fatalf("Icon 不是 ICO（ICONDIR 魔数应为 % x，实际 % x）", icoMagic, opts.Icon[:min(8, len(opts.Icon))])
	}
	if bytes.HasPrefix(opts.Icon, pngMagic) {
		t.Fatal("Icon 是 PNG：CreateLargeHIconFromImage 解析 ICONDIR，PNG 会导致 setIcon 失败")
	}
	// ICONDIR: 6 字节头（reserved/type/count），count 在偏移 4（小端 uint16）
	if len(opts.Icon) < 6 {
		t.Fatalf("ICO 太短，无法解析帧数：%d 字节", len(opts.Icon))
	}
	count := int(opts.Icon[4]) | int(opts.Icon[5])<<8
	if count < 1 {
		t.Fatalf("ICO 帧数为 %d（应 ≥1，含 256px 帧）", count)
	}
	// 逐帧校验：ICONDIR 条目 16 字节，宽度/高度字节为 0 表示 256px。
	// 标题栏/任务栏大图标走最大帧，缺 256px 会发糊。
	hasLarge := false
	for i := 0; i < count; i++ {
		off := 6 + i*16
		if off+16 > len(opts.Icon) {
			t.Fatalf("ICO 第 %d 帧条目越界（off=%d len=%d）", i, off, len(opts.Icon))
		}
		w, h := int(opts.Icon[off]), int(opts.Icon[off+1])
		size := int(opts.Icon[off+8]) | int(opts.Icon[off+9])<<8 |
			int(opts.Icon[off+10])<<16 | int(opts.Icon[off+11])<<24
		imgOff := int(opts.Icon[off+12]) | int(opts.Icon[off+13])<<8 |
			int(opts.Icon[off+14])<<16 | int(opts.Icon[off+15])<<24
		if imgOff < 0 || size < 0 || imgOff+size > len(opts.Icon) {
			t.Fatalf("ICO 第 %d 帧数据越界（off=%d size=%d total=%d）", i, imgOff, size, len(opts.Icon))
		}
		if w == 0 && h == 0 {
			hasLarge = true
		}
	}
	if !hasLarge {
		t.Error("ICO 缺少 256x256 帧：Windows 标题栏/任务栏大图标会发糊")
	}

	// Options 其余装配不得在重构中丢失
	if opts.Name != "SiteLens" || opts.Description == "" {
		t.Errorf("Name/Description 丢失：%q / %q", opts.Name, opts.Description)
	}
	if opts.ErrorHandler == nil {
		t.Error("ErrorHandler 丢失：Wails 内部错误将无处落日志（FE-08）")
	}
	if opts.Assets.Handler == nil {
		t.Error("Assets.Handler 丢失：启动页/回退资源无法伺服")
	}
	if got := opts.Windows.AdditionalBrowserArgs; len(got) != len(args) || got[0] != args[0] || got[1] != args[1] {
		t.Errorf("AdditionalBrowserArgs 未透传：got %v want %v", got, args)
	}
	// 空参数也应得到可用 Options（cdpBrowserArgs 未开启时的常态）
	if opts := newAppOptions(nil, nil); len(opts.Icon) == 0 {
		t.Error("browserArgs 为空时 Icon 也必须存在")
	}
}

// TestNewShellNonce D-07：nonce 必须是 32 字节随机数的 hex（64 字符），且每次不同。
func TestNewShellNonce(t *testing.T) {
	a, err := newShellNonce()
	if err != nil {
		t.Fatalf("newShellNonce 失败：%v", err)
	}
	if len(a) != 64 {
		t.Fatalf("nonce 长度应为 64，实际 %d：%q", len(a), a)
	}
	if !usercfg.ValidAPIToken(a) { // 同一套 64-hex 校验（字符集 + 长度）
		t.Fatalf("nonce 不是 64 位 hex：%q", a)
	}
	b, err := newShellNonce()
	if err != nil {
		t.Fatalf("newShellNonce 失败：%v", err)
	}
	if a == b {
		t.Error("两次生成的 nonce 不应相同")
	}
}

// TestWaitReadyNonce D-07：引擎 /api/version 回显的 nonce 必须与本壳注入的一致。
// 端口 TOCTOU：抢占端口的进程不会知道 nonce → 必须拒绝启动，而不是把它的页面交给主窗。
func TestWaitReadyNonce(t *testing.T) {
	const want = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"nonce 匹配", `{"version":"5.3.0","nonce":"` + want + `"}`, true},
		{"缺失 nonce", `{"version":"5.3.0"}`, false},
		{"nonce 不等", `{"version":"5.3.0","nonce":"deadbeef"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			ver, err := waitReady(srv.URL+"/api/version", 800*time.Millisecond, want, "")
			if c.ok {
				if err != nil || ver != "5.3.0" {
					t.Fatalf("应通过并返回版本：ver=%q err=%v", ver, err)
				}
				return
			}
			if !errors.Is(err, errNonceMismatch) {
				t.Fatalf("应返回 errNonceMismatch，实际 ver=%q err=%v", ver, err)
			}
		})
	}
}

// TestWaitReadyTimeout 非 200/非法 JSON 时重试到超时并报错（不误判就绪）。
func TestWaitReadyTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	start := time.Now()
	_, err := waitReady(srv.URL+"/api/version", 600*time.Millisecond, "abc", "")
	if err == nil {
		t.Fatal("持续 503 时应超时报错")
	}
	if time.Since(start) < 400*time.Millisecond {
		t.Errorf("应重试到接近预算再失败，实际仅 %v", time.Since(start))
	}
	if errors.Is(err, errNonceMismatch) {
		t.Error("503 不应被当作 nonce 不匹配")
	}
}

// TestWaitReadySendsAPIToken A-01/D-02：配置 web.api_token 后，引擎对**所有**
// /api/*（含 /api/version）都要求 X-Token（internal/server 的令牌守卫）。
// 壳的探测请求必须带 token，否则会永远"未就绪"而误杀引擎（实机验证踩到过）。
func TestWaitReadySendsAPIToken(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const nonce = "shell-nonce-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != tok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"未授权：需要 X-Token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"5.2.3","nonce":"` + nonce + `"}`))
	}))
	defer srv.Close()

	// 带正确 token → 通过并返回版本
	ver, err := waitReady(srv.URL+"/api/version", 800*time.Millisecond, nonce, tok)
	if err != nil || ver != "5.2.3" {
		t.Fatalf("带 X-Token 应通过：ver=%q err=%v", ver, err)
	}
	// 不带 token → 401 会一直重试到超时，必须失败（不能把 401 当就绪）
	if _, err := waitReady(srv.URL+"/api/version", 500*time.Millisecond, nonce, ""); err == nil {
		t.Fatal("不带 token 时应超时失败，而不是误判就绪")
	}
}
