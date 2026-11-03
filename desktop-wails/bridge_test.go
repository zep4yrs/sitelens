package main

// D-06 / D-07 的回归测试：桥协议解析/回包、关闭行为归一化与持久化、
// 引擎就绪的 nonce 校验（httptest 假引擎，不起 Wails、不连真引擎）。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func TestParseBridgeRequest(t *testing.T) {
	// 正常消息：id/method/args 都要解出来
	id, method, args, ok := parseBridgeRequest(`{"sl":{"id":7,"method":"SetAutoStart","args":[true]}}`)
	if !ok || id != 7 || method != "SetAutoStart" || len(args) != 1 || string(args[0]) != "true" {
		t.Fatalf("解析结果不符：ok=%v id=%d method=%q args=%v", ok, id, method, args)
	}
	// 非桥消息（Wails 自身的 wails:* 消息）必须静默忽略，不能报错/回包
	for _, raw := range []string{
		"", "   ", "wails:drag", `{"foo":1}`, `{"sl":{"id":1}}`, `{"sl":{"id":1,"method":"  "}}`,
		`{"sl":not-json}`, `null`,
	} {
		if _, _, _, ok := parseBridgeRequest(raw); ok {
			t.Errorf("消息 %q 不应被当作桥请求", raw)
		}
	}
}

func TestBridgeReplyScript(t *testing.T) {
	// 成功回包：JSON 结果原样嵌入，带 id
	s := bridgeReplyScript(3, map[string]any{"available": true}, nil)
	if !strings.Contains(s, `"id":3`) || !strings.Contains(s, `"ok":true`) ||
		!strings.Contains(s, `"available":true`) {
		t.Fatalf("成功回包脚本不符：%s", s)
	}
	if !strings.HasPrefix(s, "window.__slShellReply&&window.__slShellReply(") {
		t.Fatalf("回包必须走 __slShellReply 守卫：%s", s)
	}
	// 失败回包：ok=false + error 文本
	es := bridgeReplyScript(4, nil, errors.New(`未知桥方法：X"y`))
	if !strings.Contains(es, `"ok":false`) || !strings.Contains(es, "未知桥方法") {
		t.Fatalf("失败回包脚本不符：%s", es)
	}
	// 引号必须被 JSON 转义，不能截断 JS 字符串
	if strings.Contains(es, `X"y`) {
		t.Errorf("错误文本里的引号未转义：%s", es)
	}
}

func TestNormalizeCloseAction(t *testing.T) {
	cases := map[string]string{
		"tray": closeActionTray, "TRAY": closeActionTray, " tray ": closeActionTray,
		"exit": closeActionExit, "": closeActionExit, "quit": closeActionExit,
		"close": closeActionExit, "<script>": closeActionExit,
	}
	for in, want := range cases {
		if got := normalizeCloseAction(in); got != want {
			t.Errorf("normalizeCloseAction(%q)=%q，期望 %q", in, got, want)
		}
	}
}

func TestCloseActionPersists(t *testing.T) {
	dir := t.TempDir()
	b := &ShellBridge{userData: dir}
	if got := b.GetCloseAction(); got != closeActionExit {
		t.Fatalf("默认关闭行为应为 exit，实际 %q", got)
	}
	if got := b.SetCloseAction("tray"); got != closeActionTray {
		t.Fatalf("SetCloseAction(tray)=%q", got)
	}
	// 落盘（0600，Windows 上 mode 位不生效，只断言文件存在且内容正确）
	p := filepath.Join(dir, "shell-prefs.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("偏好文件未落盘：%v", err)
	}
	var p2 shellPrefs
	if err := json.Unmarshal(data, &p2); err != nil || p2.CloseAction != closeActionTray {
		t.Fatalf("偏好文件内容不符：%s (%v)", data, err)
	}
	// 重新加载（模拟下次启动）
	b2 := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	if got := b2.GetCloseAction(); got != closeActionTray {
		t.Errorf("重启后应读回 tray，实际 %q", got)
	}
	// 非法值回落 exit
	if got := b2.SetCloseAction("rm -rf"); got != closeActionExit {
		t.Errorf("非法关闭行为应回落 exit，实际 %q", got)
	}
}

func TestBridgeNilAppSafe(t *testing.T) {
	// 桥在 app 未装配（单测/降级）时不得 panic
	b := &ShellBridge{userData: t.TempDir()}
	if b.GetAutoStart() {
		t.Error("无 app 时自启动应为 false")
	}
	if b.SetAutoStart(true) {
		t.Error("无 app 时 SetAutoStart 应为 false")
	}
	info := b.GetInfo()
	if info.ProductVersion != Version || info.DataDir == "" {
		t.Errorf("GetInfo 基础字段不符：%+v", info)
	}
}

// TestGetInfoReportsStateDir 口径：DataDir 报引擎状态目录（<userData>/state，
// history.json 所在），不是 userData 根——与设置页/README 的写法一致。
func TestGetInfoReportsStateDir(t *testing.T) {
	userData := t.TempDir()
	stateDir := filepath.Join(userData, "state")
	b := newShellBridge(nil, nil, userData, stateDir)
	if got := b.GetInfo().DataDir; got != stateDir {
		t.Errorf("DataDir=%q，期望状态目录 %q", got, stateDir)
	}
	// dataDir 为空时回退 userData（兼容旧调用）
	b2 := newShellBridge(nil, nil, userData, "")
	if got := b2.GetInfo().DataDir; got != userData {
		t.Errorf("空 dataDir 应回退 userData，实际 %q", got)
	}
}

func TestShellInfoJSONShape(t *testing.T) {
	b := &ShellBridge{userData: t.TempDir()}
	data, err := json.Marshal(b.GetInfo())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"product_version"`, `"engine_version"`, `"data_dir"`, `"autostart"`, `"close_action"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Errorf("ShellInfo 缺少字段 %s：%s", key, data)
		}
	}
}

func TestBridgeDispatchRejectsUnknownAndBadArgs(t *testing.T) {
	b := &ShellBridge{userData: t.TempDir()}
	if _, err := b.dispatch("Nope", nil); err == nil {
		t.Error("未知方法必须拒绝")
	}
	if _, err := b.dispatch("SetAutoStart", []json.RawMessage{json.RawMessage(`"not-a-bool"`)}); err == nil {
		t.Error("SetAutoStart 参数类型错误必须拒绝")
	}
	if _, err := b.dispatch("SetCloseAction", []json.RawMessage{json.RawMessage(`123`)}); err == nil {
		t.Error("SetCloseAction 参数类型错误必须拒绝")
	}
	// 合法调用
	if v, err := b.dispatch("GetCloseAction", nil); err != nil || v != closeActionExit {
		t.Errorf("GetCloseAction 应返回 exit：v=%v err=%v", v, err)
	}
	_ = application.Window(nil) // 保持 application 导入（bridge 依赖该接口）
}

// 更新源地址回归：GitHub 账号曾写错（zep4rs vs zep4yrs），导致 latest.yml 404、
// 自动更新永久失效且日志只报「更新清单不可达」。地址必须是实际仓库账号 + https。
func TestUpdateBaseURLPointsToRealRepo(t *testing.T) {
	const want = "https://github.com/zep4yrs/sitelens/releases/download/desktop-stable/"
	if updateBaseURL != want {
		t.Fatalf("更新源地址不符：got %q want %q", updateBaseURL, want)
	}
	if !strings.HasPrefix(updateBaseURL, "https://") {
		t.Fatalf("更新源必须 https：%q", updateBaseURL)
	}
}
