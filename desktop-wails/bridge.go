package main

// D-06：桌面壳 ↔ 前端桥。
//
// 为什么不用 Wails 生成的 JS bindings：主窗加载的是**引擎页面**（http://127.0.0.1:port），
// 不是 Wails 资产页，拿不到 /wails/runtime.js 与生成的 bindings（那套走的是 Wails
// 资产服务器的 HTTP 传输 + 代码生成）。这里用 Wails v3 官方提供的两个能力拼一条
// 不依赖代码生成的通道：
//   前端 → 壳：页面 `chrome.webview.postMessage(json)`（Wails 注入的
//              window._wails.invoke），壳侧 Options.RawMessageHandler 接收；
//   壳 → 前端：`window.ExecJS("window.__slShellReply({...})")` 回包。
// 页面侧封装见 web/js/bridge.js（window.sitelens）。
//
// 安全边界：只有主窗自己的页面能 postMessage（WebView2 只投递本窗页面消息），
// 壳侧仍做白名单方法分发 + 参数 JSON 解码失败即拒，不执行任何字符串拼接的代码。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// feedForDisplay 更新源（可能被 SITLENS_UPDATE_URL 覆盖）——只用于 UI 展示。
func feedForDisplay() string {
	if v := strings.TrimSpace(os.Getenv(updateFeedEnv)); v != "" {
		return v
	}
	return updateBaseURL
}

// 关闭行为取值（D-06 契约："exit" | "tray"）。
const (
	closeActionExit = "exit"
	closeActionTray = "tray"
)

// shellPrefs 壳侧用户偏好（落 <userData>/shell-prefs.json，0600）。
type shellPrefs struct {
	CloseAction string `json:"close_action"`
	// AutoUpdate 启动/周期自动更新（5.3.2）：nil = 未设置（默认开启）。
	AutoUpdate *bool `json:"auto_update,omitempty"`
}

// ShellInfo GetInfo 的返回（JSON 用 snake_case，前端直接用）。
type ShellInfo struct {
	ProductVersion string `json:"product_version"`
	EngineVersion  string `json:"engine_version"`
	InstallDir     string `json:"install_dir"`
	DataDir        string `json:"data_dir"`
	AutoStart      bool   `json:"autostart"`
	CloseAction    string `json:"close_action"`
	AutoUpdate     bool   `json:"auto_update"`
}

// UpdateInfo CheckUpdate 的返回。
type UpdateInfo struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
	Current   string `json:"current"`
	Feed      string `json:"feed"`
	Notes     string `json:"notes"`
	Error     string `json:"error,omitempty"`
}

// ShellBridge 桌面壳服务：既注册进 Wails（app.RegisterService，方法可按名调用），
// 也负责 RawMessageHandler 的 postMessage 协议分发。
//
// userData = %APPDATA%\SiteLens-Wails（配置/偏好/更新包根）
// dataDir  = %APPDATA%\SiteLens-Wails\state（引擎 store.data_dir / SITLENS_DATA_DIR，
//
//	扫描历史与图谱落这里；口径见 main.go 的 C-17 注释）
type ShellBridge struct {
	app      *application.App
	shell    *shellCtx
	userData string
	dataDir  string

	prefsMu sync.Mutex
	prefs   shellPrefs

	winMu sync.Mutex
	win   application.Window // 主窗（回包目标；见 HandleRawMessage）
}

// newShellBridge 装配桥服务并加载已持久化的偏好。
// dataDir 为空时回退 userData（兼容旧调用/测试）。
func newShellBridge(app *application.App, shell *shellCtx, userData, dataDir string) *ShellBridge {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = userData
	}
	b := &ShellBridge{app: app, shell: shell, userData: userData, dataDir: dataDir}
	b.prefs.CloseAction = closeActionExit // 默认保持历史行为：点 X 退出
	defAuto := true                       // 默认开启自动更新（产品承诺「内置自动更新」）
	b.prefs.AutoUpdate = &defAuto
	if data, err := os.ReadFile(b.prefsPath()); err == nil {
		var p shellPrefs
		if json.Unmarshal(data, &p) == nil {
			b.prefs.CloseAction = normalizeCloseAction(p.CloseAction)
			if p.AutoUpdate != nil {
				b.prefs.AutoUpdate = p.AutoUpdate
			}
		}
	}
	return b
}

func (b *ShellBridge) prefsPath() string {
	return filepath.Join(b.userData, "shell-prefs.json")
}

// normalizeCloseAction 只接受 "exit" | "tray"，其余一律回落 "exit"。
func normalizeCloseAction(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), closeActionTray) {
		return closeActionTray
	}
	return closeActionExit
}

// ---- 注册服务方法（Wails app.RegisterService） ----

// GetInfo 返回产品/引擎版本、数据目录、自启动与关闭行为。
// DataDir 报的是引擎状态目录（<userData>/state，history.json 所在），
// 与设置页/README 的口径一致；壳偏好等仍在 userData 根。
func (b *ShellBridge) GetInfo() ShellInfo {
	installDir := ""
	if exe, err := os.Executable(); err == nil {
		installDir = filepath.Dir(exe)
	}
	dataDir := b.dataDir
	if dataDir == "" {
		dataDir = b.userData
	}
	info := ShellInfo{
		ProductVersion: Version,
		InstallDir:     installDir,
		DataDir:        dataDir,
		AutoStart:      b.GetAutoStart(),
		CloseAction:    b.GetCloseAction(),
		AutoUpdate:     b.GetAutoUpdate(),
	}
	if b.shell != nil {
		info.EngineVersion = b.shell.EngineVersion()
	}
	return info
}

// OpenDataDir 在资源管理器里打开数据目录（设置页「打开数据目录」按钮）：
// 打开引擎状态目录（扫描历史/图谱所在），而非整个 userData 根。
func (b *ShellBridge) OpenDataDir() bool {
	dir := b.dataDir
	if dir == "" {
		dir = b.userData
	}
	if dir == "" {
		return false
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("建数据目录失败：%v", err)
		return false
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer.exe", dir)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("打开数据目录失败：%v", err)
		return false
	}
	return true
}

// GetAutoStart 读自启动状态（Wails AutostartManager：Windows 走 Run 键）。
func (b *ShellBridge) GetAutoStart() bool {
	if b.app == nil || b.app.Autostart == nil {
		return false
	}
	on, err := b.app.Autostart.IsEnabled()
	if err != nil {
		log.Printf("读自启动状态失败：%v", err)
		return false
	}
	return on
}

// SetAutoStart 开/关自启动，返回设置后的真实状态（失败时保持原状）。
func (b *ShellBridge) SetAutoStart(on bool) bool {
	if b.app == nil || b.app.Autostart == nil {
		return false
	}
	var err error
	if on {
		err = b.app.Autostart.Enable()
	} else {
		err = b.app.Autostart.Disable()
	}
	if err != nil {
		log.Printf("设置自启动失败（on=%v）：%v", on, err)
	}
	return b.GetAutoStart()
}

// GetCloseAction 返回 "exit" | "tray"。
func (b *ShellBridge) GetCloseAction() string {
	b.prefsMu.Lock()
	defer b.prefsMu.Unlock()
	return normalizeCloseAction(b.prefs.CloseAction)
}

// SetCloseAction 设置关闭行为并落盘，返回归一化后的值。
func (b *ShellBridge) SetCloseAction(action string) string {
	next := normalizeCloseAction(action)
	b.prefsMu.Lock()
	b.prefs.CloseAction = next
	prefs := b.prefs
	b.prefsMu.Unlock()
	if err := b.savePrefs(prefs); err != nil {
		log.Printf("保存关闭行为失败：%v", err)
	}
	return next
}

func (b *ShellBridge) savePrefs(p shellPrefs) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.userData, 0o755); err != nil {
		return err
	}
	return os.WriteFile(b.prefsPath(), append(data, '\n'), 0o600)
}

// notifyFn 返回壳通知函数（可能为 nil）。
func (b *ShellBridge) notifyFn() func(kind, title, body string) {
	if b.shell != nil {
		return b.shell.notifier.Show
	}
	return nil
}

// GetAutoUpdate 是否启用启动/周期自动更新（默认 true）。
func (b *ShellBridge) GetAutoUpdate() bool {
	b.prefsMu.Lock()
	defer b.prefsMu.Unlock()
	if b.prefs.AutoUpdate == nil {
		return true
	}
	return *b.prefs.AutoUpdate
}

// SetAutoUpdate 持久化自动更新开关（单向动作：页面无需回包）。
func (b *ShellBridge) SetAutoUpdate(on bool) bool {
	b.prefsMu.Lock()
	v := on
	b.prefs.AutoUpdate = &v
	prefs := b.prefs
	b.prefsMu.Unlock()
	if err := b.savePrefs(prefs); err != nil {
		log.Printf("保存自动更新偏好失败：%v", err)
	}
	log.Printf("自动更新已%s", map[bool]string{true: "开启", false: "关闭"}[on])
	return on
}

// CheckUpdate 5.3.2 起是"完整更新动作"而不是只查询：
// Wails 壳没有可靠的壳→页面回包通道（见 InfoFragment 注释），设置页点「检查更新」
// 只能单向触发；因此这里直接走 检查 → 原生确认 → 下载 → 校验 → 安装 → 退出。
// 结果写 shell.log 与托盘通知（发现新版本/失败都会提示）。
func (b *ShellBridge) CheckUpdate() UpdateInfo {
	go runUpdateCheck(b.userData, b.app, b.notifyFn())
	return UpdateInfo{Current: Version, Feed: feedForDisplay()}
}

// InstallUpdate 用户点击「安装更新」：Go 侧原生确认框（默认「否」）→ 后台下载安装。
// 返回 nil 表示已开始（或用户取消时返回 errUpdateDeclined，前端据此给中性提示）。
func (b *ShellBridge) InstallUpdate() error {
	d, m, err := checkUpdate(Version)
	if err != nil {
		return err
	}
	if d.State != "available" {
		return fmt.Errorf("当前已是最新版本 v%s", d.Current)
	}
	if !confirmInstallDialog(d.Latest, d.Current) {
		return errUpdateDeclined
	}
	go func() {
		// 确认已由桥做过，这里传"永远同意"避免二次弹窗。
		always := func(string, string) bool { return true }
		if err := downloadAndInstall(d, m, b.userData, always); err != nil {
			log.Printf("桥触发更新失败：%v", err)
			return
		}
		if b.app != nil {
			b.app.Quit()
		}
	}()
	return nil
}

// ---- postMessage 协议 ----

// bridgeRequest 前端消息体：{"sl":{"id":1,"method":"GetInfo","args":[...]}}。
type bridgeRequest struct {
	SL struct {
		ID     int               `json:"id"`
		Method string            `json:"method"`
		Args   []json.RawMessage `json:"args"`
	} `json:"sl"`
}

// parseBridgeRequest 解析前端消息；非桥消息（不含 "sl"）返回 ok=false 静默忽略。
func parseBridgeRequest(raw string) (id int, method string, args []json.RawMessage, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, `"sl"`) {
		return 0, "", nil, false
	}
	var req bridgeRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return 0, "", nil, false
	}
	if strings.TrimSpace(req.SL.Method) == "" {
		return 0, "", nil, false
	}
	return req.SL.ID, req.SL.Method, req.SL.Args, true
}

// dispatch 白名单方法分发（未知方法一律拒绝，不做反射调用）。
func (b *ShellBridge) dispatch(method string, args []json.RawMessage) (any, error) {
	switch method {
	case "GetInfo":
		return b.GetInfo(), nil
	case "GetAutoStart":
		return b.GetAutoStart(), nil
	case "SetAutoStart":
		var on bool
		if len(args) > 0 {
			if err := json.Unmarshal(args[0], &on); err != nil {
				return nil, fmt.Errorf("SetAutoStart 参数非法")
			}
		}
		return b.SetAutoStart(on), nil
	case "GetCloseAction":
		return b.GetCloseAction(), nil
	case "SetCloseAction":
		var action string
		if len(args) > 0 {
			if err := json.Unmarshal(args[0], &action); err != nil {
				return nil, fmt.Errorf("SetCloseAction 参数非法")
			}
		}
		return b.SetCloseAction(action), nil
	case "GetAutoUpdate":
		return b.GetAutoUpdate(), nil
	case "SetAutoUpdate":
		var on bool
		if len(args) > 0 {
			if err := json.Unmarshal(args[0], &on); err != nil {
				return nil, fmt.Errorf("SetAutoUpdate 参数非法")
			}
		}
		return b.SetAutoUpdate(on), nil
	case "CheckUpdate":
		return b.CheckUpdate(), nil
	case "OpenDataDir":
		return b.OpenDataDir(), nil
	case "InstallUpdate":
		if err := b.InstallUpdate(); err != nil {
			return nil, err
		}
		return map[string]any{"started": true}, nil
	default:
		return nil, fmt.Errorf("未知桥方法：%s", method)
	}
}

// bridgeReplyScript 生成回包 JS（只拼 JSON，不拼用户字符串）。
func bridgeReplyScript(id int, result any, err error) string {
	payload := map[string]any{"id": id, "ok": err == nil}
	if err != nil {
		payload["error"] = err.Error()
	} else {
		payload["result"] = result
	}
	data, jerr := json.Marshal(payload)
	if jerr != nil {
		return ""
	}
	return "window.__slShellReply&&window.__slShellReply(" + string(data) + ");"
}

// InfoFragment 把 ShellInfo 编码成 URL fragment 值（base64url JSON）。
//
// 为什么需要它：Wails v3 beta.22 在「URL 指向引擎页面」的窗口上 ExecJS 不落地
// （实测连 `window.__x=1` 这种独立探针都不执行，且无任何错误日志），所有
// 「壳 → 页面」回包都收不到。GetInfo 这类只读信息改为随 URL fragment 一次性
// 注入（fragment 不发给服务端、页面读完即抹掉），不再依赖回包通道。
func (b *ShellBridge) InfoFragment() string {
	if b == nil {
		return ""
	}
	data, err := json.Marshal(b.GetInfo())
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// HandleRawMessage RawMessageHandler 入口：解析 → 分发 → 尝试 ExecJS 回包。
//
// 单向动作（SetAutoStart/SetCloseAction/OpenDataDir/CheckUpdate/InstallUpdate）
// 只依赖「入站」通道——入站已验证可靠；回包仅为前向兼容保留（当前 Wails 版本
// 上不会落地，见 InfoFragment 注释），前端 bridge.js 不依赖它。
func (b *ShellBridge) HandleRawMessage(w application.Window, raw string) {
	id, method, args, ok := parseBridgeRequest(raw)
	if !ok {
		return
	}
	result, err := b.dispatch(method, args)
	if err != nil {
		log.Printf("桥动作失败：method=%s id=%d err=%v", method, id, err)
	}
	script := bridgeReplyScript(id, result, err)
	if script == "" {
		return
	}
	if target := b.targetWindow(w); target != nil {
		target.ExecJS(script)
	}
}

// SetWindow 记录主窗引用（主窗创建后调用）。见 HandleRawMessage 的说明。
func (b *ShellBridge) SetWindow(w application.Window) {
	b.winMu.Lock()
	b.win = w
	b.winMu.Unlock()
}

// targetWindow 回包目标：优先主窗，其次 RawMessageHandler 的回调参数。
func (b *ShellBridge) targetWindow(fallback application.Window) application.Window {
	b.winMu.Lock()
	defer b.winMu.Unlock()
	if b.win != nil {
		return b.win
	}
	return fallback
}
