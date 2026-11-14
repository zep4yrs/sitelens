// SiteLens Wails 壳（实验，4.0 Track：GUI 换壳验证）。
//
// 职责与 Electron 壳对齐的最小子集：
//  1. 探测引擎目录（打包态 = exe 同级 engine/；开发态 = 仓库 build/engine，
//     可用 SITLENS_ENGINE_DIR 覆盖）
//  2. 取空闲端口，生成最小配置（web.listen）落【用户目录】——不写安装目录
//     （v3.0.1 EPERM 教训：Program Files 只读）
//  3. 拉起 sitelens-engine.exe serve（cwd=引擎目录，相对 data/ 路径随 cwd 解析）
//     —— 5.2 起引擎与 CLI 拆成两个二进制：引擎只做 serve + update-seed，
//     CLI（scan/audit/update-*）独立分发、不随桌面安装包发布。
//  4. /api/version 健康检查通过后开窗，窗口直接加载引擎 URL（引擎零改动）
//  5. 退出时回收引擎进程
//
// 引擎 UI 即引擎 HTTP 服务本身，本壳不做任何资源伺服（无 ASAR 白名单问题）。
//
// 构建（Windows）：go build -ldflags "-s -w -H windowsgui" -o sitelens-wails.exe .
// （-H windowsgui = GUI 子系统不弹控制台；图标资源在 rsrc_windows_amd64.syso，
// 由 go-winres simply --icon assets/icon.ico 生成，仓库已带，日常构建无需重造）。
//
// 构建（Linux/macOS）：go build -ldflags "-s -w" -o sitelens-wails .
//
//	Linux 需 CGO + 系统依赖：libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config gcc；
//	macOS 需 Xcode Command Line Tools（Cocoa/WebKit 由系统框架提供）。
//	打包见 tools/wails_package.sh（AppImage/.deb 与 .app/.dmg）。
package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"gopkg.in/yaml.v3"

	"sitelens-wails/internal/usercfg"
)

//go:embed assets/index.html
var fallbackAssets embed.FS

//go:embed assets/icon.ico
var iconICO []byte // SiteLens 品牌 logo（与 Electron 壳 desktop/build/icon.ico 同源）：
// Windows 窗口/任务栏/资源管理器/任务管理器图标统一由 exe 内嵌资源提供
//（rsrc_windows_amd64.syso），托盘图标用这份字节运行时注入

//go:embed assets/splash.html
var splashTmpl string

//go:embed assets/icon.png
var splashPNG []byte

// buildSplashHTML 组装启动页：logo 以 data URI 注入（资产原样），无图则降级隐藏品牌标。
func buildSplashHTML() string {
	logoTag := `<img class="logo" alt="" style="display:none">`
	if len(splashPNG) > 0 {
		logoTag = `<img class="logo" alt="SiteLens" src="data:image/png;base64,` +
			base64.StdEncoding.EncodeToString(splashPNG) + `">`
	}
	// 全量替换（-1）：注释与正文槽位都吃，避免「第一处在注释里」把正文槽漏掉
	h := strings.ReplaceAll(splashTmpl, "{{LOGO}}", logoTag)
	// VER 槽注入版本号（Version 单一来源，见 version.go）——此前恒传空串，
	// 启动页版本号位一直是空白，用户无从核对装的是哪一版。
	return strings.ReplaceAll(h, "{{VER}}", "v"+Version)
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	// 生命周期落盘：GUI 子系统没有控制台，退出原因必须留痕可查（D-16：带轮转与上限）
	if f := openShellLog(); f != nil {
		log.SetOutput(f)
		defer f.Close()
	}
	log.Println("---- shell 启动 ----")

	engineDir, ok := detectEngineDir()
	if !ok {
		log.Fatal("未找到引擎（期望 exe 同级 engine/ 或 ../build/engine，或设 SITLENS_ENGINE_DIR）")
	}
	engineExe, ok := findEngineExe(engineDir)
	if !ok {
		log.Fatalf("引擎程序不存在（期望 %s 或 %s）: %s",
			engineExeName, "sitelens"+exeSuffix(), engineDir)
	}

	// 用户数据区与受管路径：可写数据（历史/情报/模板池/插件）归用户区，
	// 只读资产留安装目录。路径决策见 internal/usercfg（有跨平台单测）。
	userData, err := userDataDir()
	if err != nil {
		log.Fatalf("取用户数据目录失败: %v", err)
	}
	managed := usercfg.Resolve(userData, engineDir)
	if err := prepareUserData(managed); err != nil {
		log.Fatalf("建用户数据目录失败: %v", err)
	}

	// 覆盖更新的一环：把随包只读种子按**包版本**交付到用户数据区。
	// 版本变化才覆盖，同版本二次启动 no-op；边界见引擎 internal/seedrefresh。
	deliverSeeds(engineExe, managed.SeedDir, userData)

	// 端口决策：壳偏好 > 配置原文 > 默认 5087，被占用才随机（见 port.go）。
	listen, port := chooseListen()
	// A-01/D-02：写配置时顺带确保 web.api_token 存在（64 hex），返回值用于
	// 主窗 URL fragment 注入（fragment 不发服务端、不进访问日志）。
	cfgPath, apiToken, err := writeUserConfig(listen, managed)
	if err != nil {
		log.Fatalf("写用户配置失败: %v", err)
	}

	// D-07：一次性随机 nonce —— 引擎 /api/version 会回显它，壳据此确认
	// 监听端口的确实是本壳拉起的引擎（而不是抢占端口的其它进程）。
	shellNonce, err := newShellNonce()
	if err != nil {
		log.Fatalf("生成 nonce 失败: %v", err)
	}
	// C-17：数据目录显式指向用户区（引擎 config 的 applyEnvOverrides 里
	// SITLENS_DATA_DIR 优先级高于 yaml）。取 managed.DataDir 而不是另拼一个
	// 路径：与写进 yaml 的 store.data_dir 同源，避免"配置一个目录、环境变量
	// 又一个目录"的双份状态（旧用户的历史也不会因为路径漂移而"消失"）。
	// 落点口径（全仓统一）：%APPDATA%\SiteLens-Wails\state —— 即 history.json
	// 所在的状态目录；<userData>\data 只放随包种子与 intel_overrides.json。
	// 安装目录只读资产保持不动，安装态不再往 Program Files 写 data/。
	engineDataDir := managed.DataDir
	if err := os.MkdirAll(engineDataDir, 0o755); err != nil {
		log.Fatalf("建引擎数据目录失败: %v", err)
	}

	cmd := exec.Command(engineExe, "-config", cfgPath, "serve")
	cmd.Dir = engineDir // 只读资产与相对 data/ 路径随引擎目录解析
	cmd.Env = append(os.Environ(),
		"SITLENS_SHELL_NONCE="+shellNonce,
		"SITLENS_DATA_DIR="+engineDataDir,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	// 不弹控制台窗口（BUG-032）：引擎是控制台子系统程序，GUI 壳拉起它时
	// Windows 会给它新建一个控制台 → 桌面上弹出一个黑窗。
	// CREATE_NO_WINDOW 让子进程**不创建**控制台（比只设 HideWindow 更彻底：
	// 后者只是把窗口藏起来，窗口仍被创建、仍会抢焦点）。
	// ⚠️ 引擎本身保持控制台子系统是有意的：CLI 要靠 stdout 输出结果，
	// 引擎侧 update-seed 也要输出交付报告——「不弹窗」由这里解决，
	// 不能靠给引擎加 -H windowsgui（那会连带打死 CLI 的 stdout）。
	// 非 Windows 平台该函数是空操作（POSIX 无控制台窗口概念）。
	hideChildWindow(cmd)
	if err := cmd.Start(); err != nil {
		log.Fatalf("引擎启动失败: %v", err)
	}
	eng := cmd.Process
	log.Printf("引擎已启动 pid=%d listen=%s dir=%s", eng.Pid, listen, engineDir)
	defer func() {
		killEngineTree(eng)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// CDP 调试通道默认关：设 SITLENS_CDP_PORT=9223 才开启（验证/排查用）。
	// D-12：只接受 1-65535 的整数端口，且显式绑回环（见 cdpBrowserArgs）。
	browserArgs := cdpBrowserArgs()
	// SITLENS_RM=1：强制 prefers-reduced-motion（启动页降级路径的验证开关，产品路径不感知）
	if os.Getenv("SITLENS_RM") == "1" {
		browserArgs = append(browserArgs, "--force-prefers-reduced-motion")
	}
	// D-06：壳↔前端桥。RawMessageHandler 在 application.New 之前装配，
	// 但它真正被调用是在窗口页面 postMessage 时（那时 bridge 已赋值）。
	var bridge *ShellBridge
	app := application.New(newAppOptions(browserArgs, func(w application.Window, msg string, _ *application.OriginInfo) {
		if bridge != nil {
			bridge.HandleRawMessage(w, msg)
		}
	}))

	// 启动页「对焦」先行：引擎冷启动期间的唯一可见面（与 Electron 壳 splash 同源设计）
	splashBorn := time.Now() // 最低展示时长的起点（暖启动引擎 ~300ms 就绪，动画需 ~1.9s 播完）
	splashWin := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "SiteLens 启动中",
		Width:            460,
		Height:           330,
		Frameless:        true,
		DisableResize:    true,
		AlwaysOnTop:      true,
		Windows:          application.WindowsWindow{HiddenOnTaskbar: true},
		BackgroundType:   application.BackgroundTypeTransparent,
		BackgroundColour: application.NewRGB(0, 0, 0),
		HTML:             buildSplashHTML(),
	})

	// 主窗在引擎就绪后由 goroutine 创建（URL 指向引擎，避免加载死引擎出错页）；
	// 创建即隐藏——憋到启动页最低展示期满才现身，与启动页退场同时呈现
	hiddenForMeasure := len(os.Args) > 1 && os.Args[1] == "-hidden"
	// FE-08 窗口材质：默认 Mica（Win11 22H2+）+ 深色标题栏跟随系统主题
	//（Theme=SystemDefault，Wails 订阅系统主题变更自动切换）；更老 Windows 由
	// Wails 降级为 blur-behind，不会失败。SITLENS_WIN_MATERIAL=off 回退纯色窗。
	mainBG, mainWinOpts := windowMaterial()
	// A-01/D-02 + D-06：主窗 URL fragment 携带两类一次性信息：
	//   token=<hex>   引擎 API Token（页面 bootstrap 存进 localStorage 后抹掉）
	//   si=<base64url> 壳静态信息（GetInfo 的替代通道：Wails beta.22 的 ExecJS
	//                  在该 URL 窗口上不落地，回包收不到，故改一次性注入）
	// fragment 不发给服务端、不进访问日志。
	windowURL := func() string {
		frag := ""
		if apiToken != "" {
			frag = "token=" + apiToken
		}
		if bridge != nil {
			if si := bridge.InfoFragment(); si != "" {
				if frag != "" {
					frag += "&"
				}
				frag += "si=" + si
			}
		}
		if frag == "" {
			return baseURL
		}
		return baseURL + "#" + frag
	}
	makeMain := func() application.Window {
		return app.Window.NewWithOptions(application.WebviewWindowOptions{
			Title:            "SiteLens 扫描工作台",
			Width:            1360,
			Height:           850,
			MinWidth:         980,
			MinHeight:        620,
			BackgroundType:   mainBG,
			BackgroundColour: application.NewRGB(250, 250, 250), // 纯色模式下的主题底色
			Windows:          mainWinOpts,
			Hidden:           true, // 交接时序由 goroutine 控制（见下方 handoff 注释）
			URL:              windowURL(),
		})
	}
	// mainWin 跨 goroutine 共享：就绪 goroutine 写（下方 ApplicationStarted 回调），
	// 托盘「显示主界面」OnClick 在另一执行流读，必须 mutex 同步——否则数据竞争
	//（-race 必标），且冷启动 waitReady 期间托盘读到撕裂/未发布的值。
	var (
		mainWinMu sync.Mutex
		mainWin   application.Window
	)
	setMainWin := func(w application.Window) {
		mainWinMu.Lock()
		mainWin = w
		mainWinMu.Unlock()
	}
	getMainWin := func() application.Window {
		mainWinMu.Lock()
		defer mainWinMu.Unlock()
		return mainWin
	}
	// FE-08 壳侧能力装配：托盘/快捷键共用的快速扫描、通知窗、对比窗口。
	// 用依赖注入而非全局变量：核心启动流程（引擎拉起、窗口交接）保持原样可读。
	shell := &shellCtx{
		app:      app,
		baseURL:  baseURL,
		cfgPath:  cfgPath,
		getMain:  getMainWin,
		notifier: newToastNotifier(app),
	}
	// D-06：桌面壳桥服务（Wails app.RegisterService）。方法既供 RawMessageHandler
	// 的 postMessage 协议调用，也可被将来生成的 JS bindings 直接调用。
	// engineDataDir（= <userData>/state）一并传入：GetInfo/OpenDataDir 报/开的是
	// 引擎状态目录（history.json 所在），与文档口径一致。
	bridge = newShellBridge(app, shell, userData, engineDataDir)
	app.RegisterService(application.NewService(bridge))
	holdSplash := os.Getenv("SITLENS_SPLASH_HOLD") == "1" // 验证/预览：启动页常驻不自动退场
	app.Event.OnApplicationEvent(events.Windows.ApplicationStarted, func(*application.ApplicationEvent) {
		// 全局快捷键在应用启动后注册：被其它程序占用时 Register 同步返回错误，
		// 结论落 shell.log；托盘菜单是等价入口，功能降级但不影响壳运行。
		shell.registerGlobalShortcuts()
		go func() {
			// D-07：健康检查同时校验 nonce（引擎回显 SITLENS_SHELL_NONCE），
			// 端口被抢占/响应异常时直接拒绝启动，不把抢占者的页面交给主窗。
			engineVersion, err := waitReady(baseURL+"/api/version", 30*time.Second, shellNonce, apiToken)
			if err != nil {
				killEngineTree(eng) // log.Fatalf=os.Exit 跳过 defer，先树杀再退出
				splashWin.ExecJS("setError(" + strconv.Quote("引擎健康检查失败") + ")")
				time.Sleep(3500 * time.Millisecond)
				splashWin.Close()
				log.Fatalf("引擎健康检查失败: %v", err)
			}
			shell.setEngineVersion(engineVersion)
			win := makeMain()
			setMainWin(win)
			// D-06：记录主窗（回包前向兼容用；当前 Wails 版本 ExecJS 不落地，
			// 前端改用 URL fragment 注入的静态信息，见 bridge.go InfoFragment）。
			bridge.SetWindow(win)
			// D-06：关闭行为（exit = 直接退出；tray = 收进托盘继续运行）。
			win.OnWindowEvent(events.Common.WindowClosing, func(e *application.WindowEvent) {
				if bridge.GetCloseAction() == closeActionTray {
					e.Cancel()
					win.Hide()
				}
			})
			log.Println("窗口已创建（隐藏，待交接）")
			if !holdSplash {
				// 交接时序：补齐最低展示 1.9s（入场动画完整可感）→
				// 主窗现身与启动页两段退场同时开始——工作台不抢动画的镜
				if d := 1900*time.Millisecond - time.Since(splashBorn); d > 0 {
					time.Sleep(d)
				}
				if !hiddenForMeasure {
					win.Show()
				}
				splashWin.ExecJS("fadeOut()")
				time.Sleep(450 * time.Millisecond)
				splashWin.Close()
			}
		}()
	})

	// 通知栏托盘（FE-08 扩展）：快速扫描 / 打开工作台 / 对比窗口 / 检查更新 / 退出。
	// 菜单与全局快捷键共用同一实现；快捷键被占用时菜单入口仍可用（降级不崩溃）。
	tray := app.SystemTray.New()
	tray.SetIcon(iconICO)
	tray.SetTooltip("SiteLens 站点透视 v" + Version)
	trayMenu := app.NewMenu()
	trayMenu.Add("快速扫描剪贴板 URL").SetAccelerator("Ctrl+Shift+Q").
		OnClick(func(*application.Context) {
			go safeRun("快速扫描", shell.quickScanClipboard)
		})
	trayMenu.Add("打开工作台").SetAccelerator("Ctrl+Shift+S").
		OnClick(func(*application.Context) {
			go safeRun("唤起工作台", shell.wakeAndFocusURL)
		})
	trayMenu.Add("打开对比窗口").OnClick(func(*application.Context) {
		go safeRun("打开对比窗口", func() { shell.openDiffWindow() })
	})
	trayMenu.AddSeparator()
	trayMenu.Add("检查更新").OnClick(func(*application.Context) {
		go runUpdateCheck(userData, app, shell.notifier.Show)
	})
	trayMenu.AddSeparator()
	trayMenu.Add("退出 SiteLens").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(trayMenu)
	// 左键单击托盘图标 = 唤起工作台（右键出菜单）；与 Electron 壳单击行为对齐。
	tray.OnClick(func() { go safeRun("唤起工作台", shell.wakeAndFocusURL) })

	// 启动/周期自动更新（5.3.2）：auto_update 默认开启——启动 8s 后检查一次，
	// 运行期每 6 小时复查；发现新版本自动下载+校验+静默安装（会弹一次 UAC），
	// 装完由安装器拉起新版本。关闭开关时退回「只提示、不安装」的旧行为。
	// 更新源仍强制 https + sha512 校验（fail-closed），检查失败静默留日志。
	go func() {
		time.Sleep(8 * time.Second) // 让启动页/引擎就绪先走完，不抢启动期资源
		tick := func() {
			if bridge != nil && bridge.GetAutoUpdate() {
				runUpdateCheckAuto(userData, app, shell.notifier.Show)
			} else {
				runUpdateCheckStartup(shell.notifier.Show)
			}
		}
		tick()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			tick()
		}
	}()

	log.Println("进入事件循环")
	if err := app.Run(); err != nil {
		log.Printf("app.Run 退出: %v", err)
		log.Println("---- shell 结束(带错误) ----")
		killEngineTree(eng) // log.Fatal=os.Exit 跳过 defer，退出前显式树杀引擎
		log.SetOutput(os.Stderr)
		log.Fatal(err)
	}
	log.Println("---- shell 正常结束 ----")
}

// shellLogMaxBytes 单个 shell.log 的上限（超过即轮转一次到 shell.log.1）。
const shellLogMaxBytes = 2 << 20 // 2 MiB

// openShellLog 打开壳日志：超限先轮转、权限 0600。
//
// D-16：GUI 子系统没有控制台，shell.log 是唯一排障入口；旧实现 append 无上限，
// 长期运行会把日志涨到几百 MB（其中还含快速扫描的目标 URL）。这里保留单份
// 备份（shell.log.1）即可，不做多份归档——排障只关心最近一次。
func openShellLog() *os.File {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil
	}
	f, err := openShellLogAt(filepath.Join(dir, "SiteLens-Wails"))
	if err != nil {
		return nil
	}
	return f
}

// openShellLogAt 在指定目录打开（可测版本）：目录不存在先建；超限轮转一次。
func openShellLogAt(dir string) (*os.File, error) {
	p := filepath.Join(dir, "shell.log")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if st, serr := os.Stat(p); serr == nil && st.Size() > shellLogMaxBytes {
		_ = os.Remove(p + ".1") // Windows 上 Rename 可覆盖，但先删更稳
		if rerr := os.Rename(p, p+".1"); rerr != nil {
			log.Printf("壳日志轮转失败（继续追加）：%v", rerr)
		}
	}
	return os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// cdpBrowserArgs 返回 WebView 的调试参数（由 SITLENS_CDP_PORT 开启 CDP 通道）。
//
// D-12：只接受 1-65535 的整数端口，并显式把调试端口绑到回环地址。
// CDP 通道等于「本机任意进程可完全控制主 WebView」（读页面数据、代发 API 请求），
// 不能因为一个非法或恶意构造的环境变量就把它开到非回环或任意取值。
func cdpBrowserArgs() []string {
	raw := strings.TrimSpace(os.Getenv("SITLENS_CDP_PORT"))
	if raw == "" {
		return nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		log.Printf("SITLENS_CDP_PORT=%q 非法（需 1-65535 的整数），调试通道未开启", raw)
		return nil
	}
	log.Printf("CDP 调试通道已开启（仅回环）：127.0.0.1:%d", port)
	return []string{
		"--remote-debugging-address=127.0.0.1",
		"--remote-debugging-port=" + strconv.Itoa(port),
	}
}

// rawMessageHandler 前端 postMessage → 壳桥的分发入口（D-06）。
type rawMessageHandler func(window application.Window, message string, origin *application.OriginInfo)

// newAppOptions 组装 Wails 应用选项（抽成函数便于单测，见 hardening_test.go）。
//
// 图标（用户报的「左上角图标是坏的」根因，已按 Wails v3 beta.22 源码实测定位）：
// Windows 窗口初始化先找 **exe 资源里 ID=3 的 RT_GROUP_ICON**，失败才回退到
// application.Options.Icon（CreateLargeHIconFromImage 解析 ICO 头）。go-winres
// 生成的资源是 ID=1，所以 ID=3 必然找不到；旧实现又没设 Icon → 回退同样为 nil
// → 窗口类沿用 IDI_APPLICATION（Windows 通用「应用」图标，即截图里那个坏图标）。
//
// 这里显式给出 ICO 字节。**必须是 ICO 不能是 PNG**：CreateLargeHIconFromImage
// 走的是 ICONDIR 解析（PNG 会失败）。splash / 主窗共用这一份——Windows 后端只读
// application.Options.Icon（以及 Windows.DisableIcon），
// WebviewWindowOptions.Icon 在 Windows 上不生效，故不另设。
func newAppOptions(browserArgs []string, onRawMessage rawMessageHandler) application.Options {
	return application.Options{
		Name:        "SiteLens",
		Description: "SiteLens 站点透视（Wails 壳）",
		Icon:        iconICO, // 资源 ID=3 不存在时的窗口图标回退（ICO，含 256px 帧）
		// FE-08：把 Wails 内部错误（含全局快捷键被占用等）统一落到 shell.log，
		// 否则 GUI 子系统没有控制台，这类降级事实不可查。
		ErrorHandler: func(err error) { log.Printf("wails 错误：%v", err) },
		// D-06：主窗加载的是引擎页面（不是 Wails 资产页），拿不到 Wails 的
		// HTTP/IPC 运行时与生成的 bindings；这里用官方的 RawMessageHandler 接收
		// 页面 postMessage，再用 Window.ExecJS 回包，构成不依赖代码生成的桥。
		RawMessageHandler: func(w application.Window, msg string, origin *application.OriginInfo) {
			if onRawMessage != nil {
				onRawMessage(w, msg, origin)
			}
		},
		Windows: application.WindowsOptions{
			AdditionalBrowserArgs: browserArgs,
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(fallbackAssets),
		},
	}
}

// killEngineTree 树杀引擎进程（平台实现见 platform_windows.go / platform_unix.go）：
// Windows 用 taskkill /T 把引擎拉起的 Chrome 等孙进程一并强杀；POSIX 退化为
// Kill 引擎本身。log.Fatal=os.Exit 会跳过 defer，故引擎启动后的所有 Fatal
// 退出路径都必须显式调用本函数。
func killEngineTree(p *os.Process) {
	killProcessTree(p)
}

// detectEngineDir 引擎目录探测：环境变量 > exe 同级 engine/ > 开发态 ../build/engine。
func detectEngineDir() (string, bool) {
	if v := os.Getenv("SITLENS_ENGINE_DIR"); v != "" {
		if st, err := os.Stat(v); err == nil && st.IsDir() {
			return v, true
		}
	}
	exeDir, err := os.Executable()
	if err != nil {
		return "", false
	}
	exeDir = filepath.Dir(exeDir)
	// 打包态 = exe 同级 engine/（安装器布局）；开发态 = 仓库 build/engine
	// （tools/build-engine.js 的暂存产物）；SITLENS_ENGINE_DIR 可覆盖（上方已处理）。
	// 原「本机绝对路径兜底」已删——切正式交付后，产品产物里不该出现开发机路径。
	for _, cand := range []string{
		filepath.Join(exeDir, "engine"),
		filepath.Join(exeDir, "..", "build", "engine"),
	} {
		if _, ok := findEngineExe(cand); ok {
			return cand, true
		}
	}
	return "", false
}

// exeSuffix 平台可执行文件后缀（Windows=.exe，Linux/macOS 无后缀）。
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// engineExeName 引擎二进制文件名（5.2 起：引擎与 CLI 拆成两个二进制）。
//
// 引擎只提供 serve + update-seed，由桌面壳拉起；CLI（scan/audit/update-*）
// 是独立二进制，不随桌面安装包发布，故此处用独立文件名以示区分。
var engineExeName = "sitelens-engine" + exeSuffix()

// findEngineExe 在引擎目录里定位引擎二进制；找不到返回 ("", false)。
// 兼容：先找 sitelens-engine.exe（5.2 起的正式产物），再退回 sitelens.exe
// （拆分前的旧引擎，便于开发态与灰度安装目录平滑过渡）。
func findEngineExe(dir string) (string, bool) {
	for _, name := range []string{engineExeName, "sitelens" + exeSuffix()} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// freePort 向系统要一个空闲端口（占用窗口期极短，冲突时上层重试代价可忽略）。
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// writeUserConfig 写引擎配置（%APPDATA%/SiteLens-Wails/config.yml）。
//
// 受管键 = 壳语义：监听地址 + **所有可写路径**（扫描历史 / 情报覆盖 / 模板池 /
// 插件），后者的值由 usercfg 归到用户数据区。这一步不是"顺手补齐"：
// 引擎以 cwd（安装目录 engine/）解析相对路径，只写 web.listen 时，扫描历史与
// 情报会写进 $PROGRAMFILES64\SiteLens\engine\data —— 普通用户对该目录只读，
// 写入即失败（Electron 壳 v3.0.0 踩过同一个坑）。
//
// merge 语义（与 Electron 壳 yml-merge 同思路）：保留文件里已有的其余键
// （用户的 scan/loginbrute 等自定义），只更新受管键；解析失败时按行文本合并、
// 原文其余内容原样保留（不整文件重建清空用户键）。
func writeUserConfig(listen string, m usercfg.Managed) (string, string, error) {
	dir, err := userDataDir()
	if err != nil {
		return "", "", err
	}
	return writeUserConfigAt(dir, listen, m)
}

// writeUserConfigAt 是 writeUserConfig 的可测版本（目录可注入，单测不碰 %APPDATA%）。
// 返回 (配置文件路径, 本次生效的 api_token, error)。
func writeUserConfigAt(dir, listen string, m usercfg.Managed) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	p := filepath.Join(dir, "config.yml")
	var cfg map[string]any
	if b, rerr := os.ReadFile(p); rerr == nil {
		if uerr := yaml.Unmarshal(b, &cfg); uerr != nil {
			// 解析失败（重复键/Tab 缩进等手滑）时 cfg 为 nil，继续走结构化合并
			// 会把文件重置成只剩受管键，用户的 scan/loginbrute 等全部键被
			// 静默抹掉，违反上方 merge 契约。改为按行文本合并兜底：坏文件其余
			// 行原样保留，只更新 web.listen 一行，并留日志告警（其余受管键
			// 无法按行安全插入，宁可留给用户修好 YAML 后下次启动补齐）。
			log.Printf("writeUserConfig: %s 解析失败(%v)，按行合并仅更新 web.listen，其余内容原样保留", p, uerr)
			if werr := os.WriteFile(p, []byte(mergeWebListen(string(b), listen)), 0o600); werr != nil {
				return "", "", werr
			}
			// 配置坏掉时不注入 token（写不进去，前端也会因鉴权不匹配而 401）。
			log.Printf("警告：配置解析失败，本次不启用 API Token（修好 YAML 后重启自动补齐）")
			return p, "", nil
		}
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	// A-01/D-02：确保 web.api_token 存在且为本壳格式（64 hex）。
	// 契约（Lead 定稿）：为空或**不是 64 位 hex** → 生成新 token 并写回。
	// 统一格式的原因：壳必须持有 token 才能经 URL fragment 注入前端，
	// 且 64-hex 是"本壳管理"的判定依据（校验逻辑与引擎 X-Token 比较解耦）。
	apiToken := usercfg.APITokenOf(cfg)
	if apiToken == "" || !usercfg.ValidAPIToken(apiToken) {
		gen, gerr := usercfg.NewAPIToken()
		if gerr != nil {
			return "", "", fmt.Errorf("生成 API Token 失败：%w", gerr)
		}
		apiToken = gen
		// 绝不打印 token 本身，只记录"已注入"这一事实。
		log.Printf("已为引擎生成新的本地 API Token（64 hex，仅存配置与 URL fragment）")
	}
	m.APIToken = apiToken
	usercfg.ApplyManaged(cfg, listen, m)
	body, merr := yaml.Marshal(cfg)
	if merr != nil {
		body = []byte(fmt.Sprintf("web:\n  listen: %s\n  api_token: %s\n", listen, apiToken))
	}
	// 0600（D-16）：配置文件可能含 web.api_token 明文，与引擎侧 settings.go
	// 的 BUG-024 收紧保持一致（旧实现 0644 会把权限回退）。
	if err := os.WriteFile(p, body, 0o600); err != nil {
		return "", "", err
	}
	return p, apiToken, nil
}

// 两层结构行匹配（对齐 desktop/lib/yml-merge.js 的段头/段内键正则）：
// 顶层段头如 "web:" 或 "web: # 注释"；段内键如 "  listen: 127.0.0.1:8080"。
var (
	sectionRe = regexp.MustCompile(`^([A-Za-z_][\w-]*):\s*(#.*)?$`)
	kvRe      = regexp.MustCompile(`^(\s+)([A-Za-z_][\w-]*):\s*(.*)$`)
)

// mergeWebListen 在原文上按行合并 web.listen（与 Electron 壳 yml-merge.mergeManaged
// 的文本合并同思路，仅受管 web.listen 一个键）：web: 段下已有 listen 行则原位替换值，
// 没有则追加到段尾；web: 段不存在则整段追加到文件末尾；注释、空行、其余键一律
// 原样保留。仅在原文件 YAML 解析失败时兜底调用，坏文件不做结构化重建。
func mergeWebListen(src, listen string) string {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines)+2)
	inWeb, seenWeb, seenListen := false, false, false
	for _, line := range lines {
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			inWeb = m[1] == "web"
			if inWeb {
				seenWeb = true
			}
			out = append(out, line)
			continue
		}
		if m := kvRe.FindStringSubmatch(line); m != nil && inWeb && m[2] == "listen" {
			seenListen = true
			nl := "" // 保留原行尾（CRLF 文件避免行尾混用）
			if strings.HasSuffix(line, "\r") {
				nl = "\r"
			}
			out = append(out, m[1]+"listen: "+listen+nl)
			continue
		}
		out = append(out, line)
	}
	if !seenWeb {
		if n := len(out); n > 0 && strings.TrimSpace(out[n-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "web:", "  listen: "+listen, "")
		return strings.Join(out, "\n")
	}
	if !seenListen {
		if at := lastLineOfWebSection(out); at >= 0 {
			out = append(out, "")
			copy(out[at+2:], out[at+1:])
			out[at+1] = "  listen: " + listen
		}
	}
	return strings.Join(out, "\n")
}

// lastLineOfWebSection 返回 web: 段（段头起直到下一个顶层段前）最后一行的下标，
// 对齐 desktop/lib/yml-merge.js 的 lastLineOfSection。
func lastLineOfWebSection(lines []string) int {
	at := -1
	for i, line := range lines {
		if line == "web:" || strings.HasPrefix(line, "web: ") {
			at = i
			continue
		}
		if at >= 0 {
			if line != "" && line[0] != ' ' && line[0] != '\t' { // 下一个顶层段：结束
				break
			}
			if strings.TrimSpace(line) != "" {
				at = i // 段内子行（含注释）
			}
		}
	}
	return at
}

// waitReady 轮询引擎健康端点直到就绪或超时。
// engineVersionInfo /api/version 里壳关心的字段。
//
// D-07：引擎侧（internal/server/shell_bridge.go）在 SITLENS_SHELL_NONCE 存在时
// 会把同一个 nonce 回显在 /api/version 响应里。
type engineVersionInfo struct {
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
}

// errNonceMismatch nonce 不匹配：监听端口上不是本壳拉起的引擎。
var errNonceMismatch = errors.New("引擎端口被其他进程占用或响应异常（nonce 不匹配）")

// waitReady 轮询引擎健康端点直到就绪或超时，返回引擎版本号。
//
// 两个必须同时满足的判据：
//   - A-01/D-02：配置了 web.api_token 后，引擎对**所有** /api/*（含 /api/version）
//     都要求 X-Token（见 internal/server 的令牌守卫），所以探测请求必须带 token，
//     否则壳会永远"未就绪"而误杀引擎；
//   - D-07（端口 TOCTOU）：壳的端口协商是「先 bind 探测 → close → 再让引擎 bind」，
//     中间窗口可能被其它本机进程抢占。只认 HTTP 200 会把抢占者的页面当引擎交给
//     主窗（钓鱼/伪装面），所以必须校验 /api/version 回显的 nonce 与本壳注入的一致；
//     缺失或不等立即失败（不重试——真引擎不会在稍后变出正确的 nonce）。
func waitReady(url string, budget time.Duration, wantNonce, apiToken string) (string, error) {
	deadline := time.Now().Add(budget)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		req, rerr := http.NewRequest(http.MethodGet, url, nil)
		if rerr != nil {
			return "", rerr
		}
		if apiToken != "" {
			req.Header.Set("X-Token", apiToken)
		}
		resp, err := client.Do(req)
		if err == nil {
			body, berr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if berr == nil && resp.StatusCode == http.StatusOK {
				var v engineVersionInfo
				if jerr := json.Unmarshal(body, &v); jerr == nil {
					if wantNonce != "" && v.Nonce != wantNonce {
						return "", errNonceMismatch
					}
					return v.Version, nil
				}
				lastErr = fmt.Errorf("健康检查响应不是合法 JSON")
			} else if berr != nil {
				lastErr = berr
			} else {
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr != nil {
		return "", fmt.Errorf("30s 内未就绪: %s（最后一次错误：%v）", url, lastErr)
	}
	return "", fmt.Errorf("30s 内未就绪: %s", url)
}

// newShellNonce 生成 32 字节随机 hex（64 字符），仅经环境变量交给引擎。
func newShellNonce() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
