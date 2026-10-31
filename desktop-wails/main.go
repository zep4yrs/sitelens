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
// 构建：go build -ldflags "-s -w -H windowsgui" -o sitelens-wails.exe .
// （-H windowsgui = GUI 子系统不弹控制台；图标资源在 rsrc_windows_amd64.syso，
// 由 go-winres simply --icon assets/icon.ico 生成，仓库已带，日常构建无需重造）。
package main

import (
	"embed"
	"encoding/base64"
	"fmt"
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
	"syscall"
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

// createNoWindow = CREATE_NO_WINDOW（Windows SDK WinBase.h，值 0x08000000）。
//
// 语义：创建子进程时**不分配控制台窗口**。壳是 GUI 子系统程序，拉起引擎
// （控制台子系统）时若不带这个标志，Windows 会给子进程新建一个控制台 →
// 桌面弹出一个黑窗（BUG-032）；退出时树杀用的 taskkill 同理会闪一个
// （BUG-033）。
//
// Go 的 syscall 包未导出该常量（它在 x/sys/windows 里，而本模块不引那个
// 依赖），故按 WinBase.h 的定义就地硬编码——该值是 Windows ABI 的一部分，
// 长期稳定。
const createNoWindow = 0x08000000

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
	// 生命周期落盘：GUI 子系统没有控制台，退出原因必须留痕可查
	if dir, err := os.UserConfigDir(); err == nil {
		if f, err := os.OpenFile(filepath.Join(dir, "SiteLens-Wails", "shell.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			log.SetOutput(f)
			defer f.Close()
		}
	}
	log.Println("---- shell 启动 ----")

	engineDir, ok := detectEngineDir()
	if !ok {
		log.Fatal("未找到引擎（期望 exe 同级 engine/ 或 ../build/engine，或设 SITLENS_ENGINE_DIR）")
	}
	engineExe, ok := findEngineExe(engineDir)
	if !ok {
		log.Fatalf("引擎程序不存在（期望 %s 或 sitelens.exe）: %s",
			engineExeName, engineDir)
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
	cfgPath, err := writeUserConfig(listen, managed)
	if err != nil {
		log.Fatalf("写用户配置失败: %v", err)
	}

	cmd := exec.Command(engineExe, "-config", cfgPath, "serve")
	cmd.Dir = engineDir // 只读资产与相对 data/ 路径随引擎目录解析
	cmd.Stdout = nil
	cmd.Stderr = nil
	// 不弹控制台窗口（BUG-032）：引擎是控制台子系统程序，GUI 壳拉起它时
	// Windows 会给它新建一个控制台 → 桌面上弹出一个黑窗。
	// CREATE_NO_WINDOW 让子进程**不创建**控制台（比只设 HideWindow 更彻底：
	// 后者只是把窗口藏起来，窗口仍被创建、仍会抢焦点）。
	// ⚠️ 引擎本身保持控制台子系统是有意的：CLI 要靠 stdout 输出结果，
	// 引擎侧 update-seed 也要输出交付报告——「不弹窗」由这里解决，
	// 不能靠给引擎加 -H windowsgui（那会连带打死 CLI 的 stdout）。
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("引擎启动失败: %v", err)
	}
	eng := cmd.Process
	log.Printf("引擎已启动 pid=%d listen=%s dir=%s", eng.Pid, listen, engineDir)
	defer func() {
		killEngineTree(eng)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// CDP 调试通道默认关：设 SITLENS_CDP_PORT=9223 才开启（验证/排查用）
	var browserArgs []string
	if v := os.Getenv("SITLENS_CDP_PORT"); v != "" {
		browserArgs = append(browserArgs, "--remote-debugging-port="+v)
	}
	// SITLENS_RM=1：强制 prefers-reduced-motion（启动页降级路径的验证开关，产品路径不感知）
	if os.Getenv("SITLENS_RM") == "1" {
		browserArgs = append(browserArgs, "--force-prefers-reduced-motion")
	}
	app := application.New(application.Options{
		Name:        "SiteLens",
		Description: "SiteLens 站点透视（Wails 壳）",
		// FE-08：把 Wails 内部错误（含全局快捷键被占用等）统一落到 shell.log，
		// 否则 GUI 子系统没有控制台，这类降级事实不可查。
		ErrorHandler: func(err error) { log.Printf("wails 错误：%v", err) },
		Windows: application.WindowsOptions{
			AdditionalBrowserArgs: browserArgs,
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(fallbackAssets),
		},
	})

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
			URL:              baseURL,
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
	holdSplash := os.Getenv("SITLENS_SPLASH_HOLD") == "1" // 验证/预览：启动页常驻不自动退场
	app.Event.OnApplicationEvent(events.Windows.ApplicationStarted, func(*application.ApplicationEvent) {
		// 全局快捷键在应用启动后注册：被其它程序占用时 Register 同步返回错误，
		// 结论落 shell.log；托盘菜单是等价入口，功能降级但不影响壳运行。
		shell.registerGlobalShortcuts()
		go func() {
			if err := waitReady(baseURL+"/api/version", 30*time.Second); err != nil {
				killEngineTree(eng) // log.Fatalf=os.Exit 跳过 defer，先树杀再退出
				splashWin.ExecJS("setError(" + strconv.Quote("引擎健康检查超时") + ")")
				time.Sleep(3500 * time.Millisecond)
				splashWin.Close()
				log.Fatalf("引擎健康检查超时: %v", err)
			}
			win := makeMain()
			setMainWin(win)
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
		go runUpdateCheck(userData, app)
	})
	trayMenu.AddSeparator()
	trayMenu.Add("退出 SiteLens").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(trayMenu)
	// 左键单击托盘图标 = 唤起工作台（右键出菜单）；与 Electron 壳单击行为对齐。
	tray.OnClick(func() { go safeRun("唤起工作台", shell.wakeAndFocusURL) })

	// 启动静默检查一次：发现新版本即下载并静默覆盖安装（装完由安装器拉起新版）。
	// 失败完全静默（离线/源不可达是常态，不该打扰用户），shell.log 留痕可查。
	go func() {
		time.Sleep(8 * time.Second) // 让启动页/引擎就绪先走完，不抢启动期资源
		runUpdateCheckQuiet(userData, app)
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

// killEngineTree 树杀引擎进程（对齐 Electron 壳 stop() 的 taskkill /T 语义，
// 见 .archive/desktop-electron/engine.js:302-325）：Windows 上 os.Process.Kill=TerminateProcess
// 只杀引擎 PID 本身，引擎扫描时经 chromedp 拉起的 Chrome 等子进程会成孤儿
// 继续驻留内存；taskkill /PID /T /F 把整棵树连同孙进程一并强杀（引擎已退出
// 时 taskkill 报错属常态，忽略）。POSIX 下引擎未单独设进程组（cmd 未用
// Setpgid），组杀无对象，退化为 Kill 引擎本身（与原 eng.Kill 行为一致）。
// log.Fatal=os.Exit 会跳过 defer，故引擎启动后的所有 Fatal 退出路径都必须
// 显式调用本函数。
func killEngineTree(p *os.Process) {
	if p == nil {
		return
	}
	if runtime.GOOS == "windows" {
		// taskkill 是控制台程序，直接 exec 会闪一个黑窗（BUG-033）。
		// 加 CREATE_NO_WINDOW 后它不再创建控制台窗口，树杀语义不变。
		tk := exec.Command("taskkill", "/PID", strconv.Itoa(p.Pid), "/T", "/F")
		tk.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: createNoWindow,
		}
		_ = tk.Run()
	}
	_ = p.Kill() // 兜底：树杀失败时至少杀引擎本身（已死则返回错误，忽略）
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

// engineExeName 引擎二进制文件名（5.2 起：引擎与 CLI 拆成两个二进制）。
//
// 引擎只提供 serve + update-seed，由桌面壳拉起；CLI（scan/audit/update-*）
// 是独立二进制，不随桌面安装包发布，故此处用独立文件名以示区分。
const engineExeName = "sitelens-engine.exe"

// findEngineExe 在引擎目录里定位引擎二进制；找不到返回 ("", false)。
// 兼容：先找 sitelens-engine.exe（5.2 起的正式产物），再退回 sitelens.exe
// （拆分前的旧引擎，便于开发态与灰度安装目录平滑过渡）。
func findEngineExe(dir string) (string, bool) {
	for _, name := range []string{engineExeName, "sitelens.exe"} {
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
func writeUserConfig(listen string, m usercfg.Managed) (string, error) {
	dir, err := userDataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
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
			if werr := os.WriteFile(p, []byte(mergeWebListen(string(b), listen)), 0o644); werr != nil {
				return "", werr
			}
			return p, nil
		}
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	usercfg.ApplyManaged(cfg, listen, m)
	body, merr := yaml.Marshal(cfg)
	if merr != nil {
		body = []byte(fmt.Sprintf("web:\n  listen: %s\n", listen))
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		return "", err
	}
	return p, nil
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
func waitReady(url string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("30s 内未就绪: %s", url)
}
