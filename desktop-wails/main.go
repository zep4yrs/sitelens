// SiteLens Wails 壳（实验，4.0 Track：GUI 换壳验证）。
//
// 职责与 Electron 壳对齐的最小子集：
//  1. 探测引擎目录（打包态 = exe 同级 engine/；开发态 = 仓库 desktop/engine，
//     可用 SITLENS_ENGINE_DIR 覆盖）
//  2. 取空闲端口，生成最小配置（web.listen）落【用户目录】——不写安装目录
//     （v3.0.1 EPERM 教训：Program Files 只读）
//  3. 拉起 sitelens.exe serve（cwd=引擎目录，相对 data/ 路径随 cwd 解析）
//  4. /api/version 健康检查通过后开窗，窗口直接加载引擎 URL（引擎零改动）
//  5. 退出时回收引擎进程
//
// 引擎 UI 即引擎 HTTP 服务本身，本壳不做任何资源伺服（无 ASAR 白名单问题）。
//
// 构建：go build -ldflags "-s -w -H windowsgui" -o sitelens-wails.exe .
//（-H windowsgui = GUI 子系统不弹控制台；图标资源在 rsrc_windows_amd64.syso，
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
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"gopkg.in/yaml.v3"
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
	return strings.ReplaceAll(h, "{{VER}}", "")
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
		log.Fatal("未找到引擎（期望 exe 同级 engine/ 或 ../desktop/engine，或设 SITLENS_ENGINE_DIR）")
	}
	engineExe := filepath.Join(engineDir, "sitelens.exe")
	if _, err := os.Stat(engineExe); err != nil {
		log.Fatalf("引擎程序不存在: %s", engineExe)
	}

	port, err := freePort()
	if err != nil {
		log.Fatalf("取空闲端口失败: %v", err)
	}
	listen := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	cfgPath, err := writeUserConfig(listen)
	if err != nil {
		log.Fatalf("写用户配置失败: %v", err)
	}

	cmd := exec.Command(engineExe, "-config", cfgPath, "serve")
	cmd.Dir = engineDir // 只读资产与相对 data/ 路径随引擎目录解析
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Fatalf("引擎启动失败: %v", err)
	}
	eng := cmd.Process
	log.Printf("引擎已启动 pid=%d listen=%s dir=%s", eng.Pid, listen, engineDir)
	defer func() {
		_ = eng.Kill()
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
		Windows: application.WindowsOptions{
			AdditionalBrowserArgs: browserArgs,
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(fallbackAssets),
		},
	})

	// 启动页「对焦」先行：引擎冷启动期间的唯一可见面（与 Electron 壳 splash 同源设计）
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

	// 主窗在引擎就绪后由 goroutine 创建（URL 指向引擎，避免加载死引擎出错页）
	hiddenForMeasure := len(os.Args) > 1 && os.Args[1] == "-hidden"
	makeMain := func() application.Window {
		return app.Window.NewWithOptions(application.WebviewWindowOptions{
			Title:            "SiteLens 扫描工作台",
			Width:            1360,
			Height:           850,
			MinWidth:         980,
			MinHeight:        620,
			BackgroundColour: application.NewRGB(250, 250, 250), // 主题底色：跨文档导航空帧期不闪白
			Hidden:           hiddenForMeasure, // 内存测量用：窗口隐藏照常分配
			URL:              baseURL,
		})
	}
	var mainWin application.Window
	holdSplash := os.Getenv("SITLENS_SPLASH_HOLD") == "1" // 验证/预览：启动页常驻不自动退场
	app.Event.OnApplicationEvent(events.Windows.ApplicationStarted, func(*application.ApplicationEvent) {
		go func() {
			if err := waitReady(baseURL+"/api/version", 30*time.Second); err != nil {
				_ = eng.Kill()
				splashWin.ExecJS("setError(" + strconv.Quote("引擎健康检查超时") + ")")
				time.Sleep(3500 * time.Millisecond)
				splashWin.Close()
				log.Fatalf("引擎健康检查超时: %v", err)
			}
			mainWin = makeMain()
			log.Println("窗口已创建")
			if !holdSplash {
				splashWin.ExecJS("fadeOut()")
				time.Sleep(450 * time.Millisecond)
				splashWin.Close()
			}
		}()
	})

	// 通知栏托盘（对齐 Electron 壳 createTray 的最小集）：品牌图标 + 显示主界面/退出
	tray := app.SystemTray.New()
	tray.SetIcon(iconICO)
	tray.SetTooltip("SiteLens 站点透视")
	trayMenu := app.NewMenu()
	trayMenu.Add("显示主界面").OnClick(func(*application.Context) {
		if mainWin != nil {
			mainWin.Show()
		}
	})
	trayMenu.AddSeparator()
	trayMenu.Add("退出 SiteLens").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(trayMenu)

	log.Println("进入事件循环")
	if err := app.Run(); err != nil {
		log.Printf("app.Run 退出: %v", err)
		log.Println("---- shell 结束(带错误) ----")
		log.SetOutput(os.Stderr)
		log.Fatal(err)
	}
	log.Println("---- shell 正常结束 ----")
}

// detectEngineDir 引擎目录探测：环境变量 > exe 同级 engine/ > 开发态 ../desktop/engine。
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
	for _, cand := range []string{
		filepath.Join(exeDir, "engine"),                       // 打包态（安装器布局）
		filepath.Join(exeDir, "..", "desktop", "engine"),      // 开发态（仓库布局）
		`D:\fengqiao\Desktop\26-08python实训\实训考核2\desktop\engine`, // 本机实验兜底
	} {
		if _, err := os.Stat(filepath.Join(cand, "sitelens.exe")); err == nil {
			return cand, true
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

// writeUserConfig 最小配置落用户目录（%APPDATA%/SiteLens-Wails/config.yml）。
// merge 语义（与 Electron 壳 yml-merge 同思路）：保留文件里已有的其余键
// （用户的 scan/loginbrute 等自定义），只更新 web.listen；解析失败时重建新文件。
func writeUserConfig(listen string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "SiteLens-Wails")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "config.yml")
	var cfg map[string]any
	if b, rerr := os.ReadFile(p); rerr == nil {
		_ = yaml.Unmarshal(b, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	web, _ := cfg["web"].(map[string]any)
	if web == nil {
		web = map[string]any{}
		cfg["web"] = web
	}
	web["listen"] = listen
	body, merr := yaml.Marshal(cfg)
	if merr != nil {
		body = []byte(fmt.Sprintf("web:\n  listen: %s\n", listen))
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		return "", err
	}
	return p, nil
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
