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
package main

import (
	"embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed assets/index.html
var fallbackAssets embed.FS

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
	if err := waitReady(baseURL+"/api/version", 30*time.Second); err != nil {
		_ = eng.Kill()
		log.Fatalf("引擎健康检查超时: %v", err)
	}

	// CDP 调试通道默认关：设 SITLENS_CDP_PORT=9223 才开启（验证/排查用）
	var browserArgs []string
	if v := os.Getenv("SITLENS_CDP_PORT"); v != "" {
		browserArgs = append(browserArgs, "--remote-debugging-port="+v)
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
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "SiteLens 扫描工作台",
		Width:            1360,
		Height:           850,
		MinWidth:         980,
		MinHeight:        620,
		BackgroundColour: application.NewRGB(250, 250, 250), // 主题底色：跨文档导航空帧期不闪白
		Hidden:           len(os.Args) > 1 && os.Args[1] == "-hidden", // 内存测量用：窗口隐藏照常分配
		URL:              baseURL,
	})
	log.Println("窗口已创建，进入事件循环")
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
// 其余配置项由引擎默认值合并，壳只注入 listen——与 Electron 壳 yml-merge 同思路的最小子集。
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
	body := fmt.Sprintf("web:\n  listen: %s\n", listen)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
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
