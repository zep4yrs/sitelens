// quick.go FE-08 桌面深化：托盘快速扫描 / 全局快捷键 / 多窗口对比的壳侧逻辑。
//
// 设计边界：
//   - 引擎零改动：快速扫描就是一次 POST /api/scan {"level":"quick"}，结果由引擎
//     自己落库（history），壳只负责「读剪贴板 → 发起 → 轮询 → 通知」。
//   - 不引入新依赖：剪贴板用 Wails runtime（app.Clipboard），通知与对比窗用
//     Wails 多窗口（同一模块），全局快捷键用 app.GlobalShortcut；没有网络请求
//     出本机（引擎监听 127.0.0.1）。
//   - 不静默装死：无剪贴板/剪贴板无 URL/引擎不可达/快捷键被占用 都写 shell.log；
//     引擎类失败另给一次轻量通知，剪贴板不可用一类「无输入」只留痕不打扰。
//
// 可测性：HTTP 交互（postScan/pollScan）、URL 提取、token 解析、通知 HTML、
// 窗口位置与材质选择都是纯函数，单测在 quick_test.go（不启动 Wails）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"gopkg.in/yaml.v3"
)

// shellCtx 壳侧运行时依赖集合（main.go 装配）。用依赖注入而不是全局变量，
// 一是让 quick/notify 逻辑可单测，二是将来换掉某个能力（如通知）只改装配处。
type shellCtx struct {
	app      *application.App
	baseURL  string // 引擎基址，如 http://127.0.0.1:5087
	cfgPath  string // 引擎配置文件（读 web.api_token 用于 API 鉴权）
	getMain  func() application.Window
	notifier *toastNotifier

	scanMu sync.Mutex // 同时只允许一个快捷扫描（重复触发直接忽略，不排队）

	// 引擎版本（waitReady 拿到 /api/version 后写入；D-06 桥的 GetInfo 读取）。
	// 跨 goroutine（启动 goroutine 写 / 桥调用读）→ mutex 保护。
	engineVerMu sync.Mutex
	engineVer   string
}

// setEngineVersion 记录引擎版本（waitReady 成功后调用）。
func (s *shellCtx) setEngineVersion(v string) {
	s.engineVerMu.Lock()
	s.engineVer = v
	s.engineVerMu.Unlock()
}

// EngineVersion 返回引擎版本（未就绪时为空串）。
func (s *shellCtx) EngineVersion() string {
	s.engineVerMu.Lock()
	defer s.engineVerMu.Unlock()
	return s.engineVer
}

// ---- 快捷键 / 窗口唤起 ----

// focusURLInputJS 在主窗内聚焦 URL 输入框。
//
// 目标页是引擎自带工作台（web/app.html，URL 输入框 id="url"）；壳不改前端，
// 所以按「已知 id → 常见属性 → 任意可见输入框」三级降级，全部失败也不报错
// （页面可能还停在启动页/404，此时聚焦无对象是正常态）。
const focusURLInputJS = `(function () {
  try {
    var sels = ['#url', 'input#url', '#target',
      'input[name="url"]', 'input[type="url"]',
      'input[placeholder*="https://"]', 'input[placeholder*="URL"]',
      'input[placeholder*="url"]', 'input[placeholder*="网址"]',
      'input[placeholder*="目标"]', 'input[placeholder*="域名"]',
      'textarea[placeholder*="URL"]', 'textarea[placeholder*="网址"]'];
    for (var i = 0; i < sels.length; i++) {
      var el = document.querySelector(sels[i]);
      if (el && el.offsetParent !== null) {
        el.focus();
        if (el.select) { el.select(); }
        return;
      }
    }
    var all = document.querySelectorAll('input,textarea');
    for (var j = 0; j < all.length; j++) {
      var e = all[j];
      if (e.type === 'hidden' || e.disabled || e.offsetParent === null) { continue; }
      e.focus();
      if (e.select) { e.select(); }
      return;
    }
  } catch (err) { /* 前端结构变化不影响快捷键可用性 */ }
})()`

// registerGlobalShortcuts 注册两个全局快捷键。
//
// 冲突处理（任务硬要求：不崩溃）：Register 返回错误只记日志，托盘菜单的等价
// 入口仍在——功能降级但壳照常运行。若在 app.Run 之前注册，冲突会被 Wails
// 转给 ErrorHandler（main.go 已接日志）；这里放在 ApplicationStarted 回调里，
// 冲突能拿到同步错误、结论直接落 shell.log。
func (s *shellCtx) registerGlobalShortcuts() {
	if err := s.app.GlobalShortcut.Register("Ctrl+Shift+S", s.wakeAndFocusURL); err != nil {
		log.Printf("全局快捷键 Ctrl+Shift+S 注册失败（可能被其它程序占用），已降级为托盘菜单：%v", err)
	} else {
		log.Println("全局快捷键已注册：Ctrl+Shift+S = 唤起工作台并聚焦 URL 输入框")
	}
	if err := s.app.GlobalShortcut.Register("Ctrl+Shift+Q", func() {
		go safeRun("快速扫描", s.quickScanClipboard)
	}); err != nil {
		log.Printf("全局快捷键 Ctrl+Shift+Q 注册失败（可能被其它程序占用），已降级为托盘菜单：%v", err)
	} else {
		log.Println("全局快捷键已注册：Ctrl+Shift+Q = 快速扫描剪贴板 URL")
	}
}

// wakeAndFocusURL 唤起主窗（最小化先还原）并聚焦 URL 输入框。
// 窗口已创建但页面可能还在导航：延迟 150ms 再注入聚焦脚本，失败无副作用。
func (s *shellCtx) wakeAndFocusURL() {
	w := s.getMain()
	if w == nil {
		log.Println("唤起工作台：主窗尚未就绪（引擎仍在启动），忽略本次请求")
		return
	}
	safeRun("唤起工作台", func() {
		if w.IsMinimised() {
			w.Restore()
		}
		w.Show()
		w.Focus()
		time.AfterFunc(150*time.Millisecond, func() {
			safeRun("聚焦 URL 输入框", func() { w.ExecJS(focusURLInputJS) })
		})
	})
}

// openDiffWindow 打开「对比报告」第二窗口（FE-08 多窗口）。
//
// 页面用引擎自带的 /history 页（其 diff 区需要用户勾选两条记录后对比；前端
// 目前不消费 ?diff=1，壳侧注入一小段脚本把 diff 区滚入视野并高亮「对比」按钮，
// 不改 web/）。窗口材质与主窗一致（Mica + 跟随系统主题）。
func (s *shellCtx) openDiffWindow() application.Window {
	bg, winOpts := windowMaterial()
	winOpts.HiddenOnTaskbar = false
	w := s.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "SiteLens 对比报告",
		Width:            1200,
		Height:           820,
		MinWidth:         860,
		MinHeight:        560,
		BackgroundType:   bg,
		BackgroundColour: application.NewRGB(250, 250, 250),
		Windows:          winOpts,
		URL:              diffURL(s.baseURL),
	})
	// 页面加载完成前 ExecJS 可能落空；2.5s 后尽力注入（失败无副作用）。
	time.AfterFunc(2500*time.Millisecond, func() {
		safeRun("对比页提示", func() { w.ExecJS(diffHintJS) })
	})
	return w
}

// diffURL 对比窗口地址：引擎自带 /history 页 + diff=1 语义参数。
// 前端目前不解析该参数（见 README「已知边界」），壳侧靠 diffHintJS 补偿。
func diffURL(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/history?diff=1"
}

// diffHintJS 在 /history?diff=1 上把 diff 区带入视野并提示操作方式。
// 前端不解析该参数，故由壳侧补偿；DOM 结构变化时 try/catch 兜底不报错。
const diffHintJS = `(function () {
  try {
    if (location.search.indexOf('diff=1') < 0) { return; }
    var box = document.getElementById('diff');
    if (box && box.scrollIntoView) {
      box.scrollIntoView({ block: 'center' });
    }
    var btns = document.querySelectorAll('button');
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].textContent && btns[i].textContent.indexOf('对比') >= 0) {
        btns[i].style.outline = '2px solid #2563eb';
        btns[i].style.outlineOffset = '2px';
        break;
      }
    }
  } catch (err) { /* 忽略：仅视觉提示 */ }
})()`

// windowMaterial 选择窗口材质（FE-08「Mica/Acrylic 或深色标题栏跟随主题」）。
//
//   - Windows：BackgroundTypeTranslucent + Windows.BackdropType=Mica（Win11 22621+
//     显示 Mica；更老系统 Wails 自动降级为 blur-behind，不会崩、不会黑屏）。
//   - Linux/macOS：Wails 没有 Mica，用不透明纯色窗（原生标题栏/系统主题接管），
//     避免 Translucent 在无合成器环境下黑底/透明穿透。
//   - Theme 恒为 SystemDefault：标题栏深/浅色跟随系统主题。
//   - 逃生阀：SITLENS_WIN_MATERIAL=off 退回纯色窗（不透明、无材质）。
func windowMaterial() (application.BackgroundType, application.WindowsWindow) {
	w := application.WindowsWindow{Theme: application.SystemDefault}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SITLENS_WIN_MATERIAL")), "off") {
		return application.BackgroundTypeSolid, w
	}
	if runtime.GOOS != "windows" {
		return application.BackgroundTypeSolid, w
	}
	w.BackdropType = application.Mica
	return application.BackgroundTypeTranslucent, w
}

// ---- 剪贴板 → URL ----

// urlInText 从一段文本里捞第一个 http(s) 链接（宽容尾随标点，含中文标点）。
var urlInText = regexp.MustCompile(`https?://[^\s"'<>\x60，。；、）】》」』]+`)

// extractURL 把剪贴板文本解析成可扫描 URL。
//
//   - 整段就是 URL：直接校验（容忍首尾空白/换行）；
//   - 文本里夹着 URL（「看看这个 https://a.com/x 页面」）：取第一个；
//   - 其余（空/非 http(s)/没有 host/超长）：返回 false，由调用方决定提示方式。
func extractURL(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if t == "" {
		return "", false
	}
	if u, ok := cleanURL(t); ok {
		return u, true
	}
	if m := urlInText.FindString(t); m != "" {
		return cleanURL(m)
	}
	return "", false
}

// cleanURL 校验并清理单个候选：只接受 http/https + 有 host + 长度 ≤ 2048。
// 尾随的空白与句读标点（含中文）去掉——复制来的链接常带这些。
func cleanURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, ".,;:!?)]}>'\"，。；、）】》」』")
	if s == "" || len(s) > 2048 {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	return s, true
}

// ---- 引擎 API 交互 ----

// readAPIToken 解析引擎 API token（引擎 guard：X-Token 头；空值 = 不鉴权）。
// 优先级与引擎一致：环境变量 SLENS_API_TOKEN > 配置文件 web.api_token。
func readAPIToken(cfgPath string) string {
	if v := strings.TrimSpace(os.Getenv("SLENS_API_TOKEN")); v != "" {
		return v
	}
	if cfgPath == "" {
		return ""
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var cfg struct {
		Web struct {
			APIToken string `yaml:"api_token"`
		} `yaml:"web"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Web.APIToken)
}

// postScan 发起一次快速档扫描，返回引擎 job_id。
// level=quick 是引擎语义档位（server.levelPresets），等价于「只关 deep，其余默认」。
func postScan(client *http.Client, baseURL, token, target string) (string, error) {
	body, err := json.Marshal(map[string]any{"url": target, "level": "quick"})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimSuffix(baseURL, "/")+"/api/scan", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("连接引擎失败：%w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		JobID string `json:"job_id"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return "", fmt.Errorf("引擎拒绝扫描（HTTP %d）：%s", resp.StatusCode, out.Error)
		}
		return "", fmt.Errorf("引擎拒绝扫描（HTTP %d）", resp.StatusCode)
	}
	if out.JobID == "" {
		return "", fmt.Errorf("引擎未返回 job_id（响应体 %q）", truncateForLog(string(raw), 160))
	}
	return out.JobID, nil
}

// scanOutcome 轮询结果（done/error/cancelled 三态 + 历史扫描 id）。
type scanOutcome struct {
	Status string // done / error / cancelled
	ScanID string // done 时 = 历史记录 id（引擎 store.Save 返回）
	Msg    string // 引擎给的人话说明
}

// jobState /api/job/{id} 的响应子集（壳只关心状态、说明与历史 id）。
type jobState struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	ScanID  json.RawMessage `json:"scan_id"`
}

// pollScan 轮询 /api/job/{id} 直到终态、超时或 ctx 取消。
// interval≈800ms：引擎 job 是内存表，轮询成本可忽略；超时防呆不设死。
func pollScan(ctx context.Context, client *http.Client, baseURL, token, jobID string,
	interval, timeout time.Duration) (scanOutcome, error) {
	deadline := time.Now().Add(timeout)
	jobURL := strings.TrimSuffix(baseURL, "/") + "/api/job/" + url.PathEscape(jobID)
	for {
		if err := ctx.Err(); err != nil {
			return scanOutcome{}, fmt.Errorf("快速扫描已取消：%w", err)
		}
		out, err := getJob(client, jobURL, token)
		if err != nil {
			return scanOutcome{}, err
		}
		switch out.Status {
		case "done":
			return scanOutcome{Status: "done", ScanID: scanIDString(out.ScanID), Msg: out.Message}, nil
		case "error", "cancelled":
			return scanOutcome{Status: out.Status, Msg: out.Message}, nil
		}
		if time.Now().After(deadline) {
			return scanOutcome{}, fmt.Errorf("等待扫描完成超时（%s）", timeout)
		}
		select {
		case <-ctx.Done():
			return scanOutcome{}, fmt.Errorf("快速扫描已取消：%w", ctx.Err())
		case <-time.After(interval):
		}
	}
}

// getJob 取一次 job 状态（拆成独立函数便于轮询循环与单测复用）。
func getJob(client *http.Client, jobURL, token string) (jobState, error) {
	var out jobState
	req, err := http.NewRequest(http.MethodGet, jobURL, nil)
	if err != nil {
		return out, err
	}
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("查询任务状态失败：%w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("查询任务状态失败（HTTP %d）：%s",
			resp.StatusCode, truncateForLog(string(raw), 160))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("解析任务状态失败：%w", err)
	}
	return out, nil
}

// scanIDString 把 scan_id 的 JSON 原始值转成字符串（引擎回数字，工具链里可能是字符串）。
func scanIDString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if i, err := n.Int64(); err == nil {
			return strconv.FormatInt(i, 10)
		}
		// 引擎实际回整数，但 12.0 这类整值浮点也归一成整数字符串（历史 id 呈现不想要 ".0"）。
		if f, err := n.Float64(); err == nil && f == float64(int64(f)) {
			return strconv.FormatInt(int64(f), 10)
		}
		return n.String()
	}
	return ""
}

// truncateForLog 截断超长文本用于日志/错误消息（按 rune，避免切坏 UTF-8）。
func truncateForLog(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// ---- 快速扫描主流程 ----

// quickScanClipboard 托盘/快捷键入口：读剪贴板 → 快速扫描 → 结果入历史 → 通知。
//
// 并发：同一时刻只跑一个（再次触发直接忽略并留痕），避免用户连按快捷键把
// 引擎并发槽打满；不阻塞调用方（tray/onClick 里另起 goroutine）。
func (s *shellCtx) quickScanClipboard() {
	if !s.scanMu.TryLock() {
		log.Println("快速扫描：已有扫描在进行，忽略重复触发")
		return
	}
	defer s.scanMu.Unlock()

	text, ok := s.app.Clipboard.Text()
	if !ok {
		// 无剪贴板访问（远程桌面/权限异常）：静默降级，只留痕。
		log.Println("快速扫描：剪贴板不可用，静默忽略（功能降级不影响其它入口）")
		return
	}
	target, ok := extractURL(text)
	if !ok {
		log.Printf("快速扫描：剪贴板没有可扫描的 http(s) URL（长度 %d）", len(text))
		s.notifier.Show(toastInfo, "快速扫描", "剪贴板里没有可扫描的 http(s) 链接")
		return
	}
	log.Printf("快速扫描：发起 %s（level=quick）", target)
	// 开始反馈：快速档也可能跑几十秒，先给一个短提示；完成时会被下一条替换。
	s.notifier.Show(toastInfo, "正在快速扫描", target)

	client := &http.Client{Timeout: 20 * time.Second}
	token := readAPIToken(s.cfgPath)
	jobID, err := postScan(client, s.baseURL, token, target)
	if err != nil {
		log.Printf("快速扫描：发起失败：%v", err)
		s.notifier.Show(toastErr, "快速扫描未发起", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	out, err := pollScan(ctx, client, s.baseURL, token, jobID, 800*time.Millisecond, 11*time.Minute)
	if err != nil {
		log.Printf("快速扫描：%v", err)
		s.notifier.Show(toastErr, "快速扫描失败", err.Error())
		return
	}
	switch out.Status {
	case "done":
		loc := ""
		if out.ScanID != "" {
			loc = fmt.Sprintf("，已存历史 #%s", out.ScanID)
		}
		log.Printf("快速扫描完成：%s%s（job=%s）", target, loc, jobID)
		s.notifier.Show(toastOK, "快速扫描完成", target+loc)
	case "cancelled":
		log.Printf("快速扫描被取消：%s（job=%s）", target, jobID)
		s.notifier.Show(toastInfo, "快速扫描已取消", target)
	default:
		msg := out.Msg
		if msg == "" {
			msg = "引擎未给出原因"
		}
		log.Printf("快速扫描失败：%s：%s（job=%s）", target, msg, jobID)
		s.notifier.Show(toastErr, "快速扫描失败", msg)
	}
}

// safeRun 包裹可能 panic 的壳侧回调（窗口已关闭/前端结构变化/通知窗创建失败）。
// 「冲突降级不崩溃」的兜底：任何一条附加功能出问题都只留日志，不带走整个壳。
func safeRun(name string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s：已降级（panic: %v）", name, r)
		}
	}()
	f()
}
