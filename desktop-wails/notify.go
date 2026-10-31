// notify.go FE-08：壳内轻量通知（无新依赖的「结果通知」实现）。
//
// 为什么不用系统 Toast：Wails 的 notifications 服务在 Windows 侧引入
// git.sr.ht/~jackmordaunt/go-toast 依赖，而本轮约束是「优先无新依赖」，且
// 构建机无网络。这里用 Wails 自己的多窗口做一个短暂停留的通知窗：
//   - 无边框 + 置顶 + 不占任务栏，右下角弹出，6s 自动关闭；
//   - 半透明材质（Acrylic，Win11 22H2+；更老系统由 Wails 降级为 blur-behind）；
//   - 任何创建失败都只记日志（safeRun 兜底），绝不带走主进程。
//
// 文案约定：kind 仅决定配色与角标（ok/err/info），不改变行为。
package main

import (
	"fmt"
	"html"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

const (
	toastOK   = "ok"
	toastErr  = "err"
	toastInfo = "info"

	toastWidth  = 380
	toastHeight = 132
	toastMargin = 18
	toastLife   = 6 * time.Second
)

// toastNotifier 管理「同一时刻最多一条」通知窗：新通知替换旧通知，
// 避免用户连按快捷键时窗口堆积成墙。
type toastNotifier struct {
	app *application.App
	mu  sync.Mutex
	cur application.Window
}

func newToastNotifier(app *application.App) *toastNotifier {
	return &toastNotifier{app: app}
}

// Show 弹一条通知；永不 panic、永不阻塞调用方（窗口操作是快调用）。
func (n *toastNotifier) Show(kind, title, body string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("通知窗：创建失败已降级（panic: %v），本条通知仅留日志：%s / %s", r, title, body)
		}
	}()
	if n == nil || n.app == nil {
		log.Printf("通知窗：未初始化，仅留日志：%s / %s", title, body)
		return
	}
	// 先摘掉并关闭上一条（关闭动作本身也可能 panic：窗口已被用户点掉）。
	n.mu.Lock()
	old := n.cur
	n.cur = nil
	n.mu.Unlock()
	if old != nil {
		safeRun("关闭上一条通知", func() { old.Close() })
	}

	bg, winOpts := windowMaterial()
	winOpts.HiddenOnTaskbar = true
	if bg == application.BackgroundTypeTranslucent {
		// 小窗用 Acrylic 更轻、更像「通知」而不是一块不透明卡片。
		winOpts.BackdropType = application.Acrylic
	}
	win := n.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "SiteLens 通知",
		Width:            toastWidth,
		Height:           toastHeight,
		Frameless:        true,
		DisableResize:    true,
		AlwaysOnTop:      true,
		BackgroundType:   bg,
		BackgroundColour: application.NewRGB(0, 0, 0),
		Windows:          winOpts,
		HTML:             toastHTML(kind, title, body),
	})
	if win == nil {
		log.Printf("通知窗：窗口管理器未返回窗口，仅留日志：%s / %s", title, body)
		return
	}
	if sc := n.app.Screen.GetPrimary(); sc != nil {
		wa := sc.WorkArea
		x, y := bottomRight(wa.X, wa.Y, wa.Width, wa.Height, toastWidth, toastHeight, toastMargin)
		safeRun("通知窗定位", func() { win.SetPosition(x, y) })
	}
	n.mu.Lock()
	n.cur = win
	n.mu.Unlock()
	time.AfterFunc(toastLife, func() { n.closeIf(win) })
}

// closeIf 只关闭仍是「当前条」的通知（防止旧定时器关掉新通知）。
func (n *toastNotifier) closeIf(win application.Window) {
	n.mu.Lock()
	if n.cur != win {
		n.mu.Unlock()
		return
	}
	n.cur = nil
	n.mu.Unlock()
	safeRun("关闭通知", func() { win.Close() })
}

// bottomRight 通知窗定位：工作区右下角内缩 margin。屏幕坐标与窗口位置同为
// DIP 量纲（Wails Screen.WorkArea 与 Window.SetPosition 一致）；负/越界时
// 夹回工作区左上角，保证窗口始终可见（多屏/缩放异常时的兜底）。
func bottomRight(areaX, areaY, areaW, areaH, winW, winH, margin int) (int, int) {
	x := areaX + areaW - winW - margin
	y := areaY + areaH - winH - margin
	if x < areaX {
		x = areaX
	}
	if y < areaY {
		y = areaY
	}
	return x, y
}

// toastHTML 通知内容页：自包含、无外部资源（不依赖引擎是否就绪），
// 半透明卡片 + 跟随系统深浅色（prefers-color-scheme），正文一律 HTML 转义。
func toastHTML(kind, title, body string) string {
	class, glyph := toastInfo, "i"
	switch kind {
	case toastOK:
		class, glyph = toastOK, "✓"
	case toastErr:
		class, glyph = toastErr, "!"
	}
	escTitle := html.EscapeString(title)
	escBody := strings.ReplaceAll(html.EscapeString(body), "\n", "<br>")
	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="color-scheme" content="light dark">
<style>
html,body{margin:0;height:100%%;background:transparent;overflow:hidden;
  font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif}
.card{box-sizing:border-box;height:100%%;display:flex;gap:10px;align-items:flex-start;
  padding:14px 16px;border-radius:12px;border:1px solid rgba(0,0,0,.12);
  background:rgba(255,255,255,.86);box-shadow:0 10px 30px rgba(0,0,0,.18);
  backdrop-filter:blur(14px);color:#111827;animation:in .18s ease-out both}
.badge{flex:none;width:22px;height:22px;border-radius:50%%;display:grid;place-items:center;
  color:#fff;font-size:13px;font-weight:700;margin-top:1px}
.ok .badge{background:#16a34a}.err .badge{background:#dc2626}.info .badge{background:#2563eb}
.t{font-size:13.5px;font-weight:600;margin:0 0 2px;line-height:1.4}
.b{font-size:12.5px;line-height:1.5;color:#4b5563;margin:0;word-break:break-all;
  max-height:56px;overflow:hidden}
@media (prefers-color-scheme: dark){
  .card{background:rgba(24,24,27,.86);border-color:rgba(255,255,255,.14);color:#fafafa}
  .b{color:#a1a1aa}
}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
</style></head>
<body><div class="card %s"><div class="badge">%s</div>
<div><p class="t">%s</p><p class="b">%s</p></div></div></body></html>`,
		class, glyph, escTitle, escBody)
}
