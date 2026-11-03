//go:build windows

// Windows 平台专属的壳能力：控制台子进程隐藏、进程树强杀、原生确认对话框。
// 这些 API 只存在于 Windows（syscall.SysProcAttr 的 HideWindow/CreationFlags、
// user32 MessageBoxW），故单独放在 _windows.go 里，非 Windows 平台见
// platform_unix.go 的同名实现（no-op / 降级）。
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// createNoWindow = CREATE_NO_WINDOW（Windows SDK WinBase.h，值 0x08000000）。
//
// 语义：创建子进程时**不分配控制台窗口**。壳是 GUI 子系统程序，拉起引擎
// （控制台子系统）时若不带这个标志，Windows 会给子进程新建一个控制台 →
// 桌面弹出一个黑窗（BUG-032）；退出时树杀用的 taskkill 同理会闪一个（BUG-033）。
//
// Go 的 syscall 包未导出该常量（它在 x/sys/windows 里，而本模块不引那个依赖），
// 故按 WinBase.h 的定义就地硬编码——该值是 Windows ABI 的一部分，长期稳定。
const createNoWindow = 0x08000000

// hideChildWindow 让控制台子进程不弹黑窗。
// 只设 HideWindow 不够彻底：窗口仍会被创建、仍可能抢焦点，故同时带
// CREATE_NO_WINDOW（子进程根本不创建控制台）。
func hideChildWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}

// killProcessTree 树杀进程（对齐 Electron 壳 stop() 的 taskkill /T 语义）。
//
// Windows 上 os.Process.Kill=TerminateProcess 只杀引擎 PID 本身，引擎扫描时经
// chromedp 拉起的 Chrome 等子进程会成孤儿继续驻留内存；taskkill /PID /T /F 把
// 整棵树连同孙进程一并强杀（引擎已退出时 taskkill 报错属常态，忽略）。
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	tk := exec.Command("taskkill", "/PID", strconv.Itoa(p.Pid), "/T", "/F")
	hideChildWindow(tk) // taskkill 也是控制台程序，直接 exec 会闪黑窗（BUG-033）
	_ = tk.Run()
	_ = p.Kill() // 兜底：树杀失败时至少杀引擎本身（已死则返回错误，忽略）
}

// ---- 原生确认对话框（Windows MessageBoxW，不引入第三方依赖） ----

const (
	mbYesNo       = 0x00000004
	mbIconWarning = 0x00000030
	mbDefButton2  = 0x00000100 // 默认按钮 = 第二个（「否」）：防误触回车即更新
	idYes         = 6
)

var procMessageBoxW = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

// confirmInstallDialog 弹原生「是/否」对话框（默认选中「否」）。
// 只有用户明确点「是」才返回 true。
func confirmInstallDialog(latest, current string) bool {
	// 显示实际生效的更新源（可能被 SITLENS_UPDATE_URL 覆盖），不要骗用户。
	feed := updateBaseURL
	if v := strings.TrimSpace(os.Getenv(updateFeedEnv)); v != "" {
		feed = v
	}
	title, err := syscall.UTF16PtrFromString("SiteLens 更新确认")
	if err != nil {
		return false
	}
	text, err := syscall.UTF16PtrFromString(fmt.Sprintf(
		"发现新版本 v%s（当前 v%s）。\n\n"+
			"将下载安装包并校验 SHA512，校验通过后静默覆盖安装并重启。\n"+
			"更新源：%s\n\n是否现在更新？", latest, current, feed))
	if err != nil {
		return false
	}
	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		uintptr(mbYesNo|mbIconWarning|mbDefButton2),
	)
	log.Printf("更新确认对话框返回 %d（6=是）", int(ret))
	return int(ret) == idYes
}
