//go:build !windows

// 非 Windows 平台（Linux/macOS）的壳能力降级实现。
//
// POSIX 没有「控制台子系统新建黑窗」的概念，子进程默认继承终端/无终端，
// 因此 hideChildWindow 是空操作；进程回收也没有 taskkill 树杀语义，
// 引擎子进程由壳直接 Kill（引擎自身退出时会清理其子进程）。
//
// 自动更新当前只支持 Windows NSIS 安装器：非 Windows 平台 confirm 返回 false，
// 且 downloadAndInstall 会提前拒绝，不会去执行 .exe。
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// hideChildWindow 非 Windows 平台空操作（没有控制台窗口可隐藏）。
func hideChildWindow(cmd *exec.Cmd) { _ = cmd }

// killProcessTree 非 Windows 平台退化为 Kill 引擎进程本身。
func killProcessTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
}

// confirmInstallDialog 非 Windows 平台不支持静默安装器：直接拒绝并留痕。
func confirmInstallDialog(latest, current string) bool {
	log.Printf("当前平台不支持自动更新安装器（v%s → v%s），已跳过；请手动下载对应平台安装包",
		current, latest)
	return false
}

// launchInstaller 非 Windows 平台不支持 NSIS 安装器（downloadAndInstall 会提前
// 拒绝，不会走到这里）；返回错误而不是静默成功。
func launchInstaller(path string) error {
	return fmt.Errorf("当前平台不支持自动更新安装器：%s", path)
}
