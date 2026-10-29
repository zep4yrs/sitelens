// Package seedcmd 把随包只读种子按包版本合并进用户数据区。
//
// 桌面壳在「版本变化后首次启动」自动调用它，实现真正的**覆盖更新**：
// 引擎升级了、包内 NVD 快照/指纹规则/情报行也更新了，用户区那份旧副本
// 必须让位，否则「升了版本、情报还是旧的」。同版本二次启动是 no-op，
// 用户之后手动 update-* 的成果不会再被覆盖。
//
// 本包独立于 cmd/：5.2 起桌面交付线把**引擎与 CLI 拆成两个二进制**
// （cmd/sitelens-engine 只做 serve + update-seed；cmd/sitelens 是 CLI），
// 两个入口都要用同一份交付逻辑，故抽到 internal 共享。
package seedcmd

import (
	"fmt"
	"os"
	"path/filepath"

	"cnb.cool/feng-qiao/sitelens/internal/seedrefresh"
	"cnb.cool/feng-qiao/sitelens/internal/server"
)

// Run 执行种子交付；返回进程退出码。
//
// seedDir 为空时取 cwd/data（安装目录布局：引擎与 data 同级）。
// userDir 为空时取 cwd 的上级（桌面版 engine/ 的父目录即用户数据区，
// 仅作为手跑兜底；壳总是显式传入）。
func Run(seedDir, userDir string) int {
	cwd, _ := os.Getwd()
	if seedDir == "" {
		seedDir = filepath.Join(cwd, "data")
	}
	if userDir == "" {
		userDir = filepath.Dir(cwd)
	}
	if st, err := os.Stat(seedDir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "种子目录不可用：%s\n", seedDir)
		return 1
	}
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "数据目录不可写：%s（%v）\n", userDir, err)
		return 1
	}
	installed := seedrefresh.LoadManifest(userDir).Version
	plan, err := seedrefresh.Build(seedDir, userDir, server.Version, installed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "种子比对失败：", err)
		return 1
	}
	if plan.Skipped {
		fmt.Printf("种子交付：已是 v%s，跳过\n", server.Version)
		return 0
	}
	n, err := seedrefresh.Apply(plan, userDir)
	if err != nil {
		// 交付失败不阻断启动：引擎会照常读用户区里那份（可能旧一点）。
		fmt.Fprintln(os.Stderr, "种子交付未完成：", err)
		return 1
	}
	fmt.Printf("种子交付：v%s → %s，覆盖 %d 份（保留用户区独有 %d 份）\n",
		server.Version, userDir, n, len(plan.Keep))
	return 0
}
