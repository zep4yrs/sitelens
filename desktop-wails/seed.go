package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sitelens-wails/internal/usercfg"
)

// seedDeliverTimeout 种子交付的硬上限。
//
// D-08：deliverSeeds 在创建任何窗口之前同步执行（main.go），旧实现用
// CombinedOutput 无超时等待子进程——引擎一旦卡住（AV 拦截 / 磁盘锁 /
// 大种子拷贝）壳会在开窗之前无限阻塞，用户看到的是「双击没反应」。
// 这里给硬超时，超时即降级启动（引擎照常读用户区那份旧种子）。
const seedDeliverTimeout = 20 * time.Second

// userDataDir 桌面壳的用户数据区（%APPDATA%\SiteLens-Wails）。
// 与 Electron 壳的 %APPDATA%\SiteLens 不同——两条壳并存时不互相污染。
func userDataDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "SiteLens-Wails"), nil
}

// prepareUserData 建齐用户数据区目录骨架（幂等）。
func prepareUserData(m usercfg.Managed) error {
	for _, d := range m.WritableDirs() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// deliverSeeds 调引擎的 update-seed 按包版本交付随包种子（覆盖更新的一环）。
//
// 为什么必须做：安装包内置的 NVD 快照/情报行/指纹规则若只在「用户区不存在时」
// 拷贝（旧 Electron 壳的行为），包内快照永远进不来——用户没手动跑过
// update-nvd 时，升级到带更新 NVD 的版本，用户区那份旧副本仍是权威源，
// 等于「升了版本、情报还是旧的」。update-seed 按引擎版本收敛：版本变化才覆盖，
// 同版本二次启动 no-op（用户之后 update-* 的成果不会再被抹掉）。
//
// 覆盖边界（哪些能覆盖）由引擎侧 internal/seedrefresh 白名单决定，壳不重复实现。
// 失败不阻断启动：引擎照常读用户区那份（可能旧一点），shell.log 留痕。
func deliverSeeds(engineExe, seedDir, userData string) {
	if _, err := os.Stat(seedDir); err != nil {
		log.Printf("种子目录缺失，跳过交付：%s", seedDir)
		return
	}
	// D-08：带超时的 CommandContext——超时即杀掉子进程并降级启动，
	// 不允许「引擎卡住 → 壳在开窗之前无限阻塞」。
	ctx, cancel := context.WithTimeout(context.Background(), seedDeliverTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, engineExe,
		"update-seed", "--seed-dir", seedDir, "--user-dir", userData)
	cmd.Dir = filepath.Dir(engineExe) // 与引擎 serve 同 cwd，相对路径语义一致
	// 同 BUG-032：引擎是控制台子系统程序，不加这行会在启动时闪一个黑窗。
	// 输出仍走 CombinedOutput 的管道，不受影响（子进程不创建控制台，
	// 但 stdout/stderr 句柄照常经管道传给父进程）。
	hideChildWindow(cmd)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("种子交付超时（%s），跳过本次交付，引擎照常启动", seedDeliverTimeout)
		return
	}
	if err != nil {
		log.Printf("种子交付未完成（%v）：%s", err, string(out))
		return
	}
	log.Printf("种子交付：%s", trimNL(string(out)))
}

// trimNL 去掉子命令输出的尾部换行（日志一行一条）。
func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
