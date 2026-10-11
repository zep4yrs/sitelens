package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"sitelens-wails/internal/usercfg"
)

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
	cmd := exec.Command(engineExe,
		"update-seed", "--seed-dir", seedDir, "--user-dir", userData)
	cmd.Dir = filepath.Dir(engineExe) // 与引擎 serve 同 cwd，相对路径语义一致
	out, err := cmd.CombinedOutput()
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
