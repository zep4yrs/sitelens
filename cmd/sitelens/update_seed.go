// update-seed 子命令：把随包只读种子（安装目录 resources/engine/data）
// 按包版本合并进用户数据区。
//
// 桌面壳在「版本变化后首次启动」自动调用它，实现真正的**覆盖更新**：
// 引擎升级了、包内 NVD 快照/指纹规则/情报行也更新了，用户区那份旧副本
// 必须让位，否则「升了版本、情报还是旧的」。同版本二次启动是 no-op，
// 用户之后手动 update-* 的成果不会再被覆盖。
//
// 用法（桌面壳内部）：
//
//	sitelens update-seed --seed-dir <安装目录>/data --user-dir <用户数据区>
//
// 两者都缺省时按「引擎 cwd 的 data」→「引擎 cwd 的上级」推断，便于手跑排障。
//
// 实现已抽到 internal/seedcmd —— 5.2 起引擎（cmd/sitelens-engine）与
// CLI（cmd/sitelens）是两个二进制，两边都要用同一份交付逻辑。
package main

import (
	"cnb.cool/feng-qiao/sitelens/internal/seedcmd"
)

// updateSeedCommand 执行种子交付；返回进程退出码。
func updateSeedCommand(seedDir, userDir string) int {
	return seedcmd.Run(seedDir, userDir)
}
