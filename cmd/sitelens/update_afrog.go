// update-afrog 子命令：镜像 afrog 社区 POC 库到 nuclei_dir/afrog/。
// 引擎索引对同目录 YAML 统一走三前端漏斗（path/raw/afrog），
// 无需单独索引链路；索引缓存随文件数变化自动重建。
//
// 下载闸：强制 https + 实测 sha256 留痕/可钉校验（见 update_guard.go）。
package main

import (
	"fmt"
	"os"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
)

func updateAfrogCommand(cfg *config.Config, url string) int {
	dir := cfg.Checks.NucleiDir
	if dir == "" {
		fmt.Fprintln(os.Stderr, "配置未启用 nuclei_dir，无法镜像 afrog POC 库")
		return 1
	}
	if url == "" {
		url = nuclei.AfrogFetchURL
	}
	fmt.Fprintf(os.Stderr, "下载 afrog POC 库：%s\n", url)
	// 256MB 上限沿用旧口径（zip 解压前的输入预算）
	path, _, cleanup, err := downloadUpdate(url, 30*time.Minute, 256<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer cleanup()
	buf, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取下载内容失败：", err)
		return 1
	}
	kept, removed, err := nuclei.SyncAfrogFromZip(buf, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "镜像失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "afrog POC 库镜像完成：落盘 %d，清理旧文件 %d（%s/afrog）\n", kept, removed, dir)
	fmt.Fprintln(os.Stderr, "索引缓存将随文件数变化自动重建。")
	return 0
}
