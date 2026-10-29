// update-nuclei 子命令：把官方模板库镜像到本地（1.0 运营链路）。
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

func updateNucleiCommand(cfg *config.Config, url string) int {
	dir := cfg.Checks.NucleiDir
	if dir == "" {
		fmt.Fprintln(os.Stderr, "配置未启用 nuclei_dir，无法镜像模板库")
		return 1
	}
	if url == "" {
		url = nuclei.FetchURL
	}
	fmt.Fprintf(os.Stderr, "下载模板库：%s\n", url)
	path, _, cleanup, err := downloadUpdate(url, 30*time.Minute, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer cleanup()
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取下载内容失败：", err)
		return 1
	}
	defer f.Close()
	kept, removed, err := nuclei.SyncFromTar(f, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "镜像失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "模板库镜像完成：保留 %d，删除 %d（%s/http）\n", kept, removed, dir)
	fmt.Fprintln(os.Stderr, "索引缓存将随文件数变化自动重建。")
	return 0
}
