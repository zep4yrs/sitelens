// update-nuclei 子命令：把官方模板库镜像到本地（1.0 运营链路）。
package main

import (
	"fmt"
	"net/http"
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
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "下载失败：", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, "下载失败：HTTP", resp.StatusCode)
		return 1
	}
	kept, removed, err := nuclei.SyncFromTar(resp.Body, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "镜像失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "模板库镜像完成：保留 %d，删除 %d（%s/http）\n", kept, removed, dir)
	fmt.Fprintln(os.Stderr, "索引缓存将随文件数变化自动重建。")
	return 0
}
