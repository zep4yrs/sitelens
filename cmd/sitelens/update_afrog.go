// update-afrog 子命令：镜像 afrog 社区 POC 库到 nuclei_dir/afrog/。
// 引擎索引对同目录 YAML 统一走三前端漏斗（path/raw/afrog），
// 无需单独索引链路；索引缓存随文件数变化自动重建。
package main

import (
	"fmt"
	"io"
	"net/http"
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
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取失败：", err)
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
