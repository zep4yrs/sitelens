// update-nvd 子命令：全量镜像 NVD CVE 字典（公开 API，无需凭据；
// NVD_API_KEY 环境变量非必填，有则放宽限速）。公开数据可再生，
// 不随源码分发、不进仓库。
package main

import (
	"fmt"
	"os"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

func updateNVDCommand(cfg *config.Config) int {
	out := cfg.Intel.NVDPath
	if out == "" {
		out = "data/nvd_cves.json.gz"
	}
	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey != "" {
		fmt.Fprintln(os.Stderr, "已从 NVD_API_KEY 读取凭据（放宽限速）")
	} else {
		fmt.Fprintln(os.Stderr, "无 NVD_API_KEY：按官方无 key 限速节流（约 21 分钟/全库）")
	}
	fmt.Fprintf(os.Stderr, "目标文件：%s\n", out)
	done := 0
	t0 := time.Now()
	err := intel.SyncNVD(out, apiKey, func(n, total, skipped int) {
		done = n
		if n%20000 == 0 || n == total {
			fmt.Fprintf(os.Stderr, "\r进度：%d/%d（跳过 Rejected %d）", n, total, skipped)
		}
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "同步失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "NVD 镜像完成：%d 条（耗时 %s）\n", done, time.Since(t0).Round(time.Second))
	return 0
}
