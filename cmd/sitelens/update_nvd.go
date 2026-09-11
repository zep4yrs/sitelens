// update-nvd 子命令：全量镜像 NVD CVE 字典（公开 API，无需凭据）。
// API key 通道暂不开放：env→请求头的凭证流需要专项安全评审后启用；
// 当前固定走无 key 限速（官方 5 请求/30 秒，全库约 50 分钟，可后台跑）。
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
	fmt.Fprintln(os.Stderr, "无 key 模式：按官方限速节流（约 50 分钟/全库，可后台跑）")
	fmt.Fprintf(os.Stderr, "目标文件：%s\n", out)
	done := 0
	t0 := time.Now()
	err := intel.SyncNVD(out, "", func(n, total, skipped int) {
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
