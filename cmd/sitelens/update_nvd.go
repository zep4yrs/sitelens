// update-nvd 子命令：镜像 NVD CVE 字典（公开数据，无需凭据）。
//
// 两种模式：
//
//	update-nvd              API 2.0 逐页拉取（无 key 限速，全库约数小时，可后台跑）
//	update-nvd feed [起] [止] 年度批量 feed（CDN 分发，按年打包，快得多；推荐）
//
// 两种模式的产出文件格式一致（含 P5 新增的 cwes 字段，版本 v2）。
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// updateNVDCommand 按参数分派 API / feed 模式。
// args 为 update-nvd 之后的剩余参数（如 ["feed","2018","2024"]）。
func updateNVDCommand(cfg *config.Config) int {
	args := os.Args[1:]
	for i, a := range args {
		if a == "update-nvd" {
			args = args[i+1:]
			break
		}
	}
	if len(args) > 0 && args[0] == "feed" {
		return updateNVDFeedCommand(cfg, args[1:])
	}
	return updateNVDApiCommand(cfg)
}

// updateNVDApiCommand API 2.0 逐页拉取（原路径）。
func updateNVDApiCommand(cfg *config.Config) int {
	out := cfg.Intel.NVDPath
	if out == "" {
		out = "data/nvd_cves.json.gz"
	}
	fmt.Fprintln(os.Stderr, "无 key 模式：按官方限速节流（全库数小时，可后台跑）")
	fmt.Fprintf(os.Stderr, "目标文件：%s\n", out)
	done := 0
	t0 := time.Now()
	err := intel.SyncNVD(out, "", func(n, total, skipped int) {
		done = n
		if n%2000 == 0 || n == total { // 每页一次（页大小 2000）
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

// updateNVDFeedCommand 年度批量 feed 模式。
// args 形如 ["2018","2024"] 或 ["2018"] 或 []（默认 2002..当前年）。
func updateNVDFeedCommand(cfg *config.Config, args []string) int {
	out := cfg.Intel.NVDPath
	if out == "" {
		out = "data/nvd_cves.json.gz"
	}
	fromYear, toYear := 2002, time.Now().Year()
	if len(args) >= 1 && args[0] != "" {
		if y, err := strconv.Atoi(args[0]); err == nil {
			fromYear = y
		}
	}
	if len(args) >= 2 && args[1] != "" {
		if y, err := strconv.Atoi(args[1]); err == nil {
			toYear = y
		}
	}
	fmt.Fprintf(os.Stderr, "年度 feed 模式：%d..%d（CDN 分发，比 API 快得多）\n", fromYear, toYear)
	fmt.Fprintf(os.Stderr, "目标文件：%s\n", out)

	years := toYear - fromYear + 1
	t0 := time.Now()
	err := intel.SyncNVDFeed(out, fromYear, toYear, func(done, total, skipped int) {
		fmt.Fprintf(os.Stderr, "\r进度：%d/%d 年（跳过 Rejected %d）", done, total, skipped)
		if done%10 == 0 && total > 20 {
			fmt.Fprintf(os.Stderr, "\n")
		}
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "feed 同步失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "NVD feed 镜像完成：%d 年（耗时 %s）\n", years, time.Since(t0).Round(time.Second))
	return 0
}
