// SiteLens Go 引擎 CLI。
//
// 用法：
//
//	sitelens scan <url>    全流水线扫描（指纹/爬取/check/情报关联），JSON 输出
//	sitelens serve         启动内置 Web 服务（默认 127.0.0.1:5000）
//	sitelens -config <path> 指定 .sitelens.yml 配置
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/server"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func main() {
	cfgPath := flag.String("config", ".sitelens.yml", "配置文件路径")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SiteLens Go 引擎

用法：
  sitelens [flags] scan <url>    全流水线扫描，JSON 输出
  sitelens [flags] serve         启动内置 Web 服务

配置：%s（缺省用内置最佳实践默认值）
`, *cfgPath)
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	cfg := config.LoadOrDefault(*cfgPath)

	switch args[0] {
	case "serve":
		srv, err := server.New(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "服务装配失败:", err)
			os.Exit(1)
		}
		if err := srv.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "服务退出:", err)
			os.Exit(1)
		}
	case "scan":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		runScan(cfg, args[1])
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", args[0])
		flag.Usage()
		os.Exit(2)
	}
}

func runScan(cfg *config.Config, rawURL string) {
	matcher, err := sitelens.LoadMatcher(cfg.Intel.TechnologiesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告：指纹库加载失败（%v），跳过指纹识别\n", err)
		matcher = nil
	}
	kb, err := intel.Load(cfg.Intel.DumpPath, cfg.Intel.RangesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告：知识库加载失败（%v），跳过情报关联\n", err)
		kb = nil
	}
	eng := engine.New(cfg, matcher, kb)
	opts := engine.Options{
		Deep:    cfg.Scan.Deep,
		Checks:  cfg.Checks.Level,
		Netsec:  cfg.Modules.Netsec,
		Passive: true,
	}
	res := eng.Scan(rawURL, opts, nil, nil)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))

	if res.Error != "" {
		os.Exit(1)
	}
	// 摘要输出到 stderr（JSON 走 stdout 可直接管道消费）
	fmt.Fprintf(os.Stderr, "\n目标 %s：%d 项技术，%d 条已验证发现，%d 条漏洞情报，安全评分 %s\n",
		res.URL, len(res.Technologies), len(res.Verified), len(res.Vulnerabilities),
		gradeOf(res))
}

func gradeOf(res *engine.Result) string {
	if res.Security == nil {
		return "-"
	}
	return fmt.Sprintf("%s(%d)", res.Security.Grade, res.Security.Score)
}
