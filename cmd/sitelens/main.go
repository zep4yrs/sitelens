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

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/server"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func main() {
	cfgPath := flag.String("config", ".sitelens.yml", "配置文件路径")
	showVersion := flag.Bool("version", false, "输出版本号并退出")
	envFile := flag.String("env", ".env", "环境变量文件（PG 连接参数来源）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SiteLens Go 引擎

用法：
  sitelens [flags] scan <url>    全流水线扫描，JSON 输出
  sitelens [flags] serve         启动内置 Web 服务
  sitelens [flags] migrate-pg    迁移 Python 版 PG 扫描历史到本地文件库

配置：%s（缺省用内置最佳实践默认值）
`, *cfgPath)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("SiteLens " + server.Version)
		return
	}
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	cfg := config.LoadOrDefault(*cfgPath)

	switch args[0] {
	case "audit":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		rep, err := audit.Run(args[1], cfg.Audit, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "审计失败:", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		fmt.Fprintf(os.Stderr, "\n审计完成：%d 文件，%d 行，%d 发现（高 %d / 中 %d / 低 %d）\n",
			rep.Files, rep.Lines, len(rep.Findings),
			rep.BySeverity["high"], rep.BySeverity["medium"], rep.BySeverity["low"])
	case "migrate-pg":
		loadEnvFile(*envFile)
		os.Exit(migratePGCommand(*cfgPath))
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
	checks.ConfigurePlugins(cfg.Checks.PluginDir)
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
