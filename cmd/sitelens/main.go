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
	"path/filepath"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/chain"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/correlate"
	"cnb.cool/feng-qiao/sitelens/internal/cwe"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/model"
	"cnb.cool/feng-qiao/sitelens/internal/resource"
	"cnb.cool/feng-qiao/sitelens/internal/server"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func main() {
	cfgPath := flag.String("config", ".sitelens.yml", "配置文件路径")
	showVersion := flag.Bool("version", false, "输出版本号并退出")
	envFile := flag.String("env", ".env", "环境变量文件（PG 连接参数来源）")
	graphFlag := flag.Bool("graph", false, "收集结构化事实图 graph（4.0，默认关；开启时结果 JSON 增 graph 字段）")
	astFlag := flag.Bool("ast", false, "源码审计启用 AST 污点分析（4.0，默认关；需 CGO 构建，非 CGO 自动回退行级）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SiteLens Go 引擎

用法：
  sitelens [flags] scan <url>    全流水线扫描，JSON 输出
  sitelens [flags] serve         启动内置 Web 服务
  sitelens [flags] migrate-pg    迁移 Python 版 PG 扫描历史到本地文件库
  sitelens [flags] update-nuclei [url]
                                 镜像官方 Nuclei 模板库到 nuclei_dir
  sitelens [flags] update-afrog [url]
                                 镜像 afrog 社区 POC 库到 nuclei_dir/afrog
  sitelens [flags] update-fp [url]
                                 镜像 enthec/webappanalyzer 社区指纹并合并精编库
  sitelens [flags] update-osv    从 OSV.dev 同步受影响区间与 CVSS 评分
  sitelens [flags] update-nvd [feed [起] [止]]
                                 镜像 NVD CVE 字典；feed=年度批量（推荐，快）
  sitelens [flags] update-tplintel
                                 模板 CVE × NVD 关联生成模板情报行
  sitelens [flags] update-ehole [url]
                                 合并 EHole 中文产品指纹（exact 字面量通道）
  sitelens [flags] audit <dir>   源码静态审计，JSON 输出
  sitelens [flags] correlate <blackbox.graph.jsonl> <whitebox.graph.jsonl>
                                 合并黑/白盒图并做证据关联，输出合并图 JSONL
  sitelens graph-read <file.graph.jsonl> [--self-test]
                                 读取结构化事实图：摘要或契约自检（只读）
  sitelens [flags] regression <scan_id>
                                 重放历史扫描的已验证发现（退出码表达回归）

配置：%s（缺省用内置最佳实践默认值）

扫描/审计 4.0 开关：
  -graph   扫描结果增结构化事实图（默认关）
  -ast     源码审计启用 AST 污点分析（默认关；需 CGO 构建）
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

	// 4.0 Track A / A1：GC 软上限（零行为变化，仅让 GC 在尖峰前更早介入）。
	// 放在所有子命令之前——serve 常驻与 scan 一次性调用都受益。
	resource.Apply(resource.DefaultGCConfig())

	if *graphFlag {
		cfg.Scan.Graph = true // CLI 开关覆盖配置
	}
	if *astFlag {
		cfg.Audit.ASTEnabled = true // CLI 开关覆盖配置
	}

	switch args[0] {
	case "audit":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		runAudit(cfg, args[1])
	case "correlate":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "用法：sitelens correlate <blackbox.graph.jsonl> <whitebox.graph.jsonl>")
			os.Exit(2)
		}
		runCorrelate(cfg, args[1], args[2])
	case "update-osv":
		os.Exit(updateOSVCommand(cfg, 8))
	case "update-nvd":
		os.Exit(updateNVDCommand(cfg))
	case "update-tplintel":
		os.Exit(updateTplIntelCommand(cfg))
	case "update-ehole":
		os.Exit(updateEHoleCommand(cfg, flag.Arg(1)))
	case "graph-read":
		os.Exit(graphReadCommand(args[1:]))
	case "regression":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		os.Exit(regressionCommand(cfg, args[1]))
	case "update-nuclei":
		os.Exit(updateNucleiCommand(cfg, flag.Arg(1)))
	case "update-afrog":
		os.Exit(updateAfrogCommand(cfg, flag.Arg(1)))
	case "update-fp":
		os.Exit(updateFPCommand(cfg, flag.Arg(1)))
	case "migrate-pg":
		loadEnvFile(*envFile)
		os.Exit(migratePGCommand(*cfgPath))
	case "serve":
		srv, err := server.New(cfg, *cfgPath)
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
	} else {
		if nvd, nerr := intel.LoadNVD(cfg.Intel.NVDPath); nerr == nil && nvd != nil {
			kb.AttachNVD(nvd)
		}
		if tc, terr := intel.LoadTechCPE("data/go/tech_cpe.json"); terr == nil && tc != nil {
			kb.AttachTechCPE(tc)
		}
		if tr, terr := intel.LoadTplIntel(cfg.Intel.TplIntelPath); terr == nil && tr != nil {
			kb.AttachTplIntel(tr)
		}
	}
	eng := engine.New(cfg, matcher, kb)
	opts := engine.Options{
		Deep:    cfg.Scan.Deep,
		Checks:  cfg.Checks.Level,
		Netsec:  cfg.Modules.Netsec,
		Passive: true,
		Exploit: cfg.Exploit.Enabled, // 利用级验证：配置总闸
		Graph:   cfg.Scan.Graph,      // 4.0 P2：结构化事实图（默认关）
	}
	res := eng.Scan(rawURL, opts, nil, nil)
	// 4.0 Track A / A4：扫描结束把堆归还 OS（任务管理器可见回落）。
	// 放在序列化之前——JSON 编码仍需内存，归还发生在扫描峰值之后即可。
	out, _ := json.MarshalIndent(res, "", "  ")
	resource.ReleaseToOS()
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

// runAudit 执行源码审计；-graph 时额外输出白盒图 JSONL（供 correlate）。
func runAudit(cfg *config.Config, root string) {
	var wb *model.ScanGraph
	if cfg.Scan.Graph {
		wb = model.NewGraph("")
	}
	rep, err := audit.RunWithFacts(root, cfg.Audit, wb, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "审计失败:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	if wb != nil {
		// 白盒图写 stderr 之后的独立文件，避免与报告 JSON 混流。
		p := filepath.Join(cfg.Store.DataDir, "whitebox.graph.jsonl")
		if err := writeGraphJSONL(p, wb); err != nil {
			fmt.Fprintln(os.Stderr, "白盒图写出失败:", err)
		} else {
			fmt.Fprintf(os.Stderr, "白盒图已写出：%s（%d 实体）\n", p, len(wb.SortedEntities()))
		}
	}
	fmt.Fprintf(os.Stderr, "\n审计完成：%d 文件，%d 行，%d 发现（高 %d / 中 %d / 低 %d）\n",
		rep.Files, rep.Lines, len(rep.Findings),
		rep.BySeverity["high"], rep.BySeverity["medium"], rep.BySeverity["low"])
}

// runCorrelate 读入黑盒/白盒两张图，合并后做黑白盒关联，输出合并图 JSONL。
func runCorrelate(cfg *config.Config, blackPath, whitePath string) {
	black, err := readGraphJSONL(blackPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取黑盒图失败:", err)
		os.Exit(1)
	}
	white, err := readGraphJSONL(whitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取白盒图失败:", err)
		os.Exit(1)
	}
	merged := mergeGraphs(black, white)
	// P5：补 CWE 关联（CVE 通道需 NVD 数据；文件缺失时跳过）。
	nvdPath := cfg.Intel.NVDPath
	if nvdPath == "" {
		nvdPath = "data/nvd_cves.json.gz"
	}
	if nvd, _ := intel.LoadNVD(nvdPath); nvd != nil {
		cwe.Relate(merged, nvd)
	}
	// P4：黑白盒关联。
	res := correlate.Run(merged, correlate.Options{})
	// P6：攻击链（证据驱动；无证据不成边）。
	cr := chain.Build(merged, chain.Options{})
	if err := merged.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "合并图校验异常:", err)
	}
	data, err := merged.MarshalJSONL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "序列化合并图失败:", err)
		os.Exit(1)
	}
	os.Stdout.Write(data)
	fmt.Fprintf(os.Stderr, "\n关联完成：%d 条 evidence_link（黑盒 %d 节点 × 白盒 %d 事实）\n",
		len(res.Links), countBlackbox(merged), countWhitebox(merged))
	fmt.Fprintf(os.Stderr, "攻击链：%d 节点 / %d 边（无证据跳过候选边 %d 条）\n",
		len(cr.Nodes), len(cr.Edges), cr.Skipped)
}

// mergeGraphs 合并两张图（同 ID 实体幂等去重）。
func mergeGraphs(a, b *model.ScanGraph) *model.ScanGraph {
	out := model.NewGraph(a.ScanID)
	out.GeneratedAt = a.GeneratedAt
	for _, e := range a.SortedEntities() {
		out.Add(e)
	}
	for _, e := range b.SortedEntities() {
		out.Add(e)
	}
	return out
}

// writeGraphJSONL 把图写为 JSONL 文件（建目录 + 原子替换）。
func writeGraphJSONL(path string, g *model.ScanGraph) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := g.MarshalJSONL()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readGraphJSONL 读取 graph JSONL 文件。
func readGraphJSONL(path string) (*model.ScanGraph, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return model.ReadJSONL(f)
}

// countBlackbox / countWhitebox 统计（用于摘要输出）。
func countBlackbox(g *model.ScanGraph) int {
	n := 0
	for _, v := range g.VulnNodes {
		if v.Origin == model.OriginBlackbox {
			n++
		}
	}
	return n
}

func countWhitebox(g *model.ScanGraph) int {
	n := len(g.Dataflows)
	for _, v := range g.VulnNodes {
		if v.Origin == model.OriginWhitebox {
			n++
		}
	}
	return n
}
