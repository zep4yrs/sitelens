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
	var g globalFlags
	bindGlobalFlags(flag.CommandLine, &g)
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
  sitelens [flags] update-seed [--seed-dir <包内种子>] [--user-dir <用户数据区>]
                                 按包版本把随包只读种子覆盖到用户数据区
                                 （桌面壳在版本变化后首启自动调用）
  sitelens [flags] update-tplintel
                                 模板 CVE × NVD 关联生成模板情报行
  sitelens [flags] update-ehole [url]
                                 合并 EHole 中文产品指纹（exact 字面量通道）
  sitelens [flags] audit <dir> [--sarif <out.sarif>]
                                  [--baseline <file>] [--update-baseline <file>]
                                  [--diff <old.json>] [--sca]
                                  源码静态审计，JSON 输出；SARIF/基线/diff/SCA 可选
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
`, g.Config)
		flag.PrintDefaults()
	}
	flag.Parse()
	if g.Version {
		fmt.Println("SiteLens " + server.Version)
		return
	}
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	// BUG-005：flag.Parse() 在子命令名处停止，子命令之后的全局开关会落进
	// flag.Args()。这里补扫一次已知全局开关（前置写法行为不变），未知参数
	// 原样留给子命令/直通。
	rest, rerr := rescanGlobalFlags(args[1:], &g)
	if rerr != nil {
		fmt.Fprintln(os.Stderr, rerr)
		flag.Usage()
		os.Exit(2)
	}
	if g.Version { // `sitelens scan -version` 与前置写法同语义
		fmt.Println("SiteLens " + server.Version)
		return
	}
	args = append(args[:1], rest...)
	// update-seed 是「路径参数」型子命令（--seed-dir/--user-dir），
	// 而 flag.Parse() 在遇到子命令名时已停止解析——参数落进 flag.Args()。
	// 这里局部再解析一次，只认这两个开关，其余命令零影响。
	if len(args) > 0 && args[0] == "update-seed" {
		fs := flag.NewFlagSet("update-seed", flag.ContinueOnError)
		seed := fs.String("seed-dir", "", "随包只读种子目录")
		usr := fs.String("user-dir", "", "用户数据区目录")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(2)
		}
		os.Exit(updateSeedCommand(*seed, *usr))
	}

	cfg := config.LoadOrDefault(g.Config)

	// 4.0 Track A / A1：GC 软上限（零行为变化，仅让 GC 在尖峰前更早介入）。
	// 放在所有子命令之前——serve 常驻与 scan 一次性调用都受益。
	// SITLENS_RESOURCE_OFF=1 仅用于时长 A/B 实测（治理开/关同机对照），产品路径不感知。
	if os.Getenv("SITLENS_RESOURCE_OFF") != "1" {
		resource.Apply(resource.DefaultGCConfig())
	}

	if g.Graph {
		cfg.Scan.Graph = true // CLI 开关覆盖配置
	}
	if g.AST {
		cfg.Audit.ASTEnabled = true // CLI 开关覆盖配置
	}

	switch args[0] {
	case "audit":
		// AU-01/02/03：audit 支持 --sarif / --baseline / --update-baseline /
		// --diff / --sca；既有用法 `audit <dir>` 与 JSON 输出保持不变。
		a, aerr := parseAuditArgsFull(args[1:])
		if aerr != nil {
			fmt.Fprintln(os.Stderr, aerr)
			flag.Usage()
			os.Exit(2)
		}
		if a.Root == "" {
			flag.Usage()
			os.Exit(2)
		}
		runAuditWithOptions(cfg, a)
	case "correlate":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "用法：sitelens correlate <blackbox.graph.jsonl> <whitebox.graph.jsonl>")
			os.Exit(2)
		}
		runCorrelate(cfg, args[1], args[2])
	case "update-osv":
		os.Exit(updateOSVCommand(cfg, 8))
	case "update-nvd":
		// 参数已由 main 的全局开关补扫清理过，避免 updateNVDCommand 自己
		// 再从 os.Args 里捞（那样子命令后跟全局开关时 feed 模式会被错判）
		os.Exit(updateNVDCommand(cfg, args[1:]))
	case "update-tplintel":
		os.Exit(updateTplIntelCommand(cfg))
	case "update-ehole":
		os.Exit(updateEHoleCommand(cfg, argAt(args, 1)))
	case "graph-read":
		os.Exit(graphReadCommand(args[1:]))
	case "regression":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		os.Exit(regressionCommand(cfg, args[1]))
	case "update-nuclei":
		os.Exit(updateNucleiCommand(cfg, argAt(args, 1)))
	case "update-afrog":
		os.Exit(updateAfrogCommand(cfg, argAt(args, 1)))
	case "update-fp":
		os.Exit(updateFPCommand(cfg, argAt(args, 1)))
	case "migrate-pg":
		loadEnvFile(g.Env)
		os.Exit(migratePGCommand(g.Config))
	case "serve":
		srv, err := server.New(cfg, g.Config)
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
		kb.AttachNVDPath(cfg.Intel.NVDPath) // A3 惰性：首次用到时才解码
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
		// DAST 主动注入探测：CLI scan 此前漏开（只有 serve 的 scanOptions 开了），
		// 导致命令行扫描永远拿不到参数级注入发现——与"deep 档含 DAST"的
		// 档位语义不符。此处按配置总闸打开（[dast] 段可关）。
		DAST:    true,
		JSMap:   true,                // JS 攻击面提取（bundle 端点 / SourceMap，只读）
		Exploit: cfg.Exploit.Enabled, // 利用级验证：配置总闸
		Graph:   cfg.Scan.Graph,      // 4.0 P2：结构化事实图（默认关）
	}
	res := eng.Scan(rawURL, opts, nil, nil)
	// 4.0 Track A / A4：扫描结束把堆归还 OS（任务管理器可见回落）。
	// 放在序列化之前——JSON 编码仍需内存，归还发生在扫描峰值之后即可。
	out, merr := json.MarshalIndent(res, "", "  ")
	if merr != nil {
		// 序列化失败绝不能静默：旧行为忽略错误后 out=nil，扫描以退出码 0
		// 打印空输出，下游管道消费方拿到的是"成功 + 空结果"。
		fmt.Fprintf(os.Stderr, "错误：结果 JSON 序列化失败：%v\n", merr)
		out, _ = json.MarshalIndent(map[string]any{
			"url":   rawURL,
			"error": "结果序列化失败：" + merr.Error(),
		}, "", "  ")
	}
	resource.ReleaseToOS()
	fmt.Println(string(out))

	if res.Error != "" || merr != nil {
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

// parseAuditArgs 兼容 AU-01 既有调用（root/sarif 两字段视图）。
// AU-02/03 的完整参数（--baseline/--update-baseline/--diff/--sca）见
// parseAuditArgsFull（audit_au02.go）。
//
// 全局开关（-config/-graph/-ast 等）已由 main 在调用前补扫剔除，不会到这里。
func parseAuditArgs(argv []string) (root, sarifPath string, err error) {
	a, aerr := parseAuditArgsFull(argv)
	if aerr != nil {
		return "", "", aerr
	}
	return a.Root, a.SarifPath, nil
}

// runAudit 兼容 AU-01 既有调用（仅 --sarif）；完整选项走 runAuditWithOptions。
// -graph 时额外输出白盒图 JSONL（供 correlate）；sarifPath 非空时另导出
// SARIF 2.1.0（stdout 的 JSON 报告不变）。
func runAudit(cfg *config.Config, root, sarifPath string) {
	runAuditWithOptions(cfg, auditCLIArgs{Root: root, SarifPath: sarifPath})
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
