// audit 子命令参数与执行（AU-01 SARIF + AU-02 基线/diff + AU-03 SCA）。
//
// 参数形态与既有 audit 一致：首个非开关参数 = 审计目标；开关同时支持
// `--flag value`、`--flag=value`、单横线；未知开关沿用旧行为忽略。
// 所有新开关均为 additive：不带时 stdout 的 JSON 报告与 AU-01 逐字节一致。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/audit"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/model"
	"cnb.cool/feng-qiao/sitelens/internal/server"
)

// auditCLIArgs audit 子命令全部参数。
type auditCLIArgs struct {
	Root               string // 审计目标（目录或单文件）
	SarifPath          string // --sarif：SARIF 2.1.0 导出
	BaselinePath       string // --baseline：只报基线外新增
	UpdateBaselinePath string // --update-baseline：写入当前指纹
	DiffPath           string // --diff：与上次审计 JSON 对比
	SCA                bool   // --sca：依赖清单（SCA）
}

// parseAuditArgsFull 解析 audit 子命令参数（AU-02/03 扩展版）。
// 缺值/空值报错；未知开关忽略（不吞后续参数）。
func parseAuditArgsFull(argv []string) (auditCLIArgs, error) {
	var a auditCLIArgs
	// takePath 取路径型开关取值（支持 = 内联与空格两种形态）。
	takePath := func(i *int, inlineVal string, hasInline bool, flagName string) (string, error) {
		val := inlineVal
		if !hasInline {
			if *i+1 >= len(argv) {
				return "", fmt.Errorf("--%s 缺少路径", flagName)
			}
			*i = *i + 1
			val = argv[*i]
		}
		val = strings.TrimSpace(val)
		if val == "" {
			return "", fmt.Errorf("--%s 路径不能为空", flagName)
		}
		return val, nil
	}
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		name, inlineVal, hasInline := splitGlobalToken(tok)
		switch name {
		case "sarif":
			v, err := takePath(&i, inlineVal, hasInline, "sarif")
			if err != nil {
				return a, err
			}
			a.SarifPath = v
		case "baseline":
			v, err := takePath(&i, inlineVal, hasInline, "baseline")
			if err != nil {
				return a, err
			}
			a.BaselinePath = v
		case "update-baseline":
			v, err := takePath(&i, inlineVal, hasInline, "update-baseline")
			if err != nil {
				return a, err
			}
			a.UpdateBaselinePath = v
		case "diff":
			v, err := takePath(&i, inlineVal, hasInline, "diff")
			if err != nil {
				return a, err
			}
			a.DiffPath = v
		case "sca":
			b := true
			if hasInline {
				pb, perr := strconv.ParseBool(inlineVal)
				if perr != nil {
					return a, fmt.Errorf("--sca 取值非法：%q", inlineVal)
				}
				b = pb
			}
			a.SCA = b
		default:
			if strings.HasPrefix(tok, "-") {
				continue // 未知开关：沿用旧行为忽略（不吞后续参数）
			}
			if a.Root == "" {
				a.Root = tok
			}
		}
	}
	return a, nil
}

// runAuditWithOptions 执行审计并输出 JSON + 可选 SARIF/白盒图/基线/diff/SCA。
// stdout 只放 JSON 报告；其它信息一律 stderr（既有流分离约定不变）。
func runAuditWithOptions(cfg *config.Config, a auditCLIArgs) {
	var wb *model.ScanGraph
	if cfg.Scan.Graph {
		wb = model.NewGraph("")
	}
	rep, err := audit.RunWithFactsOptions(a.Root, cfg.Audit, audit.RunOptions{
		BaselinePath:       a.BaselinePath,
		UpdateBaselinePath: a.UpdateBaselinePath,
		DiffPath:           a.DiffPath,
		SCA:                a.SCA,
	}, wb, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "审计失败:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	// AU-01：SARIF 导出（独立文件；stdout 的 JSON 报告不受影响）
	if a.SarifPath != "" {
		data, serr := audit.ToSARIF(rep, server.Version)
		if serr != nil {
			fmt.Fprintln(os.Stderr, "SARIF 序列化失败:", serr)
			os.Exit(1)
		}
		if werr := os.WriteFile(a.SarifPath, data, 0o644); werr != nil {
			fmt.Fprintln(os.Stderr, "SARIF 写出失败:", werr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "SARIF 已写出：%s（%d 条发现）\n", a.SarifPath, len(rep.Findings))
	}
	// AU-02：基线与 diff 提示（报告内已是 additive 字段）
	if a.UpdateBaselinePath != "" {
		if b, lerr := audit.LoadBaseline(a.UpdateBaselinePath); lerr == nil {
			fmt.Fprintf(os.Stderr, "基线已更新：%s（%d 条指纹）\n",
				a.UpdateBaselinePath, len(b.Fingerprints))
		} else {
			fmt.Fprintf(os.Stderr, "基线已更新：%s\n", a.UpdateBaselinePath)
		}
	}
	if rep.BaselineIgnored != nil {
		fmt.Fprintf(os.Stderr, "基线过滤：忽略 %d 条已接受发现（只报新增）\n", *rep.BaselineIgnored)
	}
	if rep.Diff != nil {
		fmt.Fprintf(os.Stderr, "diff：新增 %d 条 / 已修复 %d 条\n", rep.Diff.New, rep.Diff.Fixed)
	}
	// AU-03：SCA 摘要（漏洞状态 unknown 时明确提示，不暗示已扫漏洞）
	if rep.SCA != nil {
		if rep.SCA.Status == "queried" {
			fmt.Fprintf(os.Stderr, "SCA：%d 个依赖，其中 %d 个命中已知漏洞（来源 %s）\n",
				rep.SCA.Total, rep.SCA.Vulnerable, rep.SCA.OSVSource)
		} else {
			fmt.Fprintf(os.Stderr, "SCA：%d 个依赖；%s\n", rep.SCA.Total, rep.SCA.Note)
		}
	}
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
