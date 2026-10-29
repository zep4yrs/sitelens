// 全局 flag 解析（BUG-005）。
//
// Go 的 flag.Parse() 在遇到第一个非 flag 参数（= 子命令名）时即停止解析，
// 于是 `sitelens serve -config x.yml` 里的 -config/-graph/-ast/-env 全部落进
// flag.Args()：被当成子命令的位置参数（`scan url -config cf` 里的 cf 成了
// 第二个位置参数、`scan -config cf url` 的目标变成 "-config"），或直接被
// 忽略（serve 静默用默认配置）。这与 `sitelens -config x.yml serve` 的写法
// 结果不同，用户按自然直觉写命令就会踩到。
//
// 修法：前置 flag.Parse 行为完全不变；在子命令名之后再补扫一次**已知全局
// 开关**。未知参数原样保留——TUI 直通型命令会把 [引擎参数...] 原样转发给
// CLI，子命令自己的 flag（如 graph-read 的 --self-test、update-seed 的
// --seed-dir）也必须留给子命令自己解析。
package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

// globalFlags 全局开关取值（前置解析与子命令后补扫共用同一份定义）。
type globalFlags struct {
	Config  string // -config：配置文件路径
	Env     string // -env：环境变量文件（PG 连接参数来源）
	Version bool   // -version：输出版本号并退出
	Graph   bool   // -graph：扫描结果增结构化事实图
	AST     bool   // -ast：源码审计启用 AST 污点分析
}

// bindGlobalFlags 注册全局 flag（main 与单测共用，避免两处定义漂移）。
func bindGlobalFlags(fs *flag.FlagSet, g *globalFlags) {
	fs.StringVar(&g.Config, "config", ".sitelens.yml", "配置文件路径")
	fs.BoolVar(&g.Version, "version", false, "输出版本号并退出")
	fs.StringVar(&g.Env, "env", ".env", "环境变量文件（PG 连接参数来源）")
	fs.BoolVar(&g.Graph, "graph", false, "收集结构化事实图 graph（4.0，默认关；开启时结果 JSON 增 graph 字段）")
	fs.BoolVar(&g.AST, "ast", false, "源码审计启用 AST 污点分析（4.0，默认关；需 CGO 构建，非 CGO 自动回退行级）")
}

// splitGlobalToken 拆分形如 -flag / --flag / -flag=value / --flag=value 的
// token，返回（开关名，= 后取值，是否带 =）。非开关（空串、裸 "-"、"--"
// 终止符）返回空名，由调用方原样保留。
func splitGlobalToken(tok string) (name, val string, hasVal bool) {
	if len(tok) < 2 || tok[0] != '-' {
		return "", "", false
	}
	body := tok[1:]
	if strings.HasPrefix(body, "-") {
		body = body[1:]
		if body == "" {
			return "", "", false // "--"：参数终止符，原样保留
		}
	}
	if k, v, ok := strings.Cut(body, "="); ok {
		return k, v, true
	}
	return body, "", false
}

// rescanGlobalFlags 在「子命令之后的参数」里补扫已知全局开关（BUG-005）。
//
// 返回值为剔除已消费开关后的参数（保持原相对顺序），调用方用它替换
// flag.Args()[1:]。支持 -flag value / -flag=value / --flag 形态；
// 字符串开关缺值、布尔开关取值非法时返回错误（不静默吞掉）。
// 未知参数一律原样保留。
func rescanGlobalFlags(argv []string, g *globalFlags) ([]string, error) {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		name, inlineVal, hasInline := splitGlobalToken(argv[i])
		switch name {
		case "config", "env":
			val := inlineVal
			if !hasInline {
				if i+1 >= len(argv) {
					return nil, fmt.Errorf("全局开关 -%s 缺少取值", name)
				}
				i++
				val = argv[i]
			}
			if name == "config" {
				g.Config = val
			} else {
				g.Env = val
			}
		case "version", "graph", "ast":
			b := true
			if hasInline {
				v, err := strconv.ParseBool(inlineVal)
				if err != nil {
					return nil, fmt.Errorf("全局开关 -%s 取值非法：%q", name, inlineVal)
				}
				b = v
			}
			switch name {
			case "version":
				g.Version = b
			case "graph":
				g.Graph = b
			case "ast":
				g.AST = b
			}
		default:
			out = append(out, argv[i]) // 未知参数/子命令自有 flag：原样保留
		}
	}
	return out, nil
}

// argAt 取子命令位置参数（缺省返回空串，与 flag.Arg 语义一致）。
func argAt(args []string, i int) string {
	if i >= 0 && i < len(args) {
		return args[i]
	}
	return ""
}
