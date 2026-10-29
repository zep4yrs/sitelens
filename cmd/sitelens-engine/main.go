// SiteLens 引擎二进制入口（桌面交付线内置）。
//
// 与 CLI（cmd/sitelens）的分工（5.2 起拆分）：
//
//	引擎（本二进制）= serve（Web 控制台 + 扫描引擎）+ update-seed
//	                （随包只读种子 → 用户数据区的覆盖更新）。不含任何 CLI 子命令。
//	CLI（cmd/sitelens）= 控制台子系统：scan / serve / audit / correlate /
//	                graph-read / regression / migrate-pg / update-*。
//	                独立分发，**不随桌面安装包发布**。
//
// 为什么拆：此前**一个 exe 既是引擎又是 CLI**，带来两个具体问题——
//
//	① 桌面壳（GUI 子系统）拉起它时必然弹出一个黑色控制台窗口
//	   （引擎是控制台子系统；BUG-032），退出时树杀用的 taskkill 又闪一个
//	   （BUG-033）；
//	② CLI 能力被整个塞进桌面安装包，白占体积与维护面。
//
// 拆开后：引擎只管被拉起，CLI 独立成产品，两条线互不牵连。
//
// 构建（桌面线）：
//
//	go build -o sitelens-engine.exe ./cmd/sitelens-engine
//
// ⚠️ 本二进制**保持控制台子系统**（不加 -H windowsgui）：引擎侧仍需写日志、
// update-seed 仍需输出交付结果；"不弹控制台窗口"由桌面壳在拉起时用
// CREATE_NO_WINDOW / HideWindow 实现（desktop-wails/main.go），
// 不靠改二进制子系统——那会连带打死 CLI 的 stdout。
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/seedcmd"
	"cnb.cool/feng-qiao/sitelens/internal/server"
)

func main() {
	cfgPath := flag.String("config", ".sitelens.yml", "配置文件路径")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SiteLens 引擎（桌面交付线内置）

用法：
  sitelens-engine [flags]              启动 Web 控制台（等价于 serve）
  sitelens-engine [flags] serve        同上（兼容既有调用方）
  sitelens-engine update-seed --seed-dir <包内种子> --user-dir <用户数据区>
                                 把随包只读种子合并进用户数据区（桌面壳自动调用）

说明：本二进制只提供引擎能力。命令行扫描（scan / audit / update-* 等）
     在独立的 CLI 二进制中，不随桌面安装包发布。

配置：%s（缺省用内置最佳实践默认值）
`, *cfgPath)
	}
	flag.Parse()
	args := flag.Args()

	// 子命令之后的全局 flag 补扫（与 cmd/sitelens 的 BUG-005 同型修复）：
	// flag.Parse() 遇第一个非 flag 参数（子命令名）即停止，于是
	// `sitelens-engine serve -config x.yml` 的 -config 落进 args 被忽略，
	// 静默用默认配置。桌面壳用前置写法不受影响，但手跑排障按自然直觉写
	// 就会踩到。引擎只关心 -config，补扫这一项即可，其余参数原样保留。
	if len(args) > 0 {
		args = append([]string{args[0]}, rescanConfigFlag(args[1:], cfgPath)...)
	}

	// update-seed 是「路径参数」型子命令（--seed-dir/--user-dir），而
	// flag.Parse() 遇到子命令名即停止解析——参数落进 flag.Args()，这里
	// 局部再解析一次（与 cmd/sitelens 的同款做法）。
	if len(args) > 0 && args[0] == "update-seed" {
		fs := flag.NewFlagSet("update-seed", flag.ContinueOnError)
		seed := fs.String("seed-dir", "", "随包只读种子目录")
		usr := fs.String("user-dir", "", "用户数据区目录")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(2)
		}
		os.Exit(seedcmd.Run(*seed, *usr))
	}
	// 未知子命令直接报错——**不要静默当 serve 跑**（那会让人以为命令
	// 生效了，实际起了一个 Web 控制台）。CLI 的全部子命令在 cmd/sitelens。
	if len(args) > 0 && args[0] != "serve" {
		fmt.Fprintf(os.Stderr, "未知命令 %q——引擎只提供 serve 与 update-seed；\n"+
			"命令行扫描等能力在 CLI 二进制中（npm 线：sitelens scan …）。\n", args[0])
		os.Exit(2)
	}

	cfg := config.LoadOrDefault(*cfgPath)
	srv, err := server.New(cfg, *cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "服务装配失败:", err)
		os.Exit(1)
	}
	if err := srv.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "服务退出:", err)
		os.Exit(1)
	}
}

// rescanConfigFlag 在子命令之后的参数里补扫 -config（BUG-005 同型修复）。
//
// 支持 -config v / --config v / -config=v / --config=v 四种形态；未知参数
// 原样保留（update-seed 的 --seed-dir 等子命令自有 flag 不能吞掉）。
// 看到 "--" 终止符后不再扫描，其余参数逐字保留。
func rescanConfigFlag(argv []string, cfg *string) []string {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		if tok == "--" {
			out = append(out, argv[i:]...)
			break
		}
		if len(tok) < 2 || tok[0] != '-' {
			out = append(out, tok)
			continue
		}
		body := tok[1:]
		if strings.HasPrefix(body, "-") {
			body = body[1:]
		}
		name, val, hasVal := strings.Cut(body, "=")
		if name != "config" {
			out = append(out, tok)
			continue
		}
		if !hasVal {
			if i+1 >= len(argv) {
				fmt.Fprintln(os.Stderr, "全局开关 -config 缺少取值")
				os.Exit(2)
			}
			i++
			val = argv[i]
		}
		*cfg = val
	}
	return out
}
