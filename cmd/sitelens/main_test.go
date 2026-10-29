package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

// TestRescanGlobalFlags BUG-005 回归：子命令之后的全局开关必须被识别并
// 从位置参数里剔除；未知参数（子命令自有 flag / TUI 直通参数）原样保留。
func TestRescanGlobalFlags(t *testing.T) {
	def := globalFlags{Config: ".sitelens.yml", Env: ".env"}
	cases := []struct {
		name  string
		argv  []string
		want  []string
		wantG globalFlags
	}{
		{
			name:  "serve 后跟 -config（空格形态）",
			argv:  []string{"-config", "prod.yml"},
			want:  []string{},
			wantG: globalFlags{Config: "prod.yml", Env: ".env"},
		},
		{
			name:  "scan 目标后跟 -config（等号形态）",
			argv:  []string{"http://127.0.0.1:5000", "-config=prod.yml"},
			want:  []string{"http://127.0.0.1:5000"},
			wantG: globalFlags{Config: "prod.yml", Env: ".env"},
		},
		{
			name:  "双横线 + 多个布尔开关",
			argv:  []string{"--graph", "--ast", "-config", "x.yml", "http://t"},
			want:  []string{"http://t"},
			wantG: globalFlags{Config: "x.yml", Env: ".env", Graph: true, AST: true},
		},
		{
			name:  "显式关掉布尔开关（-graph=false）",
			argv:  []string{"-graph=false", "-config", "y.yml"},
			want:  []string{},
			wantG: globalFlags{Config: "y.yml", Env: ".env"},
		},
		{
			name:  "-env 也可后置（migrate-pg）",
			argv:  []string{"-env=.env.prod", "https://x"},
			want:  []string{"https://x"},
			wantG: globalFlags{Config: ".sitelens.yml", Env: ".env.prod"},
		},
		{
			name:  "未知参数原样保留（update-seed / graph-read 自有 flag）",
			argv:  []string{"--seed-dir", "seed", "--user-dir", "user", "--self-test"},
			want:  []string{"--seed-dir", "seed", "--user-dir", "user", "--self-test"},
			wantG: def,
		},
		{
			name:  "位置参数顺序不变",
			argv:  []string{"feed", "2018", "2024", "-config", "z.yml"},
			want:  []string{"feed", "2018", "2024"},
			wantG: globalFlags{Config: "z.yml", Env: ".env"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := def
			got, err := rescanGlobalFlags(c.argv, &g)
			if err != nil {
				t.Fatalf("rescanGlobalFlags: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("剩余参数 = %v，期望 %v", got, c.want)
			}
			if g != c.wantG {
				t.Errorf("全局开关 = %+v，期望 %+v", g, c.wantG)
			}
		})
	}

	// 错误形态：缺值 / 布尔取值非法 —— 不能静默吞掉
	for _, argv := range [][]string{{"-config"}, {"-env"}, {"-graph=notabool"}} {
		g := def
		if _, err := rescanGlobalFlags(argv, &g); err == nil {
			t.Errorf("%v 应报错", argv)
		}
	}
}

// parseGlobalArgs 复刻 main 的解析顺序（前置 flag.Parse + 子命令后补扫），
// 返回（子命令，位置参数，全局开关取值）供前置/后置写法等价性断言。
func parseGlobalArgs(t *testing.T, argv []string) (string, []string, globalFlags) {
	t.Helper()
	var g globalFlags
	fs := flag.NewFlagSet("sitelens-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bindGlobalFlags(fs, &g)
	if err := fs.Parse(argv); err != nil {
		t.Fatalf("前置解析失败 %v: %v", argv, err)
	}
	args := fs.Args()
	if len(args) < 1 {
		t.Fatalf("%v 缺子命令", argv)
	}
	rest, err := rescanGlobalFlags(args[1:], &g)
	if err != nil {
		t.Fatalf("补扫失败 %v: %v", argv, err)
	}
	return args[0], rest, g
}

// TestGlobalFlagPrefixSuffixEquivalent BUG-005 验收：全局开关写在子命令前
// 与写在子命令后，必须得到**相同**的配置路径/开关状态与相同的位置参数。
func TestGlobalFlagPrefixSuffixEquivalent(t *testing.T) {
	pairs := [][2][]string{
		{ // serve：BUG 报告里的原样
			{"-config", "prod.yml", "serve"},
			{"serve", "-config", "prod.yml"},
		},
		{ // scan + 开关组合
			{"-config", "prod.yml", "-graph", "-ast", "scan", "http://target"},
			{"scan", "http://target", "-config", "prod.yml", "-graph", "-ast"},
		},
		{ // 等号形态 + -- 前缀
			{"--config=prod.yml", "--graph=true", "scan", "http://a", "http://b"},
			{"scan", "http://a", "http://b", "--config=prod.yml", "--graph=true"},
		},
		{ // -env 后置（migrate-pg 的 .env 来源）
			{"-env", ".env.prod", "migrate-pg"},
			{"migrate-pg", "-env", ".env.prod"},
		},
		{ // update-nvd feed 参数与全局开关混排
			{"-config", "prod.yml", "update-nvd", "feed", "2018", "2024"},
			{"update-nvd", "feed", "2018", "2024", "-config", "prod.yml"},
		},
	}
	for i, p := range pairs {
		cmdA, argsA, gA := parseGlobalArgs(t, p[0])
		cmdB, argsB, gB := parseGlobalArgs(t, p[1])
		if cmdA != cmdB {
			t.Errorf("#%d 子命令不一致: %q vs %q", i, cmdA, cmdB)
			continue
		}
		if gA != gB {
			t.Errorf("#%d 全局开关不一致（前置 %+v / 后置 %+v）", i, gA, gB)
		}
		if !reflect.DeepEqual(argsA, argsB) {
			t.Errorf("#%d 位置参数不一致: %v vs %v", i, argsA, argsB)
		}
	}

	// 具体值断言：serve -config prod.yml 必须真的拿到 prod.yml
	cmd, rest, g := parseGlobalArgs(t, []string{"serve", "-config", "prod.yml"})
	if cmd != "serve" || g.Config != "prod.yml" || len(rest) != 0 {
		t.Fatalf("serve -config prod.yml 解析错位: cmd=%q cfg=%q rest=%v", cmd, g.Config, rest)
	}
}
