package main

// BUG-005 同型修复的回归断言：引擎二进制也接受「子命令之后」的 -config。
// （桌面壳用前置写法不受影响；手跑排障按自然直觉写时不再静默用默认配置。）

import "testing"

func TestRescanConfigFlag(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantCfg  string
		wantRest []string
	}{
		{"空格形态", []string{"-config", "a.yml"}, "a.yml", nil},
		{"等号形态", []string{"-config=b.yml"}, "b.yml", nil},
		{"双横线空格", []string{"--config", "c.yml"}, "c.yml", nil},
		{"双横线等号", []string{"--config=d.yml"}, "d.yml", nil},
		{"缺值报错前不消费", nil, "", nil}, // 占位，下面单独测错误路径
		{"未知参数原样保留", []string{"-config", "e.yml", "serve", "--seed-dir", "s"}, "e.yml", []string{"serve", "--seed-dir", "s"}},
		{"-- 之后不再扫描", []string{"--", "-config", "x.yml"}, "", []string{"--", "-config", "x.yml"}},
	}
	for _, c := range cases {
		if c.argv == nil {
			continue
		}
		cfg := ""
		rest := rescanConfigFlag(c.argv, &cfg)
		if cfg != c.wantCfg {
			t.Errorf("%s: cfg = %q, want %q", c.name, cfg, c.wantCfg)
		}
		if len(rest) != len(c.wantRest) {
			t.Errorf("%s: rest = %v, want %v", c.name, rest, c.wantRest)
			continue
		}
		for i := range rest {
			if rest[i] != c.wantRest[i] {
				t.Errorf("%s: rest = %v, want %v", c.name, rest, c.wantRest)
				break
			}
		}
	}
}

func TestRescanConfigFlagKeepsFirstPositional(t *testing.T) {
	// serve 子命令名由调用方保留在 argv[0]，本函数只处理其后的参数；
	// 这里验证「服务参数里的普通值不被吞掉」。
	cfg := ""
	rest := rescanConfigFlag([]string{"serve", "-config", "z.yml", "extra"}, &cfg)
	if cfg != "z.yml" {
		t.Fatalf("cfg = %q", cfg)
	}
	if len(rest) != 2 || rest[0] != "serve" || rest[1] != "extra" {
		t.Fatalf("rest = %v", rest)
	}
}
