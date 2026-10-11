package portpolicy

import "testing"

func TestValid(t *testing.T) {
	for _, p := range []int{1, 80, 5087, 65535} {
		if !Valid(p) {
			t.Errorf("Valid(%d) = false, 期望 true", p)
		}
	}
	for _, p := range []int{0, -1, 65536, 99999} {
		if Valid(p) {
			t.Errorf("Valid(%d) = true, 期望 false", p)
		}
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		pref, conf int
		want       int
		src        string
	}{
		{5087, 8080, 5087, "shell"}, // 壳偏好优先
		{0, 8080, 8080, "config"},   // 偏好无效 → 配置原文
		{0, 0, DefaultFallback, "default"},
		{-1, 0, DefaultFallback, "default"},
		{70000, 0, DefaultFallback, "default"}, // 非法偏好被遮蔽
	}
	for _, c := range cases {
		got, src := Resolve(c.pref, c.conf)
		if got != c.want || src != c.src {
			t.Errorf("Resolve(%d,%d) = (%d,%q)，期望 (%d,%q)", c.pref, c.conf, got, src, c.want, c.src)
		}
	}
}

func TestDescribe(t *testing.T) {
	if Describe("shell") != "壳偏好" || Describe("config") != "配置原文" || Describe("default") != "默认" {
		t.Fatal("来源文案不符")
	}
}

func TestParseConfListenPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"裸端口", "web:\n  listen: 127.0.0.1:5087\n", 5087},
		{"带引号值", "web:\n  listen: \"127.0.0.1:8080\"\n", 8080},
		{"纯端口值", "web:\n  listen: 9090\n", 9090},
		{"段内其他键夹杂", "web:\n  addr: x\n  listen: 127.0.0.1:6000\n", 6000},
		{"web 段在中间", "scan:\n  x: 1\nweb:\n  listen: 127.0.0.1:7777\nchecks:\n  y: 2\n", 7777},
		{"无 web 段", "scan:\n  listen: 127.0.0.1:5087\n", 0},
		{"注释行忽略", "web:\n  # listen: 127.0.0.1:1234\n  listen: 127.0.0.1:5087\n", 5087},
		{"空文本", "", 0},
		{"非法端口", "web:\n  listen: 127.0.0.1:abc\n", 0},
		{"越界端口", "web:\n  listen: 127.0.0.1:70000\n", 0},
	}
	for _, c := range cases {
		if got := ParseConfListenPort(c.in); got != c.want {
			t.Errorf("%s: ParseConfListenPort = %d，期望 %d", c.name, got, c.want)
		}
	}
}
