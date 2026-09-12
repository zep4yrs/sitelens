package rex

import (
	"strings"
	"testing"
	"time"
)

// must 建立用例公共入口：编译失败即测试失败。
func must(t *testing.T, expr string) *Regexp {
	t.Helper()
	re, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	return re
}

func TestLiteralsAndClasses(t *testing.T) {
	cases := []struct {
		expr, s string
		want    bool
	}{
		{`abc`, "xxabcyy", true},
		{`abc`, "ab", false},
		{`^abc$`, "abc", true},
		{`^abc$`, "xabc", false},
		{`a\.c`, "a.c", true},
		{`a\.c`, "abc", false},
		{`a.c`, "abc", true},
		{`a.c`, "a\nc", false}, // 默认点号不匹配换行
		{`(?s)a.c`, "a\nc", true},
		{`[a-z]+`, "ABC123def", true},
		{`^[a-z]+$`, "ABC", false},
		{`[^a-z]`, "abc", false},
		{`[^a-z]`, "abc1", true},
		{`[\d]{2,4}`, "a1234", true},
		{`^\D+$`, "abc", true},
		{`^\D+$`, "abc1", false},
		{`[\w.,_-]+\*`, "ab.c,d_*", true},
		{`\x41B`, "AB", true},
		{`\x{41}B`, "AB", true},
		{`[\x20-\x7e]+`, "abc def", true},
		{`a\sb`, "a\tb", true},
		{`^[\x00-\x04]\x00\x00`, "\x01\x00\x00x", true},
		{`a|b|c`, "zzb", true},
		{`^(a|b)+$`, "abab", true},
		{`^(a|b)+$`, "abc", false},
		{`(foo|bar)baz`, "xxbarbaz", true},
		{`x{3}`, "xx", false},
		{`x{3}`, "xxx", true},
		{`a{2,}b`, "aaaab", true},
		{`a{2,3}`, "aaaa", true},
		{`^a{899,1536}$`, strings.Repeat("a", 1000), true},
		{`^a{899,1536}$`, strings.Repeat("a", 100), false},
		{`a+?b`, "aaab", true},
		{`<.+?>`, "<a><b>", true},
		{`a{`, "a{", true}, // 非法 {} 按字面量
		{`\bword\b`, "a word here", true},
		{`\bword\b`, "sword", false},
		{`(?i)ABC`, "abc", true},
		{`(?i:[A-Z]+)x`, "abcX", true},
		{`(?i:ABC)x`, "ABCX", true},
		{`(?i:ABC)x`, "ABCx", true},
		{`(?i)AB(?-i)CD`, "abcd", false},
		{`(?i)AB(?-i)CD`, "abCD", true},
		{`(?m)^line$`, "x\nline\ny", true},
		{`^line$`, "x\nline\ny", false}, // 非 multiline：文本锚点
		{`\Z`, "abc", true},
		{`abc\Z`, "abc", true},
		{`[\]]`, "]", true},
		{`[a-]`, "-", true},
		{`[]a]`, "]", true}, // PCRE/RE2 规则：首位 ']' 为字面量
		{`[]a]`, "a", true},
		{`[^]]`, "a", true},
		{`[^]]`, "]", false},
		{`[][\w._ ]+`, "][ab ", true},
	}
	for _, c := range cases {
		re, err := Compile(c.expr)
		if err != nil {
			t.Errorf("Compile(%q): %v", c.expr, err)
			continue
		}
		if got := re.MatchString(c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.expr, c.s, got, c.want)
		}
	}
}

func TestLookaround(t *testing.T) {
	cases := []struct {
		expr, s string
		want    bool
	}{
		// 前向否定环视（数据主力：671 条）
		{`220-(?!FileZilla).*`, "220-Welcome", true},
		{`220-(?!FileZilla).*`, "220-FileZilla", false},
		{`foo(?!bar)`, "foobar", false},
		{`foo(?!bar)`, "foobaz", true},
		{`Version (?!9\.)`, "Version 8.1", true},
		// 前向肯定环视
		{`foo(?=bar)`, "foobar", true},
		{`foo(?=bar)`, "foobaz", false},
		{`\d+(?=px)`, "12px", true},
		// 后向环视（数据中 2 条）
		{`(?<=.)IOS`, "CIOS", true},
		{`(?<=.)IOS`, "IOS", false},
		{`(?<=ab)c`, "abc", true},
		{`(?<!a)b`, "cb", true},
		{`(?<!a)b`, "ab", false},
	}
	for _, c := range cases {
		re := must(t, c.expr)
		if got := re.MatchString(c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.expr, c.s, got, c.want)
		}
	}
}

func TestBackref(t *testing.T) {
	re := must(t, `(..)\x00\x00\1`)
	if !re.MatchString("AB\x00\x00AB\n") {
		t.Fatalf("backref 基本匹配失败")
	}
	if re.MatchString("AB\x00\x00XY") {
		t.Fatalf("backref 不应匹配不同内容")
	}
	re2 := must(t, `(\w+) \1`)
	if !re2.MatchString("hello hello") {
		t.Fatalf("词重复 backref 失败")
	}
	if re2.MatchString("hello world") {
		t.Fatalf("词重复 backref 误报")
	}
	// 未参与匹配的组按空串
	re3 := must(t, `(x)?y\1z`)
	if !re3.MatchString("yz") {
		t.Fatalf("未捕获组 backref 应按空串")
	}
	// 大小写折叠
	re4 := must(t, `(?i)(ab)\1`)
	if !re4.MatchString("abAB") {
		t.Fatalf("fold backref 失败")
	}
	// 前向引用拒绝
	if _, err := Compile(`\1(x)`); err == nil {
		t.Fatalf("前向引用应报错")
	}
}

func TestSubmatch(t *testing.T) {
	re := must(t, `SSH-([\d.]+)-OpenSSH`)
	m := re.FindStringSubmatch("SSH-2.0-OpenSSH_8.9")
	if m == nil || m[1] != "2.0" {
		t.Fatalf("submatch = %v, want [SSH-2.0 2.0]", m)
	}
	re2 := must(t, `(a)(b)?c`)
	m2 := re2.FindStringSubmatch("ac")
	if m2 == nil || m2[1] != "a" || m2[2] != "" {
		t.Fatalf("未参与组应为空串: %v", m2)
	}
	if got := must(t, `\d+`).FindString("ab123cd"); got != "123" {
		t.Fatalf("FindString = %q", got)
	}
	// 左最先
	if got := must(t, `a`).FindString("xxaxa"); got != "a" {
		t.Fatalf("左最先失败")
	}
}

func TestBudgetBounded(t *testing.T) {
	// 灾难性回溯形态：预算内必须有界退出，不挂死
	re := must(t, `(a+)+b`)
	re.Budget = 100000
	done := make(chan bool, 1)
	go func() {
		start := time.Now()
		ok := re.MatchString(strings.Repeat("a", 60) + "X")
		if ok {
			t.Error("不应匹配")
		}
		done <- time.Since(start) < 5*time.Second
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("预算未能有界退出")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("灾难性回溯未受预算约束")
	}
	if !reMatchExhausted(re, strings.Repeat("a", 60)+"X") {
		t.Fatal("预算耗尽应置 exhausted 标记")
	}
}

func reMatchExhausted(re *Regexp, s string) bool {
	m := &matcher{s: s, budget: re.Budget}
	m.caps = make([]int, 2*(re.ncap+1))
	for i := range m.caps {
		m.caps[i] = -1
	}
	m.match(re.root, 0, func(int) bool { return true })
	return m.exhausted
}

func TestEmptyLoopTerminates(t *testing.T) {
	cases := []struct {
		expr, s string
		want    bool
	}{
		{`(a|)*b`, "aaab", true},
		{`(a|)*b`, "b", true},
		{`(a?)*b`, "aaab", true},
		{`(?:x?){3}y`, "y", true},
		{`(a|){4,}`, "", true},   // 空迭代补足下限
		{`(a|){4,}`, "a", true},  // 一次实迭代+空迭代
		{`(a|){4,}b`, "b", true}, // 空迭代补足下限后收口
		{`(|a)*b`, "b", true},
		{`(|a)*b`, "aab", true},
	}
	for _, c := range cases {
		re := must(t, c.expr)
		re.Budget = 50000
		if got := re.MatchString(c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.expr, c.s, got, c.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		`(`,           // 未闭合组
		`)`,           // 多余右括号
		`[`,           // 未闭合类
		`[]`,          // 空类
		`a**`,         // 嵌套量词
		`a*+`,         // 占有量词
		`(?>a)b`,      // 原子组
		`(?P<n>a)`,    // 命名组
		`(?!`,         // 未闭合环视
		`a\q`,         // 未知转义
		`\x4`,         // 半个十六进制
		`[\d-z]`,      // 类别缩写作范围端点
		`[[:alpha:]]`, // POSIX 类
		`a{200000}`,   // 超上界
		`a{3,2}`,      // 逆序
		`*a`,          // 量词缺原子
	}
	for _, expr := range bad {
		if _, err := Compile(expr); err == nil {
			t.Errorf("Compile(%q) 应报错", expr)
		}
	}
}

// TestRE2Agreement 抽样比对：RE2 可编译的服务指纹模式在 rex 与标准库
// 下结论一致（基座语法语义对齐的规模化验证）。
func TestRE2Agreement(t *testing.T) {
	rows := loadDumpPatterns(t)
	if len(rows) == 0 {
		t.Fatal("dump 数据为空")
	}
	// 隔 50 取 1 抽样，覆盖全库且测试耗时可控
	corpus := []string{
		"220 Welcome to FileZilla Server 1.2.3\r\n220 ready",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
		"+OK Dovecot ready.",
		"Microsoft Windows [Version 10.0.19045.3086]",
		"530 Please login with USER and PASS.",
		"\x00\x00\x00\x04\x00\x00ABCD\x00\x00",
		"GET / HTTP/1.0\r\n\r\n",
		"abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"",
	}
	sampled := 0
	for i, p := range rows {
		if i%50 != 0 || p == "" {
			continue
		}
		re2, err := compileStd(p)
		if err != nil {
			continue // RE2 拒收的由环视/反向引用专项与 golden 向量覆盖
		}
		rx, err := Compile(p)
		if err != nil {
			t.Errorf("RE2 可编译模式 rex 失败: %q: %v", p, err)
			continue
		}
		sampled++
		for _, s := range corpus {
			want := re2.FindStringSubmatch(s)
			got := rx.FindStringSubmatch(s)
			if !sameSubmatch(want, got) {
				t.Errorf("不一致 %q on %q:\n  re2 = %q\n  rex = %q", p, s, want, got)
			}
		}
	}
	t.Logf("RE2 一致性抽样 %d 条模式", sampled)
	if sampled < 100 {
		t.Fatalf("抽样过少: %d", sampled)
	}
}

func sameSubmatch(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
