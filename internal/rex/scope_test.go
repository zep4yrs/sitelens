package rex

// 分组 flag 作用域回归（C2-07）。
//
// PCRE/RE2 语义：(?i:abc) 的 i 只作用到组内，(?-i:…) 同理；组外必须回到
// 进入组前的现场。旧实现把现场快照放在 parseGroupBody（flag 已被
// parseFlags 改写之后），于是 (?i:abc) 等价于 (?i)，会把后续模式也变成
// 大小写不敏感——服务指纹里"分组 flag + 环视"的回退模式会因此误识别产品。
//
// 注意：rex 只在 RE2 编译失败时启用，所以用例特意带环视，让标准库拒收。

import (
	"regexp"
	"testing"
)

func TestScopedFlagDoesNotLeak(t *testing.T) {
	cases := []struct {
		expr string
		s    string
		want bool
		why  string
	}{
		// (?i:abc) 只让 abc 忽略大小写，后面的 def 仍区分大小写。
		{`(?i:abc)(?=def)`, "ABCdef", true, "组内 i 生效"},
		{`(?i:abc)(?=def)`, "ABCDEF", false, "组内 i 不得外泄到 def"},
		{`(?i:abc)def`, "ABCDEF", false, "非捕获位置的等价语义（无环视，标准库可编译）"},
		// 反向：组内显式关闭大小写（外层 i 保留在组外）
		{`(?i)(?-i:ABC)def`, "ABCdef", true, "组内 -i 生效，组外 i 恢复"},
		{`(?i)(?-i:ABC)def`, "abcDEF", false, "组内 -i 使 ABC 必须精确匹配"},
		// s 标志同理：组内 . 匹配换行，组外仍不匹配。
		{`(?s:a.c)(?=d)`, "a\ncd", true, "组内 s 生效"},
		{`(?s:a.c)(?=d)...`, "a\ncd\nx", false, "组外 . 不得匹配换行"},
	}
	for _, c := range cases {
		// 带环视的用例标准库会拒收，用 rex；其余仅作语义对照。
		rx, err := Compile(c.expr)
		if err != nil {
			t.Fatalf("Compile(%q): %v", c.expr, err)
		}
		if got := rx.MatchString(c.s); got != c.want {
			t.Errorf("%q vs %q = %v，期望 %v（%s）", c.expr, c.s, got, c.want, c.why)
		}
	}
}

// TestScopedFlagParityWithRE2 对标准库可编译的子集做对拍，保证修复后与
// RE2/PCRE 语义一致（不是"只让自家用例通过"）。
func TestScopedFlagParityWithRE2(t *testing.T) {
	exprs := []string{
		`(?i:abc)def`,
		`(?i:abc)(?-i:DEF)ghi`,
		`x(?i:yz)W`,
		`(?s:a.b)c.d`,
		`(?m:^a$)\nb`,
	}
	inputs := []string{
		"ABCdef", "ABCDEF", "abcdef", "abcDEFghi", "abcDEFGHI",
		"xyzW", "xyZW", "a\nbc.d", "a\nbc\nd",
	}
	for _, expr := range exprs {
		std, err := regexp.Compile(expr)
		if err != nil {
			t.Fatalf("标准库拒绝 %q: %v", expr, err)
		}
		rx, err := Compile(expr)
		if err != nil {
			t.Fatalf("rex 拒绝 %q: %v", expr, err)
		}
		for _, s := range inputs {
			if want, got := std.MatchString(s), rx.MatchString(s); want != got {
				t.Errorf("%q vs %q: rex=%v RE2=%v", expr, s, got, want)
			}
		}
	}
}
