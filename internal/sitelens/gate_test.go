package sitelens

// 正则「必含字面量」门控（gate.go）的单元 + 健全性回归：
// 门控只允许「证明正则不可能命中」时跳过；任何跳过都必须经得起
// 「跳过 ⇒ 正则实际不匹配」的直接校验（宁可不跳，不可误跳）。

import (
	"regexp"
	"strings"
	"testing"
)

func TestGateNodeMiss(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		present []string
		want    bool
	}{
		// 纯字面量：不在正文 ⇒ 必不命中
		{"literal-miss", `wordpress`, nil, true},
		{"literal-hit", `wordpress`, []string{"wordpress"}, false},
		// 必含多个字面量（AND）：任一缺席即不可能命中
		{"and-miss", `foo.*?bar`, []string{"foo"}, true},
		{"and-hit", `foo.*?bar`, []string{"foo", "bar"}, false},
		// 交替（OR）：每个分支都要有必含字面量；全部分支缺席才可跳
		{"or-miss", `(?:alpha|beta)`, nil, true},
		{"or-one-present", `(?:alpha|beta)`, []string{"beta"}, false},
		// 可选/星号不构成必含条件
		{"optional-only", `(?:alpha)?beta`, nil, true},
		{"optional-hit", `(?:alpha)?beta`, []string{"beta"}, false},
		{"star-no-gate", `(?:alpha)*`, nil, false}, // 推不出条件 ⇒ 永不跳
		// 有分支推不出条件 ⇒ 整体不设门（保守）
		{"alternate-weak-branch", `(?:alpha|.{2})`, nil, false},
		// 转义字符类不能被当字面量（旧 literalGate 的 \s 陷阱）
		{"escaped-class", `WordPress\s*([\d.]+)?`, []string{"wordpress"}, false},
		{"escaped-class-miss", `WordPress\s*([\d.]+)?`, nil, true},
		// 非 ASCII 字面量不设门（大小写折叠轨道特例）
		{"non-ascii", `™`, nil, false},
		{"mixed-ascii", `Forum software by XenForo™`, []string{"forum software by xenforo"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tn := buildGateNode(c.raw)
			present := func(lit string) bool {
				for _, p := range c.present {
					if p == lit {
						return true
					}
				}
				return false
			}
			if got := tn.miss(present); got != c.want {
				t.Fatalf("gateNode(%q).miss = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

// TestGateNodeNilNeverSkips 推不出条件的模式必须永不跳过（保守语义）。
func TestGateNodeNilNeverSkips(t *testing.T) {
	for _, raw := range []string{`.`, `.*`, `[a-z]+`, `^$`, `.*?`} {
		if n := buildGateNode(raw); n != nil {
			t.Fatalf("%q 应推不出必含条件，实际得到 %+v", raw, n)
		}
	}
	// present == nil（无预筛信息）时永不跳过
	pat := pattern{re: mustRegexp(t, `alpha.*beta`), gateTree: buildGateNode(`alpha.*beta`)}
	if pat.gateMiss(nil) {
		t.Fatal("present==nil 时不应跳过")
	}
}

func mustRegexp(t *testing.T, raw string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile("(?i)" + raw)
	if err != nil {
		t.Fatalf("regexp.Compile(%q): %v", raw, err)
	}
	return re
}

// TestGateTreeSoundnessOnCorpus 门控健全性直接校验：
// 对库里每条挂了条件树的正则 × 语料里的每段待匹配文本（正文 + meta 内容），
// 若条件树判定「确定不成立」，则正则必须确实不命中。
func TestGateTreeSoundnessOnCorpus(t *testing.T) {
	techs := loadTestTechs(t)
	pats := libraryGateTreePatterns(techs)
	if len(pats) == 0 {
		t.Skip("库里没有带门控条件树的正则")
	}
	inputs := corpusInputs(t)
	for name, list := range inputs {
		for _, input := range list {
			low := strings.ToLower(input)
			present := func(lit string) bool { return strings.Contains(low, lit) }
			for _, p := range pats {
				if !p.gateTree.miss(present) {
					continue
				}
				if p.re.MatchString(input) {
					t.Fatalf("%s: 门控误跳——正则 %q 实际命中输入 %.120q", name, p.raw, input)
				}
			}
		}
	}
}

// TestGateTreeSoundnessSyntheticEdges 针对边界形状（空串/超短/纯大写/无字面量）
// 再校验一遍健全性。
func TestGateTreeSoundnessSyntheticEdges(t *testing.T) {
	techs := loadTestTechs(t)
	pats := libraryGateTreePatterns(techs)
	inputs := []string{"", "a", "ab", "ABC", "<html></html>", "wordpress 6.4", "WORDPRESS 6.4.2",
		"powered by pelican", "Powered By Pelican", "<!--XF:branding-->", "<a href='x'>hi</a>"}
	for _, input := range inputs {
		low := strings.ToLower(input)
		present := func(lit string) bool { return strings.Contains(low, lit) }
		for _, p := range pats {
			if p.gateTree.miss(present) && p.re.MatchString(input) {
				t.Fatalf("门控误跳——正则 %q 实际命中输入 %q", p.raw, input)
			}
		}
	}
}
