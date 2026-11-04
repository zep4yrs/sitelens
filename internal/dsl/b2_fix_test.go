package dsl

import "testing"

// ---- B2-07 compare_versions ----

// TestCompareVersionsNotEqual B2-07 回归。
//
// 旧实现的两个缺陷（此处断言的是**修复后**的直觉语义）：
//  1. `!=` 在运算符白名单里，却只参与"相等即返回 true"的 default 分支 →
//     相等时返回 true、不等时返回 false，**两个方向都反**；
//  2. 约束前缀 `=` 未被识别（只识别 <=、>=、==、!=、<、>），`=1.0` 会被当成
//     版本串 "=1.0" 去 ParseInt → 静默归零 → 恒不相等。
//
// 因此本用例同时覆盖"`!=` 方向"与"`=` 前缀"两处；若实现回退到旧语义，
// 第 13/14 行会先失败。不要为了修绿而放宽断言。
func TestCompareVersionsNotEqual(t *testing.T) {
	cases := []struct {
		version, constraint string
		want                bool
	}{
		{"1.0", "!=1.0", false}, // 相等 → != 不成立（旧实现返回 true）
		{"2.0", "!=1.0", true},  // 不等 → != 成立（旧实现返回 false）
		{"1.0", "!=2.0", true},
		{"1.0", "==1.0", true},
		{"1.0", "1.0", true},
		{"1.0", "=1.0", true}, // 显式 `=` 前缀（旧实现把 "=1.0" 当版本串 → false）
		{"1.0", ">1.0", false},
		{"1.1", ">1.0", true},
		{"1.0", ">=1.0", true},
		{"1.0", "<=1.0", true},
		{"0.9", "<1.0", true},
	}
	for _, c := range cases {
		if got := compareVersions(c.version, c.constraint); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %v, want %v", c.version, c.constraint, got, c.want)
		}
	}
}

// TestCompareVersionsPrerelease B2-07 回归：非数字段不再静默归零——
// `1.0.0-beta` 此前被判等于 `1.0.0`。
func TestCompareVersionsPrerelease(t *testing.T) {
	if compareVersions("1.0.0-beta", "1.0.0") {
		t.Error("1.0.0-beta 不应等于 1.0.0")
	}
	if !compareVersions("1.0.0-beta", "<1.0.0") {
		t.Error("1.0.0-beta 应小于 1.0.0（semver：预发布 < 正式版）")
	}
	// 完全无法解析的版本：不可比 → 一律 false（不臆造结论）
	if compareVersions("abc", "abc") {
		t.Error("非数字版本应判为不可比（false）")
	}
	if compareVersions("1.x", ">=1.0") {
		t.Error("含非数字段的版本应判为不可比（false）")
	}
}

// ---- B2-12 整数字面量溢出 ----

func TestCompileIntegerOverflow(t *testing.T) {
	if _, err := Compile("status_code == 99999999999999999999"); err == nil {
		t.Fatal("超 int64 的整数字面量应编译失败（不得静默回绕）")
	}
	if _, err := Compile("status_code == 9223372036854775807"); err != nil {
		t.Fatalf("int64 上界应可解析: %v", err)
	}
}

// ---- B2-09 regex 首参限制 ----

func TestCompileRegexRequiresLiteral(t *testing.T) {
	if _, err := CompileWithVars("regex(ver, body)", []string{"ver"}); err == nil {
		t.Fatal("regex 第一个参数不是字面量时应编译失败（不接受响应内容作为正则源）")
	}
	if _, err := Compile(`regex('(\d+)', body)`); err != nil {
		t.Fatalf("字面量正则应可编译: %v", err)
	}
	long := make([]byte, maxRegexPatternLen+1)
	for i := range long {
		long[i] = 'a'
	}
	expr := `regex('` + string(long) + `', body)`
	if _, err := Compile(expr); err == nil {
		t.Fatal("超长正则模式应编译失败")
	}
}

// ---- B2-13 字符串转义 ----

// TestStringEscapeUnknownKeepsBackslash B2-13 回归：未知转义保留反斜杠，
// `'(\d+)'` 不得被吃成 `'(d+)'`。
func TestStringEscapeUnknownKeepsBackslash(t *testing.T) {
	p, err := Compile(`regex('^v(\d+)\.(\d+)$', body)`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	ok, err := p.Eval(testEnv{body: "v1.2"})
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if !ok {
		t.Fatal(`regex('^v(\d+)\.(\d+)$', body) 应命中 "v1.2"（反斜杠被吃掉会导致不命中）`)
	}
	if ok, _ := p.Eval(testEnv{body: "vdd.dd"}); ok {
		t.Fatal(`'(\d+)' 被吃成 '(d+)' 时 "vdd.dd" 会误命中`)
	}
}

// TestStringEscapeKnown B2-13：已知转义按 Go 语义解码。
func TestStringEscapeKnown(t *testing.T) {
	p, err := Compile(`contains(body, 'a\nb')`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, _ := p.Eval(testEnv{body: "a\nb"}); !ok {
		t.Fatal(`'a\nb' 应解码为换行并命中 "a\nb"`)
	}
	p2, err := Compile(`contains(body, 'a\tb')`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, _ := p2.Eval(testEnv{body: "a\tb"}); !ok {
		t.Fatal(`'a\tb' 应解码为制表符并命中 "a\tb"`)
	}
}
