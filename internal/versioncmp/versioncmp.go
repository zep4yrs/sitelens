// Package versioncmp 版本比较与区间判定（移植自 scanner/version_cmp.py）。
//
// 区间语法：
//
//	">=8.3,<8.3.7"  多条件逗号分隔，全部满足才命中
//	"<=2.4.1" / ">1.0" / "=3.2" / "!=1.9"
//	"*"             任意版本
package versioncmp

import (
	"math"
	"regexp"
	"strings"
)

// Parse 版本字符串 → 数字三元组（每段取前导数字，忽略非数字后缀）。
func Parse(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	for i, seg := range strings.Split(v, ".") {
		if i >= 3 {
			break
		}
		out[i] = parseSeg(seg)
	}
	return out
}

func parseSeg(seg string) int {
	digits := ""
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c < '0' || c > '9' {
			break
		}
		digits += string(c)
	}
	if digits == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(digits); i++ {
		n = n*10 + int(digits[i]-'0')
	}
	return n
}

// Cmp a<b 返回 -1，相等 0，a>b 返回 1（逐段比较，与 Python 元组比较一致）。
func Cmp(a, b string) int {
	pa, pb := Parse(a), Parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

// VersionIn version 是否命中 affected 区间串；空区间 = 不判定（false）。
func VersionIn(version, affected string) bool {
	if version == "" || affected == "" {
		return false
	}
	if strings.TrimSpace(affected) == "*" {
		return true
	}
	version = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	for _, cond := range strings.Split(affected, ",") {
		cond = strings.TrimSpace(cond)
		if cond == "" || cond == "*" {
			continue
		}
		op, val := "=", cond
		for _, cand := range []string{">=", "<=", "!=", ">", "<", "="} {
			if strings.HasPrefix(cond, cand) {
				op, val = cand, strings.TrimPrefix(cond, cand)
				break
			}
		}
		c := Cmp(version, val)
		ok := map[string]bool{
			"=": c == 0, "!=": c != 0, ">=": c >= 0,
			"<=": c <= 0, ">": c > 0, "<": c < 0,
		}[op]
		if !ok {
			return false
		}
	}
	return true
}

var yearRe = regexp.MustCompile(`^(19|20)\d{2}$`)

// ExtractVersion 从包含 keyword 的文本行提取版本号（首个可信版本或空）。
// 纯 4 位年份（如 2026）视为行号/日期误判跳过。
func ExtractVersion(text, keyword string) string {
	if text == "" || keyword == "" {
		return ""
	}
	kw := strings.ToLower(keyword)
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(strings.ToLower(line), kw) {
			continue
		}
		for _, loc := range verRe.FindAllStringIndex(line, -1) {
			v := line[loc[0]:loc[1]]
			pre := strings.SplitN(strings.SplitN(v, "+", 2)[0], "-", 2)[0]
			head := strings.Split(pre, ".")[0]
			// 纯年份（2026）与无点长数字（20260401/工单号）都是误判样式
			if yearRe.MatchString(head) && !strings.Contains(pre, ".") {
				continue
			}
			if !strings.Contains(pre, ".") && len(pre) > 5 {
				continue
			}
			return v
		}
	}
	return ""
}

var verRe = regexp.MustCompile(`\d{1,5}(?:\.\d{1,5}){1,3}`)

// Round1 CVSS 类分数的一位小数舍入（ Go math.Round 即银行家舍入之外的常规四舍五入）。
func Round1(f float64) float64 {
	return math.Round(f*10) / 10
}
