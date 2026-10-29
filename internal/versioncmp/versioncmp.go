// Package versioncmp 版本比较与区间判定（移植自 scanner/version_cmp.py）。
//
// 区间语法：
//
//	">=8.3,<8.3.7"  多条件逗号分隔，全部满足才命中
//	"<=2.4.1" / ">1.0" / "=3.2" / "!=1.9"
//	"*"             任意版本
package versioncmp

import (
	"regexp"
	"strings"
)

// Parse 版本字符串 → 数字段切片（每段取前导数字，忽略非数字后缀）。
//
// 段数不设上限（BUG-007）：Windows 补丁号 10.0.19041.1234、Java/Oracle
// 方案号等是 4 段版本，旧实现只取前 3 段会把「4 段补丁号」与「3 段基版本」
// 判为相等，进而把不在受影响区间的目标误报成 confirmed。
func Parse(v string) []int {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	segs := strings.Split(v, ".")
	out := make([]int, len(segs))
	for i, seg := range segs {
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

// Cmp a<b 返回 -1，相等 0，a>b 返回 1（逐段比较，与 Python 元组比较一致：
// 公共前缀相等时短者为小，即 4.17.3.0 > 4.17.3、1.2.3.4 > 1.2.3）。
//
// 不做零补齐——这是 BUG-007 验收表的直接要求（docs/bug清单-5.1.0.md
// BUG-007）：`1.2.3.4 <=1.2.3`、`10.0.19041.1234 <=10.0.19041`、
// `4.17.3.0 <=4.17.3` 期望均 false（不误报 confirmed）；若改成零补齐，
// 4.17.3.0 会与 4.17.3 判等 → `<=` 成立 → 与验收表相反。前缀语义下
// 多出的段一律视为「更晚」，宁可漏报受影响（少报）也不误报 confirmed。
func Cmp(a, b string) int {
	pa, pb := Parse(a), Parse(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// VersionIn version 是否命中 affected 区间串；空区间 = 不判定（false）。
// versionLike 判断区间值是否为可比较的版本号形态：每个点分段必须是
// 纯数字。commit hash（如 14c49408…）会被 parseSeg 取前导数字误判成
// 小版本号，造成虚假 confirmed——这类值直接判不可比（宁少报）。
func versionLike(val string) bool {
	if val == "" {
		return false
	}
	for _, seg := range strings.Split(val, ".") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

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
		if !versionLike(val) {
			return false // hash/非版本段：不可比即不命中（宁少报）
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

// 注：CVSS 分数的一位小数取整按 CVSS 3.1 规范是 Roundup（向上取整），
// 实现见 intel.roundup1（internal/intel/cvss.go）。本包曾导出一个用
// math.Round 的 Round1（语义错误且全仓无调用方），BUG-026 已删除；
// 需要 CVSS 取整的消费方请走 intel 的规范实现，勿在本包重新引入。
