// html 字面量模式的全局前缀桶预筛：正文单遍扫描即得「哪些字面量出现」，
// 替代逐技术逐模式 Contains（万级指纹库的数量级优化，bench 固化）。
package sitelens

import "strings"

// litPrescreen 字面量预筛索引。
type litPrescreen struct {
	buckets map[uint32][]string // 4 字节前缀哈希 → 小写字面量
	shorts  []string            // <4 字节的短字面量（退化为直接 Contains）
}

// fnv4 前 4 字节的 FNV-1a（桶键）。
func fnv4(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// buildLitPrescreen 从全部技术的 html 字面量模式建索引。
func buildLitPrescreen(techs []*compiledTech) *litPrescreen {
	ps := &litPrescreen{buckets: map[uint32][]string{}}
	seen := map[string]bool{}
	add := func(lit string) {
		if seen[lit] {
			return
		}
		seen[lit] = true
		if len(lit) < 4 {
			ps.shorts = append(ps.shorts, lit)
			return
		}
		h := fnv4(lit[:4])
		ps.buckets[h] = append(ps.buckets[h], lit)
	}
	for _, ct := range techs {
		for _, p := range ct.html {
			if p.isLit {
				add(p.lit)
			}
		}
	}
	return ps
}

// scan 单遍扫描小写正文，返回出现过的字面量集合。
func (ps *litPrescreen) scan(sLow string) map[string]bool {
	hits := map[string]bool{}
	n := len(sLow)
	for i := 0; i+4 <= n; i++ {
		for _, lit := range ps.buckets[fnv4(sLow[i:i+4])] {
			if !hits[lit] && len(lit) <= n-i && sLow[i:i+len(lit)] == lit {
				hits[lit] = true
			}
		}
	}
	for _, lit := range ps.shorts {
		if strings.Contains(sLow, lit) {
			hits[lit] = true
		}
	}
	return hits
}
