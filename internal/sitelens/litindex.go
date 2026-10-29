// html 字面量模式的全局前缀桶预筛：正文单遍扫描即得「哪些字面量出现」，
// 替代逐技术逐模式 Contains（万级指纹库的数量级优化，bench 固化）。
package sitelens

import "strings"

// litEntry 预筛条目：正文中出现过的字面量。
// isGate=true 表示这是正则的「必然包含字面量」门控（结果只进 gateHits）。
type litEntry struct {
	lit    string
	isGate bool
}

// litPrescreen 字面量预筛索引。
//
// 结构：滚动 4 字节小写前缀 → 开放寻址哈希表（每槽打包 key+桶号）→ 桶内条目。
// 每个字节位置的常规成本只有「一次乘法/移位 + 一次数组访问」，命中桶才做子串
// 比较；相比旧的「每位置算 fnv4 + map 查桶」，省掉 4 万次/页的 Go map 查找。
type litPrescreen struct {
	tab     []uint64 // 槽：高 32 位 = 4 字节小写 key（0 = 空槽），低 32 位 = 桶号+1
	mask    uint32
	shift   uint32
	buckets []litBucket
	shorts  []litEntry // <4 字节条目（无法用 4 字节前缀索引）：退化为 Contains
	zeros   []litEntry // 4 字节 key 恰为 0 的极端条目（同上）
}

// litBucket 同一 4 字节前缀下的条目（绝大多数只有 1 条）。
type litBucket struct{ entries []litEntry }

// litKey4 小写字面量前 4 字节（小端打包）作桶键。
func litKey4(s string) uint32 {
	return uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24
}

// litHash 4 字节 key → 槽号的乘法散列（Fibonacci hashing，取高位）。
func litHash(k, shift uint32) uint32 { return (k * 0x9E3779B1) >> shift }

// buildLitPrescreen 从全部技术建索引：
//   - html 字面量模式（scan 返回 litHits，命中集合与旧实现逐字面量 Contains 一致）；
//   - html/inline 正则的门控字面量（scan 返回 gateHits，等价于逐正则
//     strings.Contains(正文小写, gate)，省掉 40KB 正文上的重复 Contains）。
func buildLitPrescreen(techs []*compiledTech) *litPrescreen {
	ps := &litPrescreen{}
	keyIdx := map[uint32]int32{} // 4 字节 key → 桶号
	seenLit := map[string]bool{}
	seenGate := map[string]bool{}
	add := func(lit string, isGate bool) {
		if lit == "" {
			return
		}
		if isGate {
			if seenGate[lit] {
				return
			}
			seenGate[lit] = true
		} else {
			if seenLit[lit] {
				return
			}
			seenLit[lit] = true
		}
		if len(lit) < 4 {
			ps.shorts = append(ps.shorts, litEntry{lit: lit, isGate: isGate})
			return
		}
		k := litKey4(lit)
		if k == 0 {
			ps.zeros = append(ps.zeros, litEntry{lit: lit, isGate: isGate})
			return
		}
		bi, ok := keyIdx[k]
		if !ok {
			bi = int32(len(ps.buckets))
			keyIdx[k] = bi
			ps.buckets = append(ps.buckets, litBucket{})
		}
		ps.buckets[bi].entries = append(ps.buckets[bi].entries, litEntry{lit: lit, isGate: isGate})
	}
	for _, ct := range techs {
		for _, p := range ct.html {
			if p.isLit {
				add(p.lit, false)
			}
		}
	}
	// 正则门控字面量：只有正文通道（html/inline）的输入是正文；header/cookie/
	// meta/src 通道的输入各不相同，其门控仍在通道内按 Contains 判定。
	treeLits := map[string]bool{}
	for _, ct := range techs {
		for _, p := range ct.html {
			if p.isLit {
				continue
			}
			if p.gate != "" {
				add(p.gate, true)
			}
			p.gateTree.literals(treeLits)
		}
		for _, p := range ct.inline {
			if p.isLit {
				continue
			}
			if p.gate != "" {
				add(p.gate, true)
			}
			p.gateTree.literals(treeLits)
		}
	}
	for lit := range treeLits {
		add(lit, true)
	}
	// 开放寻址表：槽数取 ≥2×key 数的 2 次幂（负载因子 ≤0.5，线性探测均摊 ~1.5 次）。
	size := 8
	for size < len(keyIdx)*2 {
		size <<= 1
	}
	bits := 0
	for 1<<bits < size {
		bits++
	}
	ps.tab = make([]uint64, size)
	ps.mask = uint32(size - 1)
	ps.shift = uint32(32 - bits)
	for k, bi := range keyIdx {
		h := litHash(k, ps.shift)
		for ps.tab[h] != 0 {
			h = (h + 1) & ps.mask
		}
		ps.tab[h] = uint64(k)<<32 | uint64(uint32(bi)+1)
	}
	return ps
}

// scan 单遍扫描小写正文，返回出现过的 html 字面量集合与正文通道正则门控集合。
// litHits 的语义与旧实现（逐字面量 strings.Contains）完全一致。
func (ps *litPrescreen) scan(sLow string) (litHits, gateHits map[string]bool) {
	litHits = make(map[string]bool, 16)
	gateHits = make(map[string]bool, 8)
	n := len(sLow)
	if n >= 4 && len(ps.buckets) > 0 {
		// 滚动 4 字节小端 key：每步右移 1 字节再补新字节，无需重读 4 次。
		k := uint32(sLow[0]) | uint32(sLow[1])<<8 | uint32(sLow[2])<<16 | uint32(sLow[3])<<24
		for i := 0; i+4 <= n; i++ {
			h := litHash(k, ps.shift)
			for {
				slot := ps.tab[h]
				if uint32(slot>>32) != k {
					if slot == 0 {
						break // 空槽：该前缀不存在
					}
					h = (h + 1) & ps.mask
					continue
				}
				for _, e := range ps.buckets[uint32(slot)-1].entries {
					if len(e.lit) <= n-i && sLow[i:i+len(e.lit)] == e.lit {
						if e.isGate {
							gateHits[e.lit] = true
						} else if !litHits[e.lit] {
							litHits[e.lit] = true
						}
					}
				}
				break
			}
			if i+4 < n {
				k = k>>8 | uint32(sLow[i+4])<<24
			}
		}
	}
	for _, e := range ps.shorts {
		if strings.Contains(sLow, e.lit) {
			if e.isGate {
				gateHits[e.lit] = true
			} else {
				litHits[e.lit] = true
			}
		}
	}
	for _, e := range ps.zeros {
		if strings.Contains(sLow, e.lit) {
			if e.isGate {
				gateHits[e.lit] = true
			} else {
				litHits[e.lit] = true
			}
		}
	}
	return litHits, gateHits
}
