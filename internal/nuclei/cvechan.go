// CVE 通道（准入收口）：把「目标指纹确实受影响的 CVE」反查到模板，
// 让这些模板不必等 LRU 轮转就能进本次扫描预算。
//
// 为什么需要：调度此前只有 tag 硬匹配 + LRU 轮转两路。tag 路径依赖
// 模板作者写的 tag 与指纹技术名对上，而大量模板只用 CVE 命名、不带
// 产品 tag；轮转则对单次扫描不承诺结论（EXP-1003：wordfence 源
// 82,709 条在靶场命中 0——不是模板写错，是「它瞄的这台目标上没有」
// 却照样排进队列，把预算吃完）。
//
// 本通道用现成的 tech→CVE 链路（intel KB：指纹技术名 → 受影响漏洞行）
// 取目标实际受影响 CVE 集合，再按 Entry.CVEs 反向命中模板：
//   - 命中的模板置顶（优先于 tag 命中）——「这台机器真的中的」优先跑；
//   - 未命中的模板仍走既有 tag / LRU 路径，不做删除。
//
// 边界（诚实）：CVE 集合来自 intel 关联（可能含 possible 级），本通道
// 只调整调度优先级，不改变任何判定逻辑——跑出来的结论仍由模板自身的
// matcher + 二次确认负责。所以它零误报风险，收益是「对的有机会跑」。
package nuclei

import "strings"

// CVEIndex 模板 CVE → 模板下标（建一次，供调度期反查）。
func CVEIndex(entries []Entry) map[string][]int {
	idx := make(map[string][]int)
	for i := range entries {
		for _, c := range entries[i].CVEs {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c == "" {
				continue
			}
			idx[c] = append(idx[c], i)
		}
	}
	return idx
}

// CountCVEHits 命中目标 CVE 集合的模板条数（调度可见性）。
func CountCVEHits(entries []Entry, cveSet map[string]bool) int {
	if len(cveSet) == 0 {
		return 0
	}
	n := 0
	for i := range entries {
		for _, c := range entries[i].CVEs {
			if cveSet[strings.ToUpper(strings.TrimSpace(c))] {
				n++
				break
			}
		}
	}
	return n
}

// entryMatchesCVE 条目是否声明了目标 CVE 集合中的任一 CVE。
func entryMatchesCVE(e Entry, cveSet map[string]bool) bool {
	if len(cveSet) == 0 {
		return false
	}
	for _, c := range e.CVEs {
		if cveSet[strings.ToUpper(strings.TrimSpace(c))] {
			return true
		}
	}
	return false
}
