// 正文通道正则的「必含字面量」门控公式：从正则语法树推导出「任何命中都必然
// 满足」的字面量布尔条件，条件确定不成立即可安全跳过正则执行（结果不变）。
//
// 为什么需要：社区指纹库里大量正则写成 `(?:A|B)` 交替或 `.*?` 长跨度形态，
// 旧实现只提取「最长字面量运行」当门（交替内容整段跳过），这类模式常常没有
// 门或只有 href / <link 这种处处都有的弱门，于是每页都要在 40KB 正文上执行
// 一次 NFA（实测单条可达 1~3ms）。用语法树推导出 `powered|built|generated`
// 这类必然字面量条件后，绝大多数不可能命中的正则直接被跳过。
package sitelens

import "regexp/syntax"

// gateNode 必含字面量条件树：叶子是字面量，内部节点是 AND / OR。
// 语义：正则命中 ⇒ 条件成立。条件不成立 ⇒ 正则必不命中（可跳过）。
type gateNode struct {
	lit string      // 非空 = 字面量叶子（小写 ASCII）
	and []*gateNode // 非空 = 全部子条件都必须成立
	or  []*gateNode // 非空 = 至少一个子条件成立
}

// buildGateNode 从原始正则串推导必含字面量条件（nil = 推导不出可用条件）。
// 只采信 ASCII 字面量：正文按 ToLower 归一后查字面量，ASCII 大小写折叠与
// ToLower 一一对应（非 ASCII 折叠轨道可能有「ſ / s」「K / K」这类特例）。
func buildGateNode(raw string) *gateNode {
	re, err := syntax.Parse("(?i)"+raw, syntax.Perl)
	if err != nil {
		return nil // 与 regexp.Compile 同源解析；正常不会失败
	}
	return gateNodeOf(re)
}

// gateNodeOf 递归推导语法树的必含条件。
func gateNodeOf(re *syntax.Regexp) *gateNode {
	switch re.Op {
	case syntax.OpLiteral:
		lit := gateLongestASCII(re.Rune)
		if len(lit) < 3 {
			return nil
		}
		return &gateNode{lit: lit}
	case syntax.OpCapture:
		return gateNodeOf(re.Sub[0])
	case syntax.OpConcat:
		subs := make([]*gateNode, 0, len(re.Sub))
		for _, sub := range re.Sub {
			if n := gateNodeOf(sub); n != nil {
				subs = append(subs, n)
			}
		}
		return gateAnd(subs)
	case syntax.OpPlus:
		// x+ 至少出现一次：x 的必含条件成立
		return gateNodeOf(re.Sub[0])
	case syntax.OpRepeat:
		// x{m,} / x{m,n}：m≥1 时至少出现一次
		if re.Min >= 1 {
			return gateNodeOf(re.Sub[0])
		}
		return nil
	case syntax.OpAlternate:
		// 任一分支命中即整体命中：每条分支都必须有必含条件，
		// 否则（某分支无约束）整体推导不出条件。
		subs := make([]*gateNode, 0, len(re.Sub))
		for _, sub := range re.Sub {
			n := gateNodeOf(sub)
			if n == nil {
				return nil
			}
			subs = append(subs, n)
		}
		return gateOr(subs)
	}
	// CharClass / 任意字符 / 锚点 / * ? {0,} 等：不产生必含字面量
	return nil
}

// gateLongestASCII 取字面量节点里最长的小写 ASCII 连续片段：
// 含非 ASCII 字符时只采信其中 ASCII 段（非 ASCII 折叠轨道可能有
// 「ſ / s」「K / K」这类特例，不能按 ToLower 归一后查字面量）。
func gateLongestASCII(runes []rune) string {
	var best []byte
	cur := make([]byte, 0, len(runes))
	flush := func() {
		if len(cur) > len(best) {
			best = append(best[:0], cur...)
		}
		cur = cur[:0]
	}
	for _, r := range runes {
		if r >= 128 {
			flush()
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		cur = append(cur, byte(r))
	}
	flush()
	return string(best)
}

func gateAnd(subs []*gateNode) *gateNode {
	switch len(subs) {
	case 0:
		return nil
	case 1:
		return subs[0]
	}
	return &gateNode{and: subs}
}

func gateOr(subs []*gateNode) *gateNode {
	switch len(subs) {
	case 0:
		return nil
	case 1:
		return subs[0]
	}
	return &gateNode{or: subs}
}

// miss 判断条件是否「确定不成立」（present 报告字面量是否出现在输入里）。
// 只有能证明不成立时才返回 true，任何不确定都返回 false（宁可不跳，不误跳）。
func (n *gateNode) miss(present func(string) bool) bool {
	if n == nil || present == nil {
		return false
	}
	if n.lit != "" {
		return !present(n.lit)
	}
	if len(n.and) > 0 {
		for _, sub := range n.and {
			if sub.miss(present) {
				return true
			}
		}
		return false
	}
	for _, sub := range n.or {
		if !sub.miss(present) {
			return false
		}
	}
	return true
}

// literals 收集条件树里的全部字面量（建正文预筛索引用）。
func (n *gateNode) literals(out map[string]bool) {
	if n == nil {
		return
	}
	if n.lit != "" {
		out[n.lit] = true
		return
	}
	for _, sub := range n.and {
		sub.literals(out)
	}
	for _, sub := range n.or {
		sub.literals(out)
	}
}

// gateTreeFor 取原始 pattern 串对应的门控条件树（同一串共享一份，加载期解析一次）。
func gateTreeFor(raw string, cache map[string]*gateNode) *gateNode {
	if n, ok := cache[raw]; ok {
		return n
	}
	n := buildGateNode(raw)
	cache[raw] = n
	return n
}

// attachGateTrees 给正文通道正则挂必含字面量条件树（同一 raw 串共享一份）。
func attachGateTrees(pats []pattern, cache map[string]*gateNode) {
	for i := range pats {
		p := &pats[i]
		if p.isLit || p.re == nil {
			continue
		}
		p.gateTree = gateTreeFor(p.raw, cache)
	}
}

// gateMiss 正则的跳过判定：true ⇒ 该正则不可能在 present 描述的输入里命中。
// present == nil（无预筛信息）时一律不跳，保持旧的逐模式执行行为。
func (p pattern) gateMiss(present func(string) bool) bool {
	if present == nil {
		return false
	}
	if p.gate != "" && !present(p.gate) {
		return true
	}
	return p.gateTree != nil && p.gateTree.miss(present)
}
