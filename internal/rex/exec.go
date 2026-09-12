package rex

// 回溯执行器：连续传递（CPS）风格，k 为「匹配成功后接下来做什么」。
// 每步消耗 1 预算，预算耗尽立即整体失败（exhausted 标记，宁少报）。

// Regexp 编译后的正则；编译后不可变，可并发使用。
type Regexp struct {
	root     node
	ncap     int  // 捕获组数
	anchored bool // 根节点以 ^/\A 开头，只需尝试起点 0
	// Budget 每次匹配尝试（单个起点）的步数上限；匹配前可调，默认 100000。
	Budget int
}

// defaultBudget 单次匹配尝试的默认步数预算。
// 服务指纹模式均为短模式短 banner，10 万步足够正常匹配；
// 灾难性回溯形态在此预算下有界退出，不挂死扫描协程。
const defaultBudget = 100000

// matcher 单次匹配尝试的状态。
type matcher struct {
	s         string
	caps      []int // 2*(ncap+1)，-1 = 未捕获
	steps     int
	budget    int
	exhausted bool
}

type cont func(pos int) bool

// Compile 解析正则模式；遇到 RE2 之外的超集语法缺口时返回错误
// （调用方应先走 regexp 标准库，失败才回退本包）。
func Compile(expr string) (*Regexp, error) {
	p := &parser{src: expr}
	root, err := p.parse()
	if err != nil {
		return nil, err
	}
	re := &Regexp{root: root, ncap: p.ncap, Budget: defaultBudget}
	switch c := root.(type) {
	case *concatNode:
		if len(c.subs) > 0 {
			if a, ok := c.subs[0].(*assertNode); ok && a.kind == asBot {
				re.anchored = true
			}
		}
	case *assertNode:
		if c.kind == asBot {
			re.anchored = true
		}
	}
	return re, nil
}

// MatchString 报告 s 中是否存在匹配。
func (re *Regexp) MatchString(s string) bool {
	_, _, ok := re.find(s)
	return ok
}

// FindString 返回左最先匹配的文本，无匹配返回空串。
// 注意空匹配也会返回空串，需存在性判断请用 MatchString。
func (re *Regexp) FindString(s string) string {
	st, en, ok := re.find(s)
	if !ok {
		return ""
	}
	return s[st:en]
}

// FindStringSubmatch 与 regexp 同形：下标 0 为整体匹配，1..n 为捕获组
// （未参与匹配的组为空串）；无匹配返回 nil。
func (re *Regexp) FindStringSubmatch(s string) []string {
	out, _ := re.submatch(s)
	return out
}

// find 在 s 中寻找左最先匹配（预算耗尽则整体放弃）。
func (re *Regexp) find(s string) (int, int, bool) {
	st, en, _ := re.findImpl(s)
	return st, en, st >= 0
}

// findImpl 执行扫描；成功时返回 (起点, 终点, 捕获组快照)。
func (re *Regexp) findImpl(s string) (int, int, []int) {
	lo, hi := 0, len(s)
	if re.anchored {
		hi = 0 // 仅起点 0
	}
	for start := lo; start <= hi; start++ {
		m := &matcher{s: s, budget: re.Budget}
		m.caps = make([]int, 2*(re.ncap+1))
		for i := range m.caps {
			m.caps[i] = -1
		}
		end := -1
		if m.match(re.root, start, func(p int) bool { end = p; return true }) {
			return start, end, m.caps
		}
		if m.exhausted {
			return -1, -1, nil // 预算耗尽：整体放弃，宁少报
		}
	}
	return -1, -1, nil
}

// FindStringSubmatch 的组快照版本：与 findImpl 协作，供内部测试使用。
func (re *Regexp) submatch(s string) ([]string, bool) {
	st, en, caps := re.findImpl(s)
	if st < 0 {
		return nil, false
	}
	out := make([]string, re.ncap+1)
	out[0] = s[st:en]
	for g := 1; g <= re.ncap; g++ {
		gs, ge := caps[2*g], caps[2*g+1]
		if gs >= 0 && ge >= gs {
			out[g] = s[gs:ge]
		}
	}
	return out, true
}

// match 单节点匹配；步数预算检查在每个节点入口。
func (m *matcher) match(n node, pos int, k cont) bool {
	if m.steps++; m.steps > m.budget {
		m.exhausted = true
		return false
	}
	switch n := n.(type) {
	case *litNode:
		if pos < len(m.s) && m.eqByte(n.b, n.fold, m.s[pos]) {
			return k(pos + 1)
		}
		return false

	case *classNode:
		if pos < len(m.s) && n.has(m.s[pos]) {
			return k(pos + 1)
		}
		return false

	case *anyNode:
		if pos < len(m.s) && (n.dotAll || m.s[pos] != '\n') {
			return k(pos + 1)
		}
		return false

	case *assertNode:
		if m.assert(n.kind, pos) {
			return k(pos)
		}
		return false

	case *concatNode:
		return m.matchSeq(n.subs, 0, pos, k)

	case *altNode:
		for _, sub := range n.subs {
			if m.match(sub, pos, k) {
				return true
			}
		}
		return false

	case *repNode:
		return m.rep(n, 0, pos, k)

	case *groupNode:
		if n.idx == 0 {
			return m.match(n.sub, pos, k)
		}
		return m.group(n, pos, k)

	case *backrefNode:
		s, e := m.caps[2*n.idx], m.caps[2*n.idx+1]
		if s < 0 || e < s {
			return k(pos) // 未参与匹配的组按空串处理（PCRE 语义）
		}
		if pos+e-s <= len(m.s) && m.eqSeg(m.s[s:e], pos, n.fold) {
			return k(pos + e - s)
		}
		return false

	case *lookNode:
		return m.look(n, pos, k)
	}
	return false
}

// matchSeq 顺序匹配 concat 的子节点序列。
func (m *matcher) matchSeq(subs []node, i, pos int, k cont) bool {
	if i == len(subs) {
		return k(pos)
	}
	return m.match(subs[i], pos, func(np int) bool {
		return m.matchSeq(subs, i+1, np, k)
	})
}

// rep 量词匹配。空迭代只计一次次数即收口，防止零宽死循环。
func (m *matcher) rep(n *repNode, count, pos int, k cont) bool {
	if m.steps++; m.steps > m.budget {
		m.exhausted = true
		return false
	}
	canMore := n.max < 0 || count < n.max
	if canMore {
		var ok bool
		if n.lazy {
			// 懒惰：先尝试收口，再进循环体
			if count >= n.min && k(pos) {
				return true
			}
			ok = m.match(n.sub, pos, m.repCont(n, count, pos, k))
		} else {
			ok = m.match(n.sub, pos, m.repCont(n, count, pos, k))
		}
		if ok {
			return true
		}
	}
	if !n.lazy {
		return count >= n.min && k(pos)
	}
	return false
}

// repCont 量词循环体的延续：处理空迭代收口与递归计数。
func (m *matcher) repCont(n *repNode, count, pos int, k cont) cont {
	return func(np int) bool {
		if np == pos {
			// 空迭代：计一次次数即收口，防止零宽无限循环
			if count+1 >= n.min {
				return k(pos)
			}
			return m.repStep(n, count+1, pos, k)
		}
		return m.repStep(n, count+1, np, k)
	}
}

// repStep 量词递归入口（懒惰/贪婪共用计数路径）。
func (m *matcher) repStep(n *repNode, count, pos int, k cont) bool {
	return m.rep(n, count, pos, k)
}

// group 捕获组：记录起止，失败时回滚现场。
func (m *matcher) group(n *groupNode, pos int, k cont) bool {
	g := 2 * n.idx
	oldS, oldE := m.caps[g], m.caps[g+1]
	m.caps[g] = pos
	ok := m.match(n.sub, pos, func(np int) bool {
		prev := m.caps[g+1]
		m.caps[g+1] = np
		if k(np) {
			return true
		}
		m.caps[g+1] = prev
		return false
	})
	if !ok {
		m.caps[g], m.caps[g+1] = oldS, oldE
	}
	return ok
}

// look 环视。前向：子式从 pos 起可匹配即成立；后向：存在 j 使子式
// 恰好匹配 s[j:pos] 即成立。否定形式成立后不留捕获（PCRE 语义：
// 肯定环视的捕获保留）。
func (m *matcher) look(n *lookNode, pos int, k cont) bool {
	saved := append([]int(nil), m.caps...)
	var hit bool
	if n.ahead {
		hit = m.match(n.sub, pos, func(int) bool { return true })
	} else {
		for j := pos; j >= 0 && !hit; j-- {
			hit = m.match(n.sub, j, func(p int) bool { return p == pos })
		}
	}
	if n.neg || !hit {
		copy(m.caps, saved)
	}
	if hit != n.neg {
		return k(pos)
	}
	return false
}

// assert 零宽断言判定。
func (m *matcher) assert(kind, pos int) bool {
	switch kind {
	case asBot: // 文本起点（^(?m) 之外）与 \A
		return pos == 0
	case asBol: // 行首
		return pos == 0 || m.s[pos-1] == '\n'
	case asEot: // 文本终点（$(?m) 之外）与 \z
		return pos == len(m.s)
	case asEol: // 行尾
		return pos == len(m.s) || m.s[pos] == '\n'
	case asEotNL: // \Z：文本终点或末尾换行前
		return pos == len(m.s) || (pos == len(m.s)-1 && m.s[pos] == '\n')
	case asWordB, asNotWordB:
		before := pos > 0 && isWordByte(m.s[pos-1])
		after := pos < len(m.s) && isWordByte(m.s[pos])
		b := before != after
		if kind == asNotWordB {
			return !b
		}
		return b
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func (m *matcher) eqByte(want byte, fold bool, got byte) bool {
	if got == want {
		return true
	}
	if !fold {
		return false
	}
	return lowerASCII(got) == lowerASCII(want)
}

func (m *matcher) eqSeg(seg string, pos int, fold bool) bool {
	if pos+len(seg) > len(m.s) {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if !m.eqByte(seg[i], fold, m.s[pos+i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
