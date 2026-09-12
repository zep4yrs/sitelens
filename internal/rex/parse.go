// Package rex 实现受限回溯正则匹配器，承接 RE2 拒收的服务指纹模式。
//
// RE2（regexp 标准库）不支持环视与反向引用，社区服务指纹库里有
// 数百条此类模式，按需丢弃等于指纹盲区。本包以字节级回溯引擎
// 实现 nmap/PCRE 风格的必需子集，匹配全程受步数预算约束
// （默认每次尝试 10 万步，超限判不匹配——宁少报，不挂死）。
//
// 仅作为 RE2 编译失败后的回退路径，语义目标与 Go regexp 一致：
// 左最先匹配（leftmost-first）、$ 为文本末尾（非末尾换行前）。
package rex

import "fmt"

// ---- AST ----

type node interface{}

// litNode 单字节字面量。
type litNode struct {
	b    byte
	fold bool // ASCII 大小写不敏感
}

// classNode 字符类，256 位位图已含取反与折叠展开。
type classNode struct {
	bits [32]byte
}

func (c *classNode) has(b byte) bool { return c.bits[b>>3]&(1<<(b&7)) != 0 }
func (c *classNode) add(b byte)      { c.bits[b>>3] |= 1 << (b & 7) }

// anyNode 点号（dotAll 决定是否匹配换行）。
type anyNode struct{ dotAll bool }

// 断言种类。
const (
	asBot      = iota // ^（文本起点，(?m) 下为行首）
	asBol             // 行首（(?m)）
	asEot             // $（文本终点，(?m) 下为行尾）
	asEol             // 行尾（(?m)）
	asEotNL           // \Z：文本终点或末尾换行前
	asWordB           // \b
	asNotWordB        // \B
)

// assertNode 零宽断言。
type assertNode struct{ kind int }

// concatNode 顺序连接。
type concatNode struct{ subs []node }

// altNode 多路分支。
type altNode struct{ subs []node }

// repNode 量词；max<0 表示无界。
type repNode struct {
	sub      node
	min, max int
	lazy     bool
}

// groupNode 捕获组；idx==0 为非捕获。
type groupNode struct {
	idx int
	sub node
}

// backrefNode 反向引用。
type backrefNode struct {
	idx  int
	fold bool
}

// lookNode 环视：ahead=true 前向，neg=true 否定。
type lookNode struct {
	sub   node
	ahead bool
	neg   bool
}

// ---- 解析器 ----

type parser struct {
	src   string
	i     int
	ncap  int
	fold  bool
	dotAl bool
	multi bool
}

// parse 顶层入口：解析整个模式并校验无残留括号。
func (p *parser) parse() (node, error) {
	n, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	if p.i < len(p.src) {
		return nil, fmt.Errorf("rex: 意外的 ')': 偏移 %d", p.i)
	}
	return n, nil
}

// parseAlt 解析 branch ('|' branch)*。
func (p *parser) parseAlt() (node, error) {
	var subs []node
	for {
		n, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		subs = append(subs, n)
		if p.i < len(p.src) && p.src[p.i] == '|' {
			p.i++
			continue
		}
		break
	}
	if len(subs) == 1 {
		return subs[0], nil
	}
	return &altNode{subs: subs}, nil
}

// parseConcat 解析一串带量词的原子；在 '|'、')' 或结尾处停止。
func (p *parser) parseConcat() (node, error) {
	var subs []node
	for p.i < len(p.src) && p.src[p.i] != '|' && p.src[p.i] != ')' {
		n, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		n, err = p.parseQuant(n)
		if err != nil {
			return nil, err
		}
		subs = append(subs, n)
	}
	if len(subs) == 0 {
		return &concatNode{}, nil // 空分支匹配空串
	}
	if len(subs) == 1 {
		return subs[0], nil
	}
	return &concatNode{subs: subs}, nil
}

// parseQuant 解析原子后的量词（含懒惰后缀），无量词原样返回。
func (p *parser) parseQuant(n node) (node, error) {
	var min, max int
	switch {
	case p.i < len(p.src) && p.src[p.i] == '*':
		p.i++
		min, max = 0, -1
	case p.i < len(p.src) && p.src[p.i] == '+':
		p.i++
		min, max = 1, -1
	case p.i < len(p.src) && p.src[p.i] == '?':
		p.i++
		min, max = 0, 1
	case p.i < len(p.src) && p.src[p.i] == '{':
		save := p.i
		mi, ma, next, st := scanBrace(p.src, save)
		if st == brError {
			return nil, fmt.Errorf("rex: 非法重复区间: 偏移 %d", save)
		}
		if st == brLiteral {
			return n, nil // 非量词语法：按字面量（与 RE2 一致）
		}
		min, max = mi, ma
		p.i = next
	default:
		return n, nil
	}
	// 懒惰后缀；再跟量词即占有量词/嵌套量词，均不支持
	lazy := false
	if p.i < len(p.src) && p.src[p.i] == '?' {
		p.i++
		lazy = true
	}
	if p.i < len(p.src) && (p.src[p.i] == '*' || p.src[p.i] == '+' || p.src[p.i] == '?') {
		return nil, fmt.Errorf("rex: 不支持占有/嵌套量词: 偏移 %d", p.i)
	}
	if p.i < len(p.src) && p.src[p.i] == '{' {
		return nil, fmt.Errorf("rex: 不支持嵌套量词: 偏移 %d", p.i)
	}
	if lazy {
		return &repNode{sub: n, min: min, max: max, lazy: true}, nil
	}
	return &repNode{sub: n, min: min, max: max}, nil
}

// scanBrace 从 src[at]=='{' 起尝试解析 {n} {n,} {n,m}。
// brOK 时 next 指向 '}' 之后；brLiteral=语法上不是量词（按字面量处理）；
// brError=形如量词但越界/逆序（RE2 语义：静默改义比报错危险）。
func scanBrace(src string, at int) (min, max, next, state int) {
	j := at + 1
	n1, j, ok1, ov1 := scanDigits(src, j)
	if !ok1 {
		return 0, 0, at, brLiteral
	}
	ma := -1
	if j < len(src) && src[j] == ',' {
		j++
		if j < len(src) && src[j] != '}' {
			n2, j2, ok2, ov2 := scanDigits(src, j)
			if !ok2 {
				return 0, 0, at, brLiteral
			}
			ma = n2
			j = j2
			if ov2 {
				return 0, 0, at, brError
			}
		}
	} else {
		ma = n1
	}
	if j >= len(src) || src[j] != '}' {
		return 0, 0, at, brLiteral
	}
	if ov1 || n1 > maxRepeat || (ma >= 0 && ma < n1) {
		return 0, 0, at, brError
	}
	return n1, ma, j + 1, brOK
}

// maxRepeat 重复上界：回溯器无展开成本，取 65535 防御性上限
// （数据中已见 {899,1536}，远超 RE2 的 1000 上限）。
const maxRepeat = 65535

// tryBrace 状态：brOK=已解析；brLiteral=非量词语法按字面量回退；
// brError=形如量词但越界/逆序，必须报错。
const (
	brOK = iota
	brLiteral
	brError
)

func scanDigits(s string, i int) (v, next int, ok, overflow bool) {
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		if v <= maxRepeat {
			v = v*10 + int(s[i]-'0')
		}
		if v > maxRepeat {
			overflow = true
		}
		i++
	}
	if i == start {
		return 0, i, false, false
	}
	return v, i, true, overflow
}

// parseAtom 解析单个原子（不含量词）。
func (p *parser) parseAtom() (node, error) {
	c := p.src[p.i]
	switch c {
	case '(':
		return p.parseGroup()
	case '[':
		return p.parseClass()
	case '.':
		p.i++
		return &anyNode{dotAll: p.dotAl}, nil
	case '^':
		p.i++
		k := asBot
		if p.multi {
			k = asBol
		}
		return &assertNode{kind: k}, nil
	case '$':
		p.i++
		k := asEot
		if p.multi {
			k = asEol
		}
		return &assertNode{kind: k}, nil
	case '\\':
		return p.parseEscape()
	case '*', '+', '?':
		return nil, fmt.Errorf("rex: 量词缺少前置原子: 偏移 %d", p.i)
	case '{':
		if _, _, _, st := scanBrace(p.src, p.i); st != brLiteral {
			return nil, fmt.Errorf("rex: 量词缺少前置原子: 偏移 %d", p.i)
		}
		p.i++
		return &litNode{b: '{'}, nil
	default:
		p.i++
		return &litNode{b: c, fold: p.fold}, nil
	}
}

// parseGroup 解析 (…)、(?:…)、(?=…)、(?!…)、(?<=…)、(?<!…) 与 (?ims) flag 组。
func (p *parser) parseGroup() (node, error) {
	open := p.i // '('
	p.i++
	if p.i >= len(p.src) || p.src[p.i] != '?' {
		// 普通捕获组
		p.ncap++
		idx := p.ncap
		sub, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if err := p.expectClose(open); err != nil {
			return nil, err
		}
		return &groupNode{idx: idx, sub: sub}, nil
	}
	p.i++ // 跳过 '?'
	if p.i >= len(p.src) {
		return nil, fmt.Errorf("rex: '(?' 后缺少构造: 偏移 %d", open)
	}
	switch c := p.src[p.i]; {
	case c == ':':
		p.i++
		return p.parseGroupBody(open, false)
	case c == '=':
		p.i++
		sub, err := p.parseGroupBody(open, false)
		if err != nil {
			return nil, err
		}
		return &lookNode{sub: sub, ahead: true}, nil
	case c == '!':
		p.i++
		sub, err := p.parseGroupBody(open, false)
		if err != nil {
			return nil, err
		}
		return &lookNode{sub: sub, ahead: true, neg: true}, nil
	case c == '<':
		if p.i+1 < len(p.src) && p.src[p.i+1] == '=' {
			p.i += 2
			sub, err := p.parseGroupBody(open, false)
			if err != nil {
				return nil, err
			}
			return &lookNode{sub: sub}, nil
		}
		if p.i+1 < len(p.src) && p.src[p.i+1] == '!' {
			p.i += 2
			sub, err := p.parseGroupBody(open, false)
			if err != nil {
				return nil, err
			}
			return &lookNode{sub: sub, neg: true}, nil
		}
		return nil, fmt.Errorf("rex: 不支持命名组: 偏移 %d", open)
	case c == '>' || c == 'P' || c == '#':
		return nil, fmt.Errorf("rex: 不支持的 (?%c) 构造: 偏移 %d", c, open)
	default:
		return p.parseFlags(open)
	}
}

// parseGroupBody 解析组体至 ')'，恢复 flag 现场。
func (p *parser) parseGroupBody(open int, capture bool) (node, error) {
	saveFold, saveDot, saveMulti := p.fold, p.dotAl, p.multi
	sub, err := p.parseAlt()
	if err == nil {
		err = p.expectClose(open)
	}
	p.fold, p.dotAl, p.multi = saveFold, saveDot, saveMulti
	return sub, err
}

// parseFlags 解析 (?flags) 与 (?flags:…) 形式（支持 i s m 与 '-' 取消）。
func (p *parser) parseFlags(open int) (node, error) {
	neg := false
	for p.i < len(p.src) {
		switch c := p.src[p.i]; c {
		case 'i':
			p.fold = !neg
		case 's':
			p.dotAl = !neg
		case 'm':
			p.multi = !neg
		case '-':
			if neg {
				return nil, fmt.Errorf("rex: 重复的 '-': 偏移 %d", p.i)
			}
			neg = true
		case ')':
			p.i++
			return &concatNode{}, nil // flag 持续到当前组结束（现场由组恢复）
		case ':':
			p.i++
			return p.parseGroupBody(open, false)
		default:
			return nil, fmt.Errorf("rex: 不支持的 flag %q: 偏移 %d", string(c), p.i)
		}
		p.i++
	}
	return nil, fmt.Errorf("rex: 未闭合的 flag 组: 偏移 %d", open)
}

func (p *parser) expectClose(open int) error {
	if p.i >= len(p.src) || p.src[p.i] != ')' {
		return fmt.Errorf("rex: 未闭合的 '(': 偏移 %d", open)
	}
	p.i++
	return nil
}

// parseClass 解析 [...] 字符类：范围、类别缩写、转义与 ^ 取反。
// 与 RE2 一致：']' 即闭合（不存在首位 ']' 字面量语法），空类报错；
// 不支持 POSIX [[:alpha:]] 嵌套类。
func (p *parser) parseClass() (node, error) {
	open := p.i // '['
	p.i++
	neg := false
	if p.i < len(p.src) && p.src[p.i] == '^' {
		neg = true
		p.i++
	}
	cls := &classNode{}
	saw := false
	// PCRE/RE2 规则：']' 位于类首（含 '^' 之后）是字面量而非闭合
	first := true
	for {
		if p.i >= len(p.src) {
			return nil, fmt.Errorf("rex: 未闭合的 '[': 偏移 %d", open)
		}
		if p.src[p.i] == ']' && !first {
			if !saw {
				return nil, fmt.Errorf("rex: 空字符类: 偏移 %d", open)
			}
			p.i++
			break
		}
		if p.src[p.i] == ']' {
			cls.add(']')
			saw = true
			first = false
			p.i++
			continue
		}
		lo, isCls, err := p.classItem(cls, open)
		if err != nil {
			return nil, err
		}
		saw = true
		first = false
		// 范围 a-z：'-' 后跟非 ']' 才构成范围；'-x' 两端均须字面量
		if !isCls && p.i+1 < len(p.src) && p.src[p.i] == '-' && p.src[p.i+1] != ']' {
			p.i++ // '-'
			hi, hiCls, err := p.classItem(cls, open)
			if err != nil {
				return nil, err
			}
			if isCls || hiCls || hi < lo {
				return nil, fmt.Errorf("rex: 非法字符范围: 偏移 %d", open)
			}
			addClassRange(cls, lo, hi)
			continue
		}
		if isCls {
			// 类别缩写不可作范围端点：\d-z 形态与 RE2 一致报错
			if p.i < len(p.src) && p.src[p.i] == '-' && p.i+1 < len(p.src) && p.src[p.i+1] != ']' {
				return nil, fmt.Errorf("rex: 非法字符范围: 偏移 %d", open)
			}
			continue
		}
		// 单字节：有 '-' 且其后是 ']' → '-' 为字面量
		cls.add(lo)
		if p.i < len(p.src) && p.src[p.i] == '-' && p.i+1 < len(p.src) && p.src[p.i+1] == ']' {
			p.i++
			cls.add('-')
		}
	}
	if neg {
		negateBits(cls)
	}
	if p.fold {
		expandFold(cls)
	}
	return cls, nil
}

// classItem 取类内一个元素：字面量字节或类别缩写。
// isCls=true 表示 lo 无效、缩写已直接写入 cls。
func (p *parser) classItem(cls *classNode, open int) (lo byte, isCls bool, err error) {
	if p.src[p.i] == '\\' {
		esc := p.i
		p.i++
		if p.i >= len(p.src) {
			return 0, false, fmt.Errorf("rex: 悬空的反斜杠: 偏移 %d", esc)
		}
		c := p.src[p.i]
		p.i++
		switch {
		case c == 'd' || c == 'D' || c == 'w' || c == 'W' || c == 's' || c == 'S':
			// 类内缩写（含否定形式）：把对应位图并入当前类
			tmp := &classNode{}
			fillShortcut(tmp, c)
			mergeInto(cls, tmp)
			return 0, true, nil
		case c == 'x':
			n, herr := p.parseHexByte(esc)
			if herr != nil {
				return 0, false, herr
			}
			return n, false, nil
		case c == 'n':
			return '\n', false, nil
		case c == 'r':
			return '\r', false, nil
		case c == 't':
			return '\t', false, nil
		case c == 'f':
			return '\f', false, nil
		case c == 'v':
			return '\v', false, nil
		case c == 'a':
			return 7, false, nil
		case c == 'e':
			return 0x1b, false, nil
		case c == 'b':
			return '\b', false, nil // 类内 \b 为退格（PCRE 惯例）
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			return 0, false, fmt.Errorf("rex: 不支持的转义 \\%c: 偏移 %d", c, esc)
		default:
			return c, false, nil
		}
	}
	if p.src[p.i] == '[' && p.i+1 < len(p.src) && p.src[p.i+1] == ':' {
		return 0, false, fmt.Errorf("rex: 不支持 POSIX 类: 偏移 %d", p.i)
	}
	c := p.src[p.i]
	p.i++
	return c, false, nil
}

// parseHexByte 类内 \xHH / \x{H+}，返回字节值。
func (p *parser) parseHexByte(esc int) (byte, error) {
	if p.i < len(p.src) && p.src[p.i] == '{' {
		p.i++
		v := 0
		for p.i < len(p.src) && p.src[p.i] != '}' {
			h, ok := hexVal(p.src[p.i])
			if !ok || v > 0xFF {
				return 0, fmt.Errorf("rex: 非法 \\x{..}: 偏移 %d", esc)
			}
			v = v<<4 | h
			p.i++
		}
		if p.i >= len(p.src) {
			return 0, fmt.Errorf("rex: 未闭合的 \\x{: 偏移 %d", esc)
		}
		p.i++
		return byte(v), nil
	}
	if p.i+1 >= len(p.src) {
		return 0, fmt.Errorf("rex: \\x 后需要两位十六进制: 偏移 %d", esc)
	}
	hi, ok1 := hexVal(p.src[p.i])
	lo, ok2 := hexVal(p.src[p.i+1])
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("rex: \\x 后需要两位十六进制: 偏移 %d", esc)
	}
	p.i += 2
	return byte(hi<<4 | lo), nil
}

// mergeInto 把 src 位图并入 dst。
func mergeInto(dst, src *classNode) {
	for i := range dst.bits {
		dst.bits[i] |= src.bits[i]
	}
}

// expandFold 大小写折叠展开：字母位置补上对应大小写。
func expandFold(cls *classNode) {
	for c := byte('a'); c <= 'z'; c++ {
		if cls.has(c) {
			cls.add(c - 32)
		}
		if cls.has(c - 32) {
			cls.add(c)
		}
	}
}

// parseEscape 解析反斜杠转义：类别缩写、断言、反向引用与字面量。
func (p *parser) parseEscape() (node, error) {
	esc := p.i // '\\' 位置
	p.i++
	if p.i >= len(p.src) {
		return nil, fmt.Errorf("rex: 悬空的反斜杠: 偏移 %d", esc)
	}
	c := p.src[p.i]
	p.i++
	switch {
	case c >= '1' && c <= '9':
		idx := int(c - '0')
		if idx > p.ncap {
			return nil, fmt.Errorf("rex: 反向引用 \\%d 超出已定义组数: 偏移 %d", idx, esc)
		}
		return &backrefNode{idx: idx, fold: p.fold}, nil
	case c == '0':
		return &litNode{b: 0}, nil
	case c == 'd' || c == 'D' || c == 'w' || c == 'W' || c == 's' || c == 'S':
		cls := &classNode{}
		fillShortcut(cls, c)
		return cls, nil
	case c == 'b':
		return &assertNode{kind: asWordB}, nil
	case c == 'B':
		return &assertNode{kind: asNotWordB}, nil
	case c == 'A':
		return &assertNode{kind: asBot}, nil
	case c == 'z':
		return &assertNode{kind: asEot}, nil
	case c == 'Z':
		return &assertNode{kind: asEotNL}, nil
	case c == 'x':
		return p.parseHexEscape(esc)
	case c == 'n':
		return &litNode{b: '\n'}, nil
	case c == 'r':
		return &litNode{b: '\r'}, nil
	case c == 't':
		return &litNode{b: '\t'}, nil
	case c == 'f':
		return &litNode{b: '\f'}, nil
	case c == 'v':
		return &litNode{b: '\v'}, nil
	case c == 'a':
		return &litNode{b: 7}, nil
	case c == 'e':
		return &litNode{b: 0x1b}, nil
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
		return nil, fmt.Errorf("rex: 不支持的转义 \\%c: 偏移 %d", c, esc)
	default:
		// 非字母数字：转义即字面量（\. \\ \( \[ \- 等）
		return &litNode{b: c, fold: p.fold}, nil
	}
}

// parseHexEscape 解析 \xHH 与 \x{H+}。
func (p *parser) parseHexEscape(esc int) (node, error) {
	if p.i < len(p.src) && p.src[p.i] == '{' {
		p.i++
		v := 0
		for p.i < len(p.src) && p.src[p.i] != '}' {
			h, ok := hexVal(p.src[p.i])
			if !ok || v > 0xFF {
				return nil, fmt.Errorf("rex: 非法 \\x{..}: 偏移 %d", esc)
			}
			v = v<<4 | h
			p.i++
		}
		if p.i >= len(p.src) {
			return nil, fmt.Errorf("rex: 未闭合的 \\x{: 偏移 %d", esc)
		}
		p.i++ // '}'
		return &litNode{b: byte(v), fold: p.fold}, nil
	}
	if p.i+1 >= len(p.src) {
		return nil, fmt.Errorf("rex: \\x 后需要两位十六进制: 偏移 %d", esc)
	}
	hi, ok1 := hexVal(p.src[p.i])
	lo, ok2 := hexVal(p.src[p.i+1])
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("rex: \\x 后需要两位十六进制: 偏移 %d", esc)
	}
	p.i += 2
	return &litNode{b: byte(hi<<4 | lo), fold: p.fold}, nil
}

func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// fillShortcut 填充 \d \w \s 及其否定。
func fillShortcut(cls *classNode, c byte) {
	switch c {
	case 'd':
		addClassRange(cls, '0', '9')
	case 'D':
		addClassRange(cls, '0', '9')
		negateBits(cls)
	case 'w':
		addClassRange(cls, '0', '9')
		addClassRange(cls, 'a', 'z')
		addClassRange(cls, 'A', 'Z')
		cls.add('_')
	case 'W':
		addClassRange(cls, '0', '9')
		addClassRange(cls, 'a', 'z')
		addClassRange(cls, 'A', 'Z')
		cls.add('_')
		negateBits(cls)
	case 's':
		for _, b := range []byte{' ', '\t', '\n', '\r', '\f', '\v'} {
			cls.add(b)
		}
	case 'S':
		for _, b := range []byte{' ', '\t', '\n', '\r', '\f', '\v'} {
			cls.add(b)
		}
		negateBits(cls)
	}
}

func addClassRange(cls *classNode, lo, hi byte) {
	for b := int(lo); b <= int(hi); b++ {
		cls.add(byte(b))
	}
}

func negateBits(cls *classNode) {
	for i := range cls.bits {
		cls.bits[i] = ^cls.bits[i]
	}
}
