// Package afrogx —— afrog 经典 rules+expression 表达式的编译与运行时求值。
//
// 背景（BUG-016）：afrog 模板的 rule 里**没有 response: 块**——判定条件全部
// 写在 rule 级 expression 上，形如：
//
//	response.status == 200 && response.body.bcontains(b"<?php")
//	response.status == 200 && "Version: (.*)".bmatches(response.body)
//
// 此前 internal/nuclei 的 afrogRule 结构体**没有 expression 字段**，yaml.v3
// 静默丢弃未知字段 → 无法构造任何 matcher → 整个 afrog 来源（1,699 条模板）
// 的通过率为 0（实测：2,519 条 rule 全部带 expression，0 条带 response 块）。
//
// 本包提供**受限**的表达式求值器，边界刻意保守：
//
//	支持：状态码比较、正文/原始体包含（大小写敏感与不敏感）、正文正则匹配、
//	      响应头与 content-type 包含、true/false，以及 && / || / ! / 括号组合。
//	不支持：带外探测（oobCheck）、随机标记回显（bytes(randbody) 等）、
//	      时延判定（response.latency）。
//	      → 这些表达式**不可判定**，Compile 返回 error，调用方必须**整条拒收**
//	        （宁少报不误报，与漏斗「不能诚实映射就拒收」的哲学一致）。
//
// 求值在**运行时**（拿到实际响应后）进行——静态编译成 matcher 会丢失
// 「大小写不敏感」「正则」「响应头」等语义。
package afrogx

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Response 求值上下文（运行时）。
type Response struct {
	Status  int
	Body    string
	Headers map[string]string
}

// header 取响应头（大小写不敏感）。
func (r Response) header(name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// node 表达式节点。
type node interface {
	eval(r Response) (bool, string)
	// ground 报告该子树是否含**正向内容判定**（neg 表示当前处于取反下）。
	ground(neg bool) bool
}

// Program 编译后的表达式。
type Program struct {
	root node
	expr string
}

// Eval 求值。返回（命中，原因）。
//
// 运行期**只有「条件不满足」一种 false**：不可判定的表达式在编译期就被拒
// （Compile 返回 error），运行期求值出错也一律按不命中处理——宁少报不误报。
func (p *Program) Eval(r Response) (bool, string) {
	if p == nil || p.root == nil {
		return false, ""
	}
	return p.root.eval(r)
}

// String 还原表达式原文（证据展示用）。
func (p *Program) String() string {
	if p == nil {
		return ""
	}
	return p.expr
}

// PositiveGround 报告表达式是否含至少一个**正向内容判定**原子。
//
// 与 internal/dsl 的 PositiveGround 同哲学：纯状态码、恒真、纯取反的判定
// 不具备"内容证据"，放行会退化成"路径存在即命中"（CDN/WAF 环境大面积误报）。
// 口径刻意保守：只认**未处于取反下**的 response.body / response.raw 包含
// 与正文正则。响应头 / content-type 包含不算——单独用它判存在性对任意
// 站点都可能恒真（如 `Server: nginx`）。
func (p *Program) PositiveGround() bool {
	if p == nil || p.root == nil {
		return false
	}
	return p.root.ground(false)
}

// cache 编译结果缓存（表达式文本 → 编译产物）。
// 编译失败也要缓存：同一批模板反复转换，失败原因不变。
var cache sync.Map // map[string]*cacheEntry

type cacheEntry struct {
	prog *Program
	err  error
}

// Get 取编译后的程序（带缓存）。编译失败返回 error —— 调用方必须整条拒收。
func Get(expr string) (*Program, error) {
	if v, ok := cache.Load(expr); ok {
		e := v.(*cacheEntry)
		return e.prog, e.err
	}
	prog, err := Compile(expr)
	cache.Store(expr, &cacheEntry{prog: prog, err: err})
	return prog, err
}

// Compile 解析并编译表达式。含不支持的原子或语法错误时返回 error。
func Compile(expr string) (*Program, error) {
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, src: expr}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if !p.atEnd() {
		return nil, fmt.Errorf("表达式尾部有多余内容 %q", p.peek().text)
	}
	return &Program{root: n, expr: expr}, nil
}

/* ---------------- 词法 ---------------- */

type tokKind int

const (
	tkEOF tokKind = iota
	tkIdent
	tkStr
	tkNum
	tkOp
)

type token struct {
	kind tokKind
	text string // ident / num / op 原文；str 则是含前缀与引号的原文
	str  string // 字符串字面量内容（已去前缀与引号）
	raw  bool   // r 前缀（原文，不解转义）
}

func (t token) String() string { return t.text }

func isStrPrefix(word string) bool {
	switch strings.ToLower(word) {
	case "b", "r", "br", "rb":
		return true
	}
	return false
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"' || c == '\'':
			tok, next, err := lexString(src, i, "")
			if err != nil {
				return nil, err
			}
			out = append(out, tok)
			i = next
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			out = append(out, token{kind: tkNum, text: src[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			word := src[i:j]
			// b/r 前缀 + 引号 = 字节串 / 原文（正则）字面量。
			// 不先判前缀，r'...' 会被拆成标识符 r + 字符串，表达式随即不可解析。
			if isStrPrefix(word) && j < len(src) && (src[j] == '"' || src[j] == '\'') {
				tok, next, err := lexString(src, j, word)
				if err != nil {
					return nil, err
				}
				out = append(out, tok)
				i = next
				continue
			}
			out = append(out, token{kind: tkIdent, text: word})
			i = j
		default:
			two := ""
			if i+1 < len(src) {
				two = src[i : i+2]
			}
			switch two {
			case "==", "!=", "<=", ">=", "&&", "||":
				out = append(out, token{kind: tkOp, text: two})
				i += 2
				continue
			}
			switch c {
			case '<', '>', '!', '(', ')', '[', ']', ',', '.':
				out = append(out, token{kind: tkOp, text: string(c)})
				i++
			default:
				return nil, fmt.Errorf("无法识别的字符 %q", string(c))
			}
		}
	}
	out = append(out, token{kind: tkEOF})
	return out, nil
}

// lexString 从 i 处（引号或已消费的 b/r 前缀之后）读取字符串字面量。
func lexString(src string, i int, prefix string) (token, int, error) {
	start := i - len(prefix)
	if i >= len(src) {
		return token{}, i, fmt.Errorf("字符串字面量未闭合：%q", src[start:])
	}
	quote := src[i]
	i++
	var sb strings.Builder
	raw := strings.Contains(strings.ToLower(prefix), "r")
	for i < len(src) {
		ch := src[i]
		if ch == '\\' && !raw && i+1 < len(src) {
			i++
			sb.WriteByte(src[i])
			i++
			continue
		}
		if ch == quote {
			i++
			return token{kind: tkStr, str: sb.String(), raw: raw, text: src[start:i]}, i, nil
		}
		sb.WriteByte(ch)
		i++
	}
	return token{}, i, fmt.Errorf("字符串字面量未闭合：%q", src[start:])
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

/* ---------------- 语法 ---------------- */

type parser struct {
	toks []token
	pos  int
	src  string
	// pendingFunc parsePath 识别出的函数名（bcontains/contains/…）。
	// 路径与函数名分开处理：路径只到数据源（response.body），
	// 函数名决定判定方式。
	pendingFunc string
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) atEnd() bool { return p.toks[p.pos].kind == tkEOF }

func (p *parser) acceptOp(op string) bool {
	if p.peek().kind == tkOp && p.peek().text == op {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expectOp(op string) error {
	if !p.acceptOp(op) {
		return fmt.Errorf("期望 %q，实际 %q", op, p.peek().text)
	}
	return nil
}

// parseOr := and ('||' and)*
func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.acceptOp("||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orNode{l: left, r: right}
	}
	return left, nil
}

// parseAnd := unary ('&&' unary)*
func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.acceptOp("&&") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &andNode{l: left, r: right}
	}
	return left, nil
}

// parseUnary := '!' unary | primary
func (p *parser) parseUnary() (node, error) {
	if p.acceptOp("!") {
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{x: x}, nil
	}
	return p.parsePrimary()
}

// parsePrimary := '(' or ')' | atom
func (p *parser) parsePrimary() (node, error) {
	if p.acceptOp("(") {
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expectOp(")"); err != nil {
			return nil, err
		}
		return n, nil
	}
	return p.parseAtom()
}

// parseAtom 处理具体的判定原子。
func (p *parser) parseAtom() (node, error) {
	t := p.peek()
	switch {
	case t.kind == tkStr:
		// "re".bmatches(response.body) / r"re".bmatches(...)
		p.next()
		if err := p.expectOp("."); err != nil {
			return nil, err
		}
		fn := p.next()
		if fn.kind != tkIdent || fn.text != "bmatches" {
			return nil, fmt.Errorf("字符串字面量后只支持 .bmatches，实际 %q", fn.text)
		}
		if err := p.expectOp("("); err != nil {
			return nil, err
		}
		target, err := p.parsePath()
		if err != nil {
			return nil, err
		}
		if err := p.expectOp(")"); err != nil {
			return nil, err
		}
		if target != "response.body" {
			return nil, fmt.Errorf("bmatches 仅支持 response.body，实际 %q", target)
		}
		re, err := regexp.Compile(t.str)
		if err != nil {
			return nil, fmt.Errorf("正则非法：%v", err)
		}
		return &regexNode{pattern: t.str, re: re}, nil

	case t.kind == tkIdent:
		switch t.text {
		case "true", "false":
			p.next()
			return &constNode{v: t.text == "true"}, nil
		case "oobCheck":
			return nil, fmt.Errorf("带外探测表达式（oobCheck）不支持：需要外部带外服务，本引擎无此能力")
		case "bytes", "string", "md5":
			return nil, fmt.Errorf("afrog 运行时函数 %s(...) 不支持", t.text)
		}
		path, err := p.parsePath()
		if err != nil {
			return nil, err
		}
		return p.parseAtomTail(path)
	}
	return nil, fmt.Errorf("无法解析的表达式片段 %q", t.text)
}

// parsePath 读取点分路径（response.body / response.status …）。
// 路径里**不含**函数名（bcontains 等）——函数名由 parseAtomTail 单独识别。
func (p *parser) parsePath() (string, error) {
	t := p.next()
	if t.kind != tkIdent {
		return "", fmt.Errorf("期望标识符，实际 %q", t.text)
	}
	path := t.text
	for p.peek().kind == tkOp && p.peek().text == "." {
		// 下一段若是已知函数名，交由 parseAtomTail 处理（不并入路径）
		p.next()
		n := p.next()
		if n.kind != tkIdent {
			return "", fmt.Errorf("路径片段非法 %q", n.text)
		}
		if isFuncName(n.text) {
			// 把函数名回退成一个「待处理」标记：路径已完整，函数名留给调用方
			p.pendingFunc = n.text
			return path, nil
		}
		path += "." + n.text
	}
	return path, nil
}

func isFuncName(s string) bool {
	switch s {
	case "bcontains", "ibcontains", "contains", "bmatches":
		return true
	}
	return false
}

// parseAtomTail 处理路径后的比较或函数调用。
func (p *parser) parseAtomTail(path string) (node, error) {
	switch path {
	case "response.status":
		op, num, err := p.parseCmp()
		if err != nil {
			return nil, err
		}
		return &cmpNode{name: "status", op: op, num: num}, nil

	case "response.latency":
		return nil, fmt.Errorf("时延判定（response.latency）不支持：需采集响应耗时，且时延判定易受网络抖动干扰")

	case "response.body", "response.raw", "response.raw_header":
		fn := p.takeFunc()
		if fn != "bcontains" && fn != "ibcontains" {
			return nil, fmt.Errorf("%s 后只支持 bcontains/ibcontains，实际 %q", path, fn)
		}
		needle, err := p.parseCallArg()
		if err != nil {
			return nil, err
		}
		return &containsNode{value: path, needle: needle, insensitive: fn == "ibcontains"}, nil

	case "response.content_type":
		fn := p.takeFunc()
		if fn != "contains" {
			return nil, fmt.Errorf("response.content_type 后只支持 contains，实际 %q", fn)
		}
		needle, err := p.parseCallArg()
		if err != nil {
			return nil, err
		}
		return &containsNode{value: "response.content_type", needle: needle}, nil

	case "response.headers":
		if err := p.expectOp("["); err != nil {
			return nil, err
		}
		name := p.next()
		if name.kind != tkStr {
			return nil, fmt.Errorf("response.headers[...] 需要字符串下标，实际 %q", name.text)
		}
		if err := p.expectOp("]"); err != nil {
			return nil, err
		}
		if err := p.expectOp("."); err != nil {
			return nil, err
		}
		fn := p.next()
		if fn.kind != tkIdent || fn.text != "contains" {
			return nil, fmt.Errorf("response.headers[...] 后只支持 contains，实际 %q", fn.text)
		}
		needle, err := p.parseCallArg()
		if err != nil {
			return nil, err
		}
		return &containsNode{value: "response.headers[" + name.str + "]", needle: needle}, nil
	}
	return nil, fmt.Errorf("不支持的表达式路径 %q", path)
}

// takeFunc 取回 parsePath 识别出的函数名。
func (p *parser) takeFunc() string {
	f := p.pendingFunc
	p.pendingFunc = ""
	return f
}

// parseCmp 读取比较运算符与数值。
func (p *parser) parseCmp() (string, int, error) {
	op := p.next()
	if op.kind != tkOp {
		return "", 0, fmt.Errorf("期望比较运算符，实际 %q", op.text)
	}
	switch op.text {
	case "==", "!=", "<=", ">=", "<", ">":
	default:
		return "", 0, fmt.Errorf("不支持的比较运算符 %q", op.text)
	}
	num := p.next()
	if num.kind != tkNum {
		return "", 0, fmt.Errorf("比较右值必须是数字，实际 %q", num.text)
	}
	n, err := strconv.Atoi(num.text)
	if err != nil {
		return "", 0, fmt.Errorf("比较右值非法 %q", num.text)
	}
	return op.text, n, nil
}

// parseCallArg 读取 (…) 包裹的字符串实参（实参与调用括号分开：
// bytes("x") 的内层括号由 parseArg 消费，外层括号在这里消费）。
func (p *parser) parseCallArg() (string, error) {
	if err := p.expectOp("("); err != nil {
		return "", err
	}
	s, err := p.parseArg()
	if err != nil {
		return "", err
	}
	if err := p.expectOp(")"); err != nil {
		return "", err
	}
	return s, nil
}

// parseArg 读取一个字符串实参：字面量或 bytes("…")。
func (p *parser) parseArg() (string, error) {
	t := p.next()
	if t.kind == tkStr {
		return t.str, nil
	}
	if t.kind == tkIdent {
		// bytes("…") —— 字节串字面量，与普通字符串等价
		if t.text != "bytes" {
			return "", fmt.Errorf("不支持的函数 %s(...)", t.text)
		}
		if err := p.expectOp("("); err != nil {
			return "", err
		}
		inner := p.next()
		if inner.kind != tkStr {
			return "", fmt.Errorf("bytes(...) 只接受字符串字面量（bytes(randbody) 等随机标记不支持）")
		}
		if err := p.expectOp(")"); err != nil {
			return "", err
		}
		return inner.str, nil
	}
	return "", fmt.Errorf("期望字符串字面量，实际 %q", t.text)
}

/* ---------------- 求值 ---------------- */

type orNode struct{ l, r node }

func (n *orNode) eval(r Response) (bool, string) {
	ok, why := n.l.eval(r)
	if ok {
		return true, why
	}
	return n.r.eval(r)
}

func (n *orNode) ground(neg bool) bool { return n.l.ground(neg) || n.r.ground(neg) }

type andNode struct{ l, r node }

func (n *andNode) eval(r Response) (bool, string) {
	ok, why := n.l.eval(r)
	if !ok {
		return false, ""
	}
	ok2, why2 := n.r.eval(r)
	if !ok2 {
		return false, ""
	}
	return true, why + " 且 " + why2
}

func (n *andNode) ground(neg bool) bool { return n.l.ground(neg) || n.r.ground(neg) }

type notNode struct{ x node }

func (n *notNode) eval(r Response) (bool, string) {
	ok, _ := n.x.eval(r)
	return !ok, ""
}

func (n *notNode) ground(neg bool) bool { return n.x.ground(!neg) }

type constNode struct{ v bool }

func (n *constNode) eval(Response) (bool, string) {
	if n.v {
		return true, "恒真"
	}
	return false, ""
}

func (n *constNode) ground(bool) bool { return false }

type cmpNode struct {
	name string
	op   string
	num  int
}

func (n *cmpNode) eval(r Response) (bool, string) {
	var got int
	switch n.name {
	case "status":
		got = r.Status
	}
	var ok bool
	switch n.op {
	case "==":
		ok = got == n.num
	case "!=":
		ok = got != n.num
	case "<=":
		ok = got <= n.num
	case ">=":
		ok = got >= n.num
	case "<":
		ok = got < n.num
	case ">":
		ok = got > n.num
	}
	if !ok {
		return false, ""
	}
	return true, fmt.Sprintf("%s %s %d", n.name, n.op, n.num)
}

// ground 状态码比较不是内容判定：纯状态码 check 在 CDN/WAF 下任意路径
// 都可能命中（与 buildChecks 的既有闸门同哲学）。
func (n *cmpNode) ground(bool) bool { return false }

type containsNode struct {
	value       string
	needle      string
	insensitive bool
}

func (n *containsNode) eval(r Response) (bool, string) {
	var hay string
	switch {
	case n.value == "response.body":
		hay = r.Body
	case n.value == "response.raw", n.value == "response.raw_header":
		// 本引擎未保留未解码的原始报文；按正文处理（少报不误报方向安全）
		hay = r.Body
	case n.value == "response.content_type":
		hay = r.header("Content-Type")
	case strings.HasPrefix(n.value, "response.headers["):
		name := strings.TrimSuffix(strings.TrimPrefix(n.value, "response.headers["), "]")
		hay = r.header(name)
	default:
		return false, ""
	}
	var ok bool
	if n.insensitive {
		ok = strings.Contains(strings.ToLower(hay), strings.ToLower(n.needle))
	} else {
		ok = strings.Contains(hay, n.needle)
	}
	if !ok {
		return false, ""
	}
	return true, fmt.Sprintf("%s 包含 %q", n.value, n.needle)
}

// ground 只有**正文**包含算内容判定；响应头 / content-type 单独使用对任意
// 站点都可能恒真（如 `Server: nginx`），不足以作为"存在性"证据。
func (n *containsNode) ground(neg bool) bool {
	if neg {
		return false // 纯取反（"不含某内容"）几乎恒真，不算内容证据
	}
	return n.value == "response.body" || n.value == "response.raw"
}

type regexNode struct {
	pattern string
	re      *regexp.Regexp
}

func (n *regexNode) eval(r Response) (bool, string) {
	if !n.re.MatchString(r.Body) {
		return false, ""
	}
	return true, fmt.Sprintf("正文匹配正则 %q", n.pattern)
}

// ground 正文正则匹配算内容判定；取反下的正则（"不匹配"）不算。
func (n *regexNode) ground(neg bool) bool { return !neg }
