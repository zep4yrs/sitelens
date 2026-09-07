// Package dsl Nuclei 模板 dsl 表达式的安全子集求值器。
//
// 仅支持可静态验证、无外部副作用的表达式形态（覆盖真实模板库 96%+
// 的 dsl 用法）：比较运算、逻辑组合、字符串函数与变量取值。Convert
// 阶段用 Compile 做准入（子集外整模板跳过），matchBody 阶段用
// Eval 求值（运行期类型错误一律不命中——宁少报不误报）。
//
// 支持面：
//
//	变量     status_code(int) body(string) header/headers(map) host(string)
//	函数     contains contains_all contains_any icontains regex
//	         to_lower/tolower to_upper/toupper starts_with ends_with len
//	运算     == != > < >= <= && || ! ( ) 以及字符串/整数/布尔字面量
//	字面量   '单引号' "双引号" r'原始串' 整数 true false
//
// 明确不支持（准入即拒）：算术与字符串拼接（+）、解包变量（status_code_2
// 等多请求形态）、extract 绑定变量（version/username/duration 等）、
// 哈希/编码/时间函数（mmh3/sha1/base64/date 等）。
package dsl

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Env 变量取值环境（求值期由调用方实现；header 名匹配大小写不敏感）。
type Env interface {
	StatusCode() int
	Body() string
	Header(name string) string // 单头取值，不存在返回空串（头 map 的整体包含不是子集语义，不支持）
	Host() string
}

// ---- 值模型：三类（字符串/整数/布尔），跨类运算即求值错误 ----

const (
	kStr = iota
	kInt
	kBool
)

type value struct {
	kind int
	s    string
	i    int64
	b    bool
}

func (v value) truth() (bool, error) {
	switch v.kind {
	case kBool:
		return v.b, nil
	default:
		return false, fmt.Errorf("dsl: 非布尔值不能作逻辑分支")
	}
}

// ---- AST ----

type node interface {
	eval(e Env) (value, error)
	// positive 报告该子树在给定取反奇偶下是否构成「正向命中依据」：
	// 引用了 status_code/body/header 且不在奇数次取反之下。用于
	// Convert 准入——纯排除式（如 !contains(host,...)）不转换为
	// check，避免对任意响应恒真的空转模板。
	positive(negated bool) bool
}

type orNode struct{ l, r node }

func (n orNode) eval(e Env) (value, error) {
	a, err := n.l.eval(e)
	if err != nil {
		return value{}, err
	}
	lb, err := a.truth()
	if err != nil {
		return value{}, err
	}
	if lb {
		return value{kind: kBool, b: true}, nil
	}
	rb, err := n.r.eval(e)
	if err != nil {
		return value{}, err
	}
	x, err := rb.truth()
	if err != nil {
		return value{}, err
	}
	return value{kind: kBool, b: x}, nil
}

func (n orNode) positive(neg bool) bool { return n.l.positive(neg) || n.r.positive(neg) }

type andNode struct{ l, r node }

func (n andNode) eval(e Env) (value, error) {
	a, err := n.l.eval(e)
	if err != nil {
		return value{}, err
	}
	lb, err := a.truth()
	if err != nil {
		return value{}, err
	}
	if !lb {
		return value{kind: kBool, b: false}, nil
	}
	rb, err := n.r.eval(e)
	if err != nil {
		return value{}, err
	}
	x, err := rb.truth()
	if err != nil {
		return value{}, err
	}
	return value{kind: kBool, b: x}, nil
}

// AND 的 positive 取存在语义：任一支含正向依据即判定整体「做了实事」
// （另一支即便是恒真的排除式也不影响命中需要正向支成立）。
func (n andNode) positive(neg bool) bool { return n.l.positive(neg) || n.r.positive(neg) }

type notNode struct{ n node }

func (n notNode) eval(e Env) (value, error) {
	v, err := n.n.eval(e)
	if err != nil {
		return value{}, err
	}
	b, err := v.truth()
	if err != nil {
		return value{}, err
	}
	return value{kind: kBool, b: !b}, nil
}

func (n notNode) positive(neg bool) bool {
	// 取反之下引用 target 变量不再构成正向依据（!contains(body,x) 单独
	// 成立时几乎恒真），但保持 OR 语义——另一分支的正向依据不受影响
	_ = neg
	return false
}

type cmpNode struct {
	op   string
	l, r node
}

func (n cmpNode) eval(e Env) (value, error) {
	a, err := n.l.eval(e)
	if err != nil {
		return value{}, err
	}
	b, err := n.r.eval(e)
	if err != nil {
		return value{}, err
	}
	switch n.op {
	case "==", "!=":
		eq, err := valuesEqual(a, b)
		if err != nil {
			return value{}, err
		}
		return value{kind: kBool, b: eq == (n.op == "==")}, nil
	}
	// 排序比较：同为 int 数值序；同为 string 字典序
	var c int
	if a.kind == kInt && b.kind == kInt {
		switch {
		case a.i < b.i:
			c = -1
		case a.i > b.i:
			c = 1
		}
	} else if a.kind == kStr && b.kind == kStr {
		c = strings.Compare(a.s, b.s)
	} else {
		return value{}, fmt.Errorf("dsl: %s 比较的两侧类型不一致", n.op)
	}
	var res bool
	switch n.op {
	case ">":
		res = c > 0
	case "<":
		res = c < 0
	case ">=":
		res = c >= 0
	case "<=":
		res = c <= 0
	default:
		return value{}, fmt.Errorf("dsl: 未知比较符 %s", n.op)
	}
	return value{kind: kBool, b: res}, nil
}

func valuesEqual(a, b value) (bool, error) {
	if a.kind != b.kind {
		// int/bool 与字符串比较：不猜测语义，报错走不命中
		return false, fmt.Errorf("dsl: == 两侧类型不一致")
	}
	switch a.kind {
	case kStr:
		return a.s == b.s, nil
	case kInt:
		return a.i == b.i, nil
	default:
		return a.b == b.b, nil
	}
}

func (n cmpNode) positive(neg bool) bool {
	if neg {
		return false
	}
	return readsTarget(n.l) || readsTarget(n.r)
}

type callNode struct {
	name string
	args []node
}

func (n callNode) eval(e Env) (value, error) {
	switch n.name {
	case "contains", "icontains", "starts_with", "ends_with":
		if len(n.args) != 2 {
			return value{}, fmt.Errorf("dsl: %s 需要 2 个参数", n.name)
		}
		hay, err := evalString(n.args[0], e)
		if err != nil {
			return value{}, err
		}
		needle, err := evalString(n.args[1], e)
		if err != nil {
			return value{}, err
		}
		var res bool
		switch n.name {
		case "contains":
			res = strings.Contains(hay, needle)
		case "icontains":
			res = strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
		case "starts_with":
			res = strings.HasPrefix(hay, needle)
		default:
			res = strings.HasSuffix(hay, needle)
		}
		return value{kind: kBool, b: res}, nil
	case "contains_all", "contains_any":
		if len(n.args) < 2 {
			return value{}, fmt.Errorf("dsl: %s 至少 2 个参数", n.name)
		}
		hay, err := evalString(n.args[0], e)
		if err != nil {
			return value{}, err
		}
		all := n.name == "contains_all"
		for _, a := range n.args[1:] {
			needle, err := evalString(a, e)
			if err != nil {
				return value{}, err
			}
			hit := strings.Contains(hay, needle)
			if all && !hit {
				return value{kind: kBool, b: false}, nil
			}
			if !all && hit {
				return value{kind: kBool, b: true}, nil
			}
		}
		return value{kind: kBool, b: all}, nil
	case "to_lower", "tolower", "to_upper", "toupper":
		if len(n.args) != 1 {
			return value{}, fmt.Errorf("dsl: %s 需要 1 个参数", n.name)
		}
		s, err := evalString(n.args[0], e)
		if err != nil {
			return value{}, err
		}
		if n.name == "to_lower" || n.name == "tolower" {
			s = strings.ToLower(s)
		} else {
			s = strings.ToUpper(s)
		}
		return value{kind: kStr, s: s}, nil
	case "regex":
		if len(n.args) != 2 {
			return value{}, fmt.Errorf("dsl: regex 需要 2 个参数")
		}
		pat, err := evalString(n.args[0], e)
		if err != nil {
			return value{}, err
		}
		s, err := evalString(n.args[1], e)
		if err != nil {
			return value{}, err
		}
		re, err := regexCache(pat)
		if err != nil {
			return value{}, err
		}
		return value{kind: kBool, b: re.MatchString(s)}, nil
	case "len":
		if len(n.args) != 1 {
			return value{}, fmt.Errorf("dsl: len 需要 1 个参数")
		}
		v, err := n.args[0].eval(e)
		if err != nil {
			return value{}, err
		}
		if v.kind == kStr {
			return value{kind: kInt, i: int64(len(v.s))}, nil
		}
		return value{}, fmt.Errorf("dsl: len 仅支持字符串")
	}
	return value{}, fmt.Errorf("dsl: 不支持的函数 %s", n.name)
}

func evalString(n node, e Env) (string, error) {
	v, err := n.eval(e)
	if err != nil {
		return "", err
	}
	if v.kind != kStr {
		return "", fmt.Errorf("dsl: 期望字符串实参")
	}
	return v.s, nil
}

var targetCallNames = map[string]bool{
	"contains": true, "contains_all": true, "contains_any": true,
	"icontains": true, "regex": true, "starts_with": true, "ends_with": true,
}

func (n callNode) positive(neg bool) bool {
	if neg || !targetCallNames[n.name] {
		return false
	}
	for _, a := range n.args {
		if readsTarget(a) {
			return true
		}
	}
	return false
}

func readsTarget(n node) bool {
	switch t := n.(type) {
	case varNode:
		return t.name == "body" || t.name == "header" || t.name == "headers" || t.name == "status_code"
	case idxNode:
		return t.mapName == "header" || t.mapName == "headers"
	case callNode:
		for _, a := range t.args {
			if readsTarget(a) {
				return true
			}
		}
	case cmpNode:
		return readsTarget(t.l) || readsTarget(t.r)
	case andNode:
		return readsTarget(t.l) && readsTarget(t.r)
	case orNode:
		return readsTarget(t.l) || readsTarget(t.r)
	}
	return false
}

type litNode struct{ v value }

func (n litNode) eval(Env) (value, error) { return n.v, nil }
func (n litNode) positive(bool) bool      { return false }

type varNode struct{ name string }

func (n varNode) eval(e Env) (value, error) {
	switch n.name {
	case "status_code":
		return value{kind: kInt, i: int64(e.StatusCode())}, nil
	case "body":
		return value{kind: kStr, s: e.Body()}, nil
	case "host":
		return value{kind: kStr, s: e.Host()}, nil
	}
	return value{}, fmt.Errorf("dsl: 未知变量 %s", n.name)
}

func (n varNode) positive(bool) bool {
	// 裸变量引用（如 body 非空真值）不单独成依据，防止恒真模板
	return false
}

type idxNode struct {
	mapName string
	key     node
}

func (n idxNode) eval(e Env) (value, error) {
	k, err := evalString(n.key, e)
	if err != nil {
		return value{}, err
	}
	switch n.mapName {
	case "header", "headers":
		return value{kind: kStr, s: e.Header(k)}, nil
	}
	return value{}, fmt.Errorf("dsl: 不支持下标的变量 %s", n.mapName)
}

func (n idxNode) positive(bool) bool { return false }

// ---- 词法 ----

type tokKind int

const (
	tEOF tokKind = iota
	tNum
	tStr
	tIdent
	tOp
	tLParen
	tRParen
	tLBracket
	tRBracket
	tComma
)

type token struct {
	kind tokKind
	text string
}

func tokenize(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			out = append(out, token{tNum, src[i:j]})
			i = j
		case c == '\'' || c == '"' || (c == 'r' && i+1 < len(src) && (src[i+1] == '\'' || src[i+1] == '"')):
			quote := c
			isRaw := false
			if c == 'r' {
				isRaw = true
				i++
				quote = src[i]
			}
			j := i + 1
			var sb strings.Builder
			closed := false
			for j < len(src) {
				ch := src[j]
				if ch == '\\' && !isRaw && j+1 < len(src) {
					j++
					switch src[j] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					default:
						sb.WriteByte(src[j])
					}
					j++
					continue
				}
				if ch == quote {
					closed = true
					j++
					break
				}
				sb.WriteByte(ch)
				j++
			}
			if !closed {
				return nil, fmt.Errorf("dsl: 字符串未闭合")
			}
			out = append(out, token{tStr, sb.String()})
			i = j
		case isIdentChar(c): // r'...' 原始串已被上方字面量分支先行截获
			j := i
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			out = append(out, token{tIdent, src[i:j]})
			i = j
		case c == '(':
			out = append(out, token{tLParen, "("})
			i++
		case c == ')':
			out = append(out, token{tRParen, ")"})
			i++
		case c == '[':
			out = append(out, token{tLBracket, "["})
			i++
		case c == ']':
			out = append(out, token{tRBracket, "]"})
			i++
		case c == ',':
			out = append(out, token{tComma, ","})
			i++
		case strings.HasPrefix(src[i:], "=="), strings.HasPrefix(src[i:], "!="),
			strings.HasPrefix(src[i:], ">="), strings.HasPrefix(src[i:], "<="),
			strings.HasPrefix(src[i:], "&&"), strings.HasPrefix(src[i:], "||"):
			out = append(out, token{tOp, src[i : i+2]})
			i += 2
		case c == '>' || c == '<' || c == '!':
			out = append(out, token{tOp, string(c)})
			i++
		default:
			return nil, fmt.Errorf("dsl: 无法识别的字符 %q", c)
		}
	}
	out = append(out, token{tEOF, ""})
	return out, nil
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ---- 语法分析（递归下降）----
// or → and → ('!' ) cmp → primary

type parser struct {
	toks  []token
	pos   int
	depth int // 括号/逻辑嵌套深度（防深嵌套递归爆栈——fuzz 实测可达）
}

// maxDepth 嵌套深度上限：真实模板的 dsl 表达式嵌套不超过个位数，
// 64 已宽松两个数量级；超出即准入拒绝而非递归到底。
const maxDepth = 64

// maxExprLen 表达式长度上限：真实 dsl 行均在数百字符内，超长即拒绝
// （正则实参的编译成本与长度和嵌套正相关，入口封顶最省心）。
const maxExprLen = 8192

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) isOp(s string) bool {
	t := p.peek()
	return t.kind == tOp && t.text == s
}

var knownFuncs = map[string]bool{
	"contains": true, "contains_all": true, "contains_any": true, "icontains": true,
	"regex": true, "to_lower": true, "tolower": true, "to_upper": true, "toupper": true,
	"starts_with": true, "ends_with": true, "len": true,
}

var knownVars = map[string]bool{
	"status_code": true, "body": true, "header": true, "headers": true, "host": true,
}

func (p *parser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isOp("||") {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = orNode{l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isOp("&&") {
		p.pos++
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = andNode{l, r}
	}
	return l, nil
}

func (p *parser) parseNot() (node, error) {
	if p.isOp("!") {
		p.pos++
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (node, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind == tOp && (t.text == "==" || t.text == "!=" || t.text == ">" ||
		t.text == "<" || t.text == ">=" || t.text == "<=") {
		p.pos++
		r, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return cmpNode{op: t.text, l: l, r: r}, nil
	}
	return l, nil
}

func (p *parser) parsePrimary() (node, error) {
	t := p.next()
	switch t.kind {
	case tNum:
		var n int64
		for _, c := range t.text {
			n = n*10 + int64(c-'0')
		}
		return litNode{value{kind: kInt, i: n}}, nil
	case tStr:
		return litNode{value{kind: kStr, s: t.text}}, nil
	case tLParen:
		p.depth++
		defer func() { p.depth-- }()
		if p.depth > maxDepth {
			return nil, fmt.Errorf("dsl: 括号嵌套超过 %d 层", maxDepth)
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next().kind != tRParen {
			return nil, fmt.Errorf("dsl: 缺少右括号")
		}
		return inner, nil
	case tIdent:
		name := strings.ToLower(t.text)
		if name == "true" {
			return litNode{value{kind: kBool, b: true}}, nil
		}
		if name == "false" {
			return litNode{value{kind: kBool, b: false}}, nil
		}
		switch p.peek().kind {
		case tLParen:
			if !knownFuncs[name] {
				return nil, fmt.Errorf("dsl: 不支持的函数 %s", name)
			}
			p.pos++
			var args []node
			if p.peek().kind != tRParen {
				for {
					a, err := p.parseOr()
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if p.peek().kind == tComma {
						p.pos++
						continue
					}
					break
				}
			}
			if p.next().kind != tRParen {
				return nil, fmt.Errorf("dsl: %s 参数列表未闭合", name)
			}
			switch name {
			case "contains", "icontains", "regex", "starts_with", "ends_with", "to_lower", "tolower", "to_upper", "toupper", "len":
				if len(args) != arityOf(name) {
					return nil, fmt.Errorf("dsl: %s 参数个数错误", name)
				}
			case "contains_all", "contains_any":
				if len(args) < 2 {
					return nil, fmt.Errorf("dsl: %s 至少 2 个参数", name)
				}
			}
			return callNode{name: name, args: args}, nil
		case tLBracket:
			if name != "header" && name != "headers" {
				return nil, fmt.Errorf("dsl: 变量 %s 不支持下标", name)
			}
			p.pos++
			k, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			if p.next().kind != tRBracket {
				return nil, fmt.Errorf("dsl: 下标未闭合")
			}
			return idxNode{mapName: name, key: k}, nil
		default:
			if !knownVars[name] {
				return nil, fmt.Errorf("dsl: 未知变量 %s", name)
			}
			return varNode{name: name}, nil
		}
	}
	return nil, fmt.Errorf("dsl: 意外的记号 %q", t.text)
}

func arityOf(name string) int {
	switch name {
	case "contains", "icontains", "regex", "starts_with", "ends_with":
		return 2
	default:
		return 1
	}
}

// ---- 对外 API ----

// Program 编译后的表达式（不可变，可并发求值）。
type Program struct {
	root node
}

// Compile 解析并校验表达式；子集外的任何形态都返回错误。
func Compile(expr string) (*Program, error) {
	if len(expr) > maxExprLen {
		return nil, fmt.Errorf("dsl: 表达式超过 %d 字符上限", maxExprLen)
	}
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, fmt.Errorf("dsl: 表达式尾部有多余内容 %q", p.peek().text)
	}
	return &Program{root: root}, nil
}

// Eval 求值；任何类型错误都原样上抛，由调用方决定不命中。
func (p *Program) Eval(e Env) (bool, error) {
	v, err := p.root.eval(e)
	if err != nil {
		return false, err
	}
	return v.truth()
}

// PositiveGround 静态判定：表达式是否含「正向命中依据」——在偶数次
// 取反之下引用了 status_code/body/header 的比较或包含函数。纯排除式
// （如 !contains(host,"x.com")）返回 false，Convert 据此跳过模板，
// 避免生成对任意响应恒真的空转 check。
func (p *Program) PositiveGround() bool { return p.root.positive(false) }

var (
	progCache    sync.Map // expr(string) → *Program（Compile 结果含 error 的不缓存，错误路径走不到 Eval）
	progCacheN   atomic.Int64
	progCacheMax = 16384 // 模板库 dsl 表达式总量有限；上限防不可信输入无限膨胀
)

// CompileCached 带缓存的编译：matchBody 每 scan 每 check 都会走到，
// 同一表达式全库复用一份 AST。
func CompileCached(expr string) (*Program, error) {
	if v, ok := progCache.Load(expr); ok {
		return v.(*Program), nil
	}
	p, err := Compile(expr)
	if err != nil {
		return nil, err
	}
	if progCacheN.Add(1) <= int64(progCacheMax) {
		progCache.Store(expr, p)
	}
	return p, nil
}

var (
	reCache    sync.Map // pattern(string) → *regexp.Regexp
	reCacheN   atomic.Int64
	reCacheMax = 4096 // 生产端模式来自模板库（有限集）；上限防不可信输入无限膨胀
)

func regexCache(pat string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(pat); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("dsl: 正则编译失败: %v", err)
	}
	if reCacheN.Add(1) <= int64(reCacheMax) {
		reCache.Store(pat, re)
	}
	return re, nil
}
