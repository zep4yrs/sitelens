//go:build cgo

package astx

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"

	"cnb.cool/feng-qiao/sitelens/internal/astx/phpgram"
)

// Available 报告本二进制是否带真实 AST 解析器（CGO 构建为 true）。
func Available() bool { return true }

// newParser 按语言取 grammar 并装配解析器。
//
// 注：PHP 未纳入——其 grammar 依赖 `php/tree_sitter/*.h` 子目录，而该目录
// 无 Go 文件、会被 `go mod vendor` 丢弃（CI 有 vendor 一致性门禁），
// 故 PHP 的 AST 解析暂缓，白盒 PHP 仍走 audit 的行级正则（无回归）。
// 启用路径见 docs/开发文档-4.0.md 第 26.10 节。
func newParser(l Lang) (*sitter.Parser, bool) {
	var g *sitter.Language
	switch l {
	case LangPython:
		g = python.GetLanguage()
	case LangJS:
		g = javascript.GetLanguage()
	case LangPHP:
		g = phpgram.GetLanguage()
	case LangJava:
		g = java.GetLanguage()
	case LangGo:
		g = golang.GetLanguage()
	default:
		return nil, false
	}
	p := sitter.NewParser()
	p.SetLanguage(g)
	return p, true
}

// ---- 各语言语法节点类型与模式 ----

// sinkPat 一条 sink 识别模式。
type sinkPat struct {
	re   *regexp.Regexp
	kind string
}

// langSpec 一种语言的解析配置：函数/调用/赋值节点类型 + source/sink 模式。
type langSpec struct {
	funcKinds   map[string]bool
	callKinds   map[string]bool
	assignKinds map[string]bool
	sources     []*regexp.Regexp
	sinks       []sinkPat
}

func reSet(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

func sinkSet(pairs ...[2]string) []sinkPat {
	out := make([]sinkPat, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, sinkPat{re: regexp.MustCompile(p[1]), kind: p[0]})
	}
	return out
}

func kindSet(types ...string) map[string]bool {
	m := make(map[string]bool, len(types))
	for _, t := range types {
		m[t] = true
	}
	return m
}

// specs 各语言的解析配置。source/sink 模式只覆盖 P0 已核实的语义类别
// （命令/代码执行、SQL、反序列化、路径、弱哈希、模板），宁缺不猜。
var specs = map[Lang]*langSpec{
	LangPython: {
		funcKinds:   kindSet("function_definition", "lambda"),
		callKinds:   kindSet("call"),
		assignKinds: kindSet("assignment", "augmented_assignment"),
		sources: reSet(
			`\binput\s*\(`,
			`\bsys\.argv\b`,
			`\brequest\.(args|form|values|cookies|json|data|files|headers|get_json)\b`,
			`\bos\.environ\b`,
		),
		sinks: sinkSet(
			[2]string{SinkExecCmd, `\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output))\b`},
			[2]string{SinkCodeExec, `\b(eval|exec)\s*\(`},
			[2]string{SinkSQL, `\.(execute|executemany)\s*\(`},
			[2]string{SinkDeser, `\b(pickle\.loads?|yaml\.load|marshal\.loads)\b`},
			[2]string{SinkPath, `\bopen\s*\(`},
			[2]string{SinkWeakHash, `\b(hashlib\.(md5|sha1)|md5|sha1)\s*\(`},
			[2]string{SinkTemplate, `\brender_template_string\s*\(`},
		),
	},
	LangJS: {
		funcKinds: kindSet("function_declaration", "function", "arrow_function",
			"method_definition", "generator_function_declaration"),
		callKinds:   kindSet("call_expression", "new_expression"),
		assignKinds: kindSet("variable_declarator", "assignment_expression"),
		sources: reSet(
			`\breq\.(query|body|params|cookies|headers)\b`,
			`\bprocess\.argv\b`,
			`\blocation\.(search|hash|href)\b`,
			`\bdocument\.cookie\b`,
		),
		sinks: sinkSet(
			[2]string{SinkExecCmd, `\b(child_process|execSync|execFile|spawn)\b|\.exec\s*\(`},
			[2]string{SinkCodeExec, `\beval\s*\(|new\s+Function\s*\(`},
			[2]string{SinkSQL, `\.(query|execute)\s*\(`},
			[2]string{SinkPath, `\b(readFile|readFileSync|createReadStream)\s*\(`},
			[2]string{SinkWeakHash, `\b(md5|sha1)\s*\(`},
		),
	},
	LangPHP: {
		funcKinds:   kindSet("function_definition", "method_declaration"),
		callKinds:   kindSet("function_call_expression", "member_call_expression", "scoped_call_expression"),
		assignKinds: kindSet("assignment_expression"),
		sources: reSet(
			`\$_GET\b`, `\$_POST\b`, `\$_REQUEST\b`, `\$_COOKIE\b`, `\$_FILES\b`, `\$_SERVER\b`,
			`php://input`,
		),
		sinks: sinkSet(
			[2]string{SinkExecCmd, `\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(`},
			[2]string{SinkCodeExec, `\b(eval|assert|create_function)\s*\(`},
			[2]string{SinkSQL, `\b(mysql_query|mysqli_query|pg_query)\s*\(|->query\s*\(`},
			[2]string{SinkDeser, `\bunserialize\s*\(`},
			[2]string{SinkPath, `\b(include|include_once|require|require_once|file_get_contents|readfile|fopen)\s*\(`},
			[2]string{SinkWeakHash, `\b(md5|sha1)\s*\(`},
		),
	},
	LangJava: {
		funcKinds:   kindSet("method_declaration", "constructor_declaration"),
		callKinds:   kindSet("method_invocation", "object_creation_expression"),
		assignKinds: kindSet("variable_declarator", "assignment_expression"),
		sources: reSet(
			`\.getParameter\s*\(`,
			`\.getHeader\s*\(`,
			`\.getQueryString\s*\(`,
			`\.getCookies\s*\(`,
		),
		sinks: sinkSet(
			[2]string{SinkExecCmd, `Runtime\.getRuntime\s*\(\s*\)\.exec|new\s+ProcessBuilder`},
			[2]string{SinkCodeExec, `\.eval\s*\(|ScriptEngine`},
			[2]string{SinkSQL, `\.(executeQuery|executeUpdate|execute)\s*\(`},
			[2]string{SinkDeser, `ObjectInputStream|readObject\s*\(`},
			[2]string{SinkWeakHash, `MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"`},
		),
	},
	LangGo: {
		funcKinds:   kindSet("function_declaration", "method_declaration", "func_literal"),
		callKinds:   kindSet("call_expression"),
		assignKinds: kindSet("short_var_declaration", "assignment_statement", "var_spec"),
		sources: reSet(
			`\.FormValue\s*\(`,
			`\.PostFormValue\s*\(`,
			`\.URL\.Query\s*\(`,
			`\.Form\.Get\s*\(`,
		),
		sinks: sinkSet(
			[2]string{SinkExecCmd, `\bexec\.Command\b`},
			[2]string{SinkSQL, `\.(Query|QueryRow|Exec)\s*\(`},
			[2]string{SinkPath, `\b(os\.Open|os\.OpenFile|ioutil\.ReadFile|os\.ReadFile)\b`},
			[2]string{SinkWeakHash, `\b(md5|sha1)\.New\b`},
		),
	},
}

// ---- 对外入口 ----

// AnalyzeSource 分析一段源码（name 用于推断语言）。
func AnalyzeSource(name string, src []byte) (*Analysis, error) {
	l, ok := DetectLang(name)
	if !ok {
		return nil, ErrUnsupportedLang
	}
	return AnalyzeSourceLang(name, src, l)
}

// AnalyzeFile 读取并分析一个源文件。
func AnalyzeFile(path string) (*Analysis, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return AnalyzeSource(path, src)
}

// AnalyzeSourceLang 用指定语言分析一段源码。
func AnalyzeSourceLang(name string, src []byte, l Lang) (*Analysis, error) {
	spec, ok := specs[l]
	if !ok {
		return nil, ErrUnsupportedLang
	}
	p, ok := newParser(l)
	if !ok {
		return nil, ErrUnsupportedLang
	}
	defer p.Close()

	tree, err := p.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("astx: 解析 %s 失败: %w", name, err)
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil {
		return nil, fmt.Errorf("astx: %s 解析无根节点", name)
	}

	an := &Analysis{File: name, Lang: l}

	// 函数清单（含嵌套函数各自成条）。
	var funcNodes []*sitter.Node
	walk(root, func(n *sitter.Node) {
		if spec.funcKinds[n.Type()] {
			funcNodes = append(funcNodes, n)
			an.Functions = append(an.Functions, Function{
				Name: fieldText(n, "name", src),
				Line: lineOf(n),
			})
		}
	})
	// 回填 EndLine（函数体末行）。
	for i, fn := range funcNodes {
		if b := fn.ChildByFieldName("body"); b != nil {
			an.Functions[i].EndLine = lineOfEnd(b)
		}
	}

	// 逐作用域分析：模块级（不含函数体）+ 每个函数体。
	analyzeScope(an, spec, src, "", root, true)
	for _, fn := range funcNodes {
		body := fn.ChildByFieldName("body")
		if body == nil {
			continue
		}
		analyzeScope(an, spec, src, fieldText(fn, "name", src), body, false)
	}
	return an, nil
}

// ---- 分析核心 ----

// analyzeScope 分析一个作用域（模块根或函数体）内的 source/sink/数据流。
// skipFuncs=true 时不下钻函数体（模块级分析用，函数各自单独分析）。
func analyzeScope(an *Analysis, spec *langSpec, src []byte, funcName string,
	root *sitter.Node, skipFuncs bool) {

	tainted := map[string][]Step{} // 变量 → 赋值轨迹
	sourceOf := map[string]Point{} // 变量 → source 端点
	flows := map[string]bool{}     // 去重键（var|sinkLine|sinkKind）

	// 变量名提取（保守：标识符全收，属性访问取末段）。
	identRe := regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

	recordSource := func(expr string, line int) Point {
		p := Point{Kind: "source", Expr: truncate(expr, 120), Func: funcName, Line: line}
		an.Sources = append(an.Sources, p)
		return p
	}

	var visit func(n *sitter.Node)
	visit = func(n *sitter.Node) {
		t := n.Type()
		if skipFuncs && spec.funcKinds[t] {
			return // 模块级不下钻函数体
		}

		// 1) 赋值：source → 变量污点 / 污点传播
		if spec.assignKinds[t] {
			lhs, rhs := assignSides(n, src)
			if rhs != "" {
				if matchesAny(spec.sources, rhs) {
					sp := recordSource(rhs, lineOf(n))
					for _, v := range identRe.FindAllString(lhs, -1) {
						tainted[v] = []Step{{Line: lineOf(n), Expr: truncate(rhs, 120)}}
						sourceOf[v] = sp
					}
				} else if vs := taintedVars(rhs, tainted); len(vs) > 0 {
					// 污点传播：y = x（x 已污点）
					for _, v := range identRe.FindAllString(lhs, -1) {
						prop := append([]Step(nil), tainted[vs[0]]...)
						prop = append(prop, Step{Line: lineOf(n), Expr: truncate(rhs, 120)})
						tainted[v] = prop
						sourceOf[v] = sourceOf[vs[0]]
					}
				}
			}
		}

		// 2) 调用：sink 识别 + 污点流入判定
		if spec.callKinds[t] {
			text := n.Content(src)
			line := lineOf(n)
			an.Calls = append(an.Calls, Call{Callee: calleeOf(n, src), Func: funcName, Line: line})
			for _, sp := range spec.sinks {
				if !sp.re.MatchString(text) {
					continue
				}
				sinkPt := Point{Kind: "sink", Sink: sp.kind, CWE: CWEForSink(sp.kind),
					Expr: truncate(text, 120), Func: funcName, Line: line}
				an.Sinks = append(an.Sinks, sinkPt)

				// 情形 a：污点变量流入 sink
				hit := false
				for v := range tainted {
					if wordIn(text, v) {
						key := v + "|" + sinkPt.Sink + "|" + itoa(line)
						if !flows[key] {
							flows[key] = true
							an.Flows = append(an.Flows, Flow{
								Func: funcName, Var: v,
								Source: sourceOf[v], Sink: sinkPt,
								Steps: append([]Step(nil), tainted[v]...),
							})
						}
						hit = true
					}
				}
				// 情形 b：source 直接写在 sink 调用里（无中间变量）
				if !hit && matchesAny(spec.sources, text) {
					key := "<direct>|" + sinkPt.Sink + "|" + itoa(line)
					if !flows[key] {
						flows[key] = true
						srcPt := Point{Kind: "source", Expr: truncate(text, 120),
							Func: funcName, Line: line}
						an.Sources = append(an.Sources, srcPt)
						an.Flows = append(an.Flows, Flow{
							Func: funcName, Var: "<direct>", Source: srcPt, Sink: sinkPt,
						})
					}
				}
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(root)
}

// ---- 语法树辅助 ----

// walk 先序遍历整棵树。
func walk(n *sitter.Node, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := 0; i < int(n.ChildCount()); i++ {
		walk(n.Child(i), fn)
	}
}

// assignSides 取赋值节点的「左值文本」「右值文本」，兼容各语言字段命名。
func assignSides(n *sitter.Node, src []byte) (lhs, rhs string) {
	if l := n.ChildByFieldName("left"); l != nil {
		lhs = l.Content(src)
	}
	if r := n.ChildByFieldName("right"); r != nil {
		rhs = r.Content(src)
	}
	if rhs == "" {
		// variable_declarator / var_spec：name=... value=...
		if nm := n.ChildByFieldName("name"); nm != nil && lhs == "" {
			lhs = nm.Content(src)
		}
		if v := n.ChildByFieldName("value"); v != nil && rhs == "" {
			rhs = v.Content(src)
		}
	}
	return lhs, rhs
}

// calleeOf 取调用节点的被调名（函数/调用关系）。
func calleeOf(n *sitter.Node, src []byte) string {
	for _, f := range []string{"function", "name", "method"} {
		if c := n.ChildByFieldName(f); c != nil {
			return truncate(c.Content(src), 80)
		}
	}
	// 兜底：取「(」之前的片段
	text := n.Content(src)
	if i := strings.IndexByte(text, '('); i > 0 {
		return truncate(strings.TrimSpace(text[:i]), 80)
	}
	return truncate(text, 80)
}

// fieldText 取字段文本（不存在返回空串）。
func fieldText(n *sitter.Node, field string, src []byte) string {
	if c := n.ChildByFieldName(field); c != nil {
		return c.Content(src)
	}
	return ""
}

// lineOf 节点起始行（1-based）。
func lineOf(n *sitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.StartPoint().Row) + 1
}

// lineOfEnd 节点结束行（1-based）。
func lineOfEnd(n *sitter.Node) int {
	if n == nil {
		return 0
	}
	return int(n.EndPoint().Row) + 1
}

// matchesAny 文本是否命中任一模式。
func matchesAny(pats []*regexp.Regexp, text string) bool {
	for _, p := range pats {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// taintedVars 文本中出现的已污点变量（保序，首个命中优先）。
func taintedVars(text string, tainted map[string][]Step) []string {
	var out []string
	for v := range tainted {
		if wordIn(text, v) {
			out = append(out, v)
		}
	}
	return out
}
