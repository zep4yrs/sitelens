// Package astx 白盒源码 AST 分析（4.0 P3）。
//
// 定位：把 3.0 `internal/audit` 的「行级正则 + 行级污点近似」升级为
// 真正基于语法树的分析——函数边界、调用关系、source/sink 定位、
// 函数内 source→sink 数据流（污点近似）。输出供 audit 映射为
// internal/model 的白盒 VulnNode / Dataflow 实体（P4 再与黑盒缝合）。
//
// **CGO 隔离（集成方式 A2，见 docs/开发文档-4.0.md 第 18.2 节）**：
// tree-sitter 是 CGO 依赖。本包在 CGO 可用时编译真实解析器
// （astx_cgo.go），不可用时编译纯 Go 桩（astx_nocgo.go，Available()=false）。
// 这样没有 C 工具链的机器（如本机 Windows）仍能 `go build ./...`，
// 只是 AST 能力优雅降级；带工具链的机器（CI / 发布机）构建完整能力。
//
// 本文件（无构建标签）只含类型、语言识别与 CWE 分类——纯标准库，必然编译。
package astx

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrUnavailable 表示本二进制未编译 AST 解析器（非 CGO 构建）。
var ErrUnavailable = errors.New("astx: 本二进制未启用 AST 解析（需 CGO 构建）")

// ErrUnsupportedLang 表示文件语言不在支持范围。
var ErrUnsupportedLang = errors.New("astx: 不支持的语言")

// Lang 支持的源码语言。
type Lang string

const (
	LangPython Lang = "python"
	LangJS     Lang = "javascript"
	LangPHP    Lang = "php"
	LangJava   Lang = "java"
	LangGo     Lang = "go"
)

// supportedAST 是当前可做 AST 解析的语言。
//
// 说明：PHP 的 grammar 源码由本仓第一方自持（internal/astx/phpgram）——
// 因 tree-sitter-php 的 C 源依赖 `tree_sitter/*.h` 子目录，而 `go mod vendor`
// 会丢弃无 Go 文件的子目录（CI 有 vendor 一致性门禁）。详见 phpgram/binding.go。
var supportedAST = []Lang{LangPython, LangJS, LangPHP, LangJava, LangGo}

// Supported 返回当前可做 AST 解析的语言列表（顺序稳定）。
func Supported() []Lang {
	out := make([]Lang, len(supportedAST))
	copy(out, supportedAST)
	return out
}

// ASTSupported 报告某语言是否可做 AST 解析。
func ASTSupported(l Lang) bool {
	for _, s := range supportedAST {
		if s == l {
			return true
		}
	}
	return false
}

// extLangs 源文件后缀 → 语言（仅含 AST 可解析语言；PHP 走后缀判定为
// 不支持 → audit 回退行级正则）。
var extLangs = map[string]Lang{
	".py":   LangPython,
	".js":   LangJS,
	".mjs":  LangJS,
	".cjs":  LangJS,
	".php":  LangPHP,
	".java": LangJava,
	".go":   LangGo,
}

// DetectLang 由文件名/路径推断语言。ok=false 表示不支持（调用方应回退行级）。
func DetectLang(path string) (Lang, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	l, ok := extLangs[ext]
	return l, ok
}

// ---- sink 分类与 CWE（纯 Go，供 audit 复用，无需 CGO）----

// sink 分类常量。
const (
	SinkExecCmd   = "exec_cmd"    // 命令执行
	SinkCodeExec  = "code_exec"   // 代码执行
	SinkSQL       = "sql"         // SQL 执行
	SinkDeser     = "deserialize" // 不安全反序列化
	SinkPath      = "path"        // 文件/路径操作
	SinkWeakHash  = "weak_hash"   // 弱哈希
	SinkTemplate  = "template"    // 模板注入
	sinkOtherName = "other"
)

// cweForSink sink 分类 → CWE 编号。
var cweForSink = map[string]string{
	SinkExecCmd:  "CWE-78",
	SinkCodeExec: "CWE-95",
	SinkSQL:      "CWE-89",
	SinkDeser:    "CWE-502",
	SinkPath:     "CWE-22",
	SinkWeakHash: "CWE-916",
	SinkTemplate: "CWE-1336",
}

// CWEForSink 返回 sink 分类对应的 CWE 编号（未收录返回空串）。
func CWEForSink(kind string) string { return cweForSink[kind] }

// ---- 分析结果（与解析器实现无关的稳定结构）----

// Function 一个函数/方法定义。
type Function struct {
	Name    string   `json:"name"`
	Line    int      `json:"line"`
	EndLine int      `json:"end_line,omitempty"`
	Params  []string `json:"params,omitempty"`
}

// Point source / sink 端点。
type Point struct {
	Kind string `json:"kind"`           // source | sink
	Sink string `json:"sink,omitempty"` // sink 分类（Point.Kind==sink 时）
	CWE  string `json:"cwe,omitempty"`
	Expr string `json:"expr"`
	Func string `json:"func,omitempty"`
	Line int    `json:"line"`
}

// Step 数据流中间步骤（赋值轨迹）。
type Step struct {
	Line int    `json:"line"`
	Expr string `json:"expr"`
}

// Flow 函数内 source→sink 数据流（污点近似）。
type Flow struct {
	Func   string `json:"func,omitempty"`
	Var    string `json:"var,omitempty"` // 承载污点的变量；"<direct>" 表示 source 直接进 sink
	Source Point  `json:"source"`
	Sink   Point  `json:"sink"`
	Steps  []Step `json:"steps,omitempty"`
}

// Call 一次函数调用（函数/调用关系）。
type Call struct {
	Callee string `json:"callee"`
	Func   string `json:"func,omitempty"` // 所在函数（""=模块级）
	Line   int    `json:"line"`
}

// Analysis 单文件分析结果。
type Analysis struct {
	File      string     `json:"file"`
	Lang      Lang       `json:"lang"`
	Functions []Function `json:"functions,omitempty"`
	Sources   []Point    `json:"sources,omitempty"`
	Sinks     []Point    `json:"sinks,omitempty"`
	Flows     []Flow     `json:"flows,omitempty"`
	Calls     []Call     `json:"calls,omitempty"`
}

// HasFlows 报告是否发现数据流。
func (a *Analysis) HasFlows() bool { return a != nil && len(a.Flows) > 0 }

// ---- 共享纯函数（与解析器实现无关，两种构建都可用）----

// wordIn 判断 text 是否以「标识符词」形式包含 v（避免 x 命中 xyz）。
// 污点变量流入 sink 的判定核心，必须精确。
func wordIn(text, v string) bool {
	if v == "" {
		return false
	}
	isIdent := func(b byte) bool {
		return b == '_' || b == '$' ||
			(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	for i := 0; i+len(v) <= len(text); {
		j := strings.Index(text[i:], v)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(v)
		okL := start == 0 || !isIdent(text[start-1])
		okR := end == len(text) || !isIdent(text[end])
		if okL && okR {
			return true
		}
		i = start + 1
	}
	return false
}

// truncate 截断过长文本（证据可读性）。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// itoa 小整数转字符串（避免 fmt 开销）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
