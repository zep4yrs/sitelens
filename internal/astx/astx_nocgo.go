//go:build !cgo

package astx

// Available 报告本二进制未带真实 AST 解析器（非 CGO 构建返回 false）。
//
// 无 C 工具链的机器（如本机 Windows）编译本桩：`go build ./...` 与全量
// 测试照常通过，AST 能力优雅降级——调用方（audit）应回退到行级正则/污点
// 近似，并在结果里如实标注「AST 未启用」，不得假装已做 AST 分析。
func Available() bool { return false }

// AnalyzeSource 无 CGO 时不可用。
// 先做语言判定：不支持的语言统一返回 ErrUnsupportedLang，
// 与 CGO 可用性无关（两种构建语义一致）。
func AnalyzeSource(name string, src []byte) (*Analysis, error) {
	if _, ok := DetectLang(name); !ok {
		return nil, ErrUnsupportedLang
	}
	return nil, ErrUnavailable
}

// AnalyzeFile 无 CGO 时不可用。
func AnalyzeFile(path string) (*Analysis, error) {
	if _, ok := DetectLang(path); !ok {
		return nil, ErrUnsupportedLang
	}
	return nil, ErrUnavailable
}

// AnalyzeSourceLang 无 CGO 时不可用。
func AnalyzeSourceLang(name string, src []byte, l Lang) (*Analysis, error) {
	supported := false
	for _, s := range Supported() {
		if s == l {
			supported = true
			break
		}
	}
	if !supported {
		return nil, ErrUnsupportedLang
	}
	return nil, ErrUnavailable
}
