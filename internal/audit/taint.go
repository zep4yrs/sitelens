// TAINT-lite：Python 源码污点数据的行级近似追踪。
//
// 与 python 分支基于 AST 的污点分析不同（Go 侧无维护良好的纯 Go
// Python 解析器，为守住零依赖原则不做完整移植），本实现按行追踪：
//
//	source：input() / request.args|form|values|cookies|data|json /
//	        files|headers / sys.argv
//	sink  ：eval / exec / os.system / os.popen / pickle.loads /
//	        yaml.load / subprocess.call|run|Popen
//
// 规则：变量在某行被赋值为污点表达式后，出现在后续行的 sink 调用
// 参数中即报「污点数据流入危险函数」。
// 定位是行级近似（无函数作用域/流敏感分析），宁少报不误报——
// 每条发现仍只是辅助人工复查的线索。
package audit

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	srcRe = regexp.MustCompile(`input\s*\(|request\.(args|form|values|cookies|data|json|files|headers)|sys\.argv`)
	// sink 按声明顺序取首个命中者报告
	sinkRes = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"eval", regexp.MustCompile(`\beval\s*\(`)},
		{"exec", regexp.MustCompile(`\bexec\s*\(`)},
		{"os.system", regexp.MustCompile(`\bos\.system\s*\(`)},
		{"os.popen", regexp.MustCompile(`\bos\.popen\s*\(`)},
		{"pickle.loads", regexp.MustCompile(`\bpickle\.loads?\s*\(`)},
		{"yaml.load", regexp.MustCompile(`\byaml\.load\s*\(`)},
		{"subprocess.call", regexp.MustCompile(`\bsubprocess\.call\s*\(`)},
		{"subprocess.run", regexp.MustCompile(`\bsubprocess\.run\s*\(`)},
		{"subprocess.Popen", regexp.MustCompile(`\bsubprocess\.Popen\s*\(`)},
	}
	assignRe = regexp.MustCompile(`^\s*(\w+)\s*=\s*(.+)$`)
	wordRe   = regexp.MustCompile(`\w+`)
)

// taintFile 对单个 py 文件做行级污点追踪。filePath 用于发现定位。
func taintFile(filePath string, lines []string) []Finding {
	var out []Finding
	tainted := map[string]int{} // 变量名 → 赋值行号（1 起）
	for ln, line := range lines {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		lineNo := ln + 1

		// 赋值：变量 ← 污点表达式
		if m := assignRe.FindStringSubmatch(code); m != nil && srcRe.MatchString(m[2]) {
			tainted[m[1]] = lineNo
			continue
		}

		// sink 调用：行内出现任一污点变量
		var sink string
		for _, s := range sinkRes {
			if s.re.MatchString(code) {
				sink = s.name
				break
			}
		}
		if sink == "" {
			continue
		}
		reported := map[string]bool{}
		for _, w := range wordRe.FindAllString(code, -1) {
			defLine, ok := tainted[w]
			if !ok || defLine >= lineNo || reported[w] {
				continue
			}
			reported[w] = true
			out = append(out, Finding{
				Rule: "TAINT-" + sink, Severity: "high",
				Title:   "污点数据流入危险函数 " + sink,
				File:    filePath,
				Line:    lineNo,
				Snippet: truncateStr(code, 160),
				Match:   w,
				Advice: "变量 " + w + "（第 " + strconv.Itoa(defLine) +
					" 行）来自不可信输入；先做白名单校验或类型转换再进入 " + sink,
			})
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
