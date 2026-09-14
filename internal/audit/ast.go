// AST 污点分析集成（4.0 P3）。
//
// 与 taint.go 的「行级近似」并列：当 config `audit.ast_enabled` 开启且本
// 二进制为 CGO 构建时，对支持语言（py/js/java/go）走 astx 的真实语法树
// 分析，产出带函数作用域与 source→sink 步骤的发现；行级正则规则
// （auditRules / taintFile）作为兜底始终运行（覆盖 AST 不支持的语言、
// 以及 AST 未命中的形态）。
//
// 发现以 `AST-<sink分类>` 规则名并入 Report.Findings——additive，
// 不改动既有 PY-*/JS-*/TAINT-* 发现，3.0 行为不变（默认关）。
package audit

import (
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/astx"
)

// astFindings 对单个文件做 AST 分析并转为发现列表（仅发现，丢弃分析细节）。
// 不可用（非 CGO）/ 不支持语言 / 解析失败时返回 nil（静默回退行级）。
func astFindings(filePath string, data []byte, maxHits int) []Finding {
	fs, _ := astAnalyze(filePath, data, maxHits)
	return fs
}

// astAnalyze 做 AST 分析，同时返回发现与原始分析结果（P4 实体化用后者）。
func astAnalyze(filePath string, data []byte, maxHits int) ([]Finding, *astx.Analysis) {
	if !astx.Available() {
		return nil, nil
	}
	if _, ok := astx.DetectLang(filePath); !ok {
		return nil, nil
	}
	an, err := astx.AnalyzeSource(filePath, data)
	if err != nil {
		return nil, nil
	}
	var out []Finding
	for i := range an.Flows {
		if len(out) >= maxHits {
			break
		}
		fl := an.Flows[i]
		name := fl.Sink.Sink
		if name == "" {
			name = "dataflow"
		}
		out = append(out, Finding{
			Rule:     "AST-" + name,
			Severity: "high",
			Title:    "污点数据流：" + astx.CWEForSink(fl.Sink.Sink) + " " + name,
			File:     filePath,
			Line:     fl.Sink.Line,
			Snippet:  fl.Sink.Expr,
			Match:    fl.Var,
			Advice:   adviceForFlow(fl),
		})
	}
	return out, an
}

// adviceForFlow 生成可读的修复建议（含函数作用域与步骤轨迹）。
func adviceForFlow(fl astx.Flow) string {
	var b strings.Builder
	b.WriteString("不可信输入经 ")
	b.WriteString(strconv.Itoa(len(fl.Steps)))
	b.WriteString(" 步赋值流入危险函数 ")
	b.WriteString(fl.Sink.Sink)
	if fl.Func != "" {
		b.WriteString("（函数 " + fl.Func + "）")
	}
	if fl.Var != "" && fl.Var != "<direct>" {
		b.WriteString("；变量 " + fl.Var)
	}
	if fl.Source.Line > 0 {
		b.WriteString("，source 在第 " + strconv.Itoa(fl.Source.Line) + " 行")
	}
	b.WriteString("。建议对输入做白名单校验/类型转换，或改用参数化/转义 API")
	return b.String()
}
