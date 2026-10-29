// afrog / raw POC 形态适配。
//
// ConvertRaw：HTTP 报文形态（http[0].raw）——官方 nuclei 库大量模板、
// 新版 afrog、TscanPlus POC 均为此形态，此前漏斗全部跳过
// （实现见 nuclei.go）。
//
// ConvertAfrog：经典 afrog 形态（rules 子请求 + response 判定 +
// expression 布尔串联）。转换哲学与主漏斗一致：能诚实映射为
// "单请求 + 内容判定"的才转换；多请求 AND 链无法降为单请求 →
// 整条拒收（宁少报，不误报）。
package nuclei

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/afrogx"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// afrogRule 经典 afrog 的单条子请求 + 响应判定。
//
// ⚠️ afrog 的判定**主要写在 rule 级 expression 上**（真实语料 1,687/1,699
// 条模板有 rule 级 expression，0 条写 response 块）。此前本结构体没有
// Expression 字段，yaml.v3 静默丢弃未知字段 → afrogNorm 拼不出 matcher →
// 整个 afrog 来源 100% 过不了漏斗（BUG-016）。
// 现由 internal/afrogx 在**转换期**编译准入、**运行期**求值。
type afrogRule struct {
	Request struct {
		Path    string            `yaml:"path"`
		Method  string            `yaml:"method"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	} `yaml:"request"`
	Response struct {
		StatusCode int               `yaml:"status_code"`
		Body       []string          `yaml:"body"`
		Headers    map[string]string `yaml:"headers"`
	} `yaml:"response"`
	// Expression rule 级判定表达式（afrog 经典形态，如
	// `response.status == 200 && response.body.bcontains(b"xxx")`）。
	// 编译失败/不可判定 → 整条模板拒收（宁少报不误报）。
	Expression string `yaml:"expression"`
}

type afrogDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
		// tags 可能是逗号串或列表，与 nuclei 同理不声明以免解析失败
	} `yaml:"info"`
	Expression string               `yaml:"expression"`
	Rules      map[string]afrogRule `yaml:"rules"`
}

// expression 仅允许 rN() 布尔串联；函数调用等一律拒收。
var afrogAtomRe = regexp.MustCompile(`^r\d+\(\)$`)
var afrogExprRe = regexp.MustCompile(`^\s*r\d+\(\)\s*(?:(?:&&|\|\|)\s*r\d+\(\)\s*)*$`)

// parseAfrogExpr 解析 expression：返回 (引用的 rule 名序列, 是否全 AND)。
// 仅支持纯 && 链或纯 || 链；混合逻辑与其他语法拒收。
func parseAfrogExpr(expr string) (atoms []string, allAnd bool, ok bool) {
	if !afrogExprRe.MatchString(expr) {
		return nil, false, false
	}
	allAnd = !strings.Contains(expr, "||")
	fields := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '&' || r == '|'
	})
	seen := map[string]bool{}
	for _, f := range fields {
		a := strings.TrimSpace(f)
		if !afrogAtomRe.MatchString(a) {
			return nil, false, false
		}
		a = strings.TrimSuffix(a, "()") // 保留 rN 全名与 rules 键对齐
		if a == "" || seen[a] {
			return nil, false, false // 重复引用语义不明，拒收
		}
		seen[a] = true
		atoms = append(atoms, a)
	}
	if len(atoms) == 0 {
		return nil, false, false
	}
	return atoms, allAnd, true
}

// afrogNorm 单条 rule → 归一化请求。
//
// 判定来源有两条，优先 rule 级 expression（真实语料全部如此）：
//   - expression 非空：编译准入（不可判定/无内容判定即拒收），matchers 取
//     response 块（真实语料为空，但两者并存时按 AND 语义更保守）；
//   - expression 为空：退回 response 块合成 matchers（历史行为）。
func afrogNorm(r afrogRule) (normReq, bool) {
	method := strings.ToUpper(strings.TrimSpace(r.Request.Method))
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "POST" {
		return normReq{}, false
	}
	path := strings.TrimSpace(r.Request.Path)
	if path == "" || strings.Contains(path, "{{") {
		return normReq{}, false // 含占位符（需变量注入）的拒收
	}
	var matchers []tplMatcher
	if r.Response.StatusCode != 0 {
		matchers = append(matchers, tplMatcher{Type: "status", Status: []int{r.Response.StatusCode}})
	}
	if len(r.Response.Body) > 0 {
		matchers = append(matchers, tplMatcher{Type: "word", Words: r.Response.Body, Condition: "and"})
	}
	expr := strings.TrimSpace(r.Expression)
	if expr != "" {
		// 编译准入：含不支持原子（oobCheck/latency/随机标记等）即整条拒收。
		prog, err := afrogx.Get(expr)
		if err != nil || prog == nil {
			return normReq{}, false
		}
		// 内容判定闸门：纯状态码/恒真/纯取反的表达式放行会退化成"路径存在
		// 即命中"——与 buildChecks「纯状态码组不转换」同哲学（宁少报不误报）。
		if !prog.PositiveGround() {
			return normReq{}, false
		}
	} else if len(matchers) == 0 {
		return normReq{}, false
	}
	return normReq{
		method:      method,
		pathSuffix:  path,
		body:        r.Request.Body,
		contentType: r.Request.Headers["Content-Type"],
		matchers:    matchers,
		cond:        "and",
		expr:        expr,
	}, true
}

// andExpr 合并两条 AND 语义的表达式（空串视为无该条件）。
// 同请求的多个 rule 拿到的是同一份响应，故 && 合并是诚实的。
func andExpr(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return "(" + a + ") && (" + b + ")"
}

// sameRequest 两条归一化请求是否等价（AND 合并的前提）。
func sameRequest(a, b normReq) bool {
	return a.method == b.method && a.pathSuffix == b.pathSuffix &&
		a.body == b.body && a.contentType == b.contentType
}

// ConvertAfrog 经典 afrog POC → checks。
func ConvertAfrog(data []byte) []checks.Check {
	var doc afrogDoc
	if len(data) > 512*1024 {
		return nil
	}
	if strings.Contains(string(data[:min(3000, len(data))]), "interactsh") {
		return nil // 需要外部回调，跳过
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	if doc.ID == "" || doc.Info.Name == "" || len(doc.Rules) == 0 {
		return nil
	}
	if noisyTemplates[strings.ToLower(doc.ID)] {
		return nil
	}

	prefix := "afrog 社区模板 " + doc.ID
	// 无 expression：仅单 rule 的 POC 才转换（多 rule 语义不明，保守拒收）
	if strings.TrimSpace(doc.Expression) == "" {
		if len(doc.Rules) != 1 {
			return nil
		}
		for _, r := range doc.Rules {
			nr, ok := afrogNorm(r)
			if !ok {
				return nil
			}
			return buildChecks("afrog-"+doc.ID, prefix, doc.Info.Name, doc.Info.Severity, nr)
		}
	}

	atoms, allAnd, ok := parseAfrogExpr(doc.Expression)
	if !ok {
		return nil
	}
	// 引用的 rule 必须全部存在；未引用的 rule 不参与（宁少报）
	rules := make([]afrogRule, 0, len(atoms))
	for _, a := range atoms {
		r, exist := doc.Rules[a]
		if !exist {
			return nil
		}
		rules = append(rules, r)
	}

	if allAnd {
		// AND：全部子请求等价时合并判定为单请求多组；否则无法诚实
		// 降为单请求语义 → 整条拒收
		var base normReq
		var matchers []tplMatcher
		for i, r := range rules {
			nr, ok := afrogNorm(r)
			if !ok {
				return nil
			}
			if i == 0 {
				base = nr
				continue
			}
			if !sameRequest(base, nr) {
				return nil
			}
			matchers = append(matchers, nr.matchers...)
			// 同请求 → 同一份响应，表达式按 && 合并是诚实的。
			base.expr = andExpr(base.expr, nr.expr)
		}
		base.matchers = append(base.matchers, matchers...)
		return buildChecks("afrog-"+doc.ID, prefix, doc.Info.Name, doc.Info.Severity, base)
	}

	// OR：每条 rule 独立成 check（请求可不同；单 rule 不合法时跳过该分支）
	var out []checks.Check
	for i, r := range rules {
		nr, ok := afrogNorm(r)
		if !ok {
			continue
		}
		out = append(out, buildChecks(
			fmt.Sprintf("afrog-%s-%s", doc.ID, atoms[i]),
			prefix, doc.Info.Name, doc.Info.Severity, nr)...)
	}
	return out
}
