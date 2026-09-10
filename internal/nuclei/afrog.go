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

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// afrogRule 经典 afrog 的单条子请求 + 响应判定。
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

// afrogNorm 单条 rule → 归一化请求（matchers 由 response 判定合成）。
// afrog 的 response.body 关键词列表默认全命中（AND 语义）。
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
	if len(matchers) == 0 {
		return normReq{}, false
	}
	return normReq{
		method:      method,
		pathSuffix:  path,
		body:        r.Request.Body,
		contentType: r.Request.Headers["Content-Type"],
		matchers:    matchers,
		cond:        "and",
	}, true
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
