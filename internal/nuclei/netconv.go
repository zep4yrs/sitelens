// 协议模板（tcp/dns/ssl）→ NetCheck：3.0 非 HTTP 检测的漏斗准入。
//
// 与 HTTP 形态（convertAny → checks.Check）并行的一条转换线：产出由
// internal/netx 执行的原始收发检测。v1 落地面：
//   - tcp：inputs（data/hex）依次发送 + banner 读取，word/regex/binary/dsl
//     匹配响应（dsl 经 CompileWithVars 注入 response 变量）；
//   - dns：name/type 查询，word/regex 匹配记录串；
//   - ssl：证书摘要串（主体/颁发者/SAN/版本），word/regex 匹配。
package nuclei

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/dsl"
)

// NetCheck 协议模板的可执行投影。
type NetCheck struct {
	ID       string
	Name     string
	Sev      string
	Proto    string // tcp | dns | ssl
	Port     int    // tcp 模板声明端口（0 = 由调度侧按服务探测提供）
	Payloads [][]byte
	DNSName  string
	DNSType  string
	Matchers []tplMatcher
	Cond     string
}

type tplTCP struct {
	Inputs []struct {
		Data string `yaml:"data"`
		Hex  string `yaml:"hex"`
	} `yaml:"inputs"`
	Port              int            `yaml:"port"`
	Host              []string       `yaml:"host"`
	Matchers          []tplMatcher   `yaml:"matchers"`
	MatchersCondition string         `yaml:"matchers-condition"`
	Extractors        []tplExtractor `yaml:"extractors"`
}

type tplDNS struct {
	Name              string         `yaml:"name"`
	Type              string         `yaml:"type"`
	Class             string         `yaml:"class"`
	Retrieval         string         `yaml:"retrieval"`
	Matchers          []tplMatcher   `yaml:"matchers"`
	MatchersCondition string         `yaml:"matchers-condition"`
	Extractors        []tplExtractor `yaml:"extractors"`
}

type tplSSL struct {
	Address           string         `yaml:"address"`
	MinVersion        string         `yaml:"min_version"`
	MaxVersion        string         `yaml:"max_version"`
	Matchers          []tplMatcher   `yaml:"matchers"`
	MatchersCondition string         `yaml:"matchers-condition"`
	Extractors        []tplExtractor `yaml:"extractors"`
}

// netDoc 协议模板的文档形状（与 tplDoc 平行，只取需要的块）。
type netDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
	} `yaml:"info"`
	TCP []tplTCP `yaml:"tcp"`
	DNS []tplDNS `yaml:"dns"`
	SSL []tplSSL `yaml:"ssl"`
}

// ConvertNetwork 协议模板 → NetCheck；不是协议模板或形态不支持返回 nil。
func ConvertNetwork(data []byte) *NetCheck {
	if len(data) > 512*1024 {
		return nil
	}
	if strings.Contains(string(data[:min(3000, len(data))]), "interactsh") {
		return nil // 需要外部回调，跳过
	}
	var doc netDoc
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	if doc.ID == "" || doc.Info.Name == "" {
		return nil
	}
	if noisyTemplates[strings.ToLower(doc.ID)] {
		return nil
	}
	nc := &NetCheck{
		ID:   "nuclei-" + doc.ID,
		Name: doc.Info.Name,
		Sev:  strings.ToLower(doc.Info.Severity),
	}
	switch {
	case len(doc.TCP) > 0:
		nc.Proto = "tcp"
		tcp := doc.TCP[0]
		nc.Port = tcp.Port
		for _, in := range tcp.Inputs {
			if in.Hex != "" {
				if b, err := hex.DecodeString(strings.Map(func(r rune) rune {
					if r == ' ' || r == '\n' || r == '\r' {
						return -1
					}
					return r
				}, in.Hex)); err == nil {
					nc.Payloads = append(nc.Payloads, b)
				}
				continue
			}
			if in.Data != "" {
				nc.Payloads = append(nc.Payloads, []byte(in.Data))
			}
		}
		if len(tcp.Matchers) == 0 {
			return nil
		}
		nc.Matchers, nc.Cond = tcp.Matchers, normCond(tcp.MatchersCondition)
		return nc
	case len(doc.DNS) > 0:
		nc.Proto = "dns"
		d := doc.DNS[0]
		nc.DNSName = d.Name
		nc.DNSType = strings.ToUpper(strings.TrimSpace(d.Type))
		if nc.DNSType == "" {
			nc.DNSType = "A"
		}
		if nc.DNSName == "" || len(d.Matchers) == 0 {
			return nil
		}
		nc.Matchers, nc.Cond = d.Matchers, normCond(d.MatchersCondition)
		return nc
	case len(doc.SSL) > 0:
		nc.Proto = "ssl"
		s := doc.SSL[0]
		if len(s.Matchers) == 0 {
			return nil
		}
		nc.Matchers, nc.Cond = s.Matchers, normCond(s.MatchersCondition)
		return nc
	}
	return nil
}

func normCond(c string) string {
	c = strings.TrimSpace(strings.ToLower(c))
	if c == "" {
		return "or"
	}
	return c
}

// MatchNetResponse 对协议响应执行匹配器（响应串：tcp/dns/ssl 统一渲染）。
// 返回 (是否命中, 命中信号描述)。dsl 引用 response 变量（CompileWithVars）。
func (nc *NetCheck) MatchNetResponse(response string) (bool, string) {
	hitAny := false
	var signals []string
	for _, m := range nc.Matchers {
		ok, sig := matchOne(m, response)
		if ok {
			hitAny = true
			signals = append(signals, sig)
		}
	}
	if nc.Cond == "and" {
		return len(signals) == len(nc.Matchers) && len(nc.Matchers) > 0, strings.Join(signals, " + ")
	}
	return hitAny, strings.Join(signals, " | ")
}

func matchOne(m tplMatcher, response string) (bool, string) {
	switch strings.ToLower(m.Type) {
	case "word":
		matched := 0
		var hit []string
		for _, w := range m.Words {
			if strings.Contains(strings.ToLower(response), strings.ToLower(w)) {
				matched++
				hit = append(hit, w)
			}
		}
		if len(m.Words) == 0 {
			return false, ""
		}
		cond := strings.ToLower(m.Condition)
		if (cond == "and" && matched == len(m.Words)) ||
			(cond != "and" && matched > 0) {
			return true, "词命中[" + strings.Join(hit, ",") + "]"
		}
	case "regex":
		matched := 0
		var hit []string
		for _, r := range m.Regex {
			if re, err := compileRE2(r); err == nil && re.MatchString(response) {
				matched++
				hit = append(hit, r)
			}
		}
		if len(m.Regex) == 0 {
			return false, ""
		}
		cond := strings.ToLower(m.Condition)
		if (cond == "and" && matched == len(m.Regex)) ||
			(cond != "and" && matched > 0) {
			return true, "正则命中[" + strings.Join(hit, ",") + "]"
		}
	case "binary":
		matched := 0
		var hit []string
		for _, w := range m.Words {
			raw, err := hex.DecodeString(strings.TrimPrefix(w, "0x"))
			if err != nil {
				continue
			}
			if strings.Contains(response, string(raw)) {
				matched++
				hit = append(hit, w)
			}
		}
		if (strings.ToLower(m.Condition) == "and" && matched == len(m.Words)) ||
			(strings.ToLower(m.Condition) != "and" && matched > 0) {
			return true, "二进制命中[" + strings.Join(hit, ",") + "]"
		}
	case "dsl":
		for _, expr := range m.DSL {
			prog, err := compileNetDSL(expr)
			if err != nil {
				continue
			}
			if ok, _ := prog.Eval(netEnv{response: response}); ok {
				return true, "dsl 命中[" + strconv.Quote(expr) + "]"
			}
		}
	case "status":
		// 协议模板无 HTTP 状态码语义，忽略
	}
	return false, ""
}

// Severity 严重度兜底（对齐 checks.Check 语义）。
func (nc *NetCheck) Severity() string {
	if nc.Sev == "" {
		return "info"
	}
	return nc.Sev
}

// Title 报告标题。
func (nc *NetCheck) Title() string {
	return fmt.Sprintf("Nuclei 协议模板 %s", strings.TrimPrefix(nc.ID, "nuclei-"))
}

// compileRE2 协议匹配正则：大小写不敏感（对齐 nuclei 语义），RE2 校验不过即弃。
func compileRE2(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

// netEnv 协议模板 dsl 求值环境：body 即原始响应，response 经 VarSource 注入。
type netEnv struct{ response string }

func (e netEnv) StatusCode() int   { return 0 }
func (e netEnv) Body() string      { return e.response }
func (e netEnv) Header(string) string { return "" }
func (e netEnv) Host() string      { return "" }
func (e netEnv) Var(name string) (string, bool) {
	if name == "response" {
		return e.response, true
	}
	return "", false
}

// compileNetDSL 协议模板 dsl：安全子集 + response 变量（CompileWithVars 注入）。
func compileNetDSL(expr string) (*dsl.Program, error) {
	return dsl.CompileWithVars(expr, []string{"response"})
}
