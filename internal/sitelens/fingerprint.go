// Package sitelens 实现证据抽取与指纹匹配（Go 引擎核心）。
package sitelens

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Technology 一条精编指纹（对齐 PG technologies 表）。
type Technology struct {
	Name    string          `json:"name"`
	Cats    []string        `json:"cats"`
	Conf    int             `json:"conf"`
	Website string          `json:"website"`
	Rules   json.RawMessage `json:"rules"`
}

// ruleChannels 指纹规则的证据通道（对齐 Python detectors 字段语义）。
// 兼容两种导出形状：html 为正则数组，或 {dom:[], html:[]} 对象
// （tools/export_intel.py 的历史形状，加载时收敛）。
type ruleChannels struct {
	Headers map[string][]string `json:"headers"` // 响应头名 → 正则组
	Cookies []string            `json:"cookies"` // Cookie 名正则组
	Meta    map[string]string   `json:"meta"`    // meta 名 → 正则
	HTML    []string            `json:"html"`    // HTML 原文正则组
	Scripts struct {
		Src     []string `json:"src"`     // 外链脚本正则组
		Content []string `json:"content"` // 内联脚本正则组
	} `json:"scripts"`
	Dom []string `json:"dom"` // DOM 选择器（暂不实现，保留通道）
}

// unmarshalRules 容错解析规则：整体直解失败时对 html 通道降级重试。
func unmarshalRules(raw json.RawMessage) (*ruleChannels, bool) {
	rc := &ruleChannels{}
	if err := json.Unmarshal(raw, rc); err == nil {
		return rc, true
	}
	// html 通道是 {dom, html} 对象的历史形状
	var loose struct {
		Headers map[string][]string `json:"headers"`
		Cookies []string            `json:"cookies"`
		Meta    map[string]string   `json:"meta"`
		HTML    struct {
			DOM  []string `json:"dom"`
			HTML []string `json:"html"`
		} `json:"html"`
		Scripts struct {
			Src     []string `json:"src"`
			Content []string `json:"content"`
		} `json:"scripts"`
		Dom []string `json:"dom"`
	}
	if err := json.Unmarshal(raw, &loose); err != nil {
		return nil, false
	}
	rc.Headers = loose.Headers
	rc.Cookies = loose.Cookies
	rc.Meta = loose.Meta
	rc.HTML = loose.HTML.HTML
	rc.Dom = append(loose.Dom, loose.HTML.DOM...)
	rc.Scripts = loose.Scripts
	return rc, true
}

// compiledTech 预编译后的单条指纹。
// 纯字面量模式走 strings.Contains 快路径（指纹库大多数模式如此），
// 仅带正则元字符的模式编译为 regexp —— 单页匹配成本的数量级优化。
type compiledTech struct {
	tech    *Technology
	headers map[string][]pattern
	cookies []pattern
	meta    map[string]*regexp.Regexp
	html    []pattern
	src     []pattern
	inline  []pattern
	usable  bool // 至少存在一个可用通道
}

// pattern 字面量或正则的单个匹配模式。
type pattern struct {
	re    *regexp.Regexp // isLit=false 时可用
	gate  string         // isLit=false 时：正则必然包含的最长字面量（小写预筛）
	lit   string         // isLit=true 时的小写子串
	raw   string         // 原始文本（证据显示用）
	isLit bool
}

// compilePats 编译模式组：无正则元字符的按字面量快路径处理；
// 正则模式提取字面量门控（gate），门不命中即跳过正则执行。
func compilePats(patterns []string) []pattern {
	out := make([]pattern, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if isSimpleLiteral(p) {
			out = append(out, pattern{lit: strings.ToLower(p), raw: p, isLit: true})
		} else {
			out = append(out, pattern{re: regexp.MustCompile("(?i)" + p), raw: p,
				gate: literalGate(p)})
		}
	}
	return out
}

func isSimpleLiteral(p string) bool {
	for _, r := range p {
		if strings.ContainsRune(`\.+*?()[]{}|^$`, r) {
			return false
		}
	}
	return true
}

// findIn 在 s（附其小写形态 sLow，避免循环内重复 ToLower 大文本）中匹配，
// 返回 (匹配文本, 捕获组)。字面量无捕获组。
func (p pattern) findIn(s, sLow string) (string, []string) {
	if p.isLit {
		if strings.Contains(sLow, p.lit) {
			return p.raw, nil
		}
		return "", nil
	}
	if p.gate != "" && !strings.Contains(sLow, p.gate) {
		return "", nil // 字面量门控：正则必然含该子串，门不过直接跳过
	}
	m := p.re.FindStringSubmatch(s)
	if m == nil {
		return "", nil
	}
	return m[0], m
}

// literalGate 提取正则中必然出现在匹配结果里的最长字面量运行。
// 保守策略：遇元字符结束当前运行；(…) […] {…} 整段跳过（其中内容
// 不保证逐字出现）；转义字符取字面量。短于 3 字节不设门控。
func literalGate(p string) string {
	var best, cur []byte
	flush := func() {
		if len(cur) > len(best) {
			best = append(best[:0], cur...)
		}
		cur = cur[:0]
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			i++
			if i < len(p) {
				cur = append(cur, p[i])
			}
		case '.', '+', '*', '?', '|', '^', '$', ')':
			flush()
		case '(', '[', '{':
			flush()
			close := byte(')')
			if c == '[' {
				close = ']'
			} else if c == '{' {
				close = '}'
			}
			for i < len(p) && p[i] != close {
				i++
			}
		default:
			cur = append(cur, c)
		}
	}
	flush()
	if len(best) < 3 {
		return ""
	}
	return strings.ToLower(string(best))
}

// Hit 一次指纹命中。
type Hit struct {
	Name     string
	Cats     []string
	Conf     int
	Evidence string
	Version  string
}

// LoadTechnologies 从 JSON 文件加载指纹规则并预编译正则。
func LoadTechnologies(path string) ([]*compiledTech, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadFrom(data)
}

func loadFrom(data json.RawMessage) ([]*compiledTech, error) {
	var box struct {
		Technologies []struct {
			Name    string          `json:"name"`
			Cats    []string        `json:"cats"`
			Conf    int             `json:"conf"`
			Website string          `json:"website"`
			Rules   json.RawMessage `json:"rules"`
		} `json:"technologies"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return nil, err
	}
	out := make([]*compiledTech, 0, len(box.Technologies))
	for _, t := range box.Technologies {
		if len(t.Rules) == 0 || t.Name == "" {
			continue
		}
		rules, ok := unmarshalRules(t.Rules)
		if !ok {
			continue // 规则格式不符的指纹跳过，不阻塞加载
		}
		ct := &compiledTech{tech: &Technology{Name: t.Name, Cats: t.Cats, Conf: t.Conf}}
		for name, pats := range rules.Headers {
			if ps := compilePats(pats); len(ps) > 0 {
				if ct.headers == nil {
					ct.headers = make(map[string][]pattern)
				}
				ct.headers[strings.ToLower(unescapeName(name))] = ps
			}
		}
		ct.cookies = compilePats(rules.Cookies)
		for name, p := range rules.Meta {
			if p == "" {
				continue
			}
			if ct.meta == nil {
				ct.meta = make(map[string]*regexp.Regexp)
			}
			// 键名是 meta 名而非正则：反转义历史导出中的 \. \- 序列
			ct.meta[strings.ToLower(unescapeName(name))] = regexp.MustCompile("(?i)" + p)
		}
		ct.html = compilePats(rules.HTML)
		ct.src = compilePats(rules.Scripts.Src)
		ct.inline = compilePats(rules.Scripts.Content)
		ct.usable = len(ct.headers) > 0 || len(ct.cookies) > 0 ||
			len(ct.meta) > 0 || len(ct.html) > 0 ||
			len(ct.src) > 0 || len(ct.inline) > 0
		if ct.usable {
			out = append(out, ct)
		}
	}
	return out, nil
}

// versionFromMatch 捕获组以数字开头才采信为版本号（对齐 Python version_from_match）。
func versionFromMatch(m []string) string {
	if len(m) > 1 && m[1] != "" && m[1][0] >= '0' && m[1][0] <= '9' {
		return m[1]
	}
	return ""
}

// Match 对已采集证据应用全部指纹，返回命中列表。
// 通道语义与 Python 版一致：通道内任一正则命中即该通道成立；
// 单条指纹声明多个通道时，全部通道命中才算命中（AND）。
func Match(techs []*compiledTech, ev *Evidence) []Hit {
	hits := make([]Hit, 0, 8)
	for _, ct := range techs {
		if evName, evVer, ok := ct.match(ev); ok {
			hits = append(hits, Hit{
				Name: ct.tech.Name, Cats: ct.tech.Cats, Conf: ct.tech.Conf,
				Evidence: evName, Version: evVer,
			})
		}
	}
	return hits
}

// match 按通道顺序应用证据；返回 (证据描述, 版本, 是否命中)。
func (ct *compiledTech) match(ev *Evidence) (string, string, bool) {
	if len(ct.headers) > 0 {
		for name, pats := range ct.headers {
			val := ev.Header(name)
			if val == "" {
				continue
			}
			valLow := strings.ToLower(val)
			for _, p := range pats {
				if text, subs := p.findIn(val, valLow); text != "" {
					return fmt.Sprintf("%s=%s", name, truncate(val, 80)),
						versionFromMatch(subs), true
				}
			}
		}
	}
	if len(ct.cookies) > 0 {
		for _, p := range ct.cookies {
			for _, cn := range ev.CookieNames {
				if text, subs := p.findIn(cn, cn); text != "" {
					return fmt.Sprintf("cookie %s", cn), versionFromMatch(subs), true
				}
			}
		}
	}
	if len(ct.meta) > 0 {
		for metaName, re := range ct.meta {
			if content := ev.Metas[metaName]; content != "" {
				if m := re.FindStringSubmatch(content); m != nil {
					return fmt.Sprintf("meta %s=%s", metaName,
						truncate(content, 60)), versionFromMatch(m), true
				}
			}
		}
	}
	if len(ct.html) > 0 || len(ct.inline) > 0 {
		bodyLow := strings.ToLower(ev.Body)
		if len(ct.html) > 0 {
			for _, p := range ct.html {
				if text, subs := p.findIn(ev.Body, bodyLow); text != "" {
					return fmt.Sprintf("正则 %s", truncate(p.raw, 40)),
						versionFromMatch(subs), true
				}
			}
		}
		if len(ct.src) > 0 {
			for _, p := range ct.src {
				for _, src := range ev.ScriptSrcs {
					if text, subs := p.findIn(src, src); text != "" {
						return fmt.Sprintf("src %s", truncate(src, 80)),
							versionFromMatch(subs), true
					}
				}
			}
		}
		if len(ct.inline) > 0 {
			for _, p := range ct.inline {
				if text, subs := p.findIn(ev.Body, bodyLow); text != "" {
					return fmt.Sprintf("内联JS %s", truncate(text, 40)),
						versionFromMatch(subs), true
				}
			}
		}
	}
	return "", "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// unescapeName 反转义规则键名中的常见正则转义（\. \-），用于 meta/头名匹配。
func unescapeName(s string) string {
	s = strings.ReplaceAll(s, `\.`, ".")
	s = strings.ReplaceAll(s, `\-`, "-")
	return s
}
