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
type compiledTech struct {
	tech    *Technology
	headers map[string][]*regexp.Regexp
	cookies []*regexp.Regexp
	meta    map[string]*regexp.Regexp
	html    []*regexp.Regexp
	src     []*regexp.Regexp
	inline  []*regexp.Regexp
	usable  bool // 至少存在一个可用通道
}

// Hit 一次指纹命中。
type Hit struct {
	Name     string
	Cats     []string
	Conf     int
	Evidence string
	Version  string
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		out = append(out, regexp.MustCompile("(?i)"+p))
	}
	return out
}

// LoadTechnologies 从 JSON 文件加载指纹规则并预编译正则。
func LoadTechnologies(path string) ([]*compiledTech, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
			if regs := compileAll(pats); len(regs) > 0 {
				if ct.headers == nil {
					ct.headers = make(map[string][]*regexp.Regexp)
				}
				ct.headers[strings.ToLower(name)] = regs
			}
		}
		ct.cookies = compileAll(rules.Cookies)
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
		ct.html = compileAll(rules.HTML)
		ct.src = compileAll(rules.Scripts.Src)
		ct.inline = compileAll(rules.Scripts.Content)
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
		for name, regs := range ct.headers {
			val := ev.Header(name)
			if val == "" {
				continue
			}
			for _, re := range regs {
				if m := re.FindStringSubmatch(val); m != nil {
					return fmt.Sprintf("%s=%s", name, truncate(val, 80)),
						versionFromMatch(m), true
				}
			}
		}
	}
	if len(ct.cookies) > 0 {
		for _, re := range ct.cookies {
			for _, cn := range ev.CookieNames {
				if m := re.FindStringSubmatch(cn); m != nil {
					return fmt.Sprintf("cookie %s", cn), versionFromMatch(m), true
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
	if len(ct.html) > 0 {
		for _, re := range ct.html {
			if m := re.FindStringIndex(ev.Body); m != nil {
				return fmt.Sprintf("正则 %s", truncate(re.String(), 40)),
					versionFromMatch(re.FindStringSubmatch(ev.Body)), true
			}
		}
	}
	if len(ct.src) > 0 {
		for _, re := range ct.src {
			for _, src := range ev.ScriptSrcs {
				if m := re.FindStringSubmatch(src); m != nil {
					return fmt.Sprintf("src %s", truncate(src, 80)),
						versionFromMatch(m), true
				}
			}
		}
	}
	if len(ct.inline) > 0 {
		for _, re := range ct.inline {
			if m := re.FindStringSubmatch(ev.Body); m != nil {
				return fmt.Sprintf("内联JS %s", truncate(m[0], 40)),
					versionFromMatch(m), true
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
