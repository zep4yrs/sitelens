package crawler

import (
	"net/url"
	"strings"
)

// robotsRule 一条 Allow/Disallow 规则。
type robotsRule struct {
	pattern   string   // 原始模式（日志用）
	segments  []string // 按 * 切分后的段
	endAnchor bool     // 原模式以 $ 结尾（须匹配到路径末尾）
	allow     bool
}

// robotsGroup 一个 User-agent 分组下的规则集合。
type robotsGroup struct {
	agents []string
	rules  []robotsRule
}

// robotsFile 解析后的 robots.txt。
type robotsFile struct {
	groups   []robotsGroup
	sitemaps []string
}

// parseRobots 解析 robots.txt。遵循 Google 规范主要部分：
// UA 分组、连续 UA 共享规则、Allow/Disallow、空 Disallow 忽略、Sitemap 全局收集。
func parseRobots(body string) robotsFile {
	var f robotsFile
	var cur *robotsGroup
	curHasRule := false

	flush := func() {
		if cur != nil && len(cur.agents) > 0 {
			f.groups = append(f.groups, *cur)
		}
		cur, curHasRule = nil, false
	}

	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])

		switch key {
		case "user-agent":
			if cur == nil {
				cur = &robotsGroup{}
			} else if curHasRule {
				flush()
				cur = &robotsGroup{}
			}
			cur.agents = append(cur.agents, strings.ToLower(val))
		case "disallow", "allow":
			if cur == nil {
				cur = &robotsGroup{}
			}
			curHasRule = true
			if val == "" {
				continue // 空值无限制
			}
			cur.rules = append(cur.rules, compileRobotsRule(val, key == "allow"))
		case "sitemap":
			if strings.HasPrefix(val, "http") {
				f.sitemaps = append(f.sitemaps, val)
			}
		}
	}
	flush()
	return f
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// compileRobotsRule 编译模式：* 为通配，$ 为末尾锚点。
func compileRobotsRule(pattern string, allow bool) robotsRule {
	r := robotsRule{pattern: pattern, allow: allow}
	p := pattern
	if strings.HasSuffix(p, "$") {
		r.endAnchor = true
		p = strings.TrimSuffix(p, "$")
	}
	r.segments = strings.Split(p, "*")
	return r
}

// matches path 是否命中该模式。
func (r robotsRule) matches(path string) bool {
	if len(r.segments) == 1 {
		// 无通配：前缀匹配；$ 锚点要求精确到末尾
		if r.endAnchor {
			return path == r.segments[0]
		}
		return strings.HasPrefix(path, r.segments[0])
	}
	// 含 *：按段在 path 中前进匹配
	pos := 0
	if first := r.segments[0]; first != "" {
		if !strings.HasPrefix(path, first) {
			return false
		}
		pos = len(first)
	}
	last := len(r.segments) - 1
	for i, seg := range r.segments[1:] {
		if seg == "" {
			continue
		}
		if i == last-1 && r.endAnchor {
			// 末段需贴尾
			return len(path)-pos >= len(seg) && strings.HasSuffix(path[pos:], seg)
		}
		idx := strings.Index(path[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	return true
}

// patternLen 规则长度（用于最长匹配优先）。
func (r robotsRule) patternLen() int { return len(r.pattern) }

// allowedBy 判断 path 是否放行：最长匹配优先，同长度 Allow 胜。
func (g robotsGroup) allowedBy(path string) bool {
	best := -1
	allow := true
	for _, r := range g.rules {
		if !r.matches(path) {
			continue
		}
		if l := r.patternLen(); l > best || (l == best && r.allow) {
			best, allow = l, r.allow
		}
	}
	return allow
}

// selectGroup 选择适用组：精确 UA 优先，其次 *，都没有返回 nil。
func (f robotsFile) selectGroup(agent string) *robotsGroup {
	agent = strings.ToLower(agent)
	var star *robotsGroup
	for i := range f.groups {
		g := &f.groups[i]
		for _, a := range g.agents {
			switch {
			case a == "*":
				if star == nil {
					star = g
				}
			case a == agent || strings.Contains(agent, a):
				return g
			}
		}
	}
	return star
}

// pathOf 提取 robots 匹配用路径（含 query，空则 "/"）。
func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}
