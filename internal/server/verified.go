package server

import (
	"sort"
	"strings"
)

// verifiedGroup verified 归并后的一个发现：同一 (check, host, path) 的多次
// 上报（多页重复、多通道重放）合成一行，并保留来源集合。
//
// 为什么需要：模板通道/被动通道按「一条记录一条发现」上报，同一站点同一
// 检查会在每个爬取页各报一次（cookie-attrs 在 24 页站点产出 48 条重复），
// 直接 len(Verified) 会系统性虚高计数，也让「按来源算精度」不可能。
// 归并只做聚合展示，不改变任何判定——原始条目全部保留在 evidence 里。
type verifiedGroup struct {
	Check    string
	Host     string
	Path     string
	Severity string
	Title    string
	Advice   string
	Srcs     map[string]bool
	URLs     []string
	Evidence []string
	Replay   string
}

// srcLabel 来源中文标签：缺失或未知一律归「自研检测」（引擎默认 src=check）。
func srcLabel(src string) string {
	switch strings.ToLower(strings.TrimSpace(src)) {
	case "nuclei":
		return "模板通道"
	case "dast":
		return "主动探测"
	case "passive":
		return "被动检查"
	case "js":
		return "JS 分析"
	case "security":
		return "安全基线"
	case "weak":
		return "弱口令"
	case "check", "":
		return "自研检测"
	default:
		return "自研检测"
	}
}

// srcName 取条目的来源标识（src 字段，默认 check）。
func srcName(v map[string]any) string {
	s, _ := v["src"].(string)
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "check"
	}
	return s
}

// urlPath 从完整 URL 取路径（无 scheme 时原样返回），用于归并键。
func urlPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return u
}

// hostOf 从完整 URL 取主机（含端口）；无 scheme 时返回空串。
func hostOfURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// siteLevelChecks 站点级发现：同一事实在每个页面都成立（Cookie 缺安全属性、
// 会话 ID 可预测），按页面重复上报只是噪声。这类检查的归并键去掉 path，
// 在 host 层收敛；其余检查（DAST/模板/自研 check）按 (check, host, path) 归并，
// 因为不同路径确实可能是不同的洞。
var siteLevelChecks = map[string]bool{
	"cookie-attrs":    true,
	"weak-session-id": true,
	"csrf-form":       true,
}

// mergeVerified 归并 verified 条目并附来源集合。
// 归并键：站点级检查用 (check, host)，其余用 (check, host, path)——前者治
// 「同一配置事实逐页重复」，后者治「同一 URL 多通道/多重放重复」。
// 输出按 (severity 名次, check, path) 稳定排序，便于报告与复核。
func mergeVerified(list []map[string]any) []verifiedGroup {
	idx := map[string]int{}
	var out []verifiedGroup
	for _, v := range list {
		check, _ := v["check"].(string)
		u, _ := v["url"].(string)
		host := hostOfURL(u)
		if host == "" {
			host, _ = v["host"].(string)
		}
		p := urlPath(u)
		key := check + "\x00" + host + "\x00"
		if !siteLevelChecks[check] {
			key += p
		}
		i, ok := idx[key]
		if !ok {
			sev, _ := v["severity"].(string)
			tit, _ := v["title"].(string)
			ad, _ := v["advice"].(string)
			rep, _ := v["replay"].(string)
			out = append(out, verifiedGroup{
				Check: check, Host: host, Path: p,
				Severity: sev, Title: tit, Advice: ad, Replay: rep,
				Srcs: map[string]bool{},
			})
			i = len(out) - 1
			idx[key] = i
		}
		g := &out[i]
		g.Srcs[srcName(v)] = true
		if u != "" && !containsStr(g.URLs, u) {
			g.URLs = append(g.URLs, u)
		}
		if ev, _ := v["evidence"].(string); ev != "" && !containsStr(g.Evidence, ev) {
			g.Evidence = append(g.Evidence, ev)
		}
		if g.Replay == "" {
			if rep, _ := v["replay"].(string); rep != "" {
				g.Replay = rep
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		ra, rb := sevClass(out[a].Severity), sevClass(out[b].Severity)
		if sevOrder(ra) != sevOrder(rb) {
			return sevOrder(ra) < sevOrder(rb)
		}
		if out[a].Check != out[b].Check {
			return out[a].Check < out[b].Check
		}
		return out[a].Path < out[b].Path
	})
	return out
}

// sevOrder severity 名次（与 sevClass 白名单同序，未知按 info）。
func sevOrder(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// srcSummary 把来源集合拼成稳定显示串（如「自研检测 / 模板通道」）。
func (g verifiedGroup) srcSummary() string {
	labels := make([]string, 0, len(g.Srcs))
	for s := range g.Srcs {
		labels = append(labels, srcLabel(s))
	}
	sort.Strings(labels)
	return strings.Join(labels, " / ")
}

// srcKeys 来源原始键（稳定排序），用于按来源分列统计。
func (g verifiedGroup) srcKeys() []string {
	keys := make([]string, 0, len(g.Srcs))
	for s := range g.Srcs {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	return keys
}

// splitBySrc 按来源分列：src → 归并组列表（组可跨来源，取首个命中来源归属）。
// 同一发现来自多个来源时归入其字母序最前的来源，保证分列计数之和 = 组数。
func splitBySrc(groups []verifiedGroup) ([]string, map[string][]verifiedGroup) {
	bySrc := map[string][]verifiedGroup{}
	var order []string
	seen := map[string]bool{}
	for _, g := range groups {
		keys := g.srcKeys()
		src := "check"
		if len(keys) > 0 {
			src = keys[0]
		}
		if !seen[src] {
			seen[src] = true
			order = append(order, src)
		}
		bySrc[src] = append(bySrc[src], g)
	}
	sort.Strings(order)
	return order, bySrc
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
