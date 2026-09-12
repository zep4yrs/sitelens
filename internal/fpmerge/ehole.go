// EHole 社区指纹（xhmcc/ehole_finger 等 finger.json 形态）合并。
//
// 规则语义：cms + location(body/title/header) + keyword 字面量列表 +
// faviconhash。合并策略：按 cms 分组为一项技术，body/title 关键词落
// html 通道（字面量精确转义），header 关键词落 headers["*"] 任意头
// 通配通道，faviconhash 落 icon_hash；同 cms 多规则关键词并集去重。
package fpmerge

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// eholeRule EHole finger.json 单条规则。
type eholeRule struct {
	CMS         string   `json:"cms"`
	Method      string   `json:"method"`
	Location    string   `json:"location"`
	Keyword     []string `json:"keyword"`
	IsImportant bool     `json:"isImportant"`
	Type        string   `json:"type"`
}

var reNonASCIISlug = regexp.MustCompile(`[^a-z0-9]+`)

// MergeEHole 合并 EHole 指纹（与 MergeFromTar 相同的精编优先/同名跳过语义）。
func MergeEHole(data []byte, technologiesPath string) (Stats, error) {
	var st Stats
	var box struct {
		Fingerprint []eholeRule `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return st, err
	}
	base, err := os.ReadFile(technologiesPath)
	if err != nil {
		return st, err
	}
	var bf boxFile
	if err := json.Unmarshal(base, &bf); err != nil {
		return st, err
	}
	existing := map[string]bool{}
	for _, t := range bf.Technologies {
		existing[strings.ToLower(t.Name)] = true
	}

	// 按 cms 分组聚合关键词
	type agg struct {
		name    string
		html    []string
		header  []string
		iconH   []int64
		important bool
	}
	groups := map[string]*agg{}
	var order []string
	for _, r := range box.Fingerprint {
		if r.CMS == "" || len(r.Keyword) == 0 {
			continue
		}
		g, ok := groups[r.CMS]
		if !ok {
			g = &agg{name: r.CMS}
			groups[r.CMS] = g
			order = append(order, r.CMS)
		}
		if r.IsImportant {
			g.important = true
		}
		for _, kw := range r.Keyword {
			kw = strings.TrimSpace(kw)
			if kw == "" || len(kw) > 200 {
				continue
			}
			switch strings.ToLower(r.Method) {
			case "faviconhash":
				h, perr := strconv.ParseInt(strings.TrimSpace(kw), 10, 64)
				if perr == nil && h != 0 && len(g.iconH) < 4 {
					g.iconH = append(g.iconH, h)
				}
			case "keyword":
				lit := kw // exact 通道：关键词按字面量精确包含，不做正则解释
				switch strings.ToLower(r.Location) {
				case "body", "title":
					if !containsStr(g.html, lit) && len(g.html) < 12 {
						g.html = append(g.html, lit)
					}
				case "header":
					if !containsStr(g.header, lit) && len(g.header) < 6 {
						g.header = append(g.header, lit)
					}
				}
			}
		}
	}

	for _, name := range order {
		g := groups[name]
		ln := strings.ToLower(name)
		if existing[ln] {
			st.SkippedDup++
			continue
		}
		rules := map[string]any{}
		if len(g.html) > 0 {
			rules["html"] = g.html
		}
		if len(g.header) > 0 {
			rules["headers"] = map[string][]string{"*": g.header}
		}
		if len(g.iconH) > 0 {
			rules["icon_hash"] = g.iconH
		}
		if len(rules) == 0 {
			st.SkippedEmpty++
			continue
		}
		raw, err := json.Marshal(rules)
		if err != nil {
			return st, err
		}
		conf := 70
		if g.important {
			conf = 80
		}
		bf.Technologies = append(bf.Technologies, entry{
			Name: g.name, Conf: conf, Rules: raw, Exact: true,
		})
		existing[ln] = true
		st.Added++
	}
	st.Total = len(bf.Technologies)
	bf.Version = 1
	bf.Count = st.Total
	out, merr := json.MarshalIndent(bf, "", " ")
	if merr != nil {
		return st, merr
	}
	return st, osWriteFile(technologiesPath, out)
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
