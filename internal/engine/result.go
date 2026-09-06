// Package engine 扫描编排器：校验 → 采集 → 指纹 → check → 爬取 → 模块 → 情报关联。
// 流水线移植自 python 分支 scanner/engine.py；结果 JSON 键位与其 to_dict() 对齐，
// 前端无需改动即可消费。
package engine

import (
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/security"
)

// Tech 结果中的一条已识别技术。
type Tech struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	Confidence int      `json:"confidence"`
	Version    string   `json:"version"`
	Website    string   `json:"website"`
	Evidence   []string `json:"evidence"`
}

// PageInfo 已访问页面摘要。
type PageInfo struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// Result 一次扫描的完整结果。
// verified 为异构条目（checks/dast/passive），统一 map 形态；
// 其余键位与 Python ScanResult.to_dict() 一致。
type Result struct {
	URL             string           `json:"url"`
	Host            string           `json:"host"`
	Title           string           `json:"title"`
	Status          int              `json:"status"`
	IP              string           `json:"ip"`
	ResponseTimeMS  int              `json:"response_time_ms"`
	ScannedAt       string           `json:"scanned_at"`
	Duration        float64          `json:"duration"`
	Error           string           `json:"error"`
	Security        *security.Report `json:"security"`
	Technologies    []Tech           `json:"technologies"`
	Vulnerabilities []intel.Finding  `json:"vulnerabilities"`
	Verified        []map[string]any `json:"verified"`
	Extras          map[string]any   `json:"extras"`
	Pages           []PageInfo       `json:"pages"`
}

// techAcc 技术聚合器：同名合并、证据累加、每次独立命中置信 +5（上限 100）。
type techAcc struct {
	byName map[string]*Tech
	order  []string
}

func newTechAcc() *techAcc { return &techAcc{byName: map[string]*Tech{}} }

// add 并入一次指纹命中。
func (a *techAcc) add(name, website, version, evidence string, base int, cats []string) {
	t, ok := a.byName[name]
	if !ok {
		if cats == nil {
			cats = []string{}
		}
		t = &Tech{
			Name: name, Categories: cats, Confidence: base, Website: website,
			Version: version, Evidence: []string{},
		}
		a.byName[name] = t
		a.order = append(a.order, name)
	}
	if evidence != "" {
		t.Evidence = append(t.Evidence, evidence)
		if len(t.Evidence) > 1 {
			t.Confidence += 5
			if t.Confidence > 100 {
				t.Confidence = 100
			}
		}
	}
	// 版本号只允许设置一次（取第一个识别出的）
	if version != "" && t.Version == "" {
		t.Version = version
	}
	if website != "" && t.Website == "" {
		t.Website = website
	}
}

// list 按发现顺序输出。
func (a *techAcc) list() []Tech {
	out := make([]Tech, 0, len(a.order))
	for _, n := range a.order {
		out = append(out, *a.byName[n])
	}
	return out
}

// techHits 输出情报关联输入（名称 + 版本）。
func (a *techAcc) techHits() []intel.TechHit {
	out := make([]intel.TechHit, 0, len(a.order))
	for _, n := range a.order {
		t := a.byName[n]
		out = append(out, intel.TechHit{Name: t.Name, Version: t.Version})
	}
	return out
}

// verifiedMap 把各来源发现规整为统一键位的 map 条目。
func verifiedMap(m map[string]any) map[string]any {
	if _, ok := m["src"]; !ok {
		m["src"] = "check"
	}
	return m
}
