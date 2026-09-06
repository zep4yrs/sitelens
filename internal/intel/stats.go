package intel

import (
	"sort"
	"strings"
)

// Stats 知识库统计（对齐 Python /api/stats 中 intel 侧字段）。
func (k *KB) Stats() map[string]any {
	bySev := map[string]int{}
	sources := map[string]int{}
	withRanges, withCVSS := 0, 0
	for i := range k.vulns {
		e := &k.vulns[i]
		if e.Severity != "" {
			bySev[strings.ToLower(e.Severity)]++
		}
		if e.Src != "" {
			sources[e.Src]++
		}
		for _, s := range strings.Split(e.Sources, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				sources[s]++
			}
		}
		if e.Affected != "" {
			withRanges++
		}
		if e.CVSSScore > 0 {
			withCVSS++
		}
	}
	return map[string]any{
		"vulns":             len(k.vulns),
		"tscan":             k.tscanCount,
		"vuln_by_severity":  bySev,
		"intel_sources":     sources,
		"intel_with_ranges": withRanges,
		"intel_with_cvss":   withCVSS,
		"cve_ms":            len(k.cveMs),
		"kev":               len(k.kev),
	}
}

// SearchResult 检索结果行（vuln_kb 子集）。
type SearchResult struct {
	ID       int64   `json:"id"`
	Src      string  `json:"src"`
	Name     string  `json:"name"`
	Product  string  `json:"product"`
	CVE      string  `json:"cve"`
	Type     string  `json:"type"`
	Severity string  `json:"severity"`
	Ref      string  `json:"ref"`
	Affected string  `json:"affected"`
	CVSS     float64 `json:"cvss_score"`
}

// Search 漏洞情报模糊检索：product/name/cve/type 子串匹配，
// product 命中排前（近似 Python trgm 检索的语义）。
func (k *KB) Search(q string, limit int) []SearchResult {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" || limit <= 0 {
		return []SearchResult{}
	}
	type scored struct {
		r    SearchResult
		score int
	}
	var hits []scored
	for i := range k.vulns {
		e := &k.vulns[i]
		s := 0
		switch {
		case strings.Contains(strings.ToLower(e.Product), q):
			s = 3
		case strings.Contains(strings.ToLower(e.Name), q):
			s = 2
		case strings.Contains(strings.ToLower(e.CVE), q),
			strings.Contains(strings.ToLower(e.Type), q):
			s = 1
		}
		if s > 0 {
			hits = append(hits, scored{SearchResult{
				ID: e.ID, Src: e.Src, Name: e.Name, Product: e.Product,
				CVE: e.CVE, Type: e.Type, Severity: e.Severity, Ref: e.Ref,
				Affected: e.Affected, CVSS: e.CVSSScore,
			}, s})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		if hits[i].r.CVSS != hits[j].r.CVSS {
			return hits[i].r.CVSS > hits[j].r.CVSS
		}
		return hits[i].r.ID < hits[j].r.ID
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	out := make([]SearchResult, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.r)
	}
	return out
}
