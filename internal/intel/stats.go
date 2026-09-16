package intel

import (
	"sort"
	"strings"
)

// Stats 知识库统计（对齐 Python /api/stats 中 intel 侧字段）。
func (k *KB) Stats() map[string]any {
	k.ensureDecoded()
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
		"nvd":               k.NVDCount(),
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
	k.ensureDecoded()
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" || limit <= 0 {
		return []SearchResult{}
	}
	type scored struct {
		r     SearchResult
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
	// NVD 旁路检索：主库命中不足 limit 时用 NVD（CVE 前缀/厂商产品子串）补位。
	nvd := k.nvdStore() // A3：用户主动检索 NVD 时按需加载
	if nvd != nil && len(out) < limit {
		seen := map[string]bool{}
		for _, r := range out {
			seen[r.CVE] = true
		}
		qcve := strings.ToUpper(q)
		nvdLimit := limit - len(out)
		if !strings.HasPrefix(qcve, "CVE-") || len(qcve) < 8 {
			// 非 CVE 词：按产品约束补
			for _, e := range nvd.ByProduct(q, nvdLimit) {
				if !seen[e.CVE] {
					seen[e.CVE] = true
					out = append(out, SearchResult{
						Src: "nvd", Name: e.Descr, Product: nvdProdsJoined(e),
						CVE: e.CVE, Severity: e.Sev, CVSS: e.Score,
					})
				}
			}
		}
		if strings.HasPrefix(qcve, "CVE-") {
			for _, e := range nvd.list {
				if len(out) >= limit {
					break
				}
				if strings.HasPrefix(e.CVE, qcve) && !seen[e.CVE] {
					seen[e.CVE] = true
					out = append(out, SearchResult{
						Src: "nvd", Name: e.Descr, Product: nvdProdsJoined(e),
						CVE: e.CVE, Severity: e.Sev, CVSS: e.Score,
					})
				}
			}
		}
	}
	return out
}

// nvdProdsJoined 检索结果展示用产品串（最多 3 个 vendor/product）。
func nvdProdsJoined(e NVDEntry) string {
	var parts []string
	for i, p := range e.Prods {
		if i >= 3 {
			break
		}
		parts = append(parts, p.VP)
	}
	return strings.Join(parts, ", ")
}
