// Package intel 漏洞情报匹配：技术 → vuln_kb 情报 + 版本区间三级判定 + KEV 红标。
//
// 定位是「情报提示」而非「漏洞验证」——只做产品名关联与版本区间判定，
// 不发起任何攻击性请求。移植自 scanner/vuln.py 的 match/match_cve_ms。
package intel

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/versioncmp"
)

// Entry vuln_kb 情报行（对齐 PG 表 + 富集列）。
type Entry struct {
	ID            int64   `json:"id"`
	Src           string  `json:"src"`
	Name          string  `json:"name"`
	Product       string  `json:"product"`
	CVE           string  `json:"cve"`
	Type          string  `json:"type"`
	Severity      string  `json:"severity"`
	Ref           string  `json:"ref"`
	Descr         string  `json:"descr"`
	Affected      string  `json:"affected"`
	Sources       string  `json:"sources"`
	CVSSScore     float64 `json:"cvss_score"`
	CVSSSev       string  `json:"cvss_sev"`
	CVSSVectorTxt string  `json:"cvss_vector_txt"`
}

// KevEntry CISA KEV 在野利用清单行。
type KevEntry struct {
	CVE        string `json:"cve"`
	DateAdded  string `json:"date_added"`
	Ransomware string `json:"ransomware"`
}

// CuratedRange 精选版本区间（data/affected_ranges.json）。
type CuratedRange struct {
	CVE      string `json:"cve"`
	Affected string `json:"affected"`
	Title    string `json:"title"`
}

// CVEMsRow cve_ms 微软公告行。
type CVEMsRow struct {
	CVE       string `json:"cve"`
	Component string `json:"component"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Impact    string `json:"impact"`
	Date      string `json:"date"`
}

// TechHit 已识别技术（名称+可选版本）。
type TechHit struct {
	Name    string
	Version string
}

// Finding 一条情报关联结论。
type Finding struct {
	ID         int64   `json:"id"`
	Tech       string  `json:"tech"`
	Version    string  `json:"version"`
	Src        string  `json:"src"`
	Name       string  `json:"name"`
	Title      string  `json:"title"`
	Product    string  `json:"product"`
	CVE        string  `json:"cve"`
	Type       string  `json:"type"`
	Severity   string  `json:"severity"`
	SeverityZh string  `json:"severity_zh"`
	CVSSScore  float64 `json:"cvss_score"`
	CVSSSev    string  `json:"cvss_sev"`
	Ref        string  `json:"ref"`
	Desc       string  `json:"desc"`
	Verdict    string  `json:"verdict"` // confirmed | possible
	Affected   string  `json:"affected"`
	KEV        bool    `json:"kev"`
}

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4,
}

var severityZh = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
}

const maxPerTech = 20

func severityOrderOf(sev string) int {
	return severityOrder[strings.ToLower(sev)]
}

func severityZhOf(sev string) string {
	if zh := severityZh[strings.ToLower(sev)]; zh != "" {
		return zh
	}
	return sev
}

// KB 漏洞情报知识库（内存索引，扫描主路径）。
type KB struct {
	vulns      []Entry
	cveMs      []CVEMsRow
	index      map[string][]*Entry
	kev        map[string]bool
	ranges     map[string][]CuratedRange
	tscanCount int
}

// Load 从知识库数据包与精选区间文件加载知识库。
func Load(dumpGz, rangesJSON string) (*KB, error) {
	f, err := os.Open(dumpGz)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var box struct {
		Tables struct {
			VulnKB []Entry `json:"vuln_kb"`
			CVEMs  []struct {
				CVE       string `json:"cve"`
				Component string `json:"component"`
				Title     string `json:"title"`
				Severity  string `json:"severity"`
				Impact    string `json:"impact"`
				Date      string `json:"date"`
			} `json:"cve_ms"`
			KEV   []KevEntry `json:"kev"`
			Tscan []struct{} `json:"tscan_fingerprints"` // 仅取条数供统计
		} `json:"tables"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		return nil, err
	}
	kb := &KB{vulns: box.Tables.VulnKB, kev: map[string]bool{},
		tscanCount: len(box.Tables.Tscan)}
	for _, k := range box.Tables.KEV {
		kb.kev[strings.ToUpper(k.CVE)] = true
	}
	kb.cveMs = make([]CVEMsRow, 0, 4096)
	for _, c := range box.Tables.CVEMs {
		kb.cveMs = append(kb.cveMs, CVEMsRow{
			CVE: c.CVE, Component: c.Component, Title: c.Title,
			Severity: c.Severity, Impact: c.Impact, Date: c.Date,
		})
	}
	kb.buildIndex()
	if rangesJSON != "" {
		if data, rerr := os.ReadFile(rangesJSON); rerr == nil {
			var curated map[string][]CuratedRange
			if jerr := json.Unmarshal(data, &curated); jerr == nil {
				kb.ranges = make(map[string][]CuratedRange, len(curated))
				for name, rs := range curated {
					kb.ranges[strings.ToLower(name)] = rs
				}
			}
		}
	}
	return kb, nil
}

var stopwords = map[string]bool{
	"api": true, "app": true, "web": true, "server": true, "service": true,
	"cloud": true, "panel": true, "manager": true, "system": true,
	"proxy": true, "framework": true, "library": true, "script": true,
	"cms": true, "cdn": true, "kit": true, "pro": true, "plus": true,
	"soft": true, "the": true, "and": true,
}

// buildIndex 建立 lower(产品关键词) → 情报 的内存索引（扫描主路径）。
func (k *KB) buildIndex() {
	k.index = make(map[string][]*Entry, 4096)
	for i := range k.vulns {
		v := &k.vulns[i]
		for kw := range Keywords(v.Product, true) {
			k.index[kw] = append(k.index[kw], v)
		}
	}
}

// Keywords 产品名 → 匹配关键词集合（移植 product_keywords）。
//
// lookup 侧（技术名→漏洞）：多词产品只按完整短语匹配，杜绝 "api"/"google"
// 泛词误报；index 侧（漏洞建索引）：短语之外再收录显著单词（>=4 字符非停用词）。
func Keywords(product string, indexSide bool) map[string]bool {
	if product == "" {
		return nil
	}
	p := strings.ToLower(strings.TrimSpace(product))
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '.', '-', '_', ' ':
			return -1
		}
		return r
	}, p)
	kws := map[string]bool{p: true, compact: true}
	words := strings.FieldsFunc(p, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == ' '
	})
	if len(words) == 1 {
		kws[words[0]] = true
	} else if indexSide {
		for _, w := range words {
			if len([]rune(w)) >= 4 && !stopwords[w] {
				kws[w] = true
			}
		}
	}
	out := map[string]bool{}
	for k := range kws {
		if len([]rune(k)) >= 3 {
			out[k] = true
		}
	}
	return out
}

// Match 漏洞情报三级判定（移植 vuln.py match）：
// confirmed（版本落在受影响区间）/ possible（同名提示）/
// excluded（有版本但不在区间，直接跳过不输出）。
func (k *KB) Match(techs []TechHit) []Finding {
	if k.index == nil {
		k.buildIndex()
	}
	out, seen := []Finding{}, map[int64]bool{}
	for _, tech := range techs {
		ranges := k.ranges[strings.ToLower(tech.Name)]
		if tech.Version != "" && len(ranges) > 0 {
			// 有精确版本且该技术有精选区间：只输出区间判定结论
			for _, r := range ranges {
				if versioncmp.VersionIn(tech.Version, r.Affected) {
					out = append(out, Finding{
						Tech: tech.Name, Version: tech.Version,
						CVE: r.CVE, Name: r.Title, Title: r.Title,
						Severity: "high", SeverityZh: "确认受影响",
						Verdict: "confirmed", Src: "intel-range",
						Product: tech.Name,
					})
				}
			}
			continue
		}
		for _, v := range k.vulnsFor(tech.Name) {
			if seen[v.ID] {
				continue
			}
			verdict, affected := "possible", ""
			if tech.Version != "" && v.Affected != "" {
				verdict = "possible"
				for _, alt := range strings.Split(v.Affected, "|") {
					alt = strings.TrimSpace(alt)
					if alt == "" {
						continue
					}
					if versioncmp.VersionIn(tech.Version, alt) {
						verdict = "confirmed"
						affected = alt
						break
					}
					verdict = "excluded"
				}
			}
			if verdict == "excluded" {
				seen[v.ID] = true
				continue
			}
			seen[v.ID] = true
			out = append(out, Finding{
				ID: v.ID, Tech: tech.Name, Version: tech.Version,
				Src: v.Src, Name: v.Name, Product: v.Product,
				CVE: v.CVE, Type: v.Type, Severity: v.Severity,
				SeverityZh: severityZhOf(v.Severity), Ref: v.Ref,
				CVSSScore: v.CVSSScore, CVSSSev: v.CVSSSev,
				Desc: v.Descr, Verdict: verdict, Affected: affected,
				KEV: k.kev[strings.ToUpper(v.CVE)],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return severityOrder[out[i].Severity] < severityOrder[out[j].Severity]
	})
	return out
}

func (k *KB) vulnsFor(techName string) []*Entry {
	if k.index == nil {
		k.buildIndex()
	}
	var out []*Entry
	seen := map[*Entry]bool{}
	for kw := range Keywords(techName, false) {
		for _, v := range k.index[kw] {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return severityOrder[out[i].Severity] < severityOrder[out[j].Severity]
	})
	return out
}

// MSAliases 技术名 → 微软公告组件名的常见别名。
var MSAliases = map[string]string{
	"microsoft iis":  "internet information services",
	"asp.net":        "asp.net core",
	"microsoft edge": "edge",
}

// CVEMsFinding 微软公告关联结论。
type CVEMsFinding struct {
	Tech       string `json:"tech"`
	CVE        string `json:"cve"`
	Title      string `json:"title"`
	Component  string `json:"component"`
	Severity   string `json:"severity"`
	SeverityZh string `json:"severity_zh"`
	Src        string `json:"src"`
	Type       string `json:"type"`
}

// MatchCVEMs 微软安全公告关联（按组件名包含匹配，双向别名）。
func (k *KB) MatchCVEMs(techs []TechHit, limit int) []CVEMsFinding {
	out := []CVEMsFinding{}
	seen := map[string]bool{}
	for _, tech := range techs {
		for _, name := range []string{tech.Name, MSAliases[strings.ToLower(tech.Name)]} {
			if name == "" {
				continue
			}
			low := strings.ToLower(name)
			for i := range k.cveMs {
				c := &k.cveMs[i]
				comp := strings.ToLower(c.Component)
				if !strings.Contains(comp, low) && !strings.Contains(low, comp) {
					continue
				}
				k := c.CVE + "|" + c.Component
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, CVEMsFinding{
					Tech: tech.Name, CVE: c.CVE, Title: c.Title,
					Component: c.Component, Severity: c.Severity,
					SeverityZh: severityZhOf(c.Severity), Src: "ms-bulletin",
					Type: c.Impact,
				})
				if len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
}
