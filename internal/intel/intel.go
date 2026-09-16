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
	"sync"

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
	ID         int64    `json:"id"`
	Tech       string   `json:"tech"`
	Version    string   `json:"version"`
	Src        string   `json:"src"`
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Product    string   `json:"product"`
	CVE        string   `json:"cve"`
	Type       string   `json:"type"`
	Severity   string   `json:"severity"`
	SeverityZh string   `json:"severity_zh"`
	CVSSScore  float64  `json:"cvss_score"`
	CVSSSev    string   `json:"cvss_sev"`
	Ref        string   `json:"ref"`
	Desc       string   `json:"desc"`
	Verdict    string   `json:"verdict"` // confirmed | possible
	Affected   string   `json:"affected"`
	KEV        bool     `json:"kev"`
	Templates  []string `json:"templates,omitempty"` // 可直接复跑的模板路径（模板情报层）
	// CWEs 弱类型编号（4.0 P5）：来自 NVD weaknesses（经 nvdFill 回填）。
	// 缺口时为空——不臆造，消费方按空处理。
	CWEs []string `json:"cwes,omitempty"`
}

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4,
}

var severityZh = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
}

const maxPerTech = 20 // 单技术最多关联的情报条数

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
	fingerDir  []FingerDirRow
	serviceFP  []ServiceFPRow
	nvd        *NVDStore // 旁路挂载，可 nil
	// A5 惰性解码：intel_dump 启动不解码，首次真正用到（Match/检索/统计）才解。
	dumpPath   string
	rangesPath string
	loadMu     sync.Mutex // 守护重解码；Release 复位后须可再次进入（Once 只触发一次）
	decoded    bool
	loadErr    error
	// 惰性期挂起的附加操作（解码后按序应用）：
	pendingTpl []Entry             // AttachTplIntel 待并入（Release 后亦存回模板行待重并）
	pendingOv  map[string]Override // 待应用的覆盖（Release 后存回最近覆盖待重放）
	lastOv     map[string]Override // 最近一次 ApplyOverrides 的数据（Release 重放的来源）
	techCPE    map[string]string   // 技术名 → CPE（NVD 通道），可 nil

	// A3 惰性加载：只记路径，**首次真正用到 NVD 数据时**才解码索引。
	// 背景：NVD 全量索引实测占 HeapSys ≈1.7GB，是引擎空闲 RSS 的主因；
	// 而纯指纹/端口场景根本用不到它，此前却在每次启动时全量解码。
	nvdPath  string
	nvdMu    sync.Mutex // 守护重加载；Release 后复位 nvdTried 允许重载
	nvdTried bool
	nvdErr   error
}

// ServiceFPRow 端口服务 banner 指纹行。
type ServiceFPRow struct {
	Service string `json:"service"`
	Pattern string `json:"pattern"`
	Product string `json:"product"`
	Version string `json:"version"`
	Soft    bool   `json:"soft"`
}

// ServiceFP 返回端口服务 banner 指纹集。
func (k *KB) ServiceFP() []ServiceFPRow {
	k.ensureDecoded()
	return k.serviceFP
}

// FingerDirRow FingerDir 主动路径指纹行。
type FingerDirRow struct {
	Product string             `json:"product"`
	Spec    FingerDirMatchSpec `json:"spec"`
}

// FingerDirMatchSpec 匹配规格（对齐 Python _spec_match 字段）。
type FingerDirMatchSpec struct {
	Paths           []string `json:"paths"`
	Status          []int    `json:"status"`
	ContentType     []string `json:"content_type"`
	BodyContains    []string `json:"body_contains"`
	HeaderContains  []string `json:"header_contains"`
	BodyNotContains []string `json:"body_not_contains"`
}

// FingerDir 返回主动路径指纹集。
func (k *KB) FingerDir() []FingerDirRow {
	k.ensureDecoded()
	return k.fingerDir
}

// Load 从知识库数据包与精选区间文件加载知识库（立即解码；行为与 3.0 一致）。
// 与 LoadLazy 共用惰性骨架：KB 保留源路径，Release 后可自动重载。
func Load(dumpGz, rangesJSON string) (*KB, error) {
	k := LoadLazy(dumpGz, rangesJSON)
	k.ensureDecoded()
	if err := k.loadErr; err != nil {
		return nil, err
	}
	return k, nil
}

// LoadLazy 惰性加载（A5，4.0 Track A）：只记路径，首次真正用到时才解码。
// 动机：intel_dump 解码占 HeapSys ≈67MB；serve 空闲期（尚未扫描）不必付。
// 与 A3 的 NVD 惰性同模式；加载失败延迟到使用点（表为空），可用 LoadError 查询。
func LoadLazy(dumpGz, rangesJSON string) *KB {
	return &KB{dumpPath: dumpGz, rangesPath: rangesJSON}
}

// LoadError 返回惰性解码失败的原因（未失败返回空）。
func (k *KB) LoadError() string {
	if k == nil {
		return ""
	}
	if k.loadErr != nil {
		return k.loadErr.Error()
	}
	return ""
}

// ensureDecoded 确保表已解码（幂等；直接构造 &KB{vulns:...} 的测试场景视为已解码）。
func (k *KB) ensureDecoded() {
	if k == nil || k.decoded {
		return
	}
	if k.dumpPath == "" && k.rangesPath == "" {
		k.decoded = true // 纯内存构造：无源可解
		return
	}
	k.loadMu.Lock()
	defer k.loadMu.Unlock()
	if k.decoded { // 双检：等锁期间他人已完成
		return
	}
	nk, err := decodeAll(k.dumpPath, k.rangesPath)
	if err != nil {
		k.loadErr = err
		k.decoded = true
		return
	}
	k.vulns, k.cveMs, k.kev = nk.vulns, nk.cveMs, nk.kev
	k.ranges, k.tscanCount = nk.ranges, nk.tscanCount
	k.fingerDir, k.serviceFP, k.techCPE = nk.fingerDir, nk.serviceFP, nk.techCPE
	k.index = nil // 留给 buildIndex 重建
	k.decoded = true
	// 应用挂起的附加操作（顺序：先并入模板情报，再打覆盖；
	// Release 后的模板行/覆盖重放也走这两步）
	if len(k.pendingTpl) > 0 {
		k.AttachTplIntel(k.pendingTpl)
		k.pendingTpl = nil
	}
	if len(k.pendingOv) > 0 {
		k.ApplyOverrides(k.pendingOv)
		k.pendingOv = nil
	}
}

// decodeAll 原 Load 的解码体（Load 与 A5 惰性路径共用）。
func decodeAll(dumpGz, rangesJSON string) (*KB, error) {
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
			KEV       []KevEntry     `json:"kev"`
			Tscan     []struct{}     `json:"tscan_fingerprints"` // 仅取条数供统计
			FingerDir []FingerDirRow `json:"fingerdir"`
			ServiceFP []ServiceFPRow `json:"service_fp"`
		} `json:"tables"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		return nil, err
	}
	kb := &KB{vulns: box.Tables.VulnKB, kev: map[string]bool{},
		tscanCount: len(box.Tables.Tscan),
		fingerDir:  box.Tables.FingerDir,
		serviceFP:  box.Tables.ServiceFP}
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
	k.ensureDecoded()
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
					k.nvdFill(&out[len(out)-1])
				}
			}
			continue
		}
		perTech := 0
		for _, v := range k.vulnsFor(tech.Name) {
			if perTech >= maxPerTech {
				break
			}
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
			perTech++
			out = append(out, Finding{
				ID: v.ID, Tech: tech.Name, Version: tech.Version,
				Src: v.Src, Name: v.Name, Product: v.Product,
				CVE: v.CVE, Type: v.Type, Severity: v.Severity,
				SeverityZh: severityZhOf(v.Severity), Ref: v.Ref,
				CVSSScore: v.CVSSScore, CVSSSev: v.CVSSSev,
				Desc: v.Descr, Verdict: verdict, Affected: affected,
				KEV: k.kev[strings.ToUpper(v.CVE)],
			})
			k.nvdFill(&out[len(out)-1])
		}
		// NVD 字典 CPE 通道：possible 级（区间判定 3.1 接入）
		k.nvdPossible(tech.Name, seen, &out)
	}
	sort.Slice(out, func(i, j int) bool {
		return severityOrder[out[i].Severity] < severityOrder[out[j].Severity]
	})
	return out
}

// lookupAliases 指纹技术名 → 情报库产品名的补充查询别名。
//
// 情报产品名与指纹名的系统性差异（WordPress 插件在情报侧带平台前缀、
// IIS 在情报侧用缩写等）导致短语匹配漏配；仅收录经全库核对同属一个
// 软件的条目——宁缺毋滥，错误的别名会把别家产品的漏洞安到无关指纹上。
// 数据来源：technologies.json 370 项与 intel 库 6511 产品逐一比对，
// 279 个未命中项中仅这三对经人工核实成立，其余均为情报未覆盖或
// 同词不同物（如各路 "editor" 互不相干）。
var lookupAliases = map[string][]string{
	"microsoft iis":      {"iis", "microsoft-iis6.0"}, // HTTP.sys RCE / WebDAV ScStoragePathFromUrl RCE
	"yoast seo":          {"wordpress yoast"},         // Yoast SEO 16.7-17.2 信息泄露
	"akamai bot manager": {"akamai"},                  // 指纹命中即平台在用，缓存投毒 XSS 适用
}

func (k *KB) vulnsFor(techName string) []*Entry {
	k.ensureDecoded()
	if k.index == nil {
		k.buildIndex()
	}
	var out []*Entry
	seen := map[*Entry]bool{}
	names := append([]string{techName}, lookupAliases[strings.ToLower(strings.TrimSpace(techName))]...)
	for _, n := range names {
		for kw := range Keywords(n, false) {
			for _, v := range k.index[kw] {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
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
	k.ensureDecoded()
	out := []CVEMsFinding{}
	seen := map[string]bool{}
	for _, tech := range techs {
		for _, name := range []string{tech.Name, MSAliases[strings.ToLower(tech.Name)]} {
			if name == "" {
				continue
			}
			low := strings.ToLower(strings.TrimSpace(name))
			if low == "" {
				continue
			}
			for i := range k.cveMs {
				c := &k.cveMs[i]
				comp := strings.ToLower(strings.TrimSpace(c.Component))
				// 空组件名在反向包含（Contains(low, "") 恒真）下会匹配
				// 任意技术——实测每次扫描 20 条配额全被无关公告占满；
				// 过短组件名同理放大误配，一律要求 ≥4 字符
				if len(comp) < 4 {
					continue
				}
				if !strings.Contains(comp, low) && !(len(low) >= 4 && strings.Contains(low, comp)) {
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

// Release 释放情报表（A10 自适应版）：清空常驻表并复位解码标记。
// 下一次访问经 ensureDecoded 自动重新加载（nvdPath/nvd 保留原惰性语义）。
//
// 背景：A10 原方案是「情报库独立 sidecar 进程」，目标是任务间隔释放内存。
// A3+A5 惰性化后，本方法以进程内方式达成同一目标（无 IPC/无额外进程），
// 供 serve 模式在长时间空闲或管理操作时调用。
func (k *KB) Release() {
	if k == nil {
		return
	}
	k.ensureDecoded() // 若尚未解码则无事发生（保持 decoded，不丢挂起队列）
	// 附加物存回待应用队列，重载后经 ensureDecoded 重放：
	// 模板行 = 负 ID 段；覆盖 = 最近一次 ApplyOverrides 的数据。
	var tpl []Entry
	for _, v := range k.vulns {
		if v.ID < 0 {
			tpl = append(tpl, v)
		}
	}
	k.pendingTpl = tpl
	k.pendingOv = k.lastOv
	k.vulns, k.cveMs, k.index = nil, nil, nil
	k.kev, k.ranges = map[string]bool{}, map[string][]CuratedRange{}
	k.tscanCount = 0
	k.decoded = false
	k.nvd = nil        // NVD 亦释放；nvdPath 保留
	k.nvdTried = false // 复位尝试标记，下次访问可重载
}
