// Package nuclei Nuclei 社区模板子集装载（MoE 式三路调度）：
// ① tag 与已识别技术硬匹配的模板置顶（severity 升序）；
// ② 其余按 TF 余弦相似度排序（查询 = 页面标题+技术名；语义向量路由
//
//	的 TF 空间同构近似，无模型依赖）；
//
// ③ 持久化 LRU：最久未跑优先，跨重启保持轮转公平——⌈C/N⌉ 次扫描
//
//	完成全量轮换。模板漏斗对齐 python 分支 tools/import_nuclei.py：
//	仅接受单请求、path 为 {{BaseURL}} 后缀、matchers 为 status/word/
//	regex/dsl（安全子集）的模板；需要外部回调（interactsh）的模板跳过。
package nuclei

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/dsl"
)

// Entry 索引条目（建索引时一次全量 Convert 验证）。
type Entry struct {
	Path        string   `json:"path"`             // 相对 dir
	Name        string   `json:"name"`             // 模板名（相关度排序用）
	Tags        []string `json:"tags"`             // 精确 tags（来自完整 Convert）
	Sev         string   `json:"sev"`              // 精确严重度
	CVEs        []string `json:"cves,omitempty"`   // 模板声明的 CVE（模板情报层）
	Proto       string   `json:"proto,omitempty"`  // tcp|dns|ssl = 协议模板（空 = HTTP）
	MTime       int64    `json:"mtime"`            // 文件修改时间
	Size        int64    `json:"size"`             // 文件大小
	Convertible bool     `json:"convertible"`      // 能通过漏斗转换为可执行 check
	LastRun     int64    `json:"lastrun"`          // 最近一次运行时间（unix nano；0=从未）
	Source      string   `json:"source,omitempty"` // 模板来源类别（路径归一，见 NormalizeSource）
}

// cacheSchema 索引缓存格式版本——格式变更时递增以强制重建
// （历史缓存中 Tags 全空，无法通过条目数区分新旧格式）。
// v5：raw 请求形态 + afrog 经典形态接入，同批文件可转换面扩大。
// v6：Entry 增 CVEs 字段（模板情报层）。
// v7：协议模板准入（tcp/dns/ssl，Proto 字段）。
// v8：Entry 增 Source 字段（路径归一来源类别，输出分列口径）。
// v9：afrog rule 级 expression 接线（BUG-016，1,699 条从"全拒"变为可运行）
//
//   - path 列表展开（BUG-022，check 数变化）→ 旧缓存必须整库重建，
//     否则升级后仍按旧"仅 8 个来源可转换"的结论调度。
//
// v10：缓存增「目录 mtime 戳」（Dirs），热路径不再全量 walk 计数，
// 改为逐个 stat 缓存里的目录戳（见 index_hot.go）。
//
//   - 升级影响：v9 及更旧缓存整体失效 → 升级后首次 Index 全量重建一次
//     （144k 满池约数秒量级），之后每次扫描走热路径；IndexCached 在重建
//     完成前返回 nil（保持"绝不 mid-scan 重建"语义）。
//   - 5.2 索引构建优化（worker pool 并行 + 前端形状预筛）是纯性能改动：
//     转换产物与 entries 顺序/去重语义经全语料差分对照确认逐条等价
//     （见 index_equiv_test.go，5,094 文件 0 差异）。
const cacheSchema = 10

type cacheFile struct {
	Schema  int        `json:"schema"`
	Files   int        `json:"files"` // 目录内 yaml/yml 总数（诊断用；热路径校验改用 Dirs）
	Dirs    []dirStamp `json:"dirs"`  // v10：模板目录树 mtime 戳（热路径新鲜度校验）
	Entries []Entry    `json:"entries"`
}

// indexWorkersCap 索引构建并行度上限。模板转换是 CPU 密集型（YAML 解析
// 占绝对大头），并行收益受核数约束；上限 8 是折中——再高收益递减，且
// 重建索引常与扫描/服务同机运行，不宜吃满全部核。
const indexWorkersCap = 8

// tplFileResult 单模板文件的并行转换结果。只承载「与顺序无关」的逐文件
// 产物；entries 顺序与 legacy 两轮同名去重仍在收集阶段按原下标顺序串行
// 回放（见 Index），语义与旧的顺序实现逐条一致。
type tplFileResult struct {
	ok     bool // 漏斗通过，可入索引
	rel    string
	name   string
	sev    string
	tags   []string
	cves   []string
	source string
	proto  string
	mtime  int64
	size   int64
}

// Index 建立（或读取缓存的）模板索引。缓存失效策略：缓存格式版本不符、
// 或模板目录树变化（目录 mtime 戳不再全等）时重建（模板库是可再生的
// 大目录，不追求细粒度失效）。
//
// 热路径（缓存有效）只做：缓存文件 stat + 目录戳校验（目录数 1-2k），
// 不做全量 walk、不解码缓存 JSON（memo 命中时）——见 index_hot.go。
func Index(dir, cachePath string) ([]Entry, error) {
	if cachePath != "" {
		if entries, ok := indexLoadHot(dir, cachePath); ok {
			return entries, nil
		}
	}

	// 冷路径 / 缓存失效：全量 walk（文件列表 + 目录戳一次取齐）。
	files, stamps, err := walkTemplateFiles(dir)
	if err != nil {
		return nil, err
	}

	// 两轮扫描：非 legacy 目录（官方 http/requests 形态 + afrog）优先，
	// legacy/ 旧语料补位——同名模板视为同一发现，保留新形态版本。
	// 模板库支持多来源并存：任何来源的 YAML 都走同一漏斗，按名称去重。
	legacyPrefix := "legacy/"
	var first, second []string
	for _, f := range files {
		rel := f
		if r, err := filepath.Rel(dir, f); err == nil {
			rel = filepath.ToSlash(r)
		}
		if strings.HasPrefix(rel, legacyPrefix) {
			second = append(second, f)
		} else {
			first = append(first, f)
		}
	}

	// 每个 pass 内部并行转换（结果按下标回填），收集阶段按原顺序串行
	// 回放两轮去重——entries 顺序、seenName 语义与旧实现逐条一致。
	workers := indexWorkers()
	entries := make([]Entry, 0, len(files))
	seenName := map[string]bool{}
	for pi, pass := range [][]string{first, second} {
		if len(pass) == 0 {
			continue
		}
		for _, r := range convertTplFiles(dir, pass, workers) {
			if !r.ok {
				continue
			}
			if pi == 1 && seenName[r.name] {
				continue // legacy 与新语料同名：新语料已收录，跳过
			}
			seenName[r.name] = true
			entries = append(entries, Entry{
				Path:        r.rel,
				Name:        r.name,
				Sev:         r.sev,
				Tags:        r.tags,
				CVEs:        r.cves,
				Source:      r.source,
				Proto:       r.proto,
				MTime:       r.mtime,
				Size:        r.size,
				Convertible: true, // 建入索引即漏斗通过（Convert 非空或协议转换成功）
			})
		}
	}
	if cachePath != "" {
		if data, jerr := json.Marshal(cacheFile{
			Schema: cacheSchema, Files: len(files), Dirs: stamps, Entries: entries,
		}); jerr == nil {
			_ = os.WriteFile(cachePath, data, 0o644)
			// 缓存落盘成功后写入 memo（键取落盘后的真实文件戳）。
			if mtime, size, ok := indexCacheStat(cachePath); ok {
				indexMemoStore(&indexMemoEntry{
					cachePath: cachePath, mtime: mtime, size: size,
					stamps: stamps, entries: entries,
				})
			}
		}
	}
	return entries, nil
}

// indexWorkers 索引构建并行度：核数上限 indexWorkersCap。
func indexWorkers() int {
	w := runtime.NumCPU()
	if w > indexWorkersCap {
		w = indexWorkersCap
	}
	if w < 1 {
		w = 1
	}
	return w
}

// convertTplFiles 并行转换一个 pass 的模板文件：results[i] 严格对应
// files[i]（每个 worker 只写自己的下标，无共享写竞争）。批量很小时
// 退回顺序执行，避免起协程的固定开销。
func convertTplFiles(dir string, files []string, workers int) []tplFileResult {
	results := make([]tplFileResult, len(files))
	if workers <= 1 || len(files) < 32 {
		for i, f := range files {
			results[i] = convertTplFile(dir, f)
		}
		return results
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(files) {
					return
				}
				results[i] = convertTplFile(dir, files[i])
			}
		}()
	}
	wg.Wait()
	return results
}

// convertTplFile 单文件转换（旧顺序实现的逐文件部分，语义逐行保留）：
// stat → 大小门禁 → 读文件 → 三前端转换 → 协议模板旁路 → 提取元信息。
func convertTplFile(dir, f string) tplFileResult {
	st, serr := os.Stat(f)
	if serr != nil || st.Size() > 512*1024 {
		return tplFileResult{}
	}
	rel, rerr := filepath.Rel(dir, f)
	if rerr != nil {
		return tplFileResult{}
	}
	rel = filepath.ToSlash(rel)
	data, rerr2 := os.ReadFile(f)
	if rerr2 != nil {
		return tplFileResult{}
	}
	var proto string
	shape := scanFrontShape(data)
	if len(convertAnyShape(data, shape)) == 0 {
		// HTTP 漏斗淘汰 → 协议模板旁路（3.0 非 HTTP 检测）。
		// 形状预筛确认顶层无 tcp/dns/ssl 键时，协议转换必然为空，整段跳过。
		if shape&frontNet == 0 {
			return tplFileResult{}
		}
		nc := ConvertNetwork(data)
		if nc == nil {
			return tplFileResult{} // 漏斗淘汰：只把可运行的模板纳入调度全集
		}
		proto = nc.Proto
	}
	name, sev, tags, cves := convertMeta(string(data))
	return tplFileResult{
		ok:     true,
		rel:    rel,
		name:   name,
		sev:    sev,
		tags:   tags,
		cves:   cves,
		source: NormalizeSource(rel),
		proto:  proto,
		mtime:  st.ModTime().Unix(),
		size:   st.Size(),
	}
}

// IndexCached 只读缓存版 Index：缓存存在且 schema 匹配则返回条目，
// 否则返回 nil（不触发全库重建）。供扫描热路径（模板情报层挂载 /
// 协议扫描）使用——热路径里一次 13 万文件的漏斗重建就是一次扫描超时；
// 全量重建只属于 serve 启动（nucleiSubset 走完整 Index）与显式 reload。
//
// 与 Index 共享进程内单条 memo：缓存文件未变时直接复用上次解码的
// []Entry，免掉每次 18MB JSON 解码（引擎热路径每扫会各调一次）。
func IndexCached(cachePath string) []Entry {
	if cachePath == "" {
		return nil
	}
	mtime, size, ok := indexCacheStat(cachePath)
	if !ok {
		return nil
	}
	if m := indexMemoLoad(cachePath, mtime, size); m != nil {
		return m.entries
	}
	cached, ok := readIndexCache(cachePath)
	if !ok {
		return nil
	}
	indexMemoStore(&indexMemoEntry{
		cachePath: cachePath, mtime: mtime, size: size,
		stamps: cached.Dirs, entries: cached.Entries,
	})
	return cached.Entries
}

// sourceTop 来源类别白名单——与 sync.go / update-afrog 的镜像目录一一对应
// （HTTP 11 类 + 协议 3 类 + afrog 独立目录），另加 legacy 与 unknown 兜底。
// 归一化只认这一张表，保证 Source 是稳定枚举，不随模板库目录命名漂移。
var sourceTop = map[string]bool{
	"cves": true, "exposed-panels": true, "technologies": true,
	"vulnerabilities": true, "misconfiguration": true, "exposures": true,
	"default-logins": true, "takeovers": true, "miscellaneous": true,
	"fuzzing": true, "cnvd": true,
	"network": true, "dns": true, "ssl": true,
	// afrog 独立镜像目录（update-afrog → nuclei_dir/afrog/）：5.2 起该来源
	// 真正可运行，必须能在调度可见性里单独成列，否则全落 unknown。
	"afrog":  true,
	"legacy": true,
}

// NormalizeSource 从模板相对路径归一出来源类别。
// 实际落盘形态有二：
//   - http/<类别>/…（HTTP 模板统一挂 http/ 下，类别是第二段）
//   - <协议>/…（network/dns/ssl，类别即首段）
//
// 另有 legacy/ 旧语料。白名单外一律归 unknown——保证 Source 是稳定枚举，
// 不随模板库目录命名漂移。目的是让输出层按来源分列、口径能单算，
// 不参与任何判定或排序。
func NormalizeSource(rel string) string {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	segs := strings.Split(rel, "/")
	if len(segs) == 0 {
		return "unknown"
	}
	first := strings.ToLower(strings.TrimSpace(segs[0]))
	// http/ 前缀下取第二段（类别）；协议类与 legacy 取首段。
	if first == "http" {
		if len(segs) < 2 {
			return "unknown"
		}
		first = strings.ToLower(strings.TrimSpace(segs[1]))
	}
	if sourceTop[first] {
		return first
	}
	return "unknown"
}

var (
	metaTagsRe = regexp.MustCompile(`(?m)^\s*tags:\s*(.+)$`)
	metaSevRe  = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)`)
	metaNameRe = regexp.MustCompile(`(?m)^\s*name:\s*(.+)$`)
	metaCveRe  = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)
)

// convertMeta 从模板全文取精确 name/sev/tags/cves（漏斗验证通过后的条目用）。
func convertMeta(data string) (name, sev string, tags []string, cves []string) {
	if m := metaNameRe.FindStringSubmatch(data); m != nil {
		name = strings.TrimSpace(m[1])
	}
	if m := metaSevRe.FindStringSubmatch(data); m != nil {
		sev = strings.ToLower(m[1])
	}
	if sev == "" {
		sev = "info"
	}
	if m := metaTagsRe.FindStringSubmatch(data); m != nil {
		for _, tg := range strings.Split(m[1], ",") {
			tg = strings.TrimSpace(strings.ToLower(tg))
			if tg != "" {
				tags = append(tags, tg)
			}
		}
	}
	seenCve := map[string]bool{}
	for _, c := range metaCveRe.FindAllString(data, 8) {
		c = strings.ToUpper(c)
		if !seenCve[c] {
			seenCve[c] = true
			cves = append(cves, c)
		}
		if len(cves) >= 8 {
			break
		}
	}
	return name, sev, tags, cves
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// Select 选子集（MoE 三路调度，可验证的完整覆盖保证）：
// ① tag 硬匹配置顶（severity 升序）——命中概率最高的必然在场；
// ② 其余按 lastRun 升序（LRU：从未运行的优先）+ 词面相关度次序排列；
// ③ 每 n 条为一批，⌈全集/n⌉ 次扫描后所有可运行模板必然各跑一遍——
// lastRun 由调用方持久化（data/state），重启不丢进度。
// cursor 语义由 lastRun 表取代：轮转位置由"最久未跑"自然推导。
func Select(entries []Entry, techTags map[string]bool, queryText string,
	n int, lastRun map[string]int64) []Entry {
	return SelectWithCVE(entries, techTags, nil, queryText, n, lastRun)
}

// SelectWithCVE 同 Select，另加 CVE 通道：cveSet 为目标指纹实际受影响的
// CVE 集合（intel 关联产出），声明这些 CVE 的模板优先于 tag 命中置顶——
// 「这台机器真的中的」比「tag 词面能对上」更值得先跑预算。cveSet 为
// nil/空时行为与 Select 完全一致（零回归）。
func SelectWithCVE(entries []Entry, techTags, cveSet map[string]bool, queryText string,
	n int, lastRun map[string]int64) []Entry {
	if n <= 0 || len(entries) == 0 {
		return nil
	}
	var cveHit, hit, rest []Entry
	for _, e := range entries {
		if entryMatchesCVE(e, cveSet) {
			cveHit = append(cveHit, e)
			continue
		}
		matched := false
		for _, tg := range e.Tags {
			if techTags[tg] {
				matched = true
				break
			}
		}
		if matched {
			hit = append(hit, e)
		} else {
			rest = append(rest, e)
		}
	}
	bySevPath := func(s []Entry) {
		sort.SliceStable(s, func(i, j int) bool {
			if sevRank[s[i].Sev] != sevRank[s[j].Sev] {
				return sevRank[s[i].Sev] < sevRank[s[j].Sev]
			}
			return s[i].Path < s[j].Path
		})
	}
	bySevPath(cveHit)
	bySevPath(hit)
	// tag 命中集的预算配比：技术名归一会让命中集显著变大（一个指纹命中
	// 一个 tag，而一个 tag 下可能有成百条模板）。不设上限时，命中集会把
	// 整个预算吃光，LRU 轮转彻底停摆——「全池迟早跑完一遍」的数学保证
	// 反而被更强的匹配破坏了。故命中集最多占预算的 2/3，余下留给轮转；
	// 命中集本身在超配比时先按截断（严重度序已排好，取前段）。
	// CVE 命中集最优先（对目标最有针对性）；随后 tag 命中。两者合计
	// 最多占预算 2/3，余下留给 LRU 轮转——「全池迟早跑完一遍」的数学
	// 保证不能被更强的匹配彻底挤掉。被截断的模板不丢弃，退回轮转池
	// 参与竞争（否则同一批每轮被截断，永远跑不到）。
	hitBudget := n * 2 / 3
	if hitBudget < 1 {
		hitBudget = 1
	}
	if len(cveHit) > hitBudget {
		rest = append(rest, cveHit[hitBudget:]...)
		cveHit = cveHit[:hitBudget]
	}
	remain := hitBudget - len(cveHit)
	if remain < 0 {
		remain = 0
	}
	if len(hit) > remain {
		rest = append(rest, hit[remain:]...)
		hit = hit[:remain]
	}
	// ② 相关度路由：TF 余弦相似度（查询 = 页面标题+技术名，
	//    文档 = 模板名+tags+路径）。与原版 embedding 余弦同构——
	//    同为余弦，只是向量空间为词频而非 256 维语义向量；
	//    LRU 主键仍是公平性的第一保证
	qTerms := tokenize(queryText)
	qVec := termVec(qTerms)
	lr := func(e Entry) int64 {
		if lastRun == nil {
			return 0
		}
		return lastRun[e.Path]
	}
	rel := func(e Entry) float64 {
		text := e.Name + " " + strings.Join(e.Tags, " ") + " " + e.Path
		return cosine(qVec, termVec(tokenize(text)))
	}
	sort.SliceStable(rest, func(i, j int) bool {
		li, lj := lr(rest[i]), lr(rest[j])
		if li != lj {
			return li < lj // 最久未跑优先（0 = 从未运行，最先覆盖）
		}
		ri, rj := rel(rest[i]), rel(rest[j])
		if ri != rj {
			return ri > rj // 同批内相关度高的优先
		}
		return rest[i].Path < rest[j].Path
	})

	out := append([]Entry{}, cveHit...)
	out = append(out, hit...)
	for _, e := range rest {
		if len(out) >= n {
			break
		}
		out = append(out, e)
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// termVec 词频向量（tokenize 结果计数）。
func termVec(terms []string) map[string]float64 {
	vec := make(map[string]float64, len(terms))
	for _, t := range terms {
		vec[t]++
	}
	return vec
}

// cosine 余弦相似度（TF 空间；零向量返回 0）。
func cosine(a, b map[string]float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var dot, na, nb float64
	for k, v := range a {
		if bv, ok := b[k]; ok {
			dot += v * bv
		}
		na += v * v
	}
	for _, v := range b {
		nb += v * v
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// tokenize 提取小写字母数字词（≥3 字符），供词面相关度计算。
func tokenize(s string) []string {
	var terms []string
	cur := []rune{}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur = append(cur, r)
		} else if len(cur) > 0 {
			if t := string(cur); len(t) >= 3 {
				terms = append(terms, t)
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= 3 {
		terms = append(terms, string(cur))
	}
	return terms
}

// ---- 模板 → check 转换（漏斗对齐 import_nuclei.convert） ----

type tplMatcher struct {
	Type      string   `yaml:"type"`
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	DSL       []string `yaml:"dsl"` // dsl 表达式（安全子集，internal/dsl 准入）
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
}

// tplExtractor 命名抽取（nuclei extractors regex 形态）：从响应抽取变量
// 供后续 dsl 表达式引用（如版本号 → compare_versions 区间判断）。
type tplExtractor struct {
	Type     string   `yaml:"type"`
	Name     string   `yaml:"name"`
	Part     string   `yaml:"part"`
	Regex    []string `yaml:"regex"`
	Internal bool     `yaml:"internal"`
}

// strList 兼容 path 的两种 YAML 形态：单值字符串与字符串列表。
// 官方 nuclei 库两种写法都大量存在——此前仅声明 []string，把全部
// string 单值写法的模板在 yaml 解析层静默拒收（真实漏检面，本轮修复）。
type strList []string

// UnmarshalYAML 标量收成单元素列表，序列收成列表。
func (s *strList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*s = strList{value.Value}
		return nil
	}
	var out []string
	if err := value.Decode(&out); err != nil {
		return err
	}
	*s = out
	return nil
}

type tplHTTP struct {
	Method            string            `yaml:"method"`
	Path              strList           `yaml:"path"`
	Raw               []string          `yaml:"raw"` // HTTP 报文形态（官方库/afrog/TscanPlus 常用，列表）
	Body              string            `yaml:"body"`
	Headers           map[string]string `yaml:"headers"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []tplMatcher      `yaml:"matchers"`
	Extractors        []tplExtractor    `yaml:"extractors"`
}

type tplDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
		// Tags 可能是逗号字符串或列表（Nuclei 两种形态都有），转换不消费它，
		// 不声明字段以免 yaml 类型不匹配导致整模板解析失败
	} `yaml:"info"`
	HTTP     []tplHTTP `yaml:"http"`
	Requests []tplHTTP `yaml:"requests"` // 上游 2025 改版：模板请求键全面迁移到 requests
}

// noisyTemplates 靶场校准定谳的误报模板（词表/正则过泛，Evidence 自证）：
// zenscrape/zenserp 的 API-key 正则命中任意长串、acme-challenge 的 XSS
// 词命中转义回显、archibus 的词命中任何登录页。转换层直接拒收。
var noisyTemplates = map[string]bool{
	"zenscrape-api-key":         true,
	"zenserp-api-key":           true,
	"acme-xss":                  true,
	"archibus-webcentral-panel": true,
}

// normReq 三种模板前端（path 形态 / raw 请求形态 / afrog rules 形态）
// 归一化后的单请求语义，交给公共组转换 buildChecks。
type normReq struct {
	method, pathSuffix, body, contentType string
	matchers                              []tplMatcher
	cond                                  string
	extracts                              []checks.ExtractSpec
	// expr afrog 经典 rule 级判定表达式（运行期求值，见 internal/afrogx）。
	// 与 matchers 并存时同样必须全部满足（AND 语义）。
	expr string
}

// Convert 单模板 → checks（多 matcher 组且 OR 时拆分为 ~gN 后缀的多条；
// path 列表展开时每条路径一组，check id 带 ~pN 后缀）。
// 不支持的形态返回 nil。
func Convert(data []byte) []checks.Check {
	doc, req, ok := parseTplPath(data)
	if !ok {
		return nil
	}
	return convertPathForm(doc, req)
}

// convertPathForm path 形态的转换主体（parseTplPath 已通过门禁）。
// 与 convertRawForm 共享同一份已解析文档：convertAny 不再为两个前端
// 各做一次 YAML 全量解析（首命中顺序与旧实现一致）。
func convertPathForm(doc tplDoc, req tplHTTP) []checks.Check {
	nrs, ok := normFromTpl(req)
	if !ok {
		return nil
	}
	prefix := "Nuclei 社区模板 " + doc.ID
	var out []checks.Check
	for i, nr := range nrs {
		id := "nuclei-" + doc.ID
		if len(nrs) > 1 {
			id = fmt.Sprintf("nuclei-%s~p%d", doc.ID, i+1)
		}
		out = append(out, buildChecks(id, prefix, doc.Info.Name, doc.Info.Severity, nr)...)
	}
	return out
}

// parseTplPath 解析 path 形态模板的公共门禁与首请求。
func parseTplPath(data []byte) (tplDoc, tplHTTP, bool) {
	var doc tplDoc
	if len(data) > 512*1024 {
		return doc, tplHTTP{}, false
	}
	if strings.Contains(string(data[:min(3000, len(data))]), "interactsh") {
		return doc, tplHTTP{}, false // 需要外部回调，跳过
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return doc, tplHTTP{}, false
	}
	if doc.ID == "" || doc.Info.Name == "" || (len(doc.HTTP) == 0 && len(doc.Requests) == 0) {
		return doc, tplHTTP{}, false
	}
	if noisyTemplates[strings.ToLower(doc.ID)] {
		return doc, tplHTTP{}, false // 靶场校准定谳的误报模板
	}
	reqs := doc.HTTP
	if len(reqs) == 0 {
		reqs = doc.Requests // 上游改版后的 requests 键形态
	}
	return doc, reqs[0], true
}

// maxPathExpand 单模板 path 列表展开上限（BUG-022）。
//
// 真实语料统计（packs/nuclei-templates.tar.gz 分层抽样各 3000 条）：
//   - community-wordfence：10.0% 模板多 path，最多 4 条（301/2999）；
//   - community-40k：7.1% 多 path，最长 64；
//   - http（官库）：14.4% 多 path，最长 64；
//   - legacy：9.0% 多 path，最长 57。
//
// 全量展开会让长尾模板（最多 64 路径）按 64 倍消耗探测预算；而多 path
// 模板整体约 10%，取 4 已覆盖 wordfence 的全部形态与其余来源的主流形态，
// 长尾截断是**覆盖率损失**（宁少报），不是误报风险。
// 预算影响：按样本估算，展开后请求量约 +17%~36%（各来源），可接受。
const maxPathExpand = 4

// normFromTpl path 形态归一化：方法白名单 + {{BaseURL}} 后缀提取。
// 返回 1..maxPathExpand 个请求语义（path 列表展开，每个 candidate 一条）。
func normFromTpl(req tplHTTP) ([]normReq, bool) {
	method := strings.ToUpper(req.Method)
	if method != "GET" && method != "POST" {
		return nil, false
	}
	if len(req.Matchers) == 0 {
		return nil, false
	}
	// path 列表里的每一项都是"候选探测路径"（多数模板以 stop-at-first-match
	// 语义依次尝试），旧实现只取第 0 项，其余全丢（BUG-022）。
	var suffixes []string
	seenSuffix := map[string]bool{}
	for _, p := range req.Path {
		p = strings.TrimSpace(p)
		if !strings.Contains(p, "{{BaseURL}}") {
			continue
		}
		suffix := strings.SplitN(p, "{{BaseURL}}", 2)[1]
		if strings.Contains(suffix, "{{") {
			continue // 含其余占位符（需变量注入）的候选路径跳过
		}
		if suffix == "" {
			suffix = "/" // 根探测
		}
		if seenSuffix[suffix] {
			continue
		}
		seenSuffix[suffix] = true
		suffixes = append(suffixes, suffix)
		if len(suffixes) >= maxPathExpand {
			break
		}
	}
	if len(suffixes) == 0 {
		return nil, false
	}
	cond := strings.ToLower(strings.TrimSpace(req.MatchersCondition))
	if cond == "" {
		cond = "or"
	}
	extracts := extractSpecs(req.Extractors)
	out := make([]normReq, 0, len(suffixes))
	for _, suffix := range suffixes {
		out = append(out, normReq{
			method:      method,
			pathSuffix:  suffix,
			body:        req.Body,
			contentType: req.Headers["Content-Type"],
			matchers:    req.Matchers,
			cond:        cond,
			extracts:    extracts,
		})
	}
	return out, true
}

// extractSpecs 从模板 extractors 块抽取命名变量定义（regex 形态，
// internal 回传型与空名跳过）。
func extractSpecs(exs []tplExtractor) []checks.ExtractSpec {
	out := make([]checks.ExtractSpec, 0, len(exs))
	for _, ex := range exs {
		if ex.Type != "regex" || ex.Name == "" || len(ex.Regex) == 0 || ex.Internal {
			continue
		}
		// B3：extractor 正则与 matcher 同走 RE2 准入——不可编译的正则
		// 会在扫描期 extractVars 的 Compile 中报错，这里直接丢弃该条，
		// 防 MustCompile 在 worker 协程内 panic（整进程挂）
		bad := false
		for _, pat := range ex.Regex {
			if _, err := regexp.Compile("(?i)" + pat); err != nil {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		out = append(out, checks.ExtractSpec{Name: ex.Name, Part: ex.Part, Regex: ex.Regex})
	}
	return out
}

// parseRawRequest 解析 raw 请求文本（HTTP 报文形态）：首行 METHOD 路径 协议，
// 随后请求头，空行后为请求体。路径必须含 {{BaseURL}} 且不含其余占位符。
func parseRawRequest(raw string) (method, suffix string, headers map[string]string, body string, ok bool) {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return "", "", nil, "", false
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return "", "", nil, "", false
	}
	method = strings.ToUpper(parts[0])
	if method != "GET" && method != "POST" {
		return "", "", nil, "", false
	}
	if !strings.Contains(parts[1], "{{BaseURL}}") {
		return "", "", nil, "", false
	}
	suffix = strings.SplitN(parts[1], "{{BaseURL}}", 2)[1]
	if strings.Contains(suffix, "{{") {
		return "", "", nil, "", false
	}
	if suffix == "" {
		suffix = "/"
	}
	headers = map[string]string{}
	i := 1
	for ; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		if strings.TrimSpace(l) == "" {
			i++
			break
		}
		k, v, found := strings.Cut(l, ":")
		if !found {
			return "", "", nil, "", false
		}
		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	body = strings.TrimSpace(strings.Join(lines[i:], "\n"))
	return method, suffix, headers, body, true
}

// ConvertRaw raw 请求形态 → checks。官方 nuclei 库大量模板、新版 afrog、
// TscanPlus POC 均为此形态（http[0].raw 报文 + matchers）。
func ConvertRaw(data []byte) []checks.Check {
	doc, req, ok := parseTplPath(data)
	if !ok {
		return nil
	}
	return convertRawForm(doc, req)
}

// convertRawForm raw 请求形态的转换主体（parseTplPath 已通过门禁）。
func convertRawForm(doc tplDoc, req tplHTTP) []checks.Check {
	if len(req.Raw) == 0 || strings.TrimSpace(req.Raw[0]) == "" || len(req.Matchers) == 0 {
		return nil
	}
	method, suffix, headers, body, ok := parseRawRequest(req.Raw[0])
	if !ok {
		return nil
	}
	cond := strings.ToLower(req.MatchersCondition)
	cond = strings.TrimSpace(cond)
	if cond == "" {
		cond = "or"
	}
	// raw 里的自定义请求头除 Content-Type 外 Check 模型不承载：
	// 丢弃只会造成少报（漏检），不会造成误报，与"宁少报"红线一致
	return buildChecks("nuclei-"+doc.ID, "Nuclei 社区模板 "+doc.ID, doc.Info.Name,
		doc.Info.Severity, normReq{
			method:      method,
			pathSuffix:  suffix,
			body:        body,
			contentType: headers["Content-Type"],
			matchers:    req.Matchers,
			cond:        cond,
		})
}

// buildChecks 公共组转换：matchers → 组（status/word/regex/dsl），
// AND 多组合并，纯状态码组拒收，装配为 checks.Check。
// 组转换与装配语义与历史版本逐行等价（含靶场回归教训注释）。
func buildChecks(checkID, advicePrefix, name, sevStr string, nr normReq) []checks.Check {
	cond := nr.cond

	// 组转换：status → StatusAny；word body+and → Contains；word body+or →
	// ContainsAny；word header → HeaderContains（全包含语义）；
	// dsl → DSL（安全子集求值，internal/dsl 准入）
	type group struct {
		status []int
		wall   []string
		wany   []string
		h      []string
		rx     []string
		dsl    []string
	}
	var groups []group
	for _, m := range nr.matchers {
		var g group
		switch strings.ToLower(m.Type) {
		case "status":
			g.status = m.Status
		case "word":
			words := make([]string, 0, len(m.Words))
			for _, w := range m.Words {
				words = append(words, strings.ToLower(w))
			}
			if len(words) == 0 {
				return nil
			}
			if strings.EqualFold(m.Part, "header") {
				// 头匹配恒为全包含（对齐 Python g["h"] 行为）
				g.h = words
			} else if strings.ToLower(m.Condition) == "and" {
				g.wall = words
			} else {
				g.wany = words
			}
		case "regex":
			pats := make([]string, 0, len(m.Regex))
			for _, pat := range m.Regex {
				if _, err := regexp.Compile("(?i)" + pat); err != nil {
					return nil // RE2 不兼容的整模板跳过
				}
				pats = append(pats, "(?i)"+pat)
			}
			if len(pats) == 0 {
				return nil
			}
			g.rx = pats
		case "dsl":
			// 安全子集准入：任一表达式编译失败或含纯排除式（对任意
			// 响应可能恒真）即整模板跳过，与 regex RE2 准入同策略。
			// 抽取变量名计入已知集（compare_versions 引用抽取变量）。
			exNames := make([]string, 0, len(nr.extracts))
			for _, ex := range nr.extracts {
				if ex.Name != "" {
					exNames = append(exNames, ex.Name)
				}
			}
			for _, expr := range m.DSL {
				prog, err := dsl.CompileWithVars(expr, exNames)
				if err != nil {
					return nil
				}
				if !prog.PositiveGround() {
					return nil
				}
			}
			if len(m.DSL) == 0 {
				return nil
			}
			g.dsl = m.DSL
		default:
			return nil // binary/其他未知形态
		}
		if len(g.status) == 0 && len(g.wall) == 0 && len(g.wany) == 0 && len(g.h) == 0 && len(g.rx) == 0 && len(g.dsl) == 0 {
			return nil
		}
		groups = append(groups, g)
	}
	if cond == "and" && len(groups) > 1 {
		merged := group{}
		for _, g := range groups {
			merged.status = append(merged.status, g.status...)
			merged.wall = append(merged.wall, g.wall...)
			merged.wany = append(merged.wany, g.wany...)
			merged.h = append(merged.h, g.h...)
			merged.rx = append(merged.rx, g.rx...)
			merged.dsl = append(merged.dsl, g.dsl...)
		}
		// AND 语义下多组 status 合并进 StatusAny（任一）——matchBody
		// 对 StatusAny 与词/头/正则本就是组内合取，status 条件必须
		// 保留：靶场回归实测证实，丢弃 status 的"宁少报"写法
		// 恰恰相反——exposure 类模板（status 200 AND 词）在 404 回显页
		// 上仅凭路径回显子串即误中，15 条假阳性全是这一行放的
		groups = []group{merged}
	}
	if len(groups) == 1 {
		g := groups[0]
		if len(g.status) == 0 && len(g.wall) == 0 && len(g.wany) == 0 && len(g.h) == 0 && len(g.rx) == 0 && len(g.dsl) == 0 {
			return nil
		}
	}

	// 纯表达式（afrog rule 级 expression）：没有静态 matcher 组时补一个空组，
	// 由 checks.Match.Expr 在运行期判定。内容判定闸门已在 afrogNorm（afrogx
	// 编译准入 + PositiveGround）把过，这里不再重复。
	if len(groups) == 0 {
		if nr.expr == "" {
			return nil
		}
		groups = []group{{}}
	}

	sev := strings.ToLower(sevStr)
	switch sev {
	case "critical", "high", "medium", "low":
	default:
		sev = "info"
	}
	if len(name) > 120 {
		name = name[:120]
	}
	var out []checks.Check
	for i, g := range groups {
		// 纯状态码组不转换：只看状态码不看内容的 check 在 CDN/WAF
		// 环境下任意路径即可命中（靶场回归实测 wp-json/server-status
		// 类模板 404/403 误报），验证型扫描器要求至少一个内容条件。
		// afrog rule 级表达式自带内容判定（afrogNorm 已把关），放行。
		if len(g.wall) == 0 && len(g.wany) == 0 && len(g.h) == 0 && len(g.rx) == 0 && len(g.dsl) == 0 &&
			nr.expr == "" {
			continue
		}
		id := checkID
		if len(groups) > 1 {
			id = checkID + "~g" + strconv.Itoa(i+1)
		}
		out = append(out, checks.Check{
			ID:   id,
			Lv:   1,
			Path: nr.pathSuffix,
			Match: checks.Match{
				Status:         firstOrZero(g.status),
				StatusAny:      g.status,
				Contains:       g.wall,
				ContainsAny:    g.wany,
				HeaderContains: g.h,
				RegexBody:      g.rx,
				DSL:            g.dsl,
				Expr:           nr.expr,
				Method:         nr.method,
				Body:           nr.body,
				ContentType:    nr.contentType,
				Extracts:       nr.extracts,
			},
			Title:  name,
			Sev:    sev,
			Advice: advicePrefix + "：按模板建议修复",
		})
	}
	return out
}

func firstOrZero(list []int) int {
	if len(list) == 1 {
		return list[0]
	}
	return 0 // 多状态码走 StatusAny
}

// convertAny 三前端依次尝试：path 形态 → raw 请求形态 → afrog 经典形态。
// 形状预筛（scanFrontShape）只跳过「已确认必然返回空」的前端，首个成功
// 前端与旧顺序逐条一致；path/raw 共享同一份解析结果，afrog 语料由 3 次
// YAML 全量解析降到 1 次。
func convertAny(data []byte) []checks.Check {
	return convertAnyShape(data, scanFrontShape(data))
}

// convertAnyShape 同 convertAny，形状位图由调用方给出（Index 复用同一份
// 扫描结果决定是否走协议模板旁路）。
func convertAnyShape(data []byte, shape frontShape) []checks.Check {
	if shape&frontHTTP != 0 {
		doc, req, ok := parseTplPath(data)
		if ok {
			if cs := convertPathForm(doc, req); len(cs) > 0 {
				return cs
			}
			if cs := convertRawForm(doc, req); len(cs) > 0 {
				return cs
			}
		}
	}
	if shape&frontAfrog != 0 {
		return ConvertAfrog(data)
	}
	return nil
}

// LoadFile 解析单个模板文件（读文件 + convertAny）。
func LoadFile(path string) ([]checks.Check, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return convertAny(data), nil
}
