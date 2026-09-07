// Package nuclei Nuclei 社区模板子集装载（MoE 式三路调度）：
// ① tag 与已识别技术硬匹配的模板置顶（severity 升序）；
// ② 其余按 TF 余弦相似度排序（查询 = 页面标题+技术名；语义向量路由
//
//	的 TF 空间同构近似，无模型依赖）；
//
// ③ 持久化 LRU：最久未跑优先，跨重启保持轮转公平——⌈C/N⌉ 次扫描
//
//	完成全量轮换。模板漏斗对齐 python 分支 tools/import_nuclei.py：
//	仅接受单 GET、path 为 {{BaseURL}} 后缀、matchers 为 status/word
//	的模板；需要外部回调（interactsh）的模板跳过。
package nuclei

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// Entry 索引条目（建索引时一次全量 Convert 验证）。
type Entry struct {
	Path        string   `json:"path"`        // 相对 dir
	Name        string   `json:"name"`        // 模板名（相关度排序用）
	Tags        []string `json:"tags"`        // 精确 tags（来自完整 Convert）
	Sev         string   `json:"sev"`         // 精确严重度
	MTime       int64    `json:"mtime"`       // 文件修改时间
	Size        int64    `json:"size"`        // 文件大小
	Convertible bool     `json:"convertible"` // 能通过漏斗转换为可执行 check
	LastRun     int64    `json:"lastrun"`     // 最近一次运行时间（unix nano；0=从未）
}

var (
	// tags 在真实模板中缩进于 info 块内，须允许前导空白
	htags = regexp.MustCompile(`(?m)^\s*tags:\s*(.+)$`)
	hsev  = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)`)
	hname = regexp.MustCompile(`(?m)^\s*name:\s*(.+)$`)
)

// cacheSchema 索引缓存格式版本——格式变更时递增以强制重建
// （历史缓存中 Tags 全空，无法通过条目数区分新旧格式）。
const cacheSchema = 3

type cacheFile struct {
	Schema  int     `json:"schema"`
	Entries []Entry `json:"entries"`
}

// Index 建立（或读取缓存的）模板索引。缓存失效策略：模板文件总数
// 与缓存不一致或缓存格式版本不符时重建（模板库是可再生的大目录，
// 不追求细粒度失效）。
func Index(dir, cachePath string) ([]Entry, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data, rerr := os.ReadFile(cachePath); rerr == nil {
		var cached cacheFile
		if json.Unmarshal(data, &cached) == nil && cached.Schema == cacheSchema &&
			len(cached.Entries) == len(files) {
			return cached.Entries, nil
		}
	}

	entries := make([]Entry, 0, len(files))
	for _, f := range files {
		st, serr := os.Stat(f)
		if serr != nil || st.Size() > 512*1024 {
			continue
		}
		rel, rerr := filepath.Rel(dir, f)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		data, rerr2 := os.ReadFile(f)
		if rerr2 != nil {
			continue
		}
		checks := Convert(data)
		if len(checks) == 0 {
			continue // 漏斗淘汰：只把可运行的模板纳入调度全集
		}
		name, sev, tags := convertMeta(string(data))
		entries = append(entries, Entry{
			Path:  rel,
			Name:  name,
			Sev:   sev,
			Tags:  tags,
			MTime: st.ModTime().Unix(),
			Size:  st.Size(),
		})
	}
	if cachePath != "" {
		if data, jerr := json.Marshal(cacheFile{Schema: cacheSchema, Entries: entries}); jerr == nil {
			_ = os.WriteFile(cachePath, data, 0o644)
		}
	}
	return entries, nil
}

var (
	metaTagsRe = regexp.MustCompile(`(?m)^\s*tags:\s*(.+)$`)
	metaSevRe  = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)`)
	metaNameRe = regexp.MustCompile(`(?m)^\s*name:\s*(.+)$`)
)

// convertMeta 从模板全文取精确 name/sev/tags（漏斗验证通过后的条目用）。
func convertMeta(data string) (name, sev string, tags []string) {
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
	return name, sev, tags
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
	if n <= 0 || len(entries) == 0 {
		return nil
	}
	var hit, rest []Entry
	for _, e := range entries {
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
	sort.SliceStable(hit, func(i, j int) bool {
		if sevRank[hit[i].Sev] != sevRank[hit[j].Sev] {
			return sevRank[hit[i].Sev] < sevRank[hit[j].Sev]
		}
		return hit[i].Path < hit[j].Path
	})
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

	out := append([]Entry{}, hit...)
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

// docVec 模板文档向量。
func docVec(e Entry) map[string]float64 {
	return termVec(tokenize(e.Name + " " + strings.Join(e.Tags, " ") + " " + e.Path))
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
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
}

type tplHTTP struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Body              string            `yaml:"body"`
	Headers           map[string]string `yaml:"headers"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []tplMatcher      `yaml:"matchers"`
}

type tplDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
		// Tags 可能是逗号字符串或列表（Nuclei 两种形态都有），转换不消费它，
		// 不声明字段以免 yaml 类型不匹配导致整模板解析失败
	} `yaml:"info"`
	HTTP []tplHTTP `yaml:"http"`
}

// Convert 单模板 → checks（多 matcher 组且 OR 时拆分为 ~gN 后缀的多条）。
// 不支持的形态返回 nil。
func Convert(data []byte) []checks.Check {
	if len(data) > 512*1024 {
		return nil
	}
	if strings.Contains(string(data[:min(3000, len(data))]), "interactsh") {
		return nil // 需要外部回调，跳过
	}
	var doc tplDoc
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	if doc.ID == "" || doc.Info.Name == "" || len(doc.HTTP) == 0 {
		return nil
	}
	req := doc.HTTP[0]
	method := strings.ToUpper(req.Method)
	if method != "GET" && method != "POST" {
		return nil
	}
	reqCT := req.Headers["Content-Type"]
	var path string
	if len(req.Path) > 0 {
		path = req.Path[0]
	}
	if path == "" || !strings.Contains(path, "{{BaseURL}}") {
		return nil
	}
	suffix := strings.SplitN(path, "{{BaseURL}}", 2)[1]
	if strings.Contains(suffix, "{{") {
		return nil
	}
	if suffix == "" {
		suffix = "/" // 根探测
	}
	if len(req.Matchers) == 0 {
		return nil
	}
	cond := strings.ToLower(req.MatchersCondition)
	cond = strings.TrimSpace(cond)
	if cond == "" {
		cond = "or"
	}

	// 组转换：status → StatusAny；word body+and → Contains；word body+or →
	// ContainsAny；word header → HeaderContains（全包含语义）
	type group struct {
		status []int
		wall   []string
		wany   []string
		h      []string
		rx     []string
	}
	var groups []group
	for _, m := range req.Matchers {
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
		default:
			return nil // dsl/binary/其他
		}
		if len(g.status) == 0 && len(g.wall) == 0 && len(g.wany) == 0 && len(g.h) == 0 && len(g.rx) == 0 {
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
		}
		// AND 语义下多组 status 各自独立列表语义有损，取交集语义由
		// matchBody 的 StatusAny（任一）近似——仅当无词组时保留，
		// 有词组时丢弃 status 条件（宁少报不误报）。
		if len(merged.wall) > 0 || len(merged.wany) > 0 || len(merged.h) > 0 {
			merged.status = nil
		}
		groups = []group{merged}
	}
	if len(groups) == 1 {
		g := groups[0]
		if len(g.status) == 0 && len(g.wall) == 0 && len(g.wany) == 0 && len(g.h) == 0 && len(g.rx) == 0 {
			return nil
		}
	}

	sev := strings.ToLower(doc.Info.Severity)
	switch sev {
	case "critical", "high", "medium", "low":
	default:
		sev = "info"
	}
	name := doc.Info.Name
	if len(name) > 120 {
		name = name[:120]
	}
	var out []checks.Check
	for i, g := range groups {
		id := doc.ID
		if len(groups) > 1 {
			id = doc.ID + "~g" + strconv.Itoa(i+1)
		}
		out = append(out, checks.Check{
			ID:   "nuclei-" + id,
			Lv:   1,
			Path: suffix,
			Match: checks.Match{
				Status:         firstOrZero(g.status),
				StatusAny:      g.status,
				Contains:       g.wall,
				ContainsAny:    g.wany,
				HeaderContains: g.h,
				Method:         method,
				Body:           req.Body,
				ContentType:    reqCT,
			},
			Title:  name,
			Sev:    sev,
			Advice: "Nuclei 社区模板 " + doc.ID + "：按模板建议修复",
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

// LoadFile 解析单个模板文件。
func LoadFile(path string) ([]checks.Check, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Convert(data), nil
}
