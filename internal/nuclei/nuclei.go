// Package nuclei Nuclei 社区模板子集装载（MoE 式两路调度）：
// tag 与已识别技术硬匹配的模板置顶，其余按轮转游标覆盖（语义向量路由
// 未迁移，见对照表）。模板漏斗对齐 python 分支 tools/import_nuclei.py：
// 仅接受单 GET、path 为 {{BaseURL}} 后缀、matchers 为 status/word 的模板；
// 需要外部回调（interactsh）的模板跳过。
package nuclei

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// Entry 索引条目（轻量：不解析全量 YAML）。
type Entry struct {
	Path  string   `json:"path"` // 相对 dir
	Tags  []string `json:"tags"`
	Sev   string   `json:"sev"`
	MTime int64    `json:"mtime"`
	Size  int64    `json:"size"`
}

var (
	htags = regexp.MustCompile(`(?m)^tags:\s*(.+)$`)
	hsev  = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)`)
)

// Index 建立（或读取缓存的）模板索引。缓存失效策略：模板文件总数
// 与缓存不一致时重建（模板库是可再生的大目录，不追求细粒度失效）。
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
		var cached []Entry
		if json.Unmarshal(data, &cached) == nil && len(cached) == len(files) {
			return cached, nil
		}
	}

	entries := make([]Entry, 0, len(files))
	for _, f := range files {
		st, serr := os.Stat(f)
		if serr != nil || st.Size() > 512*1024 {
			continue
		}
		head := readHead(f, 4096)
		e := Entry{
			Path:  filepath.ToSlash(filepath.Base(f)),
			Sev:   strings.ToLower(hsev.FindStringSubmatch(head)[1]),
			MTime: st.ModTime().Unix(),
			Size:  st.Size(),
		}
		if m := htags.FindStringSubmatch(head); m != nil {
			for _, t := range strings.Split(m[1], ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					e.Tags = append(e.Tags, strings.ToLower(t))
				}
			}
		}
		if e.Sev == "" {
			e.Sev = "info"
		}
		entries = append(entries, e)
	}
	if cachePath != "" {
		if data, jerr := json.Marshal(entries); jerr == nil {
			_ = os.WriteFile(cachePath, data, 0o644)
		}
	}
	return entries, nil
}

func readHead(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	m, _ := f.Read(buf)
	return string(buf[:m])
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// Select 选子集：tag 硬匹配置顶（severity 升序），其余按游标轮转。
// cursor 由调用方持有（跨扫描轮转，保证长期全覆盖）。
func Select(entries []Entry, techTags map[string]bool, n int, cursor *int) []Entry {
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
	out := append([]Entry{}, hit...)
	if len(out) < n && len(rest) > 0 {
		start := 0
		if cursor != nil {
			start = *cursor % len(rest)
		}
		for i := 0; i < len(rest) && len(out) < n; i++ {
			out = append(out, rest[(start+i)%len(rest)])
		}
		if cursor != nil {
			*cursor = (start + len(rest)) % len(rest)
		}
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ---- 模板 → check 转换（漏斗对齐 import_nuclei.convert） ----

type tplMatcher struct {
	Type      string   `yaml:"type"`
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
}

type tplHTTP struct {
	Method            string       `yaml:"method"`
	Path              []string     `yaml:"path"`
	MatchersCondition string       `yaml:"matchers-condition"`
	Matchers          []tplMatcher `yaml:"matchers"`
}

type tplDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string   `yaml:"name"`
		Severity string   `yaml:"severity"`
		Tags     []string `yaml:"tags"`
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
	if !strings.EqualFold(req.Method, "GET") && req.Method != "" {
		return nil
	}
	var path string
	if len(req.Path) > 0 {
		path = req.Path[0]
	}
	if path == "" || !strings.Contains(path, "{{BaseURL}}") {
		return nil
	}
	suffix := strings.SplitN(path, "{{BaseURL}}", 2)[1]
	if suffix == "" || strings.Contains(suffix, "{{") {
		return nil
	}
	if len(req.Matchers) == 0 {
		return nil
	}
	cond := strings.ToLower(req.MatchersCondition)
	cond = strings.TrimSpace(cond)
	if cond == "" {
		cond = "or"
	}

	// 组转换：status → StatusAny；word body+and → Contains；word body+or → ContainsAny
	type group struct {
		status []int
		wall   []string
		wany   []string
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
				return nil // 头匹配未迁移，整模板跳过
			}
			if strings.ToLower(m.Condition) == "and" {
				g.wall = words
			} else {
				g.wany = words
			}
		default:
			return nil // dsl/binary/其他
		}
		if len(g.status) == 0 && len(g.wall) == 0 && len(g.wany) == 0 {
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
		}
		// AND 语义下多组 status 各自独立列表语义有损，取交集语义由
		// matchBody 的 StatusAny（任一）近似——仅当无词组时保留，
		// 有词组时丢弃 status 条件（宁少报不误报）。
		if len(merged.wall) > 0 || len(merged.wany) > 0 {
			merged.status = nil
		}
		groups = []group{merged}
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
				Status:      firstOrZero(g.status),
				StatusAny:   g.status,
				Contains:    g.wall,
				ContainsAny: g.wany,
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
