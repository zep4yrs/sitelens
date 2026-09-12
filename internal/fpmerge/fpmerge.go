// Package fpmerge enthec/webappanalyzer（GPL-3.0）社区指纹库合并。
//
// 数据源是 Wappalyzer 指纹规则的开源延续（GPL-3.0，与本项目同协议）。
// 合并原则：精编条目一律保留、同名冲突精编赢、社区条目 conf 降为 70；
// 通道只落地引擎实现的 headers/meta/cookies/html/scripts；模式以 RE2
// 精确校验，编译不过的整条丢弃（加载器亦有兜底跳过）。
package fpmerge

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// FetchURL 社区指纹库 tarball（codeload，仓库默认分支）。
const FetchURL = "https://codeload.github.com/enthec/webappanalyzer/tar.gz/refs/heads/main"

// Stats 合并统计。
type Stats struct {
	Added        int `json:"added"`
	SkippedDup   int `json:"skipped_dup"`
	SkippedEmpty int `json:"skipped_empty"`
	RejectedPats int `json:"rejected_pats"`
	Total        int `json:"total"`
	CPEs         int `json:"cpes"`
}

// entry 与 internal/sitelens 的 Technology 形状一致（rules 透传原 JSON）。
type entry struct {
	Name    string          `json:"name"`
	Cats    []string        `json:"cats"`
	Conf    int             `json:"conf"`
	Website string          `json:"website"`
	Exact   bool            `json:"exact,omitempty"` // 关键词型：全部模式按字面量包含
	Rules   json.RawMessage `json:"rules"`
}

type boxFile struct {
	Version      int     `json:"version"`
	Count        int     `json:"count"`
	Technologies []entry `json:"technologies"`
}

// rawSpec enthec 条目形状（只取需要映射的通道）。
type rawSpec struct {
	Cats    []int             `json:"cats"`
	Headers map[string]rawVal `json:"headers"`
	Meta    map[string]rawVal `json:"meta"`
	Cookies map[string]string `json:"cookies"`
	HTML    []string          `json:"html"`
	Scripts []string          `json:"scripts"`
	CPE     string            `json:"cpe"`
	Website string            `json:"website"`
}

// rawVal 头/meta 规则值三形状兼容：字符串 / {"regex": ..} / 存在性判断。
type rawVal struct {
	Regex *string `json:"-"`
}

// UnmarshalJSON 兼容三种 JSON 形状；存在性判断解析为指向空串的指针。
func (v *rawVal) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		v.Regex = &s
		return nil
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if re, ok := d["regex"]; ok {
		var rs string
		_ = json.Unmarshal(re, &rs)
		v.Regex = &rs
		return nil
	}
	empty := "" // 存在性判断（任意值都算），上层替换为 "^"
	v.Regex = &empty
	return nil
}

var (
	reBadPat  = regexp.MustCompile(`\\[1-9]|\(\?<[=!]\)|\(\?=|\(\?!|\(\?>|\*\+|\+\+|\?\+`)
	reNonSlug = regexp.MustCompile(`[^a-z0-9]+`)
	rePrivate = regexp.MustCompile(`\\;`)
)

// cleanPat 剥 wappalyzer 私有后缀并做 RE2 校验，不可用返回 ""。
func cleanPat(p string) string {
	if p == "" || len(p) > 300 {
		return ""
	}
	p = strings.TrimSpace(rePrivate.Split(p, -1)[0])
	if p == "" {
		return ""
	}
	if reBadPat.MatchString(p) {
		return ""
	}
	if _, err := regexp.Compile("(?i)" + p); err != nil {
		return ""
	}
	return p
}

func cleanList(pats []string, rejected *int, cap int) []string {
	out, seen := make([]string, 0, len(pats)), map[string]bool{}
	for _, p := range pats {
		c := cleanPat(p)
		if c == "" {
			if p != "" {
				*rejected++
			}
			continue
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
		if len(out) >= cap {
			break
		}
	}
	return out
}

// rulesJSON 组装引擎对象形状的 rules（html 对象形状与精编条目一致）。
func rulesJSON(spec rawSpec, rejected *int) (json.RawMessage, error) {
	type scriptsCh struct {
		Src []string `json:"src,omitempty"`
	}
	type htmlCh struct {
		HTML []string `json:"html,omitempty"`
	}
	rules := map[string]any{}

	presence := func(v rawVal) string {
		if v.Regex == nil {
			return ""
		}
		if p := cleanPat(*v.Regex); p != "" {
			return p
		}
		return "^" // 存在性判断：任意值都算
	}

	headers := map[string][]string{}
	for h, v := range spec.Headers {
		if v.Regex == nil {
			continue
		}
		p := presence(v)
		hl := strings.ToLower(h)
		if len(headers[hl]) < 4 {
			headers[hl] = append(headers[hl], p)
		}
	}
	if len(headers) > 0 {
		rules["headers"] = headers
	}

	meta := map[string]string{}
	for m, v := range spec.Meta {
		if v.Regex == nil {
			continue
		}
		meta[strings.ToLower(m)] = presence(v)
	}
	if len(meta) > 0 {
		rules["meta"] = meta
	}

	if len(spec.Cookies) > 0 {
		cs := make([]string, 0, len(spec.Cookies))
		for c := range spec.Cookies {
			if c != "" {
				cs = append(cs, strings.ToLower(c))
			}
			if len(cs) >= 8 {
				break
			}
		}
		rules["cookies"] = cs
	}

	if html := cleanList(spec.HTML, rejected, 8); len(html) > 0 {
		rules["html"] = htmlCh{HTML: html}
	}
	if scripts := cleanList(spec.Scripts, rejected, 8); len(scripts) > 0 {
		rules["scripts"] = scriptsCh{Src: scripts}
	}

	if len(rules) == 0 {
		return nil, nil
	}
	return json.Marshal(rules)
}

// MergeFromTar 从 webappanalyzer tarball 流合并到 technologiesPath，
// 并导出 name→CPE 映射到 cpeOutPath。原有条目原样保留。
func MergeFromTar(r io.Reader, technologiesPath, cpeOutPath string) (Stats, error) {
	var st Stats
	// 1) 收集 tar 内 src/technologies/*.json 与 src/categories.json
	libs := map[string]json.RawMessage{}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return st, fmt.Errorf("gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, fmt.Errorf("tar: %w", err)
		}
		name := strings.ReplaceAll(hdr.Name, "\\", "/")
		isTech := strings.Contains(name, "src/technologies/") &&
			strings.HasSuffix(name, ".json")
		isCats := strings.HasSuffix(name, "src/categories.json")
		if hdr.Typeflag != tar.TypeReg || (!isTech && !isCats) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return st, fmt.Errorf("读取 %s: %w", name, err)
		}
		libs[basename(name)] = data
	}
	catRaw, ok := libs["categories.json"]
	if !ok {
		return st, fmt.Errorf("tar 内缺 src/categories.json（收集到 %d 个 json）", len(libs))
	}
	var rawCats map[string]struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(catRaw, &rawCats); err != nil {
		return st, fmt.Errorf("categories: %w", err)
	}
	catNames := map[int]string{}
	for k, v := range rawCats {
		var id int
		fmt.Sscanf(k, "%d", &id)
		catNames[id] = v.Name
	}
	delete(libs, "categories.json")

	// 2) 读现有精编库
	base, err := os.ReadFile(technologiesPath)
	if err != nil {
		return st, fmt.Errorf("读取 %s: %w", technologiesPath, err)
	}
	var box boxFile
	if err := json.Unmarshal(base, &box); err != nil {
		return st, fmt.Errorf("解析 %s: %w", technologiesPath, err)
	}
	existing := map[string]bool{}
	for _, t := range box.Technologies {
		existing[strings.ToLower(t.Name)] = true
	}

	// 3) 逐库转换合并
	cpeMap := map[string]string{}
	for _, libName := range sortedKeys(libs) {
		var lib map[string]rawSpec
		if err := json.Unmarshal(libs[libName], &lib); err != nil {
			return st, fmt.Errorf("解析 %s: %w", libName, err)
		}
		for name, spec := range lib {
			if spec.CPE != "" {
				cpeMap[name] = spec.CPE
			}
			ln := strings.ToLower(name)
			if existing[ln] {
				st.SkippedDup++
				continue
			}
			rules, err := rulesJSON(spec, &st.RejectedPats)
			if err != nil {
				return st, err
			}
			if rules == nil {
				st.SkippedEmpty++
				continue
			}
			cats := make([]string, 0, len(spec.Cats))
			for _, c := range spec.Cats {
				if cn := catNames[c]; cn != "" {
					cats = append(cats, reNonSlug.ReplaceAllString(strings.ToLower(cn), "-"))
				}
			}
			box.Technologies = append(box.Technologies, entry{
				Name:    name,
				Cats:    cats,
				Conf:    70,
				Website: spec.Website,
				Rules:   rules,
			})
			existing[ln] = true
			st.Added++
		}
	}
	st.Total = len(box.Technologies)
	st.CPEs = len(cpeMap)

	// 4) tmp+rename 原子写回
	box.Version = 1
	box.Count = st.Total
	data, err := json.MarshalIndent(box, "", " ")
	if err != nil {
		return st, err
	}
	if err := osWriteFile(technologiesPath, data); err != nil {
		return st, err
	}
	cpeData, _ := json.MarshalIndent(map[string]any{
		"version": 1, "count": st.CPEs, "cpe": cpeMap,
	}, "", " ")
	return st, osWriteFile(cpeOutPath, cpeData)
}

// osWriteFile tmp+rename 原子写。
func osWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
