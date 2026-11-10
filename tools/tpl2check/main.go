// Command tpl2check 把 afrog / nuclei 模板池里「只读、强判据」的暴露面模板
// 转成内置验证型 check（internal/checks 的 Check），供 5.3「模板 → 强判据」
// 转译管线使用。
//
// 设计取舍（宁少报不误报）：
//   - 只接受 GET、静态路径（仅允许 {{BaseURL}}/{{RootURL}} 前缀）、无 payload/变量；
//   - 只接受 status / body word / body regex / header word 这几类 matcher，
//     拒绝 DSL、expression 复杂逻辑（&& 之外的组合）、POST/raw 请求；
//   - 至少一个强特征（word ≥ 8 字符或 regex ≥ 12 字符）；
//   - 用内置「通用页面」样本做零误报自检：会命中通用 HTML/JSON/404 页的模板直接丢弃。
//
// 用法：
//
//	go run ./tools/tpl2check -src <模板目录> -out internal/checks/tpl_generated.go
//
// 生成结果仍需要人工抽检（见 internal/checks/builtin_test.go 的门禁测试）。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// ---------- afrog 模板 ----------

type afrogDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Tags        []string `yaml:"tags"`
	} `yaml:"info"`
	Expression string `yaml:"expression"`
	Rules      map[string]struct {
		Request struct {
			Method string `yaml:"method"`
			Path   string `yaml:"path"`
		} `yaml:"request"`
		Expression string `yaml:"expression"`
	} `yaml:"rules"`
}

// ---------- nuclei 模板 ----------

type nucleiMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
}

type nucleiRequest struct {
	Method            string          `yaml:"method"`
	Path              []string        `yaml:"path"`
	Matchers          []nucleiMatcher `yaml:"matchers"`
	MatchersCondition string          `yaml:"matchers-condition"`
	Payloads          map[string]any  `yaml:"payloads"`
	Raw               []string        `yaml:"raw"`
	Body              string          `yaml:"body"`
}

type nucleiDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Remediation string   `yaml:"remediation"`
		Tags        []string `yaml:"tags"`
	} `yaml:"info"`
	HTTP     []nucleiRequest `yaml:"http"`
	Requests []nucleiRequest `yaml:"requests"`
}

// ---------- 生成条目 ----------

type entry struct {
	ID       string
	Path     string
	Status   int
	Contains []string
	Any      []string
	Regex    []string
	Headers  []string
	Title    string
	Sev      string
	Advice   string
	Src      string
	Tags     []string
}

var (
	reAfrogStatus = regexp.MustCompile(`response\.status\s*==\s*(\d{3})`)
	reAfrogBody   = regexp.MustCompile(`response\.body\.bcontains\(b"((?:[^"\\]|\\.)*)"\)`)
	reAfrogICont  = regexp.MustCompile(`response\.body\.icontains\(b"((?:[^"\\]|\\.)*)"\)`)
	reAfrogHeader = regexp.MustCompile(`response\.headers\.bcontains\(b"((?:[^"\\]|\\.)*)"\)`)
	reVar         = regexp.MustCompile(`\{\{[^}]*\}\}`)
	reBaseURL     = regexp.MustCompile(`^\{\{(?:BaseURL|RootURL)\}\}`)
	reBadPath     = regexp.MustCompile(`[\\\s]|\.\.|%08|%00`)
)

// 攻击载荷/穿越特征：出现即拒绝（这是「无害验证」管线，不是漏洞利用器）。
var reIntrusive = regexp.MustCompile("(?i)(\\.\\.|%2e|%00|%08|%25|%3c|%3e|%22|%27|%5c|[<>'\"(){}|;`$\\\\]|etc/passwd|select\\s|union\\s|sleep\\(|alert\\(|onload|javascript:)")

// 漏洞利用类模板特征：CVE 复现/注入/穿越/上传/默认口令，一律不进内置验证集。
var reExploitTag = regexp.MustCompile(`(?i)(cve-|exploit|rce|xss|sqli|lfi|rfi|ssrf|injection|traversal|bypass|csrf|deserial|shell|upload|pwn|default.?pwd|default.?cred|weak.?pass|brute|poc|file.?write)`)

var reIDClean = regexp.MustCompile(`[^a-z0-9-]+`)

// cleanID 把模板 id 归一成 kebab-case（模板池里有空格/括号/大写）。
func cleanID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reIDClean.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// acceptable 统一安全闸：无害验证只接受「静态路径 + 非利用类」模板。
func acceptable(e *entry) bool {
	if e == nil || e.ID == "" || e.Path == "" {
		return false
	}
	if reIntrusive.MatchString(e.Path) || strings.Contains(e.Path, "?") {
		return false
	}
	if reExploitTag.MatchString(strings.Join(e.Tags, " ") + " " + e.Title + " " + e.ID) {
		return false
	}
	return true
}

// 通用页面样本：命中即视为弱判据丢弃（零误报门禁）。
var genericPages = []struct {
	status int
	body   string
}{
	{200, `<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>`},
	{200, `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>`},
	{200, `<html><head><title>Apache2 Ubuntu Default Page: It works</title></head><body><h1>It works!</h1></body></html>`},
	{200, `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error.</p></body></html>`},
	{200, `{"status":"ok","data":[],"message":"success"}`},
	{200, `{"code":0,"msg":"success","data":null}`},
	{401, `{"error":"unauthorized","message":"Authentication required"}`},
	{403, `<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>`},
	{404, `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`},
	{500, `<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>`},
}

func genericHit(m checks.Match) bool {
	for _, g := range genericPages {
		if checks.MatchForTest(m, g.status, g.body, map[string]string{"Content-Type": "text/html; charset=utf-8"}, "example.com") {
			return true
		}
	}
	return false
}

func normSev(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	case "moderate":
		return "medium"
	default:
		return "info"
	}
}

func strongWord(w string) bool { return len(strings.TrimSpace(w)) >= 8 }

func cleanAdvice(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if s == "" {
		return "确认该暴露面是否必要；不需要则下线或加访问控制"
	}
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

func staticPath(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	p = reBaseURL.ReplaceAllString(p, "")
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	if reVar.MatchString(p) || reBadPath.MatchString(p) {
		return "", false
	}
	if strings.Contains(p, "?") {
		// 静态 query 允许（无模板变量），但 payload 型 query 一律拒绝
		q := p[strings.Index(p, "?")+1:]
		if strings.ContainsAny(q, "<>'\"{}() ;|&$`") {
			return "", false
		}
	}
	return p, true
}

// ---------- afrog 解析 ----------

func parseAfrog(data []byte, src string) []entry {
	var d afrogDoc
	if err := yaml.Unmarshal(data, &d); err != nil || d.ID == "" || len(d.Rules) == 0 {
		return nil
	}
	// 模板级表达式：只接受「单规则」或「r0() || r1()」这种规则析取；
	// 规则合取（&&）意味着多请求联动，超出单 check 语义，拒绝。
	if tl := strings.TrimSpace(d.Expression); tl != "" {
		if strings.Contains(tl, "&&") {
			return nil
		}
	}
	keys := make([]string, 0, len(d.Rules))
	for k := range d.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []entry
	for _, k := range keys {
		r := d.Rules[k]
		if !strings.EqualFold(strings.TrimSpace(r.Request.Method), "GET") {
			continue
		}
		path, ok := staticPath(r.Request.Path)
		if !ok {
			continue
		}
		expr := strings.TrimSpace(r.Expression)
		if expr == "" || strings.Contains(expr, "||") {
			continue
		}
		var e entry
		e.Path = path
		if m := reAfrogStatus.FindStringSubmatch(expr); m != nil {
			e.Status, _ = strconv.Atoi(m[1])
		}
		for _, m := range reAfrogBody.FindAllStringSubmatch(expr, -1) {
			e.Contains = append(e.Contains, strings.ReplaceAll(m[1], `\"`, `"`))
		}
		for _, m := range reAfrogHeader.FindAllStringSubmatch(expr, -1) {
			e.Headers = append(e.Headers, strings.ReplaceAll(m[1], `\"`, `"`))
		}
		for _, m := range reAfrogICont.FindAllStringSubmatch(expr, -1) {
			e.Regex = append(e.Regex, "(?i)"+regexp.QuoteMeta(strings.ReplaceAll(m[1], `\"`, `"`)))
		}
		if e.Status == 0 || (len(e.Contains) == 0 && len(e.Regex) == 0 && len(e.Headers) == 0) {
			continue
		}
		if !strongEntry(&e) || !validRegex(&e) {
			continue
		}
		e.ID = "tpl-" + cleanID(d.ID)
		if len(keys) > 1 {
			e.ID += "-" + cleanID(k)
		}
		e.Title = strings.TrimSpace(d.Info.Name)
		if e.Title == "" {
			e.Title = d.ID
		}
		e.Sev = normSev(d.Info.Severity)
		e.Advice = cleanAdvice(d.Info.Description)
		e.Src = src
		e.Tags = d.Info.Tags
		if acceptable(&e) {
			out = append(out, e)
		}
	}
	return out
}

// ---------- nuclei 解析 ----------

func parseNuclei(data []byte, src string) []entry {
	var d nucleiDoc
	if err := yaml.Unmarshal(data, &d); err != nil || d.ID == "" {
		return nil
	}
	reqs := d.HTTP
	if len(reqs) == 0 {
		reqs = d.Requests
	}
	if len(reqs) == 0 {
		return nil
	}
	var out []entry
	for i, r := range reqs {
		if r.Method != "" && !strings.EqualFold(r.Method, "GET") {
			continue
		}
		if len(r.Raw) > 0 || r.Body != "" || len(r.Payloads) > 0 || len(r.Path) != 1 {
			continue
		}
		path, ok := staticPath(r.Path[0])
		if !ok || len(r.Matchers) == 0 {
			continue
		}
		var e entry
		e.Path = path
		bad := false
		condOr := strings.EqualFold(strings.TrimSpace(r.MatchersCondition), "or")
		for _, m := range r.Matchers {
			switch strings.ToLower(strings.TrimSpace(m.Type)) {
			case "status":
				if len(m.Status) > 0 {
					e.Status = m.Status[0]
				}
			case "word":
				part := strings.ToLower(strings.TrimSpace(m.Part))
				if part == "header" || part == "all_headers" {
					e.Headers = append(e.Headers, m.Words...)
					continue
				}
				if part != "" && part != "body" && part != "all" {
					bad = true
				}
				if condOr {
					e.Any = append(e.Any, m.Words...)
				} else {
					e.Contains = append(e.Contains, m.Words...)
				}
			case "regex":
				part := strings.ToLower(strings.TrimSpace(m.Part))
				if part != "" && part != "body" && part != "all" {
					bad = true
				}
				e.Regex = append(e.Regex, m.Regex...)
			default:
				bad = true // dsl / binary / xpath 等一律拒绝
			}
			if bad {
				break
			}
		}
		if bad || e.Status == 0 ||
			(len(e.Contains) == 0 && len(e.Any) == 0 && len(e.Regex) == 0 && len(e.Headers) == 0) {
			continue
		}
		if !strongEntry(&e) || !validRegex(&e) {
			continue
		}
		e.ID = "tpl-" + cleanID(d.ID)
		if len(reqs) > 1 {
			e.ID += "-r" + strconv.Itoa(i)
		}
		e.Title = strings.TrimSpace(d.Info.Name)
		if e.Title == "" {
			e.Title = d.ID
		}
		e.Sev = normSev(d.Info.Severity)
		e.Advice = cleanAdvice(d.Info.Remediation)
		e.Src = src
		e.Tags = d.Info.Tags
		if acceptable(&e) {
			out = append(out, e)
		}
	}
	return out
}

// strongEntry 至少一个强特征：header 判据 / word ≥ 8 字符 / regex ≥ 12 字符。
func strongEntry(e *entry) bool {
	if len(e.Headers) > 0 {
		return true
	}
	for _, w := range append(append([]string{}, e.Contains...), e.Any...) {
		if strongWord(w) {
			return true
		}
	}
	for _, rx := range e.Regex {
		if len(rx) >= 12 {
			return true
		}
	}
	return false
}

// validRegex 正则必须能被 Go RE2 编译（不支持 (?:...) 等 PCRE 语法）。
func validRegex(e *entry) bool {
	for _, rx := range e.Regex {
		if _, err := regexp.Compile(rx); err != nil {
			return false
		}
	}
	return true
}

// ---------- 输出 ----------

func goQuote(s string) string { return strconv.Quote(s) }

func goList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, goQuote(it))
	}
	return strings.Join(parts, ", ")
}

func render(entries []entry) string {
	var b strings.Builder
	b.WriteString("// Code generated by tools/tpl2check; DO NOT EDIT.\n")
	b.WriteString("//\n")
	b.WriteString("// 来源：afrog / nuclei 模板池中「GET + 静态路径 + 强判据」的暴露面模板，\n")
	b.WriteString("// 已过滤 payload/变量/DSL，并通过通用页面零误报自检；人工抽检后入库。\n")
	b.WriteString("// 全部 Lv=1（扩展集），只在「完整/穷尽」档运行，默认扫描请求量不变。\n\n")
	b.WriteString("package checks\n\n")
	b.WriteString("var tplChecks = []Check{\n")
	for _, e := range entries {
		var m string
		if len(e.Headers) > 0 && len(e.Contains) == 0 && len(e.Any) == 0 && len(e.Regex) == 0 {
			m = "Match{Status: " + strconv.Itoa(e.Status) + ", HeaderContains: []string{" + goList(e.Headers) + "}}"
		} else if len(e.Regex) > 0 || len(e.Any) > 0 {
			parts := []string{"Status: " + strconv.Itoa(e.Status)}
			if len(e.Contains) > 0 {
				parts = append(parts, "Contains: []string{"+goList(e.Contains)+"}")
			}
			if len(e.Any) > 0 {
				parts = append(parts, "ContainsAny: []string{"+goList(e.Any)+"}")
			}
			if len(e.Regex) > 0 {
				parts = append(parts, "RegexBody: []string{"+goList(e.Regex)+"}")
			}
			if len(e.Headers) > 0 {
				parts = append(parts, "HeaderContains: []string{"+goList(e.Headers)+"}")
			}
			m = "Match{" + strings.Join(parts, ", ") + "}"
		} else {
			m = "c(" + strconv.Itoa(e.Status) + ", " + goList(e.Contains) + ")"
		}
		fmt.Fprintf(&b, "\t{%s, 1, %s, %s, %s, %s, %s},\n",
			goQuote(e.ID), goQuote(e.Path), m, goQuote(e.Title), goQuote(e.Sev), goQuote(e.Advice))
	}
	b.WriteString("}\n")
	return b.String()
}

func main() {
	src := flag.String("src", "", "模板目录（含 afrog/ 与 community-40k/）")
	out := flag.String("out", "internal/checks/tpl_generated.go", "输出 Go 文件")
	maxN := flag.Int("max", 120, "最多生成条数")
	flag.Parse()
	if *src == "" {
		fmt.Fprintln(os.Stderr, "缺少 -src")
		os.Exit(2)
	}
	builtinPaths := checks.AllBuiltinPaths()
	seenPath := map[string]bool{}
	seenID := map[string]bool{}
	var entries []entry
	err := filepath.WalkDir(*src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(*src, path)
		var list []entry
		if strings.Contains(filepath.ToSlash(rel), "afrog/") {
			list = parseAfrog(data, rel)
		} else {
			list = parseNuclei(data, rel)
		}
		for _, e := range list {
			if builtinPaths[e.Path] || seenPath[e.Path] || seenID[e.ID] {
				continue
			}
			if genericHit(checks.Match{
				Status: e.Status, Contains: e.Contains, ContainsAny: e.Any,
				RegexBody: e.Regex, HeaderContains: e.Headers,
			}) {
				continue
			}
			seenPath[e.Path] = true
			seenID[e.ID] = true
			entries = append(entries, e)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk:", err)
		os.Exit(1)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if len(entries) > *maxN {
		entries = entries[:*maxN]
	}
	if err := os.WriteFile(*out, []byte(render(entries)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "生成 %d 条 -> %s\n", len(entries), *out)
}
