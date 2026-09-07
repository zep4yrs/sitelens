// 验证引擎执行器：RunChecks（软 404 基线 / 回显剔除 / 二次确认）。
package checks

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/dsl"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/versioncmp"
)

// Hit 一条已验证发现。
type Hit struct {
	Check    string `json:"check"`
	Version  string `json:"version,omitempty"` // 版本抽取成功时携带
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
}

// Options 执行参数。
type Options struct {
	Level       string
	IncludeIDs  []string
	CancelCheck func() bool
	OnProgress  func(done, total int, msg string)
}

var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func sortHits(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool {
		sa, sb := severityRank[hits[i].Severity], severityRank[hits[j].Severity]
		if sa != sb {
			return sa < sb
		}
		return hits[i].Check < hits[j].Check
	})
}

// RunChecks 执行 check 集（core = 核心集，all = 核心+扩展+联动）。
func RunChecks(client *httpx.Client, targetURL string, level string,
	includeIDs []string, cancelCheck func() bool,
	onProgress func(done, total int, msg string)) []Hit {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	inc := map[string]bool{}
	for _, id := range includeIDs {
		inc[id] = true
	}
	var selected []Check
	for _, c := range AllChecks() {
		if level == "all" || c.Lv == 0 || inc[c.ID] {
			selected = append(selected, c)
		}
	}
	return RunList(client, targetURL, selected, cancelCheck, onProgress)
}

// RunList 执行给定 check 集（Nuclei 子集等外部规则装载入口）。
func RunList(client *httpx.Client, targetURL string, list []Check,
	cancelCheck func() bool, onProgress func(done, total int, msg string)) []Hit {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	selected := list

	baseSize, basePrefix := soft404Baseline(client, targetURL)

	hits := []Hit{}
	total := len(selected)
	for i, chk := range selected {
		if cancelCheck != nil && cancelCheck() {
			break
		}
		u := joinURL(targetURL, strings.TrimLeft(chk.Path, "/"))
		var resp *httpx.Response
		var gerr error
		if chk.Match.Method == "POST" {
			ctype := chk.Match.ContentType
			if ctype == "" {
				ctype = "application/x-www-form-urlencoded"
			}
			resp, gerr = client.PostRaw(u, ctype, chk.Match.Body)
		} else {
			resp, gerr = client.GetFollow(u)
		}
		if gerr != nil || resp == nil {
			onProgress(i+1, total, chk.Path)
			continue
		}
		body := stripEcho(resp.Body, u, chk.Path)
		if !matchBody(chk.Match, resp.Status, body, resp.Headers, hostOf(u)) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		// 软 404：与不存在路径响应一致
		if baseSize > 0 && len(resp.Body) == baseSize &&
			strings.HasPrefix(strings.ToLower(body[:min(200, len(body))]),
				strings.ToLower(basePrefix[:min(200, len(basePrefix))])) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		// 二次确认：立即重放，两次都命中才采信
		var resp2 *httpx.Response
		var gerr2 error
		if chk.Match.Method == "POST" {
			ctype := chk.Match.ContentType
			if ctype == "" {
				ctype = "application/x-www-form-urlencoded"
			}
			resp2, gerr2 = client.PostRaw(u, ctype, chk.Match.Body)
		} else {
			resp2, gerr2 = client.GetFollow(u)
		}
		if gerr2 != nil {
			onProgress(i+1, total, chk.Path)
			continue
		}
		body2 := stripEcho(resp2.Body, u, chk.Path)
		if !matchBody(chk.Match, resp2.Status, body2, resp2.Headers, hostOf(u)) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		hits = append(hits, Hit{
			Check: chk.ID, Title: chk.Title, Severity: chk.Sev,
			URL: u, Advice: chk.Advice,
			Evidence: fmt.Sprintf("HTTP %d（二次确认）", resp2.Status),
			Version:  extractVersion(chk, body2),
		})
		onProgress(i+1, total, chk.Path)
	}
	sortHits(hits)
	return hits
}

// matchBody 判定：状态码（等值或任一列表）+ 正文包含 + 正则 + 响应头包含
// + dsl 表达式（安全子集）。Contains 为全包含（AND），ContainsAny 为任一
// 包含（OR，Nuclei 组转换），RegexBody 为任一正则命中，HeaderContains 对
// 「名=值」合并区全包含，DSL 各表达式须全部为真；多类条件可并存。
// 修复：此前实际响应状态码从未参与比较，纯状态码 check 会对任何响应命中。
// dsl 求值失败（编译/类型/正则错误）一律不命中——宁少报不误报。
func matchBody(m Match, status int, body string, headers map[string]string, host string) bool {
	if m.Status != 0 && status != m.Status {
		return false
	}
	if len(m.StatusAny) > 0 {
		okStatus := false
		for _, s := range m.StatusAny {
			if status == s {
				okStatus = true
				break
			}
		}
		if !okStatus {
			return false
		}
	}
	if len(m.Contains) > 0 {
		low := strings.ToLower(body) // 对齐 Python：关键词/正文双降比较（不区分大小写）
		for _, kw := range m.Contains {
			if !strings.Contains(low, strings.ToLower(kw)) {
				return false
			}
		}
	}
	if len(m.ContainsAny) > 0 {
		low := strings.ToLower(body)
		anyHit := false
		for _, kw := range m.ContainsAny {
			if strings.Contains(low, strings.ToLower(kw)) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return false
		}
	}
	if len(m.RegexBody) > 0 {
		anyHit := false
		for _, pat := range m.RegexBody {
			if re := compileCached(pat); re != nil && re.MatchString(body) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return false
		}
	}
	if len(m.HeaderContains) > 0 {
		joined := strings.ToLower(joinHeaders(headers))
		for _, kw := range m.HeaderContains {
			if !strings.Contains(joined, strings.ToLower(kw)) {
				return false
			}
		}
	}
	for _, expr := range m.DSL {
		prog, err := dsl.CompileCached(expr)
		if err != nil {
			return false
		}
		ok, err := prog.Eval(respEnv{status: status, body: body, headers: headers, host: host})
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// respEnv dsl 求值环境：封装单次响应的状态码/正文/头/主机名。
type respEnv struct {
	status  int
	body    string
	headers map[string]string
	host    string
}

func (e respEnv) StatusCode() int { return e.status }
func (e respEnv) Body() string    { return e.body }
func (e respEnv) Header(name string) string {
	for k, v := range e.headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
func (e respEnv) HeaderValues() []string {
	out := make([]string, 0, len(e.headers))
	for _, v := range e.headers {
		out = append(out, v)
	}
	return out
}
func (e respEnv) Host() string { return e.host }

// extractVersion 配置了版本抽取的 check：从正文按关键词提取版本号
// （wp-readme → WordPress 版本，情报关联 confirmed 的关键链路）。
func extractVersion(chk Check, body string) string {
	keyword, _, ok := ExtractFor(chk.ID)
	if !ok {
		return ""
	}
	return versioncmp.ExtractVersion(body, keyword)
}

// hostOf 从请求 URL 提取主机名（dsl 的 host 变量取值）。
func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// joinHeaders 把响应头合并为「名: 值」多行串供头匹配。
func joinHeaders(headers map[string]string) string {
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// stripEcho 剔除响应中回显的请求 URL 与路径（防自指误报）。
func stripEcho(body string, reqURL string, path string) string {
	body = strings.ReplaceAll(body, reqURL, "")
	body = strings.ReplaceAll(body, path, "")
	return body
}

func joinURL(base, path string) string {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + strings.TrimLeft(path, "/")
}

// soft404Baseline 取一个不存在路径的响应做软 404 基线。
func soft404Baseline(client *httpx.Client, targetURL string) (int, string) {
	resp, err := client.GetFollow(joinURL(targetURL, "__sitelens_probe_none__"))
	if err != nil || resp == nil {
		return 0, ""
	}
	prefix := strings.ToLower(resp.Body)
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	return len(resp.Body), prefix
}
