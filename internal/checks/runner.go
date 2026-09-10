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

// HitResponse 证据链的响应快照。
type HitResponse struct {
	Status  int    `json:"status"`
	Size    int    `json:"size"`
	Snippet string `json:"snippet"` // 命中正文摘要（压缩空白后取头部）
}

// Hit 一条已验证发现。Request/Response/Signals/Replay 构成证据链
// （2.0 验证器地基）：请求可重放、响应可核对、信号可解释、命令可复现。
type Hit struct {
	Check     string       `json:"check"`
	Version   string       `json:"version,omitempty"` // 版本抽取成功时携带
	Title     string       `json:"title"`
	Severity  string       `json:"severity"`
	URL       string       `json:"url"`
	Evidence  string       `json:"evidence"`
	Advice    string       `json:"advice"`
	Request   string       `json:"request,omitempty"`   // 重放请求（HTTP 报文文本）
	Response  *HitResponse `json:"response,omitempty"`  // 命中响应快照
	Signals   []string     `json:"signals,omitempty"`   // 通道命中信号明细
	Replay    string       `json:"replay,omitempty"`    // curl 一键复现命令
	Confirmed bool         `json:"confirmed,omitempty"` // 经独立二次确认
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

	// 同路径聚类：Method+Path+Body+ContentType 相同的 check 共享一次
	// 请求——Nuclei 子集大量模板探测同一路径（如 /），聚类后请求数从
	// O(模板数) 降到 O(路径数)，二次确认按组一次重放服务组内全部命中
	//（每条命中仍经独立重放验证，语义不变）。
	type group struct {
		idx []int
	}
	groups := map[string]*group{}
	var order []string
	for i := range selected {
		chk := selected[i]
		k := chk.Match.Method + "\x00" + chk.Path + "\x00" + chk.Match.Body + "\x00" + chk.Match.ContentType
		if groups[k] == nil {
			groups[k] = &group{}
			order = append(order, k)
		}
		groups[k].idx = append(groups[k].idx, i)
	}

	fetch := func(u string, m Match) (*httpx.Response, error) {
		if m.Method == "POST" {
			ctype := m.ContentType
			if ctype == "" {
				ctype = "application/x-www-form-urlencoded"
			}
			return client.PostRaw(u, ctype, m.Body)
		}
		return client.GetFollow(u)
	}

	hits := []Hit{}
	done := 0
	total := len(selected)
	for _, k := range order {
		if cancelCheck != nil && cancelCheck() {
			break
		}
		g := groups[k]
		chk0 := selected[g.idx[0]]
		u := joinURL(targetURL, strings.TrimLeft(chk0.Path, "/"))
		host := hostOf(u)

		resp, gerr := fetch(u, chk0.Match)
		if gerr != nil || resp == nil {
			done += len(g.idx)
			onProgress(done, total, chk0.Path)
			continue
		}
		body := stripEcho(resp.Body, u, chk0.Path)
		soft404 := baseSize > 0 && len(resp.Body) == baseSize &&
			strings.HasPrefix(strings.ToLower(body[:min(200, len(body))]),
				strings.ToLower(basePrefix[:min(200, len(basePrefix))]))

		// 组内首轮判定
		var pending []int
		reasons := map[int]string{}
		for _, ci := range g.idx {
			ok, reason := matchBodyReason(selected[ci].Match, resp.Status, body, resp.Headers, host)
			if !ok {
				continue
			}
			if soft404 {
				continue // 软 404：与不存在路径响应一致，整组共享同一响应
			}
			pending = append(pending, ci)
			reasons[ci] = reason
		}
		// 二次确认：组内共享一次独立重放
		if len(pending) > 0 {
			resp2, gerr2 := fetch(u, chk0.Match)
			if gerr2 == nil && resp2 != nil {
				body2 := stripEcho(resp2.Body, u, chk0.Path)
				for _, ci := range pending {
					chk := selected[ci]
					ok, reason := matchBodyReason(chk.Match, resp2.Status, body2, resp2.Headers, host)
					if !ok {
						continue
					}
					hits = append(hits, Hit{
						Check: chk.ID, Title: chk.Title, Severity: chk.Sev,
						URL: u, Advice: chk.Advice,
						Evidence:  fmt.Sprintf("HTTP %d（二次确认）· %s", resp2.Status, reason),
						Version:   extractVersion(chk, body2),
						Request:   requestText(u, host, chk.Match),
						Response:  &HitResponse{Status: resp2.Status, Size: len(resp2.Body), Snippet: hitSnippet(body2)},
						Signals:   strings.Split(reason, " + "),
						Replay:    curlReplay(u, chk.Match),
						Confirmed: true,
					})
				}
			}
		}
		done += len(g.idx)
		onProgress(done, total, chk0.Path)
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
	ok, _ := matchBodyReason(m, status, body, headers, host)
	return ok
}

// matchBodyReason 同 matchBody 并返回命中原因（哪些条件、命中了什么），
// 供证据展示——验证型扫描器的每条命中都应能自解释。
// 语义与 matchBody 严格一致：任一条件不满足即不命中，全部满足才通过。
func matchBodyReason(m Match, status int, body string, headers map[string]string, host string) (bool, string) {
	var why []string
	if m.Status != 0 && status != m.Status {
		return false, ""
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
			return false, ""
		}
	}
	if len(m.Contains) > 0 {
		low := strings.ToLower(body) // 对齐 Python：关键词/正文双降比较（不区分大小写）
		for _, kw := range m.Contains {
			if !strings.Contains(low, strings.ToLower(kw)) {
				return false, ""
			}
		}
	}
	if len(m.ContainsAny) > 0 {
		low := strings.ToLower(body)
		anyHit := false
		marked := ""
		for _, kw := range m.ContainsAny {
			if strings.Contains(low, strings.ToLower(kw)) {
				anyHit = true
				marked = kw
				break
			}
		}
		if !anyHit {
			return false, ""
		}
		why = append(why, "词命中 "+truncateMark(marked))
	}
	if len(m.RegexBody) > 0 {
		anyHit := false
		marked := ""
		for _, pat := range m.RegexBody {
			if re := compileCached(pat); re != nil && re.MatchString(body) {
				anyHit = true
				marked = pat
				break
			}
		}
		if !anyHit {
			return false, ""
		}
		why = append(why, "正则命中 "+truncateMark(marked))
	}
	if len(m.HeaderContains) > 0 {
		joined := strings.ToLower(joinHeaders(headers))
		for _, kw := range m.HeaderContains {
			if !strings.Contains(joined, strings.ToLower(kw)) {
				return false, ""
			}
		}
		why = append(why, "响应头词命中")
	}
	for _, expr := range m.DSL {
		prog, err := dsl.CompileCached(expr)
		if err != nil {
			return false, ""
		}
		ok, err := prog.Eval(respEnv{status: status, body: body, headers: headers, host: host})
		if err != nil || !ok {
			return false, ""
		}
	}
	if len(m.DSL) > 0 {
		why = append(why, "dsl 表达式为真")
	}
	if len(why) == 0 {
		if len(m.Contains) > 0 {
			why = append(why, "全包含词命中")
		} else {
			why = append(why, "状态码命中")
		}
	}
	return true, strings.Join(why, " + ")
}

// truncateMark 证据里的标记截断（超长正则/词不全量入库）。
func truncateMark(s string) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 60 {
		s = string([]rune(s)[:60]) + "…"
	}
	return s
}

// requestText 重放请求文本（HTTP 报文形态）：与实际发出的请求语义一致
// （方法/路径/Host/Content-Type/正文；UA/Cookie 等运行时头不落证据，
// 避免把会话敏感信息写进报告）。
func requestText(u, host string, m Match) string {
	method := m.Method
	if method == "" {
		method = "GET"
	}
	path := "/"
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		path = parsed.Path
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	if method == "POST" {
		ct := m.ContentType
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ct)
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(m.Body))
	}
	b.WriteString("\r\n")
	b.WriteString(m.Body)
	return b.String()
}

// shellQuote 单引号包裹（内部单引号按 POSIX 规则转义）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// curlReplay 一键复现命令：粘贴即重放（-sk --path-as-is 与引擎姿态一致）。
func curlReplay(u string, m Match) string {
	var b strings.Builder
	b.WriteString("curl -sk --path-as-is")
	if m.Method == "POST" {
		b.WriteString(" -X POST")
		ct := m.ContentType
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		b.WriteString(" -H " + shellQuote("Content-Type: "+ct))
		if m.Body != "" {
			b.WriteString(" --data-raw " + shellQuote(m.Body))
		}
	}
	b.WriteString(" " + shellQuote(u))
	return b.String()
}

// hitSnippet 命中正文摘要：压缩空白后取头部（证据链里给人看的窗口；
// 全量响应以重放命令复现为准，避免把整页内容塞进报告）。
func hitSnippet(body string) string {
	collapsed := strings.Join(strings.Fields(body), " ")
	r := []rune(collapsed)
	if len(r) > 240 {
		return string(r[:240]) + "…"
	}
	return collapsed
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
// Apache 类 404 页回显的是去 query 的路径，故两种形态都剔——
// 否则路径中的关键词（如 /wprm_recipe）会留在正文里喂给词匹配。
func stripEcho(body string, reqURL string, path string) string {
	body = strings.ReplaceAll(body, reqURL, "")
	body = strings.ReplaceAll(body, path, "")
	if u, err := url.Parse(path); err == nil && u.Path != "" && u.Path != "/" {
		body = strings.ReplaceAll(body, u.Path, "")
	}
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
