// 验证引擎执行器：RunChecks（软 404 基线 / 回显剔除 / 二次确认）。
package checks

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

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
	Check      string       `json:"check"`
	Version    string       `json:"version,omitempty"` // 版本抽取成功时携带
	Title      string       `json:"title"`
	Severity   string       `json:"severity"`
	URL        string       `json:"url"`
	Evidence   string       `json:"evidence"`
	Advice     string       `json:"advice"`
	Request    string       `json:"request,omitempty"`    // 重放请求（HTTP 报文文本）
	Response   *HitResponse `json:"response,omitempty"`   // 命中响应快照
	Signals    []string     `json:"signals,omitempty"`    // 通道命中信号明细
	Replay     string       `json:"replay,omitempty"`     // curl 一键复现命令
	Confirmed  bool         `json:"confirmed,omitempty"`  // 经独立二次确认
	Hypothesis string       `json:"hypothesis,omitempty"` // 验证假设（2.0 证据链扩展位）
	Impact     string       `json:"impact,omitempty"`     // 影响面说明（2.0 证据链扩展位）
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

// CheckRun 单条 check 的执行证据（T1/T2 监督标签的地基）：
// executed+hit=正样本；executed+未命中=可靠负样本；not_executed（请求失败）
// 永远不作负样本——三值语义与 5.0 ML 线的标签纪律严格对齐。
type CheckRun struct {
	Check  string `json:"check"`
	Status string `json:"status"`           // executed | not_executed
	Hit    bool   `json:"hit"`              // status=executed 时有效
	Reason string `json:"reason,omitempty"` // not_executed 原因
}

// RunChecks 执行 check 集（core = 核心集，all = 核心+扩展+联动）。
// onHit 在每条命中产生时即时回调（nil = 不回调），供上层实时事件流使用。
func RunChecks(client *httpx.Client, targetURL string, level string,
	includeIDs []string, workers int, cancelCheck func() bool,
	onProgress func(done, total int, msg string), onHit func(Hit)) []Hit {
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
	hits, _ := runList(client, targetURL, selected, workers, cancelCheck, onProgress, onHit, nil)
	return hits
}

// RunChecksWithLog = RunChecks + 每条 check 的执行证据（引擎落库用）。
func RunChecksWithLog(client *httpx.Client, targetURL string, level string,
	includeIDs []string, workers int, cancelCheck func() bool,
	onProgress func(done, total int, msg string), onHit func(Hit)) ([]Hit, []CheckRun) {
	return RunChecksWithPrior(client, targetURL, level, includeIDs, nil, workers,
		cancelCheck, onProgress, onHit)
}

// RunChecksWithPrior = RunChecksWithLog + ML 先验调度（5.0 深度融合前置
// 通道）：prior 把相关 check 提到队列前段、命中后同家族联动提前；prior
// 为 nil 时与 RunChecksWithLog 行为逐字节一致（严格清单序）。先验只调序，
// 绝不改变执行集（见 prior.go 铁律）。
func RunChecksWithPrior(client *httpx.Client, targetURL string, level string,
	includeIDs []string, prior *Prior, workers int, cancelCheck func() bool,
	onProgress func(done, total int, msg string), onHit func(Hit)) ([]Hit, []CheckRun) {
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
	return runList(client, targetURL, selected, workers, cancelCheck, onProgress, onHit, prior)
}

// RunList 执行给定 check 集（Nuclei 子集等外部规则装载入口）。
// onHit 在每条命中产生时即时回调（nil = 不回调）。
func RunList(client *httpx.Client, targetURL string, list []Check,
	workers int, cancelCheck func() bool, onProgress func(done, total int, msg string),
	onHit func(Hit)) []Hit {
	hits, _ := runList(client, targetURL, list, workers, cancelCheck, onProgress, onHit, nil)
	return hits
}

// RunListWithLog = RunList + 每条 check 的执行证据（引擎落库用）。
func RunListWithLog(client *httpx.Client, targetURL string, list []Check,
	workers int, cancelCheck func() bool, onProgress func(done, total int, msg string),
	onHit func(Hit)) ([]Hit, []CheckRun) {
	return runList(client, targetURL, list, workers, cancelCheck, onProgress, onHit, nil)
}

// runList 共同实现：返回命中与逐条执行证据。
func runList(client *httpx.Client, targetURL string, list []Check,
	workers int, cancelCheck func() bool, onProgress func(done, total int, msg string),
	onHit func(Hit), prio *Prior) ([]Hit, []CheckRun) {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	selected := list

	baseRaw, baseStripped, basePrefix := soft404Baseline(client, targetURL)

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

	// 组调度（5.0 深度融合）：默认严格清单序（与 4.0 逐字节一致）；
	// 带先验时按得分调度——基础分 = 清单序（早者高），boost 与家族
	// 联动以 2×规模基数放大，保证任意提权都压过原始顺序。
	gN := float64(len(order))
	type gstate struct {
		key   string
		score float64
		done  bool
	}
	states := make([]*gstate, 0, len(order))
	for i, k := range order {
		st := &gstate{key: k, score: gN - float64(i)}
		if prio != nil {
			for _, ci := range groups[k].idx {
				if b := prio.Boost[selected[ci].ID]; b > 0 {
					st.score += b * 2 * gN
					break // 组分取首个有先验成员即可（同组共享一次请求）
				}
			}
		}
		states = append(states, st)
	}
	bumped := map[string]bool{}
	// bumpFamily 同家族未执行组统一提权（调用方须持 mu；每家族至多一次，
	// 防连环命中反复加分）。
	bumpFamily := func(family string) {
		if family == "" || bumped[family] {
			return
		}
		bumped[family] = true
		for _, st := range states {
			if st.done {
				continue
			}
			for _, ci := range groups[st.key].idx {
				if familyOf(selected[ci].ID) == family {
					st.score += 2 * gN
					break
				}
			}
		}
	}
	// pickNext 取得分最高（同分取清单序最早——states 按序遍历保序）
	// 的未执行组；调用方须持 mu。无剩余返回 nil。
	pickNext := func() *gstate {
		var best *gstate
		for _, st := range states {
			if st.done {
				continue
			}
			if best == nil || st.score > best.score {
				best = st
			}
		}
		return best
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
	// 执行证据：按组收集（fetch 成败决定 executed/not_executed；命中集合决定 hit）
	type groupOutcome struct {
		ids      []string
		executed bool
		reason   string
	}
	var outcomes []groupOutcome
	done := 0
	total := len(selected)
	// 组级并行：路径组之间相互独立，worker 池并发执行（默认 12）。
	// 共享面仅 hits/done/onHit/进度，全部持锁；组内判定为纯函数。
	if workers <= 0 {
		workers = 12
	}
	var mu sync.Mutex
	processGroup := func(k string) {
		if cancelCheck != nil && cancelCheck() {
			return
		}
		g := groups[k]
		chk0 := selected[g.idx[0]]
		u := joinURL(targetURL, strings.TrimLeft(chk0.Path, "/"))
		host := hostOf(u)

		resp, gerr := fetch(u, chk0.Match)
		if gerr != nil || resp == nil {
			mu.Lock()
			ids := make([]string, 0, len(g.idx))
			for _, ci := range g.idx {
				ids = append(ids, selected[ci].ID)
			}
			reason := "empty response"
			if gerr != nil {
				reason = "request failed: " + gerr.Error()
			}
			outcomes = append(outcomes, groupOutcome{ids: ids, executed: false, reason: reason})
			done += len(g.idx)
			onProgress(done, total, chk0.Path)
			mu.Unlock()
			return
		}
		body := stripEcho(resp.Body, u, chk0.Path)
		// B14 复扫修正：长度门以「剔除回显后」口径比较——原始长度含回显
		// 文本，目标路径与探针路径不等长时必失配，catch-all 回显站漏判。
		// 原始长度相等（静态站）作为快速路径保留。
		soft404 := baseStripped > 0 &&
			(len(body) == baseStripped || len(resp.Body) == baseRaw) &&
			strings.HasPrefix(strings.ToLower(body[:min(200, len(body))]),
				strings.ToLower(basePrefix[:min(200, len(basePrefix))]))

		// 组内首轮判定
		var pending []int
		reasons := map[int]string{}
		var groupHits []string // 本组命中 id（中段家族联动的触发源）
		groupChecks := make([]Check, 0, len(g.idx))
		for _, ci := range g.idx {
			groupChecks = append(groupChecks, selected[ci])
		}
		extractVars := extractVars(groupChecks, resp.Headers, resp.Body)
		for _, ci := range g.idx {
			ok, reason := matchBodyReason(selected[ci].Match, resp.Status, body, resp.Headers, host, extractVars)
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
					ok, reason := matchBodyReason(chk.Match, resp2.Status, body2, resp2.Headers, host, extractVars)
					if !ok {
						continue
					}
					h := Hit{
						Check: chk.ID, Title: chk.Title, Severity: chk.Sev,
						URL: u, Advice: chk.Advice,
						Evidence:  fmt.Sprintf("HTTP %d（二次确认）· %s", resp2.Status, reason),
						Version:   extractVersion(chk, body2),
						Request:   requestText(u, host, chk.Match),
						Response:  &HitResponse{Status: resp2.Status, Size: len(resp2.Body), Snippet: hitSnippet(body2)},
						Signals:   strings.Split(reason, " + "),
						Replay:    curlReplay(u, chk.Match),
						Confirmed: true,
					}
					mu.Lock()
					if onHit != nil {
						onHit(h)
					}
					hits = append(hits, h)
					groupHits = append(groupHits, h.Check)
					mu.Unlock()
				}
			}
		}
		mu.Lock()
		// 中段家族联动（深度融合）：本组有命中时，同家族未执行组统一
		// 提前——证据确认后姊妹 check 的命中先验更高。只调序不增删。
		if len(groupHits) > 0 && prio != nil {
			for _, id := range groupHits {
				bumpFamily(familyOf(id))
			}
		}
		ids := make([]string, 0, len(g.idx))
		for _, ci := range g.idx {
			ids = append(ids, selected[ci].ID)
		}
		outcomes = append(outcomes, groupOutcome{ids: ids, executed: true})
		done += len(g.idx)
		onProgress(done, total, chk0.Path)
		mu.Unlock()
	}
	// worker 池：每轮持 mu 领取当前最优组（先验/联动提权即时生效）
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if cancelCheck != nil && cancelCheck() {
					mu.Unlock()
					return
				}
				st := pickNext()
				if st == nil {
					mu.Unlock()
					return
				}
				st.done = true
				mu.Unlock()
				processGroup(st.key)
			}
		}()
	}
	wg.Wait()
	// 执行证据组装：命中集合 × 组执行结果 → 逐条 CheckRun
	hitIDs := map[string]bool{}
	for _, h := range hits {
		hitIDs[h.Check] = true
	}
	runs := make([]CheckRun, 0, len(selected))
	for _, oc := range outcomes {
		status, reason := "executed", ""
		if !oc.executed {
			status, reason = "not_executed", oc.reason
		}
		for _, id := range oc.ids {
			runs = append(runs, CheckRun{Check: id, Status: status,
				Hit: hitIDs[id], Reason: reason})
		}
	}
	sortHits(hits)
	return hits, runs
}

// matchBody 判定：状态码（等值或任一列表）+ 正文包含 + 正则 + 响应头包含
// + dsl 表达式（安全子集）。Contains 为全包含（AND），ContainsAny 为任一
// 包含（OR，Nuclei 组转换），RegexBody 为任一正则命中，HeaderContains 对
// 「名=值」合并区全包含，DSL 各表达式须全部为真；多类条件可并存。
// 修复：此前实际响应状态码从未参与比较，纯状态码 check 会对任何响应命中。
// dsl 求值失败（编译/类型/正则错误）一律不命中——宁少报不误报。
func matchBody(m Match, status int, body string, headers map[string]string, host string) bool {
	ok, _ := matchBodyReason(m, status, body, headers, host, nil)
	return ok
}

// matchBodyReason 同 matchBody 并返回命中原因（哪些条件、命中了什么），
// 供证据展示——验证型扫描器的每条命中都应能自解释。
// 语义与 matchBody 严格一致：任一条件不满足即不命中，全部满足才通过。
func matchBodyReason(m Match, status int, body string, headers map[string]string, host string, extractVars map[string]string) (bool, string) {
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
		prog, err := compileDSLVars(expr, extractVarNames(m.Extracts))
		if err != nil {
			return false, ""
		}
		ok, err := prog.Eval(respEnv{status: status, body: body, headers: headers, host: host, vars: extractVars})
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

// extractVars 按 Match.Extracts 从响应抽取命名变量（组内 check 共享响应）。
// 正则优先用第一个捕获组；每个变量首个命中的正则生效。
func extractVars(list []Check, headers map[string]string, body string) map[string]string {
	vars := map[string]string{}
	for _, chk := range list {
		for _, ex := range chk.Match.Extracts {
			if _, dup := vars[ex.Name]; dup || ex.Name == "" {
				continue
			}
			hay := body
			if ex.Part == "header" {
				hay = joinHeaders(headers)
			}
			for _, pat := range ex.Regex {
				re, cerr := regexp.Compile(pat) // B3：Compile 兜底（插件路径无预准入），坏正则跳过不 panic
				if cerr != nil {
					continue
				}
				mm := re.FindStringSubmatch(hay)
				if len(mm) > 1 {
					vars[ex.Name] = mm[1]
					break
				}
			}
		}
	}
	return vars
}

// extractVarNames 抽取变量名列表（编译 dsl 时的已知变量集）。
func extractVarNames(exs []ExtractSpec) []string {
	names := make([]string, 0, len(exs))
	for _, ex := range exs {
		if ex.Name != "" {
			names = append(names, ex.Name)
		}
	}
	return names
}

// dslVarsCache dsl 编译缓存（键 = 表达式 + 变量名表；变量名参与编译期
// 已知集合，不同表不可复用 AST）。
var dslVarsCache sync.Map

var dslVarsCacheN atomic.Int64 // B7：编译缓存计数上限，防长驻无界增长

// compileDSLVars 带抽取变量名表的 dsl 编译缓存。
func compileDSLVars(expr string, names []string) (*dsl.Program, error) {
	key := expr + "\x00" + strings.Join(names, "\x00")
	if p, ok := dslVarsCache.Load(key); ok {
		return p.(*dsl.Program), nil
	}
	prog, err := dsl.CompileWithVars(expr, names)
	if err != nil {
		return nil, err
	}
	if dslVarsCacheN.Load() < 4096 { // B7：上限防长驻无界增长
		dslVarsCacheN.Add(1)
		dslVarsCache.Store(key, prog)
	}
	return prog, nil
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
	vars    map[string]string
}

// Var 抽取变量取值（dsl.VarSource）：不存在返回 false（表达式不命中）。
func (e respEnv) Var(name string) (string, bool) {
	v, ok := e.vars[name]
	return v, ok
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
// stripEcho 剔除响应正文中本次请求自身的回显（完整 URL 与路径形态）。
// B2 收口：路径统一为「前导 /」形态再剔除——探针侧传的路径无前导斜杠、
// 主循环侧有，此前口径不一会让 catch-all 回显站的软 404 基线残留一个
// '/'（如 "/<html>…" vs "<html>…"），前缀比对失配 → 生产可达误报。
// 两侧共用本函数，任一形态都剔净，口径不再漂移。
func stripEcho(body string, reqURL string, path string) string {
	body = strings.ReplaceAll(body, reqURL, "")
	p := path
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if p != "" {
		body = strings.ReplaceAll(body, p, "")
	}
	if u, err := url.Parse(p); err == nil && u.Path != "" && u.Path != "/" {
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
// 返回：原始长度、剔除回显后长度、剔除回显后的正文前缀（小写）。
// 与比对侧同口径（B2）：先剔除本次探针自身的回显（URL/路径）再取前缀，
// 否则 catch-all 回显站会因探针路径与目标路径不同而漏判软 404。
func soft404Baseline(client *httpx.Client, targetURL string) (int, int, string) {
	probeURL := joinURL(targetURL, "__sitelens_probe_none__")
	resp, err := client.GetFollow(probeURL)
	if err != nil || resp == nil {
		return 0, 0, ""
	}
	stripped := stripEcho(resp.Body, probeURL, "__sitelens_probe_none__")
	prefix := strings.ToLower(stripped)
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	return len(resp.Body), len(stripped), prefix
}
