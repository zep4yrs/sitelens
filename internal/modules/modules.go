// Package modules 主动探测模块：目录探测 / 子域名枚举 / WebShell 探测。
// 默认关闭；请求总量有硬上限（config.ActiveConfig），目标合规责任在使用者。
// 判定语义对齐 python 分支 scanner/modules.py：
// 目录命中 = 200/401/403 且尺寸偏离软404基线；403 可选一次绕过重试；
// 子域名 = DNS 可解析；WebShell = 200 且正文非空。
package modules

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// PageHit 一条路径探测命中（目录 / WebShell 共用行结构）。
type PageHit struct {
	URL    string `json:"url"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Title  string `json:"title"`
	Bypass string `json:"bypass,omitempty"` // 403 绕过成功的技术名（空 = 未绕过）
	// DirIndex 目录列表开启（命中响应含 IIS/Apache/Nginx 目录索引标记）。
	// 与「路径存在」是两种发现：列表页可下载源码/备份，是独立缺陷。
	DirIndex bool `json:"dir_index,omitempty"`
	// Via 命中来源：空 = 词表原生；否则为「爬取链接扩展」（带出触发它的页面），
	// 供证据链回链——避免"报了却不知道从哪来的"。
	Via string `json:"via,omitempty"`
}

// loadWords 字典加载：去空行 + 截取上限。
func loadWords(dir, name string, limit int) []string {
	if limit <= 0 {
		limit = 300
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// soft404Sizes 基线：探测随机不存在路径的响应尺寸集合。
func soft404Sizes(client *httpx.Client, baseURL string) map[int]bool {
	sizes := map[int]bool{}
	for _, p := range []string{"sl-nope-9f3a2", "sl-nope-81b7d?q=x"} {
		u := strings.TrimRight(baseURL, "/") + "/" + p
		if r, err := client.GetFollow(u); err == nil && r != nil {
			sizes[len(r.Body)] = true
		}
	}
	return sizes
}

// bypassMaxAttempts 单次扫描的绕过请求总量硬上限（无害化控量）。
const bypassMaxAttempts = 60

// bypassVariant 一条 403 绕过变体。只读无害红线：仅发 GET/HEAD/OPTIONS，
// 不发 PUT/POST/DELETE/TRACE 等写方法或回显方法。
type bypassVariant struct {
	kind   string // path / header / rewrite / method
	note   string // 命中后写入 PageHit.Bypass
	url    string
	header map[string]string
	method string
	seg    string // 路径段关键词（rewrite 类判正文用）
}

// buildBypassVariants 生成全部绕过变体：
//   - path：尾斜杠 / 点段 / 双斜杠 / ..;/ 容器路径混淆 / 尾空格 / 尾点编码
//   - header：伪造内网来源、代理头、Referer（对原 URL 重放）
//   - rewrite：请求根路径 + X-Original-URL / X-Rewrite-URL 指向目标路径
//   - method：HEAD / OPTIONS（只读方法）
func buildBypassVariants(u, path, baseURL string, rootSize int) []bypassVariant {
	var vs []bypassVariant
	for _, suf := range []string{"/", "/.", "//", "/..;/", "%20", "%2e"} {
		vs = append(vs, bypassVariant{kind: "path", note: "path:" + suf, url: u + suf})
	}
	for _, h := range []struct{ k, v string }{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Forwarded-Host", "localhost"},
		{"Client-IP", "127.0.0.1"},
		{"X-Custom-IP-Authorization", "127.0.0.1"},
		{"Referer", baseURL},
	} {
		vs = append(vs, bypassVariant{kind: "header", note: "header:" + h.k,
			url: u, header: map[string]string{h.k: h.v}})
	}
	seg := strings.Trim(strings.TrimLeft(path, "/"), "/")
	if seg != "" && rootSize > 0 {
		vs = append(vs, bypassVariant{kind: "rewrite", note: "rewrite:X-Original-URL",
			url: baseURL + "/", seg: seg, header: map[string]string{"X-Original-URL": "/" + seg}})
		vs = append(vs, bypassVariant{kind: "rewrite", note: "rewrite:X-Rewrite-URL",
			url: baseURL + "/", seg: seg, header: map[string]string{"X-Rewrite-URL": "/" + seg}})
	}
	vs = append(vs, bypassVariant{kind: "method", note: "method:HEAD", url: u, method: http.MethodHead})
	vs = append(vs, bypassVariant{kind: "method", note: "method:OPTIONS", url: u, method: http.MethodOptions})
	return vs
}

// bypassHit 判定一条绕过变体是否真绕过：
//   - path/header：目标 URL 返回 200、尺寸不在软 404 基线且异于根页
//     （catch-all 站点对任意路径都回根页——拿根页当绕过成功 = 误报）
//   - rewrite：根路径返回 200、正文含路径段关键词、尺寸异于根页和软 404 基线
//   - method：HEAD/OPTIONS 返回 200
func bypassHit(v bypassVariant, r *httpx.Response, rootSize int, baseline map[int]bool) bool {
	if r == nil {
		return false
	}
	switch v.kind {
	case "rewrite":
		return r.Status == 200 && len(r.Body) != rootSize && !baseline[len(r.Body)] &&
			strings.Contains(strings.ToLower(r.Body), strings.ToLower(v.seg))
	case "method":
		return r.Status == 200
	default:
		if r.Status != 200 || baseline[len(r.Body)] {
			return false
		}
		return rootSize <= 0 || len(r.Body) != rootSize
	}
}

// tryBypass403 对单个 403 URL 顺序尝试全部变体，返回首个命中响应与技术名。
// attempts 为跨命中共享的请求量计数（硬上限 bypassMaxAttempts）。
func tryBypass403(client *httpx.Client, u, path, baseURL string, rootSize int,
	baseline map[int]bool, attempts *int, cancel func() bool) (*httpx.Response, string) {
	for _, v := range buildBypassVariants(u, path, baseURL, rootSize) {
		if *attempts >= bypassMaxAttempts {
			return nil, ""
		}
		if cancel != nil && cancel() {
			return nil, ""
		}
		*attempts++
		var r *httpx.Response
		var err error
		if v.method == http.MethodHead || v.method == http.MethodOptions {
			r, err = client.MethodFollowWith(v.method, v.url, v.header)
		} else {
			r, err = client.GetFollowWith(v.url, v.header)
		}
		if err != nil || r == nil {
			continue
		}
		if bypassHit(v, r, rootSize, baseline) {
			return r, v.note
		}
	}
	return nil, ""
}

// serializedProgress 把并发进度回调串行化（B18）：本包内部持锁后再调
// 消费者，消费者无需自行保证线程安全——消除「谁调谁负责」的隐式契约。
// nil 进度返回 nil，保持调用侧 `if progress != nil` 的判空习惯。
func serializedProgress(f func(done, total int, msg string)) func(done, total int, msg string) {
	if f == nil {
		return nil
	}
	var mu sync.Mutex
	return func(done, total int, msg string) {
		mu.Lock()
		defer mu.Unlock()
		f(done, total, msg)
	}
}

// DirScan 目录探测：命中 = 200/401/403 且尺寸不在软404基线；
// 403 且 bypass 开启时按变体表做只读绕过尝试（路径变异/信任头/HEAD·OPTIONS），
// 命中的技术记入 PageHit.Bypass。
func DirScan(client *httpx.Client, baseURL string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []PageHit {
	return DirScanExtra(client, baseURL, cfg, nil, nil, progress, cancel)
}

// dirExtra 一条扩展探测目标（来源自爬取到的同域链接）。
type dirExtra struct {
	Path string // 站点根的相对路径（前导 /）
	Via  string // 带出它的页面（证据回链）
}

// DirScanExtra = DirScan + 爬取链接扩展。
//
// 词表探测是"猜路径"，猜不到的端点（自定义上传点 / 提交点 / SPA 路由）
// 整块漏掉——靶场实测 upload-labs 一关未命中：关卡文件名不在 1887 条
// 保守词表里（全量 full 词表 9633 条里有 upload.php，但默认档位只跑 300）。
// 爬取阶段已经抓到同域链接（含带参链接），把它们解析成站点根相对路径
// 补进候选集，请求量只增加「去掉词表重复后」的净增量，并记为 Via 溯源。
func DirScanExtra(client *httpx.Client, baseURL string, cfg config.ActiveConfig,
	extra []string, viaOf func(string) string,
	progress func(done, total int, msg string), cancel func() bool) []PageHit {
	words := loadWords(cfg.WordlistDir, "dir_default.txt", cfg.DirMaxPaths)
	if len(words) == 0 && len(extra) == 0 {
		return nil
	}
	// 词表归一：去前导斜杠，便于与扩展路径同口径去重
	normWords := make([]string, 0, len(words))
	inWords := map[string]bool{}
	for _, w := range words {
		w = strings.TrimLeft(strings.TrimSpace(w), "/")
		if w == "" || inWords[w] {
			continue
		}
		inWords[w] = true
		normWords = append(normWords, w)
	}
	words = normWords
	extraList := normalizeExtras(extra, viaOf, baseURL, inWords)
	base := strings.TrimRight(baseURL, "/")
	baseline := soft404Sizes(client, baseURL)
	// 根页基线尺寸：rewrite 类绕过需与根页区分（否则拿到的只是首页 = 误报）
	rootSize := 0
	if cfg.DirBypass403 {
		if rr, err := client.GetFollow(baseURL); err == nil && rr != nil {
			rootSize = len(rr.Body)
		}
	}
	attempts := 0
	hits := []PageHit{}

	// 候选集：词表（猜）+ 扩展（爬取到的真实端点）。扩展排在前面——
	// 它们已由爬取证明存在，命中率天然高于猜测路径，先把预算落在上面。
	type candidate struct {
		path string
		via  string
	}
	cands := make([]candidate, 0, len(words)+len(extraList))
	for _, e := range extraList {
		cands = append(cands, candidate{path: strings.TrimLeft(e.Path, "/"), via: e.Via})
	}
	for _, w := range words {
		cands = append(cands, candidate{path: strings.TrimLeft(w, "/")})
	}

	// 固定并发小池：目录探测是纯网络等待，逐条串行在 300 条词表上要等
	// 几十秒；并发 8 与模块其余部分的 worker 口径一致。写入仅主协程，
	// 子协程只投递结果到带缓冲通道。
	const dirWorkers = 8
	type dirResult struct {
		hit PageHit
		ok  bool
	}
	results := make(chan dirResult, len(cands))
	sem := make(chan struct{}, dirWorkers)
	var wg sync.WaitGroup
	for _, cd := range cands {
		if cancel != nil && cancel() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(cd candidate) {
			defer wg.Done()
			defer func() { <-sem }()
			u := base + "/" + cd.path
			r, err := client.GetFollow(u)
			if err != nil || r == nil {
				results <- dirResult{}
				return
			}
			status := r.Status
			bypassNote := ""
			if status == 403 && cfg.DirBypass403 {
				if r2, via := tryBypass403(client, u, "/"+cd.path,
					base, rootSize, baseline, &attempts, cancel); r2 != nil {
					status = r2.Status
					r = r2
					bypassNote = via
				}
			}
			if (status != 200 && status != 401 && status != 403) || baseline[len(r.Body)] {
				results <- dirResult{}
				return
			}
			results <- dirResult{ok: true, hit: PageHit{
				URL: u, Path: "/" + cd.path,
				Status: status, Size: len(r.Body),
				Title:    htmlx.Parse(r.Body).Title,
				Bypass:   bypassNote,
				DirIndex: dirIndexMark(r.Status, r.Body, r.Headers["Content-Type"]),
				Via:      cd.via,
			}}
		}(cd)
	}
	wg.Wait()
	close(results)
	done := 0
	for r := range results {
		if r.ok {
			hits = append(hits, r.hit)
		}
		done++
		if progress != nil {
			progress(done, len(cands), "")
		}
	}
	// 命中序稳定化：扩展来源优先，其余按路径字典序（并发完成序不可复现）
	sort.SliceStable(hits, func(i, j int) bool {
		if (hits[i].Via != "") != (hits[j].Via != "") {
			return hits[i].Via != ""
		}
		return hits[i].Path < hits[j].Path
	})
	return hits
}

// normalizeExtras 把爬取到的同域链接归一为「站点根相对路径」候选集。
// 规则：
//  1. 只收同域 http(s)，去 fragment/query（目录探测是路径级事实）；
//  2. 去掉站点根前缀，得到相对路径；
//  3. 已在词表内的丢弃（重复请求无新增信息），同路径只留首个来源；
//  4. 丢弃根路径本身与静态资源后缀（图片/样式/字体不是端点）；
//  5. 上限 200 条——扩展是补充不是替代，不挤占词表预算。
//
// viaOf 给出每条候选链接的来源页（可空判定，空则回落到站点根）。
// 带参链接由 DAST 负责探测，此处只取路径形态做端点存在性核查——
// 查的是「这个端点会不会直接吐源码/配置/备份」，与参数注入是两回事。
func normalizeExtras(extra []string, viaOf func(string) string,
	baseURL string, inWords map[string]bool) []dirExtra {
	if len(extra) == 0 {
		return nil
	}
	bu, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	rootPath := bu.Path
	if rootPath == "" {
		rootPath = "/"
	}
	if !strings.HasSuffix(rootPath, "/") {
		rootPath += "/"
	}
	out := make([]dirExtra, 0, 32)
	seen := map[string]bool{}
	for _, raw := range extra {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		if !strings.EqualFold(u.Scheme, bu.Scheme) || !strings.EqualFold(u.Host, bu.Host) {
			continue
		}
		pth := u.Path
		if !strings.HasPrefix(pth, rootPath) {
			continue // 站点根之外，目录探测（相对站点根拼路径）表达不了
		}
		pth = strings.TrimPrefix(pth, rootPath)
		pth = strings.Trim(pth, "/")
		if pth == "" || seen[pth] || inWords[pth] {
			continue
		}
		if staticAsset(pth) {
			continue
		}
		seen[pth] = true
		via := baseURL
		if viaOf != nil {
			if v := viaOf(raw); v != "" {
				via = v
			}
		}
		out = append(out, dirExtra{Path: "/" + pth, Via: via})
		if len(out) >= 200 {
			break
		}
	}
	return out
}

// staticAsset 静态资源后缀：不是可探测端点，扩展时跳过（词表里保留，
// 那是人工整理的路径，语义不同）。
func staticAsset(p string) bool {
	switch strings.ToLower(pathExt(p)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm",
		".mp3", ".pdf", ".gz", ".zip":
		return true
	}
	return false
}

// pathExt 取路径最后一段的扩展名（无点返回空）。
func pathExt(p string) string {
	last := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		last = p[i+1:]
	}
	if i := strings.Index(last, "."); i >= 0 {
		return last[i:]
	}
	return ""
}

// dirIndexPatterns 目录索引页标记（IIS / Apache 2.x / Nginx / Python
// SimpleHTTPServer / Node serve-index）。大小写不敏感。
var dirIndexPatterns = []string{
	"<title>index of /",
	"<h1>index of /",
	"parent directory</a>",
	"to parent directory</a>",
	"[to parent directory]",
	"directory listing for /",
}

// dirIndexMark 目录列表开启判定：响应为 200、HTML 形态、正文含索引标记，
// 且**响应体不是 SPA 外壳**（外壳也含 "index of" 类词的概率极低，但
// JSON/API 响应必须先排除——HTML 形态检查即为此）。
func dirIndexMark(status int, body, contentType string) bool {
	if status != 200 || body == "" {
		return false
	}
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "html") {
		return false
	}
	low := strings.ToLower(body)
	for _, p := range dirIndexPatterns {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// WebshellProbe WebShell 探测：命中 = 200 且正文非空（后台马常驻路径）。
func WebshellProbe(client *httpx.Client, baseURL string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []PageHit {
	words := loadWords(cfg.WordlistDir, "shell_default.txt", cfg.ShellMaxPaths)
	if len(words) == 0 {
		return nil
	}
	base := strings.TrimRight(baseURL, "/")
	// 软 404 基线：与 DirScan 同源——站点对不存在路径返回 200+内容时，
	// 未过滤会把每个探测路径都误报成 webshell（tools 站实测暴露）
	baseline := soft404Sizes(client, baseURL)
	hits := []PageHit{}
	for i, w := range words {
		if cancel != nil && cancel() {
			break
		}
		u := base + "/" + strings.TrimLeft(w, "/")
		r, err := client.GetFollow(u)
		if err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 && !baseline[len(r.Body)] {
			hits = append(hits, PageHit{
				URL: u, Path: "/" + strings.TrimLeft(w, "/"),
				Status: 200, Size: len(r.Body),
			})
		}
		if progress != nil {
			progress(i+1, len(words), w)
		}
	}
	return hits
}

// Resolver 域名解析函数（可注入替身便于离线测试）。
type Resolver func(host string) ([]string, error)

// systemResolver 系统 DNS。
func systemResolver(host string) ([]string, error) { return net.LookupHost(host) }

// SubdomainEnum 子域名枚举：字典并发解析，可解析即视为存在。
func SubdomainEnum(domain string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []string {
	return SubdomainEnumWith(domain, cfg, progress, cancel, systemResolver)
}

// SubdomainEnumWith 可注入解析器的枚举实现。
func SubdomainEnumWith(domain string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool,
	resolve Resolver) []string {
	words := loadWords(cfg.WordlistDir, "subs_default.txt", cfg.SubMaxWords)
	if len(words) == 0 || domain == "" {
		return nil
	}
	progress = serializedProgress(progress) // B18：多 worker 并发调 progress
	workers := cfg.SubWorkers
	if workers <= 0 {
		workers = 20
	}
	var mu sync.Mutex
	found := []string{}
	idx := atomic.Int64{}
	var wg sync.WaitGroup
	total := len(words)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if cancel != nil && cancel() {
					return
				}
				i := int(idx.Add(1)) - 1
				if i >= total {
					return
				}
				sub := words[i] + "." + domain
				if addrs, err := resolve(sub); err == nil && len(addrs) > 0 {
					mu.Lock()
					found = append(found, sub)
					mu.Unlock()
				}
				if progress != nil {
					progress(i+1, total, words[i])
				}
			}
		}()
	}
	wg.Wait()
	return found
}

// FormatHits 汇总行文本（进度消息用）。
func FormatHit(h PageHit) string {
	return fmt.Sprintf("%s -> %d (%dB)", h.Path, h.Status, h.Size)
}

// FPHit FingerDir 主动指纹命中。
type FPHit struct {
	Product string `json:"product"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

// ActiveFP FingerDir 主动路径指纹：对精编 spec 路径逐个探测，
// status/body_contains/body_not_contains/content_type/header_contains
// 声明的条件全命中才算（对齐 Python _spec_match）。maxRequests 为请求上限。
func ActiveFP(client *httpx.Client, baseURL string,
	rows []intel.FingerDirRow, progress func(done, total int, msg string),
	cancel func() bool, maxRequests int) []FPHit {
	if maxRequests <= 0 {
		maxRequests = 30
	}
	base := strings.TrimRight(baseURL, "/")
	total := 0
	for _, r := range rows {
		total += len(r.Spec.Paths)
	}
	if total > maxRequests {
		total = maxRequests
	}
	done := 0
	hits := []FPHit{}
	for _, row := range rows {
		for _, p := range row.Spec.Paths {
			if done >= maxRequests {
				return hits
			}
			if cancel != nil && cancel() {
				return hits
			}
			u := base + p
			r, err := client.GetDirect(u)
			done++
			if err == nil && r != nil && specMatch(r, row.Spec) {
				hits = append(hits, FPHit{Product: row.Product, Path: p, Status: r.Status})
			}
			if progress != nil {
				progress(done, total, row.Product)
			}
		}
	}
	return hits
}

// specMatch 全部声明条件均须满足。
func specMatch(r *httpx.Response, spec intel.FingerDirMatchSpec) bool {
	if len(spec.Status) > 0 {
		okStatus := false
		for _, s := range spec.Status {
			if r.Status == s {
				okStatus = true
				break
			}
		}
		if !okStatus {
			return false
		}
	}
	low := strings.ToLower(r.Body)
	for _, kw := range spec.BodyContains {
		if !strings.Contains(low, strings.ToLower(kw)) {
			return false
		}
	}
	for _, kw := range spec.BodyNotContains {
		if strings.Contains(low, strings.ToLower(kw)) {
			return false
		}
	}
	ct := ""
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
			break
		}
	}
	for _, kw := range spec.ContentType {
		if !strings.Contains(strings.ToLower(ct), strings.ToLower(kw)) {
			return false
		}
	}
	for _, kw := range spec.HeaderContains {
		found := false
		for k, v := range r.Headers {
			if strings.Contains(strings.ToLower(k+"="+v), strings.ToLower(kw)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
