// Package modules 主动探测模块：目录探测 / 子域名枚举 / WebShell 探测。
// 默认关闭；请求总量有硬上限（config.ActiveConfig），目标合规责任在使用者。
// 判定语义对齐 python 分支 scanner/modules.py：
// 目录命中 = 200/401/403 且尺寸偏离软404基线；403 可选一次绕过重试；
// 子域名 = DNS 可解析；WebShell = 200 且正文非空。
package modules

import (
	"crypto/sha256"
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
	// ContentType / BodySHA256：命中响应的内容类型与正文哈希（证据留痕）。
	// 5.2.3 起用于区分「真文件」与「WAF/兜底 200 页」：报告只写
	// "HTTP 200 · 988B" 无法自证，带上这两项才能复核是不是同一个兜底页。
	ContentType string `json:"content_type,omitempty"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	// LowConfidence 无法确证（B2-01）：敏感文件形态路径返回 200 且正文既非
	// HTML、无拦截特征、无归档魔数、也非 JSON 错误信封——既不能证明是兜底页，
	// 也没有"确为真实文件"的正向证据。这类命中保留（漏报同样有代价），但标记
	// 为低置信，报告侧应单列/降级展示。
	LowConfidence bool `json:"low_confidence,omitempty"`
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

// soft404ProbePaths 软 404 基线探测路径：普通随机名 + 敏感文件形态随机名。
//
// 5.2.3 误报修复（EdgeOne 站点实测）：WAF/兜底页常只对「敏感形态路径」返回
// 200（纯随机名照常 404），只用随机名做基线拿不到它的尺寸/正文，于是 25 个
// 配置/备份路径全被当成真实文件。必须用同形态路径探测。
var soft404ProbePaths = []string{
	"sl-nope-9f3a2",
	"sl-nope-81b7d?q=x",
	".sl-nope-9f3a2.yml",
	".sl-nope-81b7d.conf",
	".sl-nope-2c4e.env",
	"sl-nope-7d1f.zip",
	".sl-nope-5a6b.bak",
	".sl-nope-3e8c.crt",
}

// soft404Baseline 软 404 基线：响应尺寸集合 + 正文哈希集合。
// 尺寸挡「同一兜底页、长度随路径微变」；哈希挡「逐字节相同的 catch-all 页」。
type soft404Baseline struct {
	sizes  map[int]bool
	hashes map[string]bool
}

// baselineSizeTolerance 尺寸容差上限（B2-01）：兜底页常回显请求路径/时间戳/
// RequestID，长度随请求微变（差值 ≈ 路径长度差），精确相等会漏掉这类，容差
// 窗口内判兜底。窗口按基线尺寸的 5% 计算并夹在 [8,128] 字节；**小页面（<128B）
// 不给容差**——否则 48 字节的绝对容差会把"denied"这类小响应附近的真实小文件
// 全部吞掉（回归测试实测）。
const baselineSizeTolerance = 128

func baselineSizeWindow(base int) int {
	if base < 128 {
		return 0 // 小响应：精确匹配，容差只会制造漏报
	}
	win := base / 20 // 5%
	if win < 8 {
		win = 8
	}
	if win > baselineSizeTolerance {
		win = baselineSizeTolerance
	}
	return win
}

// sizeMatches 候选响应尺寸是否落在基线尺寸的容差窗口内（B2-01）。
// 空基线返回 false（无基线时不能凭尺寸否定命中）。
func (b soft404Baseline) sizeMatches(n int) bool {
	for s := range b.sizes {
		d := n - s
		if d < 0 {
			d = -d
		}
		if d <= baselineSizeWindow(s) {
			return true
		}
	}
	return false
}

// hits 命中判定：尺寸容差窗口内 或 正文逐字节相同（B2-01 统一入口）。
func (b soft404Baseline) hits(size int, body string) bool {
	return b.sizeMatches(size) || b.hashes[bodyDigest(body)]
}

// soft404BaselineOf 探测基线路径，返回尺寸与正文哈希集合。
func soft404BaselineOf(client *httpx.Client, baseURL string) soft404Baseline {
	b := soft404Baseline{sizes: map[int]bool{}, hashes: map[string]bool{}}
	base := strings.TrimRight(baseURL, "/")
	for _, p := range soft404ProbePaths {
		r, err := client.GetFollow(base + "/" + p)
		if err != nil || r == nil {
			continue
		}
		b.sizes[len(r.Body)] = true
		b.hashes[bodyDigest(r.Body)] = true
	}
	return b
}

// bodyDigest 正文 sha256 十六进制（识别「同一兜底页」）。
func bodyDigest(body string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
}

// SensitiveSuffix 路径后缀是否为「本不该被直接读取」的配置/备份/归档形态。
// 脚本端点（.php/.asp/...）返回 false：正常可达，是否存在缺陷要靠内容判定。
// 与 engine.dirFindingOf 的分类口径同源（引擎侧直接调用本函数，避免两处维护）。
func SensitiveSuffix(p string) bool {
	low := strings.ToLower(p)
	dot := strings.LastIndex(low, ".")
	if dot < 0 {
		return false
	}
	switch low[dot:] {
	case ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
		".sql", ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".gz",
		".conf", ".config", ".ini", ".yml", ".yaml", ".env", ".log",
		".key", ".pem", ".crt", ".p12", ".jks":
		return true
	}
	return false
}

// isHTMLResponse 响应是否 HTML 形态：Content-Type 优先，缺失时看正文开头。
func isHTMLResponse(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") ||
		strings.HasPrefix(head, "<head") || strings.HasPrefix(head, "<body")
}

// archiveMagicOK 归档类后缀的正文魔数校验（防 JSON/纯文本拦截页冒充文件）。
// 无魔数定义的后缀返回 true（HTML 冒充已由 isHTMLResponse 拦掉）。
func archiveMagicOK(path, body string) bool {
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".zip"):
		return strings.HasPrefix(body, "PK")
	case strings.HasSuffix(low, ".7z"):
		return strings.HasPrefix(body, "7z\xbc\xaf\x27\x1c")
	case strings.HasSuffix(low, ".rar"):
		return strings.HasPrefix(body, "Rar!")
	case strings.HasSuffix(low, ".gz"), strings.HasSuffix(low, ".tgz"):
		return strings.HasPrefix(body, "\x1f\x8b")
	case strings.HasSuffix(low, ".tar"):
		return len(body) > 262 && body[257:262] == "ustar"
	}
	return true
}

// blockPageMarkers WAF/拦截/挑战页正文特征（小写匹配；仅用于敏感文件形态
// 路径，避免误伤正常页面）。
var blockPageMarkers = []string{
	"请求被拦截", "访问被拒绝", "访问被拦截", "安全策略", "人机验证", "滑动验证",
	"验证码", "challenge-platform", "cf-chl", "just a moment", "captcha",
	"access denied", "request blocked", "requestid", "request id", "edgeone",
}

// looksGenericPage 200 响应是否为「通用兜底/拦截页」而非真实资源。
//
// 判定（任一命中即视为兜底，不产生目录/端点发现）：
//  1. 客户端已判 WAF/限流拦截（httpx.Response.Blocked）；
//  2. 正文与软 404 基线某次探测逐字节相同（catch-all 200）；
//  3. 尺寸落在软 404 基线尺寸的容差窗口内（B2-01：兜底页回显请求路径/时间戳，
//     长度随请求微变，逐字节比对抓不到）；
//  4. 敏感文件形态路径：正文回显了请求路径本身（模板化 404 页的强特征，B2-01）；
//  5. 敏感文件形态路径返回 HTML 正文、JSON/数组错误信封或拦截页特征
//     （真实 yml/zip/env 不会是 HTML，也不会以 `{`/`[` 开头）；
//  6. 归档后缀但正文魔数不符（JSON/纯文本拦截页冒充 zip）。
//
// 非敏感路径（普通入口页/目录）不受 4/5/6 影响——目录索引页本身是 HTML。
func looksGenericPage(path string, r *httpx.Response, base soft404Baseline) bool {
	if r == nil || r.Blocked {
		return true
	}
	if base.hashes[bodyDigest(r.Body)] {
		return true
	}
	// B2-01：尺寸容差窗口（此前只做精确集合查询，注释宣称的"尺寸挡长度微变"
	// 从未实现——回显路径的兜底页长度与基线差几个字节就漏过去了）。
	if base.sizeMatches(len(r.Body)) {
		return true
	}
	if !SensitiveSuffix(path) {
		return false
	}
	ct := ""
	if r.Headers != nil {
		ct = r.Headers["Content-Type"]
	}
	if isHTMLResponse(ct, r.Body) {
		return true
	}
	// B2-01：模板化兜底页常把请求路径原样回显在正文里（404 页/错误信封）。
	if echoesRequestPath(r.Body, path) {
		return true
	}
	if looksLikeErrorEnvelope(r.Body) {
		return true
	}
	low := strings.ToLower(r.Body)
	for _, m := range blockPageMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return !archiveMagicOK(path, r.Body)
}

// echoesRequestPath 正文是否回显了请求路径（B2-01）。
//
// 兜底页模板化时会带上被请求的路径（"/xxx.yml 不存在"、{"path":"/xxx.yml"}），
// 而真实配置文件/备份文件不会在自己的正文里出现自己的 URL 路径。
// 同时匹配带前导斜杠与去掉斜杠两种形态，路径需有一定长度（避免 "/a" 类短路径
// 在正文里到处撞上）。
func echoesRequestPath(body, path string) bool {
	if len(body) == 0 || len(path) < 3 {
		return false
	}
	lowBody := strings.ToLower(body)
	lowPath := strings.ToLower(strings.TrimSpace(path))
	if strings.Contains(lowBody, lowPath) {
		return true
	}
	trimmed := strings.TrimPrefix(lowPath, "/")
	return len(trimmed) >= 3 && strings.Contains(lowBody, trimmed)
}

// looksLikeErrorEnvelope 正文是否为 JSON/数组形态的错误信封（B2-01）。
//
// 真实 `.env`/`.yml`/`.conf`/`.sql`/`.bak` 不会以 `{` 或 `[` 开头；而 WAF/边缘
// 节点的 200 兜底响应常是 `{"code":404,...}` / `[{"error":...}]`。只对敏感后缀
// 调用，普通 HTML/JSON 接口不受影响。
func looksLikeErrorEnvelope(body string) bool {
	s := strings.TrimSpace(body)
	if s == "" {
		return false
	}
	return s[0] == '{' || s[0] == '['
}

// sensitiveContentUnverified 敏感后缀 200 命中是否"无法确证"（B2-01 降级依据）。
// 走到这里说明 looksGenericPage 已排除兜底/拦截页；若正文也没有可核验的形态
// 证据（无归档魔数可验、非 HTML），就只能标低置信而不是断言"确为真实文件"。
func sensitiveContentUnverified(path string, r *httpx.Response) bool {
	if r == nil || !SensitiveSuffix(path) {
		return false
	}
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".zip"), strings.HasSuffix(low, ".7z"),
		strings.HasSuffix(low, ".rar"), strings.HasSuffix(low, ".gz"),
		strings.HasSuffix(low, ".tgz"), strings.HasSuffix(low, ".tar"):
		return false // 有魔数可验，已由 archiveMagicOK 把关
	}
	return true
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
//   - path/header：目标 URL 返回 200、正文非空、尺寸不在软 404 基线容差窗口且
//     异于根页（catch-all 站点对任意路径都回根页——拿根页当绕过成功 = 误报）
//   - rewrite：根路径返回 200、正文含路径段关键词、尺寸异于根页和软 404 基线
//   - method：HEAD/OPTIONS 返回 200 只算"方法被放行"的线索（B2-03）：
//     HEAD/OPTIONS 无正文，不能作为绕过成功的证据，调用方必须再用 GET 确认内容。
func bypassHit(v bypassVariant, r *httpx.Response, rootSize int, base soft404Baseline) bool {
	if r == nil || r.Blocked {
		return false
	}
	switch v.kind {
	case "rewrite":
		return r.Status == 200 && len(r.Body) != rootSize &&
			!base.hits(len(r.Body), r.Body) &&
			strings.Contains(strings.ToLower(r.Body), strings.ToLower(v.seg))
	case "method":
		return r.Status == 200
	default:
		return bypassContentHit(r, rootSize, base)
	}
}

// bypassContentHit 绕过命中所需的"内容证据"（B2-03）：200 + 非空正文 + 尺寸不在
// 软 404 基线容差窗口 + 异于根页。HEAD/OPTIONS 的 200 必须靠这一步的 GET 复核。
func bypassContentHit(r *httpx.Response, rootSize int, base soft404Baseline) bool {
	if r == nil || r.Blocked || r.Status != 200 || len(r.Body) == 0 {
		return false
	}
	if base.hits(len(r.Body), r.Body) {
		return false
	}
	return rootSize <= 0 || len(r.Body) != rootSize
}

// tryBypass403 对单个 403 URL 顺序尝试全部变体，返回首个命中响应与技术名。
// attempts 为跨命中共享的请求量计数（硬上限 bypassMaxAttempts）；多 worker
// 并发调用，必须是原子的（B2-02：此前是裸 *int 自增，数据竞争且上限可被击穿）。
func tryBypass403(client *httpx.Client, u, path, baseURL string, rootSize int,
	baseline soft404Baseline, attempts *atomic.Int64, cancel func() bool) (*httpx.Response, string) {
	for _, v := range buildBypassVariants(u, path, baseURL, rootSize) {
		// B2-02：先占号再发请求，超过硬上限即回滚并停止——8 worker 并发下
		// 也不能超发（裸 *int 自增既有数据竞争，又会让 60 次上限失效）。
		if attempts.Add(1) > int64(bypassMaxAttempts) {
			attempts.Add(-1)
			return nil, ""
		}
		if cancel != nil && cancel() {
			return nil, ""
		}
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
		if !bypassHit(v, r, rootSize, baseline) {
			continue
		}
		// B2-03：HEAD/OPTIONS 200 不构成"能读到受保护内容"的证据，再用 GET 复核
		// 内容；命中响应取 GET 的（报告证据可复核、且 status/正文自洽）。
		if v.method != "" {
			if attempts.Add(1) > int64(bypassMaxAttempts) {
				attempts.Add(-1)
				return nil, ""
			}
			gr, gerr := client.GetFollowWith(v.url, v.header)
			if gerr != nil || gr == nil || !bypassContentHit(gr, rootSize, baseline) {
				continue
			}
			return gr, v.note
		}
		return r, v.note
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
	baseline := soft404BaselineOf(client, baseURL)
	// 根页基线尺寸：rewrite 类绕过需与根页区分（否则拿到的只是首页 = 误报）
	rootSize := 0
	if cfg.DirBypass403 {
		if rr, err := client.GetFollow(baseURL); err == nil && rr != nil {
			rootSize = len(rr.Body)
		}
	}
	// attempts 跨 8 个 worker 共享，必须原子（B2-02）。
	var attempts atomic.Int64
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
			// B2-01：基线命中改用"尺寸容差窗口 + 正文 hash"统一入口，
			// 兜底页回显路径导致长度微变时也能拦住。
			if r.Blocked || (status != 200 && status != 401 && status != 403) ||
				baseline.hits(len(r.Body), r.Body) {
				results <- dirResult{}
				return
			}
			// 200 响应再做「真文件 vs 兜底/拦截页」判定；401/403 只承载存在性
			// 与绕过语义（HTML 403 页是常态），不在此过滤。
			if status == 200 && looksGenericPage("/"+cd.path, r, baseline) {
				results <- dirResult{}
				return
			}
			// B2-01：敏感后缀且无任何可核验内容形态证据（非 HTML/非 JSON 信封/
			// 无归档魔数）时，不能断言"确为真实文件"→ 标低置信（仍上报，供人工复核）。
			lowConf := status == 200 && sensitiveContentUnverified("/"+cd.path, r)
			results <- dirResult{ok: true, hit: PageHit{
				URL: u, Path: "/" + cd.path,
				Status: status, Size: len(r.Body),
				Title:         htmlx.Parse(r.Body).Title,
				Bypass:        bypassNote,
				DirIndex:      dirIndexMark(r.Status, r.Body, r.Headers["Content-Type"]),
				Via:           cd.via,
				ContentType:   r.Headers["Content-Type"],
				BodySHA256:    bodyDigest(r.Body),
				LowConfidence: lowConf,
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
	baseline := soft404BaselineOf(client, baseURL)
	hits := []PageHit{}
	for i, w := range words {
		if cancel != nil && cancel() {
			break
		}
		u := base + "/" + strings.TrimLeft(w, "/")
		r, err := client.GetFollow(u)
		if err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 &&
			!r.Blocked && !baseline.hits(len(r.Body), r.Body) {
			ct := ""
			if r.Headers != nil {
				ct = r.Headers["Content-Type"]
			}
			hits = append(hits, PageHit{
				URL: u, Path: "/" + strings.TrimLeft(w, "/"),
				Status: 200, Size: len(r.Body),
				ContentType: ct, BodySHA256: bodyDigest(r.Body),
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
