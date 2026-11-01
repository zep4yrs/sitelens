// 上传绕过验证通道：对文件上传表单做「扩展名/内容类型黑名单绕过」判定，
// 而不是只报「存在上传受理面」。
//
// 为什么需要这条通道：upload-surface 只证明「服务端收下了无害 .txt」，
// 这是一句没有攻击含义的话——任何正常上传功能都这样。真正的漏洞形态是
// 「服务端收下了本该拒绝的可执行扩展名」。upload-labs 全部 21 关考的都是
// 这个，此前引擎整块进不来。
//
// 判定语义（非破坏性，只做「受理/拒绝」二值判定）：
//  1. 先建立基线：无害扩展名（.jpg）提交，必须被受理——否则该表单不可用，
//     整表放弃（避免把「拒绝一切」的静态网关当作绕过）。
//  2. 逐个提交危险扩展名（同一份无害文本内容），出现受理信号即判定
//     黑名单未覆盖该扩展名 —— 「扩展名黑名单绕过」。
//  3. 内容类型绕过：危险扩展名 + 伪造 image/png Content-Type 组合被受理。
//  4. 双扩展名 / 尾随字符形态：.php.jpg、.php%00.jpg、.php::$DATA、.phtml 等。
//
// 提交内容始终是唯一标记的无害文本，不含任何可执行代码；判定只看服务端
// 「收没收」，不落地文件、不尝试执行。误报防线：拒绝特征优先于受理特征。
package dast

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// uploadBypassExts 危险扩展名候选（对应常见黑名单遗漏项）。
// 顺序即提交顺序：先最经典的 .php，再各类同义/别名/容器变体。
var uploadBypassExts = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phar",
	".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cer", ".asa", ".cdx",
	".shtml", ".shtm", ".htaccess", ".svg", ".hta",
}

// uploadBypassCt 内容类型伪造候选（服务端只查 Content-Type 时常绕过）。
const uploadBypassCt = "image/png"

// uploadBypassSuffixes 双扩展名 / 截断 / 尾随形态。
var uploadBypassSuffixes = []string{
	".php.jpg", ".php.png", ".php%00.jpg", ".php\x00.jpg", ".php::$DATA",
	".php.", ".php%20", ".pHp", ".PHP", ".phtml.jpg",
}

// uploadBypassProbe 单表单的上传绕过验证。返回命中列表（可能多条）。
func (r *Runner) uploadBypassProbe(ft FormTarget, fileField string, extra map[string]string) []Finding {
	if fileField == "" || r.stopped() {
		return nil
	}
	// 基线：无害扩展名。不被受理 → 该表单不是可用的上传点（或网关全拒），放弃。
	base := r.fetch.PostMultipartSmall(ft.Action, fileField, "sl_base.jpg", uploadProbeMarker, extra)
	if base == nil || !uploadAccepted(base) {
		return nil
	}

	var out []Finding
	seen := map[string]bool{}
	attempt := func(fname, ct, kind, why string) {
		key := fname + "\x00" + ct
		if r.stopped() || seen[key] {
			return
		}
		seen[key] = true
		ctf, ok := r.fetch.(MultipartCTFetcher)
		if !ok {
			return // 不支持自定义 Content-Type 的上传：跳过，不误报
		}
		resp := ctf.PostMultipartSmallCT(ft.Action, fileField, fname, uploadProbeMarker, ct, extra)
		if resp == nil || !uploadAccepted(resp) {
			return
		}
		f := Finding{
			Check: "upload-bypass", Title: "文件上传扩展名/类型绕过（" + kind + "）",
			Severity: "high", URL: ft.Action, Param: fileField, Payload: fname,
			Evidence: "基线 .jpg 被受理；提交 " + fname + "（Content-Type: " + ct +
				"）同样被受理 —— " + why + "。判定依据：" + uploadAcceptReason(resp) +
				"；提交内容为无害文本标记，未含可执行代码。",
			Advice: "扩展名白名单化（服务端解析结果为准，非文件名后缀）+ 内容魔数校验 + " +
				"落盘目录禁用脚本执行（php-fpm/cgi 隔离）+ 文件名归一化（去 %00 / ::$DATA / 多扩展名）。",
			Impact: "可上传服务端可解析的脚本文件，进而获得命令执行能力。",
		}
		f.Request = "POST " + ft.Action + " HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n" +
			"(文件字段 " + fileField + " = " + fname + ", " + ct + "，内容为无害探针标记)"
		f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
		f.Signals = []string{"基线受理：.jpg", "绕过受理：" + fname, "判定信号：" + uploadAcceptReason(resp)}
		if r.opts.OnHit != nil {
			r.opts.OnHit(f)
		}
		out = append(out, f)
	}

	cap := r.opts.MaxProbesPerClass
	if cap <= 0 {
		cap = 12
	}
	n := 0
	// 1) 危险扩展名 + 伪造图片 Content-Type（只查 MIME 的目标）——
	// 先跑，因为它是命中率最高、成本最低的一条。
	if n < cap {
		attempt("sl_probe.php", uploadBypassCt, "仅校验 Content-Type",
			"危险扩展名配伪造 image/png 类型未被拒绝")
		n++
	}
	// 2) 危险扩展名原样提交（黑名单遗漏）。
	for _, ext := range uploadBypassExts {
		if n >= cap {
			break
		}
		attempt("sl_probe"+ext, "application/octet-stream", "扩展名黑名单未覆盖",
			"危险扩展名 "+ext+" 未被拒绝")
		n++
	}
	// 3) 双扩展名 / 截断 / 大小写形态。
	for _, sfx := range uploadBypassSuffixes {
		if n >= cap {
			break
		}
		attempt("sl_probe"+sfx, "application/octet-stream", "文件名归一化缺失",
			"变体文件名 "+sfx+" 未被拒绝")
		n++
	}
	return out
}

// uploadAccepted 上传被受理判定（拒绝特征优先）。
func uploadAccepted(resp *Resp) bool {
	return uploadAcceptReason(resp) != ""
}

// uploadAcceptReason 返回受理信号说明（空串 = 未受理）。
func uploadAcceptReason(resp *Resp) string {
	if resp == nil {
		return ""
	}
	low := strings.ToLower(resp.Body)
	for _, m := range uploadRejectMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return ""
		}
	}
	for _, m := range uploadAcceptMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return "命中受理特征 " + m
		}
	}
	if strings.Contains(resp.Body, uploadProbeMarker) {
		return "响应回显上传文件内容标记"
	}
	return ""
}

// ============================================================================
// G10 上传绕过检测原语（独立于上面的 Runner 表单通道，供上层显式调用）
//
// 用途：给定「上传 endpoint + 文件字段名」，生成候选文件名/扩展名/
// Content-Type 组合，逐个 multipart 上传，按响应判断「受理 / 可访问 /
// 疑似被解析」，输出 Finding（绕过类型 + 证据 + 复现 curl）。
//
// 安全边界：
//   - 上传内容始终是唯一标记的**无害文本**（魔数候选只是 GIF89a 前缀 +
//     文本；.htaccess 候选只有注释行），不含任何脚本/可执行代码；
//   - 不落盘：内容只在内存里构造，直接进 multipart body；
//   - 默认 dry-run（只出计划、零请求）；真正执行需显式 DryRun=false 并注入
//     Poster；
//   - 只读验证：上传后仅 GET 响应里给出的 URL 判断可访问性，不做写操作。
//
// 判定诚实性：纯文本载荷无法区分「脚本被执行」与「静态文件被原样返回」，
// Parsed 只是启发式（脚本扩展名 + 访问返回 text/html + 回显标记），报告中
// 措辞为「疑似被解析」，不据此断言 RCE。
// ============================================================================

// UploadKind 上传绕过类型。
type UploadKind string

const (
	UploadKindBaseline    UploadKind = "baseline"     // 无害基线（确认表单可用）
	UploadKindExt         UploadKind = "ext"          // 危险扩展名黑名单未覆盖
	UploadKindDoubleExt   UploadKind = "double_ext"   // 双扩展名归一化缺失
	UploadKindCase        UploadKind = "case"         // 扩展名大小写过滤缺失
	UploadKindNullByte    UploadKind = "null_byte"    // %00 截断/解码差异
	UploadKindSemicolon   UploadKind = "semicolon"    // 分号路径参数/多扩展名
	UploadKindHtaccess    UploadKind = "htaccess"     // 上传 .htaccess 覆盖配置
	UploadKindMagicBytes  UploadKind = "magic_bytes"  // 魔数前缀伪造
	UploadKindContentType UploadKind = "content_type" // Content-Type 伪造
)

// G10MaxAttempts 单次上传绕过验证的硬上限（multipart 请求数，含基线）。
const G10MaxAttempts = 8

// G10MaxBodyBytes 单次响应读取上限（证据快照/只读验证用）。
const G10MaxBodyBytes = 64 << 10

// UploadCandidate 一个候选上传（纯数据，不落盘）。
type UploadCandidate struct {
	ID          string     `json:"id"`
	Kind        UploadKind `json:"kind"`
	FileName    string     `json:"file_name"`
	ContentType string     `json:"content_type"`
	Content     []byte     `json:"-"`
	Why         string     `json:"why"`
}

// UploadPlan dry-run 产物：完整候选列表 + 本次实际执行窗口（前 Cap 条）。
type UploadPlan struct {
	Endpoint   string            `json:"endpoint"`
	FieldName  string            `json:"field_name"`
	Token      string            `json:"token"`
	DryRun     bool              `json:"dry_run"`
	Cap        int               `json:"cap"`
	Candidates []UploadCandidate `json:"candidates"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Attempts 返回本次实际会执行的候选（前 Cap 条，含基线）。
func (p UploadPlan) Attempts() []UploadCandidate {
	n := p.Cap
	if n > len(p.Candidates) {
		n = len(p.Candidates)
	}
	if n < 0 {
		n = 0
	}
	return p.Candidates[:n]
}

// CurlFor 生成单个候选的复现命令：探针内容先写临时文件（无害文本），
// 再按与探测一致的 multipart 语义上传。命令可被直接复制执行（shellQuote 防注入）。
func (p UploadPlan) CurlFor(c UploadCandidate) string {
	form := p.FieldName + "=@/tmp/sl_probe_payload.bin;filename=\"" +
		strings.ReplaceAll(c.FileName, "\"", "%22") + "\";type=" + c.ContentType
	return "# 探针内容为无害文本，仅用于复现上传请求\n" +
		"printf %s " + shellQuote(string(c.Content)) + " > /tmp/sl_probe_payload.bin && " +
		"curl -sk -X POST " + shellQuote(p.Endpoint) + " -F " + shellQuote(form)
}

// UploadHTTPResp 最小响应（Poster 返回；Body 已按上限截断）。
type UploadHTTPResp struct {
	Status int
	Header map[string]string
	Body   []byte
}

// HeaderGet 大小写不敏感取响应头。
func (r *UploadHTTPResp) HeaderGet(name string) string {
	if r == nil {
		return ""
	}
	for k, v := range r.Header {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// UploadPoster 上传/只读验证接口（可注入 fake；默认 HTTPUploader）。
type UploadPoster interface {
	PostMultipart(rawURL, field, fileName, contentType string, content []byte, extra map[string]string) *UploadHTTPResp
	Get(rawURL string) *UploadHTTPResp
}

// HTTPUploader 默认实现：net/http，内存 multipart，不跟随重定向（保留 30x 观察）。
type HTTPUploader struct {
	Client *http.Client
}

// NewHTTPUploader 构造默认上传器；client 为 nil 时用 15s 超时、不跟随重定向的客户端。
func NewHTTPUploader(client *http.Client) *HTTPUploader {
	if client == nil {
		client = newDefaultUploadClient()
	}
	return &HTTPUploader{Client: client}
}

func newDefaultUploadClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// PostMultipart 发送内存中的 multipart 上传（不落盘）。
func (u *HTTPUploader) PostMultipart(rawURL, field, fileName, contentType string, content []byte, extra map[string]string) *UploadHTTPResp {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 字段顺序确定，复现/测试可预期
	for _, k := range keys {
		_ = w.WriteField(k, extra[k])
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="`+g10HeaderSafe(field)+
		`"; filename="`+g10HeaderSafe(fileName)+`"`)
	h.Set("Content-Type", g10HeaderSafe(contentType))
	part, err := w.CreatePart(h)
	if err != nil {
		return nil
	}
	if _, err := part.Write(content); err != nil {
		return nil
	}
	if err := w.Close(); err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, &buf)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	return u.do(req)
}

// Get 只读验证请求。
func (u *HTTPUploader) Get(rawURL string) *UploadHTTPResp {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	return u.do(req)
}

func (u *HTTPUploader) do(req *http.Request) *UploadHTTPResp {
	client := u.Client
	if client == nil {
		client = newDefaultUploadClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, G10MaxBodyBytes))
	hdr := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		hdr[k] = resp.Header.Get(k)
	}
	return &UploadHTTPResp{Status: resp.StatusCode, Header: hdr, Body: body}
}

// UploadBypassOptions 执行参数。
type UploadBypassOptions struct {
	Endpoint    string              // 上传 endpoint（表单 action 或接口 URL）
	FieldName   string              // 文件字段名
	MaxAttempts int                 // 实际请求上限；0/超限按 G10MaxAttempts
	DryRun      *bool               // nil = true（默认只出计划）
	Token       string              // 可选；缺省随机（测试固定用）
	ExtraFields map[string]string   // 额外表单字段（CSRF/一次性 token 等）
	Poster      UploadPoster        // 非 dry-run 必填
	VerifyURL   func(string) string // 可选：按文件名构造访问 URL（缺省从响应里提取）
	Kinds       []UploadKind        // 可选：只保留指定绕过类型（基线始终保留）
}

// UploadAttemptResult 单次尝试结果（含被拒绝的尝试，便于证据链复核）。
type UploadAttemptResult struct {
	Candidate  UploadCandidate `json:"candidate"`
	Status     int             `json:"status"`
	Accepted   bool            `json:"accepted"`
	Accessible bool            `json:"accessible"`
	Parsed     bool            `json:"parsed"`
	URL        string          `json:"url,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Response   *RespSnap       `json:"response,omitempty"`
	Curl       string          `json:"curl,omitempty"`
}

// UploadBypassResult 一次验证的完整结果。
type UploadBypassResult struct {
	Plan             UploadPlan            `json:"plan"`
	BaselineAccepted bool                  `json:"baseline_accepted"`
	Attempts         []UploadAttemptResult `json:"attempts,omitempty"`
	Findings         []Finding             `json:"findings,omitempty"`
}

// BuildUploadPlan 纯函数：生成候选计划（不发起任何请求）。
func BuildUploadPlan(opts UploadBypassOptions) UploadPlan {
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = randToken()
	}
	marker := g10Marker(token)
	plan := UploadPlan{
		Endpoint:  opts.Endpoint,
		FieldName: opts.FieldName,
		Token:     token,
		DryRun:    g10DryRun(opts.DryRun),
		Cap:       g10Cap(opts.MaxAttempts),
		Extra:     opts.ExtraFields,
	}
	want := map[UploadKind]bool{}
	for _, k := range opts.Kinds {
		want[k] = true
	}
	add := func(kind UploadKind, fname, ct string, content []byte, why string) {
		if len(want) > 0 && kind != UploadKindBaseline && !want[kind] {
			return
		}
		plan.Candidates = append(plan.Candidates, UploadCandidate{
			ID:          string(kind) + "-" + strconv.Itoa(len(plan.Candidates)+1),
			Kind:        kind,
			FileName:    fname,
			ContentType: ct,
			Content:     content,
			Why:         why,
		})
	}
	base := []byte(marker)
	// 1) 基线：无害图片扩展名。不被受理说明表单不可用/网关全拒，整表放弃。
	add(UploadKindBaseline, "sl_probe_"+token+".jpg", "image/jpeg", base,
		"无害基线：确认上传表单可用")
	// 2) Content-Type 伪造：危险扩展名 + image/png（只查 MIME 的目标）。
	add(UploadKindContentType, "sl_probe_"+token+".php", "image/png", base,
		"只校验 Content-Type 的目标可绕过")
	// 3) 危险扩展名原样（黑名单遗漏）。
	for _, ext := range []string{".php", ".phtml", ".jsp", ".aspx"} {
		add(UploadKindExt, "sl_probe_"+token+ext, "application/octet-stream", base,
			"扩展名黑名单未覆盖 "+ext)
	}
	// 4) 双扩展名。
	add(UploadKindDoubleExt, "sl_probe_"+token+".php.jpg", "application/octet-stream", base,
		"双扩展名归一化缺失（取首段/末段不一致）")
	// 5) 大小写。
	add(UploadKindCase, "sl_probe_"+token+".PhP", "application/octet-stream", base,
		"扩展名大小写过滤缺失")
	// 6) %00 截断（编码形态：不在 HTTP 头里放原始 NUL，避免请求非法）。
	add(UploadKindNullByte, "sl_probe_"+token+".php%00.jpg", "application/octet-stream", base,
		"%00 截断/解码差异")
	// 7) 分号路径参数（IIS/PHP path-info 解析差异）。
	add(UploadKindSemicolon, "sl_probe_"+token+".php;.jpg", "application/octet-stream", base,
		"分号路径参数/多扩展名解析差异")
	// 8) .htaccess 覆盖（内容仅注释，不写任何指令）。
	add(UploadKindHtaccess, ".htaccess", "application/octet-stream",
		[]byte("# sitelens g10 upload probe "+token+" (comment only)\n"),
		"上传 .htaccess 覆盖服务器配置")
	// 9) 魔数伪造：GIF89a 前缀 + 危险扩展名（只查文件头的目标）。
	add(UploadKindMagicBytes, "sl_probe_"+token+".php", "application/octet-stream",
		append([]byte("GIF89a"), base...), "文件头魔数校验可被 GIF89a 前缀绕过")
	return plan
}

// RunUploadBypass 执行计划：dry-run 只返回计划（零请求）；否则按 Cap 逐个上传，
// 受理后尝试只读验证（响应 URL/回显），产出 Finding。基线不被受理时不产出绕过。
func RunUploadBypass(opts UploadBypassOptions) (UploadBypassResult, error) {
	plan := BuildUploadPlan(opts)
	res := UploadBypassResult{Plan: plan}
	if plan.DryRun {
		return res, nil
	}
	if strings.TrimSpace(plan.Endpoint) == "" || strings.TrimSpace(plan.FieldName) == "" {
		return res, errors.New("upload bypass: endpoint 与文件字段名必填")
	}
	if opts.Poster == nil {
		return res, errors.New("upload bypass: 非 dry-run 必须注入 Poster")
	}
	marker := g10Marker(plan.Token)
	attempts := plan.Attempts()
	if len(attempts) == 0 {
		return res, nil
	}
	base := attempts[0]
	baseResp := opts.Poster.PostMultipart(plan.Endpoint, plan.FieldName, base.FileName,
		base.ContentType, base.Content, plan.Extra)
	baseOK, baseWhy := g10UploadAccepted(baseResp, marker)
	res.BaselineAccepted = baseOK
	res.Attempts = append(res.Attempts, UploadAttemptResult{
		Candidate: base, Status: g10Status(baseResp), Accepted: baseOK,
		Reason: baseWhy, Response: g10Snap(baseResp), Curl: plan.CurlFor(base),
	})
	if !baseOK {
		return res, nil // 表单不可用/网关全拒：不产出绕过，防误报
	}
	for _, c := range attempts[1:] {
		resp := opts.Poster.PostMultipart(plan.Endpoint, plan.FieldName, c.FileName,
			c.ContentType, c.Content, plan.Extra)
		acc, why := g10UploadAccepted(resp, marker)
		ar := UploadAttemptResult{
			Candidate: c, Status: g10Status(resp), Accepted: acc,
			Reason: why, Response: g10Snap(resp), Curl: plan.CurlFor(c),
		}
		if acc {
			ar.URL = g10VerifyURL(resp, plan.Endpoint, c.FileName, opts.VerifyURL)
			if ar.URL != "" {
				back := opts.Poster.Get(ar.URL)
				ar.Accessible, ar.Parsed = g10ReadBack(back, marker, c)
				switch {
				case ar.Parsed:
					ar.Reason += "；访问回显标记且返回 text/html，疑似被解析"
				case ar.Accessible:
					ar.Reason += "；上传文件可访问"
				}
			}
			res.Findings = append(res.Findings, g10Finding(plan, c, ar))
		}
		res.Attempts = append(res.Attempts, ar)
	}
	return res, nil
}

// g10Marker 唯一无害文本标记（正常页面不可能天然出现）。
func g10Marker(token string) string {
	return "sitelens-g10-" + token + "-upload-probe-not-malicious"
}

// g10Cap 请求上限：默认 8，永不超过 G10MaxAttempts。
func g10Cap(n int) int {
	if n <= 0 || n > G10MaxAttempts {
		return G10MaxAttempts
	}
	return n
}

func g10DryRun(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

// g10UploadAccepted 受理判定：拒绝特征/4xx 优先；其次回显标记；再其次受理特征。
func g10UploadAccepted(resp *UploadHTTPResp, marker string) (bool, string) {
	if resp == nil || resp.Status == 0 {
		return false, "无响应"
	}
	body := string(resp.Body)
	low := strings.ToLower(body)
	if resp.Status >= 400 {
		return false, "HTTP " + strconv.Itoa(resp.Status)
	}
	for _, m := range uploadRejectMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return false, "命中拒绝特征 " + m
		}
	}
	if strings.Contains(body, marker) {
		return true, "响应回显上传内容标记"
	}
	for _, m := range uploadAcceptMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true, "命中受理特征 " + m
		}
	}
	return false, "无受理信号"
}

var (
	g10AbsURLRe = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	g10HrefRe   = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"']+)["']`)
	g10JSONRe   = regexp.MustCompile(`(?i)"(?:url|path|file|filename)"\s*:\s*"([^"]+)"`)
)

// g10VerifyURL 提取上传后的访问 URL：优先调用方模板，其次 Location/正文链接。
func g10VerifyURL(resp *UploadHTTPResp, endpoint, fileName string, verify func(string) string) string {
	if verify != nil {
		if u := strings.TrimSpace(verify(fileName)); u != "" {
			return u
		}
	}
	if resp == nil {
		return ""
	}
	if loc := resp.HeaderGet("Location"); loc != "" {
		if abs := g10AbsURL(endpoint, loc); abs != "" {
			return abs
		}
	}
	body := string(resp.Body)
	for _, re := range []*regexp.Regexp{g10AbsURLRe, g10HrefRe, g10JSONRe} {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			if abs := g10AbsURL(endpoint, m[1]); abs != "" {
				return abs
			}
		}
	}
	return ""
}

// g10AbsURL 把候选 URL 归一为 http(s) 绝对地址；非法 scheme 返回空。
func g10AbsURL(endpoint, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return "" // 拒绝 javascript:/data: 等
	}
	if u.IsAbs() {
		return u.String()
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

// g10ReadBack 只读验证：GET 返回标记 → 可访问；脚本扩展名 + text/html → 疑似解析。
func g10ReadBack(resp *UploadHTTPResp, marker string, c UploadCandidate) (accessible, parsed bool) {
	if resp == nil || resp.Status < 200 || resp.Status >= 300 {
		return false, false
	}
	if !strings.Contains(string(resp.Body), marker) {
		return false, false
	}
	accessible = true
	ct := strings.ToLower(resp.HeaderGet("Content-Type"))
	parsed = strings.Contains(ct, "text/html") && g10ScriptName(c.FileName)
	return accessible, parsed
}

var g10ScriptExts = []string{".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx"}

// g10ScriptName 文件名是否指向服务端脚本扩展（含双扩展/截断/分号形态）。
func g10ScriptName(name string) bool {
	low := strings.ToLower(name)
	for _, e := range g10ScriptExts {
		if strings.HasSuffix(low, e) ||
			strings.Contains(low, e+".") ||
			strings.Contains(low, e+";") ||
			strings.Contains(low, e+"%00") {
			return true
		}
	}
	return false
}

// g10KindLabel 绕过类型的中文标签（Finding 标题/证据用）。
func g10KindLabel(k UploadKind) string {
	switch k {
	case UploadKindExt:
		return "危险扩展名未被拒绝"
	case UploadKindDoubleExt:
		return "双扩展名归一化缺失"
	case UploadKindCase:
		return "扩展名大小写过滤缺失"
	case UploadKindNullByte:
		return "%00 截断绕过"
	case UploadKindSemicolon:
		return "分号路径参数绕过"
	case UploadKindHtaccess:
		return "上传 .htaccess 覆盖配置"
	case UploadKindMagicBytes:
		return "魔数伪造绕过"
	case UploadKindContentType:
		return "Content-Type 伪造绕过"
	default:
		return string(k)
	}
}

// g10Finding 组装一条上传绕过 Finding（含绕过类型/证据/复现 curl）。
func g10Finding(plan UploadPlan, c UploadCandidate, ar UploadAttemptResult) Finding {
	sev := "high"
	title := "文件上传绕过（" + g10KindLabel(c.Kind) + "）"
	if ar.Parsed {
		sev = "critical"
		title = "文件上传绕过（" + g10KindLabel(c.Kind) + "，疑似被解析）"
	}
	ev := "基线 .jpg 被受理；提交 " + c.FileName + "（Content-Type: " + c.ContentType +
		"）被受理（" + ar.Reason + "）。"
	if ar.Accessible {
		ev += " 上传文件可访问：" + ar.URL + "（GET 回显唯一标记）。"
	}
	if ar.Parsed {
		ev += " 访问响应为 text/html 且回显标记 —— 疑似被脚本处理器解析（纯文本载荷无法区分执行与静态返回，未据此确认 RCE）。"
	}
	ev += " 提交内容为无害文本标记（无脚本/可执行代码）。"
	f := Finding{
		Check:      "upload-bypass",
		Title:      title,
		Severity:   sev,
		URL:        plan.Endpoint,
		Param:      plan.FieldName,
		Payload:    c.FileName,
		Evidence:   ev,
		Replay:     plan.CurlFor(c),
		Advice:     "扩展名白名单（以服务端解析结果为准，不信任文件名后缀）+ 内容魔数校验 + 落盘目录禁用脚本执行（php-fpm/cgi 隔离）+ 文件名归一化（去 %00/;/::$DATA/多扩展名）+ 上传后重命名为随机名。",
		Impact:     "可上传服务端可解析的脚本文件，进而获得命令执行能力。",
		Hypothesis: "服务端对上传文件的扩展名/Content-Type 校验可被绕过",
		Signals: []string{
			"基线受理：.jpg",
			"绕过受理：" + c.FileName + "（" + string(c.Kind) + "）",
			"判定信号：" + ar.Reason,
		},
	}
	f.Request = "POST " + plan.Endpoint + " HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n" +
		"(字段 " + plan.FieldName + " = " + c.FileName + ", " + c.ContentType + "，内容为无害探针标记)"
	if ar.Response != nil {
		f.Response = ar.Response
	}
	return f
}

func g10Status(resp *UploadHTTPResp) int {
	if resp == nil {
		return 0
	}
	return resp.Status
}

func g10Snap(resp *UploadHTTPResp) *RespSnap {
	if resp == nil {
		return nil
	}
	return &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(string(resp.Body))}
}

// g10HeaderSafe 去掉 CR/LF 与引号，防 multipart 头注入。
func g10HeaderSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.ReplaceAll(s, "\"", "%22")
}
