package server

// HAR（HTTP Archive 1.2）导出：把已存证据链重建为「扫描器实际发出了什么」。
//
// 设计边界（诚实优先）：
//   - request 来自命中时真实生成的报文（checks/nuclei 的 Hit.Request，或
//     dast 的 replay 命令），不是事后猜测。
//   - response 当前只保存了 状态/大小/正文摘要（checks.HitResponse），
//     没有完整响应头 —— 因此 HAR 里的 response.headers 为空、content.text
//     是摘要而不是完整响应体，entry.comment 会写明这一点。
//   - 这是「可复核的证据归档」，不是网络层抓包：不替代 tcpdump/Wireshark，
//     也不需要管理员权限或抓包驱动。
//   - 敏感请求头（Cookie/Authorization/X-Token/...）默认脱敏；?raw=1 保留原值。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

const (
	// harMaxEntries 单次导出的条目上限（防超大结果撑爆浏览器/文件）。
	harMaxEntries = 2000
	// harMaxText 单条请求/响应文本上限：HAR 是给人看的证据，不是原始转储。
	harMaxText = 8 << 10
)

type harDoc struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Pages   []harPage  `json:"pages,omitempty"`
	Entries []harEntry `json:"entries"`
	Comment string     `json:"comment,omitempty"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harPage struct {
	StartedDateTime string        `json:"startedDateTime"`
	ID              string        `json:"id"`
	Title           string        `json:"title"`
	PageTimings     harPageTiming `json:"pageTimings"`
}

type harPageTiming struct {
	OnContentLoad int `json:"onContentLoad"`
	OnLoad        int `json:"onLoad"`
}

type harEntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           map[string]any `json:"cache"`
	Timings         harTimings     `json:"timings"`
	Comment         string         `json:"comment,omitempty"`
	Source          string         `json:"_source,omitempty"`
}

type harTimings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Cookies     []harNameValue `json:"cookies"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harPostData struct {
	MimeType string         `json:"mimeType"`
	Text     string         `json:"text,omitempty"`
	Params   []harNameValue `json:"params,omitempty"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Cookies     []harNameValue `json:"cookies"`
	Headers     []harNameValue `json:"headers"`
	Content     harContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
}

// harRedactedHeaders 默认脱敏的请求/响应头（大小写不敏感）。
var harRedactedHeaders = map[string]bool{
	"cookie":              true,
	"set-cookie":          true,
	"authorization":       true,
	"proxy-authorization": true,
	"x-token":             true,
	"x-auth-token":        true,
	"x-api-key":           true,
}

// buildScanHAR 把一条扫描记录重建为 HAR 1.2 文档。
func buildScanHAR(rec *store.ScanRecord, raw bool) ([]byte, error) {
	if rec == nil || rec.Result == nil {
		return nil, fmt.Errorf("记录不存在（无详细结果数据）")
	}
	res := rec.Result
	started := strings.TrimSpace(res.ScannedAt)
	if started == "" {
		started = time.Unix(0, 0).UTC().Format(time.RFC3339)
	}
	doc := harDoc{Log: harLog{
		Version: "1.2",
		Creator: harCreator{Name: "SiteLens", Version: Version},
		Pages: []harPage{{
			StartedDateTime: started,
			ID:              fmt.Sprintf("scan-%d", rec.ID),
			Title:           res.URL,
			PageTimings:     harPageTiming{OnContentLoad: -1, OnLoad: -1},
		}},
		Comment: "由 SiteLens 证据链重建：request 为命中时实际发出的报文；" +
			"response 仅含状态/大小/正文摘要（该版本未保存完整响应头），" +
			"不是网络层抓包。敏感请求头默认脱敏，?raw=1 保留原值。",
	}}
	if doc.Log.Pages[0].Title == "" {
		doc.Log.Pages[0].Title = res.Host
	}

	seen := map[string]bool{}
	for _, v := range res.Verified {
		e, ok := harEntryFromVerified(v, started, raw)
		if !ok {
			continue
		}
		// 同一 (method, url) 只保留一次：HAR 观感上不应重复同一请求；
		// 不同 check 命中同一 URL 的差异已体现在发现列表里。
		key := e.Request.Method + " " + e.Request.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		doc.Log.Entries = append(doc.Log.Entries, *e)
		if len(doc.Log.Entries) >= harMaxEntries {
			break
		}
	}
	if len(doc.Log.Entries) == 0 {
		return nil, fmt.Errorf("该记录没有可重建为 HAR 的请求证据（无语料 request/replay）")
	}
	return json.MarshalIndent(doc, "", "  ")
}

// harEntryFromVerified 从一条 verified 发现里抽取请求/响应证据。
func harEntryFromVerified(v map[string]any, started string, raw bool) (*harEntry, bool) {
	if v == nil {
		return nil, false
	}
	fallbackURL, _ := v["url"].(string)

	method, reqURL, headers, body, httpVer, ok := harReqFromVerified(v, fallbackURL)
	if !ok || reqURL == "" {
		return nil, false
	}
	reqURL = maskURLUserinfo(reqURL)
	if httpVer == "" {
		httpVer = "HTTP/1.1"
	}

	// Cookie 要在脱敏前拆：脱敏会把 Cookie 头整体替换成 ***，
	// 之后就拆不出 name=value 了。
	cookies := harCookieValues(headers, raw)
	headers = harRedactMap(headers, raw)
	req := harRequest{
		Method:      method,
		URL:         reqURL,
		HTTPVersion: httpVer,
		Cookies:     cookies,
		Headers:     harHeaderList(headers),
		QueryString: harQueryList(reqURL),
		HeadersSize: -1,
		BodySize:    -1,
	}
	if body != "" {
		mt := headerValueFold(headers, "Content-Type")
		if mt == "" {
			mt = "text/plain"
		}
		req.PostData = &harPostData{MimeType: mt, Text: truncateText(body, harMaxText)}
		req.BodySize = len(body)
	}

	resp := harResponse{
		HTTPVersion: "HTTP/1.1",
		Cookies:     []harNameValue{},
		Headers:     []harNameValue{},
		Content:     harContent{Size: -1},
		HeadersSize: -1,
		BodySize:    -1,
	}
	if rv, exists := v["response"]; exists {
		if m := asStringMap(rv); m != nil {
			resp.Status = asInt(m["status"])
			if sz := asInt(m["size"]); sz >= 0 {
				resp.Content.Size = sz
				resp.BodySize = sz
			}
			if ct, _ := m["content_type"].(string); ct != "" {
				resp.Content.MimeType = ct
			}
			if sn, _ := m["snippet"].(string); sn != "" {
				resp.Content.Text = truncateText(sn, harMaxText)
			}
		}
	}

	e := &harEntry{
		StartedDateTime: started,
		Time:            0,
		Request:         req,
		Response:        resp,
		Cache:           map[string]any{},
		Timings:         harTimings{Blocked: -1, DNS: -1, Connect: -1, Send: -1, Wait: -1, Receive: -1, SSL: -1},
		Comment:         harEntryComment(resp.Status),
	}
	if src, _ := v["src"].(string); src != "" {
		e.Source = src
	} else if _, ok := v["check"]; ok {
		e.Source = "checks"
	}
	return e, true
}

func harEntryComment(status int) string {
	if status > 0 {
		return "响应头未保存；content.text 为正文摘要"
	}
	return "未记录响应状态（仅请求证据）"
}

// harReqFromVerified 依次尝试 request 字符串 / request 结构 / replay curl。
func harReqFromVerified(v map[string]any, fallbackURL string) (method, reqURL string, headers map[string]string, body, httpVer string, ok bool) {
	if raw, isStr := v["request"].(string); isStr && strings.TrimSpace(raw) != "" {
		if m, u, h, b, ver, perr := parseRawHTTPRequest(raw, fallbackURL); perr == nil {
			return m, u, h, b, ver, true
		}
	}
	if m := asStringMap(v["request"]); m != nil {
		method, _ = m["method"].(string)
		reqURL, _ = m["url"].(string)
		if reqURL == "" {
			reqURL = fallbackURL
		}
		if method == "" {
			method = http.MethodGet
		}
		headers = asStringMapString(m["headers"])
		if s, _ := m["body"].(string); s != "" {
			body = s
		}
		return strings.ToUpper(method), reqURL, headers, body, "HTTP/1.1", reqURL != ""
	}
	if replay, isStr := v["replay"].(string); isStr && strings.Contains(replay, "curl ") {
		if m, u := parseCurlReplay(replay); u != "" {
			headers = m.headers
			return m.method, u, headers, m.body, "HTTP/1.1", true
		}
	}
	return "", "", nil, "", "", false
}

// parseRawHTTPRequest 解析 checks/nuclei 生成的真实请求报文
// （格式：`METHOD path HTTP/1.1\r\nHost:...\r\n...\r\n\r\nbody`）。
func parseRawHTTPRequest(text, fallbackURL string) (method, reqURL string, headers map[string]string, body, httpVer string, err error) {
	r, perr := http.ReadRequest(bufio.NewReader(strings.NewReader(text)))
	if perr != nil {
		return "", "", nil, "", "", perr
	}
	defer func() { _ = r.Body.Close() }()
	method = r.Method
	httpVer = r.Proto
	headers = make(map[string]string, len(r.Header)+1)
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	if r.Host != "" {
		headers["Host"] = r.Host
	}
	if b, berr := io.ReadAll(io.LimitReader(r.Body, harMaxText)); berr == nil {
		body = string(b)
	}
	// 报文没带 Content-Length 时 ReadRequest 会把正文留在缓冲里、Body 读成空。
	// 证据原文仍在我们手上：退回到分隔符后的原始尾巴（截断上限内）。
	if body == "" {
		if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
			if rest := text[idx+4:]; rest != "" {
				body = truncateText(rest, harMaxText)
			}
		}
	}
	if fallbackURL != "" {
		reqURL = fallbackURL
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		reqURL = scheme + "://" + r.Host + r.URL.RequestURI()
	}
	return method, reqURL, headers, body, httpVer, nil
}

type curlReplay struct {
	method  string
	headers map[string]string
	body    string
}

var (
	reCurlURL    = regexp.MustCompile(`'(https?://[^']*)'`)
	reCurlMethod = regexp.MustCompile(`(?:^|\s)-X\s+([A-Za-z]+)`)
	reCurlData   = regexp.MustCompile(`(?:^|\s)-d\s+'((?:[^'\\]|\\.)*)'`)
	reCurlForm   = regexp.MustCompile(`(?:^|\s)-F\s+'((?:[^'\\]|\\.)*)'`)
	reCurlHeader = regexp.MustCompile(`(?:^|\s)-H\s+'((?:[^'\\]|\\.)*)'`)
)

// parseCurlReplay 从我们生成的 curl 复现命令里还原方法/URL/头/体。
// 这是 best-effort：只为本项目 shellQuote 生成的形态服务。
func parseCurlReplay(replay string) (curlReplay, string) {
	var c curlReplay
	u := ""
	if m := reCurlURL.FindStringSubmatch(replay); len(m) > 1 {
		u = m[1]
	}
	if u == "" {
		return c, ""
	}
	c.headers = map[string]string{}
	if m := reCurlMethod.FindStringSubmatch(replay); len(m) > 1 {
		c.method = strings.ToUpper(m[1])
	}
	if m := reCurlData.FindStringSubmatch(replay); len(m) > 1 {
		c.body = unescapeShellQuoted(m[1])
	}
	if m := reCurlForm.FindStringSubmatch(replay); len(m) > 1 {
		c.body = unescapeShellQuoted(m[1])
		c.headers["Content-Type"] = "multipart/form-data"
		if c.method == "" {
			c.method = http.MethodPost
		}
	}
	for _, m := range reCurlHeader.FindAllStringSubmatch(replay, -1) {
		if len(m) < 2 {
			continue
		}
		if k, val, ok := strings.Cut(unescapeShellQuoted(m[1]), ":"); ok {
			c.headers[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	if c.method == "" {
		if c.body != "" {
			c.method = http.MethodPost
		} else {
			c.method = http.MethodGet
		}
	}
	return c, u
}

// unescapeShellQuoted 还原 `'\”` 形态的嵌入式单引号与反斜杠转义。
func unescapeShellQuoted(s string) string {
	s = strings.ReplaceAll(s, `'\''`, `'`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return s
}

// ---- HAR 小工具 ----

func harRedactMap(headers map[string]string, raw bool) map[string]string {
	if raw || len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if harRedactedHeaders[strings.ToLower(strings.TrimSpace(k))] {
			out[k] = "***"
		} else {
			out[k] = v
		}
	}
	return out
}

func harHeaderList(headers map[string]string) []harNameValue {
	out := make([]harNameValue, 0, len(headers))
	for k, v := range headers {
		out = append(out, harNameValue{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// harCookieValues 从 Cookie 头拆出 name=value；脱敏时 value 固定 ***。
func harCookieValues(headers map[string]string, raw bool) []harNameValue {
	out := []harNameValue{}
	rawCookie := headerValueFold(headers, "Cookie")
	if rawCookie == "" {
		return out
	}
	for _, part := range strings.Split(rawCookie, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		if !raw {
			v = "***"
		}
		out = append(out, harNameValue{Name: strings.TrimSpace(k), Value: v})
	}
	return out
}

func harQueryList(rawURL string) []harNameValue {
	out := []harNameValue{}
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return out
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, harNameValue{Name: k, Value: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// maskURLUserinfo 去掉 URL 里的 user:pass@（HTTP 基本认证凭据）。
func maskURLUserinfo(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return rawURL
	}
	u.User = url.User("***")
	return u.String()
}

func headerValueFold(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

// asStringMap 把 JSON 解码后的对象值转成 map[string]any（兼容 struct）。
func asStringMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func asStringMapString(v any) map[string]string {
	out := map[string]string{}
	m := asStringMap(v)
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…（截断）"
}
