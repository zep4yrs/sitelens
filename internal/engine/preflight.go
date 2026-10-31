package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// PreflightTTL 预检结果可被扫描复用的最长时效。
const PreflightTTL = 120 * time.Second

// preflightMaxBody 预检正文留存上限（复用首页所需足够，避免占内存）。
const preflightMaxBody = 256 << 10

// Preflight 一次只读预检的结果（additive：仅供建议卡展示与首页复用，
// 不参与任何漏洞判定）。
type Preflight struct {
	RequestedURL string            `json:"requested_url"`
	FinalURL     string            `json:"final_url"`
	Status       int               `json:"status"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	ContentType  string            `json:"content_type"`
	Headers      map[string]string `json:"headers,omitempty"`
	SetCookies   []string          `json:"set_cookies,omitempty"`
	Body         string            `json:"-"`
	Blocked      bool              `json:"blocked"`
	BlockReason  string            `json:"block_reason,omitempty"`
	ResponseMS   int64             `json:"response_ms"`
	Tech         []string          `json:"tech,omitempty"`
	CookieHash   string            `json:"-"`
	CreatedAt    time.Time         `json:"-"`
}

// Response 把预检缓存转成扫描可复用的首页响应（含 WAF 拦截标记）。
func (p *Preflight) Response() *httpx.Response {
	if p == nil {
		return nil
	}
	return &httpx.Response{
		Status:      p.Status,
		Headers:     p.Headers,
		SetCookies:  p.SetCookies,
		Body:        p.Body,
		FinalURL:    p.FinalURL,
		Blocked:     p.Blocked,
		BlockReason: p.BlockReason,
	}
}

// ValidFor 判断预检结果能否用于本次扫描的首页复用：
// 未过期 + 请求 URL 一致 + 认证 Cookie 一致（避免把未认证页面当认证态复用）。
func (p *Preflight) ValidFor(seedURL, authCookie string, now time.Time) bool {
	if p == nil || p.Status == 0 || p.Body == "" && p.Status < 300 {
		return false
	}
	if now.Sub(p.CreatedAt) > PreflightTTL || p.CreatedAt.After(now) {
		return false
	}
	if normalizeKey(p.RequestedURL) != normalizeKey(seedURL) {
		return false
	}
	return p.CookieHash == cookieHash(authCookie)
}

// Preflight 执行一次只读预检：GET 用户输入的 URL（≤ MaxHops 跳），
// 提取状态/标题/服务器/技术指纹/WAF 判定/正文（截断），供前端建议卡与
// 扫描首页复用。不发 payload、不爬取、不写历史。
func (e *Engine) Preflight(rawURL string, opts Options) (*Preflight, error) {
	scheme, host, port, err := target.Validate(rawURL, e.cfg.Scan.Resolve)
	if err != nil {
		return nil, err
	}
	seed := seedFromRaw(rawURL, scheme, host, port)
	client := e.newClient(opts)
	start := time.Now()
	resp, err := client.GetFollow(seed)
	if err != nil {
		return nil, fmt.Errorf("预检失败：%w", err)
	}
	pf := &Preflight{
		RequestedURL: seed,
		FinalURL:     resp.FinalURL,
		Status:       resp.Status,
		Server:       resp.Header("Server"),
		ContentType:  resp.Header("Content-Type"),
		Headers:      resp.Headers,
		SetCookies:   resp.SetCookies,
		Blocked:      resp.Blocked,
		BlockReason:  resp.BlockReason,
		ResponseMS:   time.Since(start).Milliseconds(),
		CookieHash:   cookieHash(opts.AuthCookie),
		CreatedAt:    time.Now(),
	}
	if body := resp.Body; len(body) > preflightMaxBody {
		pf.Body = body[:preflightMaxBody]
	} else {
		pf.Body = body
	}
	if doc := htmlx.Parse(pf.Body); doc != nil {
		pf.Title = strings.TrimSpace(doc.Title)
	}
	if matcher, _ := e.snapshot(); matcher != nil {
		seen := make(map[string]bool, 8)
		for _, h := range matcher.Match(sitelens.Extract(resp)) {
			if h.Name == "" || seen[h.Name] || len(pf.Tech) >= 8 {
				continue
			}
			seen[h.Name] = true
			pf.Tech = append(pf.Tech, h.Name)
		}
	}
	return pf, nil
}

// seedFromRaw 用 target.Validate 的规范化结果重建可抓取 URL
// （保留用户路径/query，统一 scheme/host/port，去掉 fragment）。
func seedFromRaw(raw, scheme, host string, port int) string {
	r := strings.TrimSpace(raw)
	if !strings.Contains(r, "://") {
		r = scheme + "://" + r
	}
	u, err := url.Parse(r)
	if err != nil {
		return scheme + "://" + host
	}
	u.Scheme = scheme
	hostPort := host
	if port > 0 && !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
		hostPort = net.JoinHostPort(host, strconv.Itoa(port))
	}
	u.Host = hostPort
	u.Fragment = ""
	return u.String()
}

// cookieHash 认证 Cookie 指纹（空 = 空串），仅用于复用一致性校验。
func cookieHash(cookie string) string {
	if cookie == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(sum[:])
}

// NormalizePreflightURL 归一化预检 URL（去 fragment、去尾部斜杠、host 小写），
// 供服务端缓存按 URL 去重。
func NormalizePreflightURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.Fragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return strings.TrimSuffix(u.String(), "/")
}
