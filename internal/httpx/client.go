// Package httpx 提供限速 HTTP 客户端：手动跟随重定向 + 逐跳 SSRF 校验。
// 行为约定移植自 scanner/fetcher.py（限速 / UA 自报 / 证据留取）。
package httpx

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Response 精简响应（对齐 Python get_small 的返回形态）。
// Set-Cookie 单独保真存放：Go http.Header 本就逐条分离，不再合并进 Headers，
// 下游 Cookie 属性/名称解析不需要启发式切分。
type Response struct {
	Status     int
	Headers    map[string]string
	SetCookies []string
	Body       string
	FinalURL   string
}

// Header 大小写不敏感取响应头。
func (r *Response) Header(name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

const defaultMaxBodyBytes = 3_000_000 // 与 Python 端一致：超 3MB 不留正文

// ClientOptions 客户端参数（全部来自 config.ScanConfig 的装配）。
type ClientOptions struct {
	Interval     time.Duration // 相邻请求最小间隔（限速），0=不限速
	Timeout      time.Duration // 单请求超时，0=20s
	MaxHops      int           // 重定向最大跳数，0=6
	MaxBodyBytes int           // 正文留存上限，0=3MB
	UserAgent    string        // 空 = SiteLens 自报 UA
	AuthCookie   string        // 附加到每个请求的 Cookie 头（授权扫描用）
	Resolve      bool          // 重定向逐跳校验是否解析并拒绝私网（继承引擎 resolve 姿态；本地靶场矩阵设 false）
}

// Client 限速 HTTP 客户端（自动重定向禁用，逐跳校验后手动跟随）。
type Client struct {
	http      *http.Client
	interval  time.Duration
	resolve   bool
	mu        sync.Mutex
	last      time.Time
	userAgent string
	maxHops   int
	maxBody   int
	cookie    string
}

// NewWithOptions 按参数创建客户端。
func NewWithOptions(o ClientOptions) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxHops <= 0 {
		o.MaxHops = 6
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = defaultMaxBodyBytes
	}
	if o.UserAgent == "" {
		o.UserAgent = "SiteLens/0.0.2 (+https://cnb.cool/feng-qiao/sitelens)"
	}
	c := &Client{
		interval:  o.Interval,
		userAgent: o.UserAgent,
		maxHops:   o.MaxHops,
		maxBody:   o.MaxBodyBytes,
		cookie:    o.AuthCookie,
		resolve:   o.Resolve,
	}
	c.http = &http.Client{
		Timeout: o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // 禁自动重定向，逐跳手动校验
		},
	}
	return c
}

// New 创建客户端；interval 为相邻请求最小间隔（限速）。
func New(interval time.Duration) *Client {
	return NewWithOptions(ClientOptions{Interval: interval})
}

func (c *Client) wait() {
	c.mu.Lock()
	d := c.interval - time.Since(c.last)
	c.last = time.Now()
	c.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// newRequest 构造带自报 UA 与授权 Cookie 的请求。
func (c *Client) newRequest(method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	return req, nil
}

// GetFollow 手动跟随重定向的 GET：每一跳都过 target.Validate SSRF 校验
// （协议白名单 + DNS 解析 + 私网拒绝）。返回最终到达的响应。
func (c *Client) GetFollow(rawURL string) (*Response, error) {
	return c.GetFollowWith(rawURL, nil)
}

// GetFollowWith 同 GetFollow，附加额外请求头（403 绕过重试等场景）。
func (c *Client) GetFollowWith(rawURL string, extra map[string]string) (*Response, error) {
	c.wait()
	cur := rawURL
	var resp *http.Response
	var err error
	for hop := 0; hop < c.maxHops; hop++ {
		req, rerr := c.newRequest(http.MethodGet, cur)
		if rerr != nil {
			return nil, &target.Error{Msg: "URL 构造失败"}
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		resp, err = c.http.Do(req)
		if err != nil {
			// 底层错误原样带出（refused/timeout/proxy 一目了然）
			return nil, &target.Error{Msg: "连接失败：" + cur + "：" + err.Error()}
		}
		if !isRedirect(resp.StatusCode) {
			break
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		next, perr := resolveRef(cur, loc)
		if perr != nil {
			break
		}
		// 逐跳校验继承配置的 resolve 姿态：公网默认 true（防重定向 SSRF）；
		// 本地/内网靶场矩阵 resolve=false 时重定向不再被私网拦截
		if _, _, _, verr := target.Validate(next, c.resolve); verr != nil {
			return nil, verr // 重定向目标未过校验：拒绝跟随
		}
		cur = next
	}
	return toResponse(resp, cur), nil
}

// GetDirect 单请求 GET：不跟随重定向、不做 SSRF 逐跳校验（URL 需预先 Validate）。
// 供 DAST 开放重定向判定等需要看原始 30x 响应的探测使用；正文上限 1MB。
func (c *Client) GetDirect(rawURL string) (*Response, error) {
	c.wait()
	req, err := c.newRequest(http.MethodGet, rawURL)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponseCap(resp, rawURL, 1_000_000), nil
}

// PostForm POST 表单提交（单请求，不跟随重定向；登录爆破用）。
func (c *Client) PostForm(rawURL string, fields map[string]string) (*Response, error) {
	c.wait()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	payload := form.Encode()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(strings.NewReader(payload))
	req.ContentLength = int64(len(payload))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponseCap(resp, rawURL, 512_000), nil
}

// PostRaw POST 自定义 Content-Type 的原始请求体（Nuclei POST 模板等）。
func (c *Client) PostRaw(rawURL, contentType, body string) (*Response, error) {
	c.wait()
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponseCap(resp, rawURL, 512_000), nil
}

// PostJSON POST JSON 请求体（单请求，不跟随重定向；JSON API 登录用）。
func (c *Client) PostJSON(rawURL, body string) (*Response, error) {
	c.wait()
	req, err := c.newRequest(http.MethodPost, rawURL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponseCap(resp, rawURL, 512_000), nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// resolveRef 以 base 解析可能为相对路径的 Location。
func resolveRef(base, ref string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return bu.ResolveReference(ru).String(), nil
}

func toResponse(resp *http.Response, finalURL string) *Response {
	return toResponseCap(resp, finalURL, defaultMaxBodyBytes)
}

func toResponseCap(resp *http.Response, finalURL string, bodyCap int) *Response {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(bodyCap)+1))
	if len(body) > bodyCap {
		body = body[:bodyCap]
	}
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue // 单独保真存放
		}
		headers[k] = strings.Join(vs, ", ")
	}
	return &Response{
		Status:     resp.StatusCode,
		Headers:    headers,
		SetCookies: resp.Header.Values("Set-Cookie"),
		Body:       string(body),
		FinalURL:   finalURL,
	}
}
