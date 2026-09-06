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
type Response struct {
	Status   int
	Headers  map[string]string
	Body     string
	FinalURL string
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

const maxBodyBytes = 3_000_000 // 与 Python 端一致：超 3MB 不留正文

// Client 限速 HTTP 客户端（自动重定向禁用，逐跳校验后手动跟随）。
type Client struct {
	http      *http.Client
	interval  time.Duration
	mu        sync.Mutex
	last      time.Time
	userAgent string
	maxHops   int
}

// New 创建客户端；interval 为相邻请求最小间隔（限速）。
func New(interval time.Duration) *Client {
	c := &Client{
		interval:  interval,
		userAgent: "SiteLens/0.1 (+https://cnb.cool/feng-qiao/sitelens)",
		maxHops:   6,
	}
	c.http = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // 禁自动重定向，逐跳手动校验
		},
	}
	return c
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

// GetFollow 手动跟随重定向的 GET：每一跳都过 target.Validate SSRF 校验
// （协议白名单 + DNS 解析 + 私网拒绝）。返回最终到达的响应。
func (c *Client) GetFollow(rawURL string) (*Response, error) {
	c.wait()
	cur := rawURL
	var resp *http.Response
	var err error
	for hop := 0; hop < c.maxHops; hop++ {
		req, rerr := http.NewRequest(http.MethodGet, cur, nil)
		if rerr != nil {
			return nil, &target.Error{Msg: "URL 构造失败"}
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		resp, err = c.http.Do(req)
		if err != nil {
			return nil, &target.Error{Msg: "连接失败：" + cur}
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
		if _, _, _, verr := target.Validate(next, true); verr != nil {
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
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponseCap(resp, rawURL, 1_000_000), nil
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
	return toResponseCap(resp, finalURL, maxBodyBytes)
}

func toResponseCap(resp *http.Response, finalURL string, cap int) *Response {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(cap)+1))
	if len(body) > cap {
		body = body[:cap]
	}
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	return &Response{
		Status:   resp.StatusCode,
		Headers:  headers,
		Body:     string(body),
		FinalURL: finalURL,
	}
}
