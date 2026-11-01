package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client 是 SiteLens 本地 HTTP API 的受控客户端。
//
// 只发 HTTP，不接触引擎内部状态；鉴权沿用既有的 X-Token 语义。
// 响应读取有硬上限（32MB），防止恶意/异常目标把 bridge 撑爆。
type Client struct {
	base  *url.URL
	token string
	hc    *http.Client
}

// APIError 非 2xx 响应。Body 截断到 2KB，避免把大页面带进模型上下文。
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("SiteLens API 返回 HTTP %d", e.Status)
	}
	return fmt.Sprintf("SiteLens API 返回 HTTP %d: %s", e.Status, e.Body)
}

// NewClient 构造 API 客户端。timeout <= 0 时用 15s。
func NewClient(rawURL, token string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("API 地址非法: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("API 地址必须是 http(s)，当前是 %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("API 地址缺少主机: %q", rawURL)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		base:  u,
		token: strings.TrimSpace(token),
		hc:    &http.Client{Timeout: timeout},
	}, nil
}

// ValidateLocalAPI 默认只允许回环 API（127.0.0.0/8、::1、localhost）。
// MCP server 由智能体拉起，不应成为打内网/云 metadata 的跳板。
func ValidateLocalAPI(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("API 地址非法: %w", err)
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("API 地址 %q 不是回环地址；如确需远程，请显式传 --allow-remote-api", host)
}

// apiURL 拼出完整 API 地址；base 允许带前缀路径。
func (c *Client) apiURL(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// do 发一次 HTTP 请求并读完响应（32MB 上限）。
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte, contentType string) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path, q), r)
	if err != nil {
		return nil, 0, err
	}
	if c.token != "" {
		req.Header.Set("X-Token", c.token)
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.5")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("连接 SiteLens API 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if rerr != nil {
		return nil, resp.StatusCode, fmt.Errorf("读取 SiteLens API 响应失败: %w", rerr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return raw, resp.StatusCode, &APIError{Status: resp.StatusCode, Body: clipString(strings.TrimSpace(string(raw)), 2000)}
	}
	return raw, resp.StatusCode, nil
}

// getJSON GET 并解析 JSON 对象。
func (c *Client) getJSON(ctx context.Context, path string, q url.Values) (map[string]any, error) {
	raw, _, err := c.do(ctx, http.MethodGet, path, q, nil, "")
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("SiteLens API 响应不是 JSON 对象: %w", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// postJSON POST 一个 JSON 请求体并解析 JSON 对象响应（空响应返回空对象）。
func (c *Client) postJSON(ctx context.Context, path string, q url.Values, in any) (map[string]any, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("请求体编码失败: %w", err)
	}
	raw, _, err := c.do(ctx, http.MethodPost, path, q, body, "application/json")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("SiteLens API 响应不是 JSON 对象: %w", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// clipString 按字节截断字符串（不保证 UTF-8 边界；调用方多用于错误/日志文本）。
func clipString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…（已截断）"
}
