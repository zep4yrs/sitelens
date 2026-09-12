// Package captcha 验证码识别 sidecar 客户端。
//
// Go 版不含 OCR 模型；通过本机 ddddocr HTTP sidecar
// （tools/ocr_server.py，仅监听 127.0.0.1）获得识别能力。
// 未配置 sidecar 地址时调用方明确报错，不静默瞎打。
package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client ddddocr sidecar 客户端。
type Client struct {
	URL     string        // sidecar 的 /ocr 地址
	Timeout time.Duration // 单次识别超时
}

// NewClient 创建客户端；timeout ≤ 0 取默认 10s。
func NewClient(url string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{URL: url, Timeout: timeout}
}

// Health 检查 sidecar 是否可用（B16 容错：配置地址带不带 /ocr 后缀、
// 带其他路径或结尾斜杠均可探测——依次尝试「剥 /ocr + /health」与
// 「根路径 /health」，任一返回 200 即可用）。
func (c *Client) Health() bool {
	cli := &http.Client{Timeout: 3 * time.Second}
	base := strings.TrimRight(c.URL, "/")
	candidates := []string{strings.TrimRight(strings.TrimSuffix(base, "/ocr"), "/") + "/health"}
	if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = "http"
		}
		if root := scheme + "://" + u.Host + "/health"; root != candidates[0] {
			candidates = append(candidates, root)
		}
	}
	for _, health := range candidates {
		resp, err := cli.Get(health)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}
	return false
}

// SolveImage 识别验证码图片字节，返回文本（已去空白）。
func (c *Client) SolveImage(img []byte) (string, error) {
	if len(img) == 0 {
		return "", fmt.Errorf("图片为空")
	}
	cli := &http.Client{Timeout: c.Timeout}
	resp, err := cli.Post(c.URL, "application/octet-stream", bytes.NewReader(img))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("sidecar 返回 HTTP %d", resp.StatusCode)
	}
	var out struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("%s", out.Error)
	}
	return strings.TrimSpace(out.Code), nil
}
