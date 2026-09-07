// Package headless 无头浏览器渲染（SPA 支持）。
//
// 通过 chromedp 驱动本机 Chrome/Chromium 执行页面 JS 后取回渲染后的
// HTML——爬虫借此看到 Vue/React 等前端框架动态生成的链接与内容。
// 本机没有浏览器时返回明确错误，调用方降级为纯 HTML 爬取。
// 仅在 crawler.headless: true 时启用，默认关闭。
package headless

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Chrome 基于 chromedp 的渲染器。
type Chrome struct {
	timeout  time.Duration
	execPath string // 浏览器可执行路径（空 = chromedp 自动探测）
}

// NewChrome 创建渲染器。timeout ≤ 0 时取默认 20s。
// execPath 指定 Chromium 系浏览器可执行文件（Chrome/Edge/Tabbit 等）；
// 为空时 chromedp 自动探测标准安装路径。
func NewChrome(timeout time.Duration, execPath string) *Chrome {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Chrome{timeout: timeout, execPath: execPath}
}

// Render 拉取页面并等待 JS 执行完成，返回渲染后的完整 HTML。
// 浏览器缺失、启动失败、超时均返回错误（调用方降级处理）。
func (c *Chrome) Render(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", fmt.Errorf("仅支持 http/https 地址")
	}
	// 浏览器路径：配置指定优先（Chromium 系均可，Tabbit/Edge 等），
	// 否则 chromedp 自动探测标准安装路径
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true))
	if c.execPath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(c.execPath))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer allocCancel()
	ctx, cancel := context.WithTimeout(allocCtx, c.timeout)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(rawURL),
		chromedp.WaitReady("body"),
		chromedp.Sleep(500*time.Millisecond), // 给 SPA 框架一个初始挂载窗口
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return "", fmt.Errorf("渲染失败：%w", err)
	}
	if strings.TrimSpace(html) == "" {
		return "", fmt.Errorf("渲染结果为空")
	}
	return html, nil
}

// Close 释放资源（chromedp 按次创建浏览器实例，无持久连接需要关闭；
// 保留方法以满足未来连接池化）。
func (c *Chrome) Close() error { return nil }
