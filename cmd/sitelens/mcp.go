package main

// mcp 子命令：MCP（Model Context Protocol）stdio server。
//
//	sitelens mcp [--api-url URL] [--api-token TOKEN] [--allow-active]
//
// 供渗透智能体（辰极 Lodestar 等）通过 MCP 工具调用 SiteLens。
// stdout 被 JSON-RPC 独占，所有日志走 stderr。

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/mcp"
	"cnb.cool/feng-qiao/sitelens/internal/server"
)

// mcpCommand 解析参数并跑 stdio 会话；返回进程退出码。
func mcpCommand(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiURL := fs.String("api-url", firstEnv("SITELENS_API_URL", "SLENS_API_URL", "http://127.0.0.1:5000"),
		"SiteLens API 地址（默认 http://127.0.0.1:5000，也可用 SITELENS_API_URL/SLENS_API_URL）")
	apiToken := fs.String("api-token", firstEnv("SITELENS_API_TOKEN", "SLENS_API_TOKEN", ""),
		"API Token（对应 web.api_token；也可用 SITELENS_API_TOKEN/SLENS_API_TOKEN）")
	allowActive := fs.Bool("allow-active", truthyEnv("SITELENS_MCP_ACTIVE"),
		"启用主动工具（scan / graphql_introspect / assets）；默认关闭")
	allowRemote := fs.Bool("allow-remote-api", false,
		"允许连接非回环 API（默认仅本机回环，防止 MCP 成为 SSRF 跳板）")
	allowHosts := fs.String("allow-hosts", strings.TrimSpace(os.Getenv("SITELENS_MCP_ALLOW_HOSTS")),
		"危险工具（scan/graphql_introspect/assets）授权白名单，逗号分隔（如 example.com,*.corp.example）；空 = 危险工具一律拒绝")
	maxBytes := fs.Int("max-bytes", 512<<10, "单次工具响应文本上限（字节）")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `sitelens mcp — MCP stdio server（供智能体调用）

用法：
  sitelens mcp [flags]

flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *maxBytes < 4096 {
		fmt.Fprintln(os.Stderr, "[sitelens-mcp] --max-bytes 至少 4096")
		return 2
	}
	if !*allowRemote {
		if err := mcp.ValidateLocalAPI(*apiURL); err != nil {
			fmt.Fprintln(os.Stderr, "[sitelens-mcp]", err)
			return 2
		}
	}
	client, err := mcp.NewClient(*apiURL, *apiToken, 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[sitelens-mcp]", err)
		return 2
	}
	srv := mcp.NewServer(client, mcp.Options{
		ServerName: "sitelens",
		Version:    server.Version,
		Active:     *allowActive,
		MaxBytes:   *maxBytes,
		AllowHosts: splitCSV(*allowHosts),
	})

	// 诊断只走 stderr；不打印 token。
	fmt.Fprintf(os.Stderr, "[sitelens-mcp] ready v%s api=%s active=%v tools=%d\n",
		server.Version, redactedURL(*apiURL), *allowActive, len(srv.Tools()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "[sitelens-mcp] 会话结束:", err)
		return 1
	}
	return 0
}

// splitCSV 逗号分隔列表（去空白、丢空项）。
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstEnv 返回第一个非空环境变量，否则返回 def。
func firstEnv(keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	def := keys[len(keys)-1]
	for _, k := range keys[:len(keys)-1] {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return def
}

// truthyEnv 读布尔型环境变量（1/true/yes/on）。
func truthyEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// redactedURL 只保留 scheme://host，避免日志带出 userinfo/token。
func redactedURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "(invalid-url)"
	}
	return u.Scheme + "://" + u.Host
}
