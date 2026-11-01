package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// maxRequestBytes 单条 JSON-RPC 请求行上限。MCP stdio 用换行分隔，
// 超大内容（如内联 OpenAPI）应走文件路径参数，不塞进协议行。
const maxRequestBytes = 8 << 20

// Options MCP server 启动参数。
type Options struct {
	// ServerName tools/list 与 initialize 里暴露的服务名（默认 sitelens）。
	ServerName string
	// Version SiteLens 版本（由 cmd 层注入，避免包依赖 internal/server）。
	Version string
	// Active 是否启用主动工具（scan / graphql_introspect / assets）。
	// 默认 false：MCP 侧与 SiteLens 产品姿态一致，主动能力需显式开启。
	Active bool
	// MaxBytes 单次工具响应文本上限（序列化后字节数）。<=0 用 512KB。
	MaxBytes int
}

// Server MCP stdio server。
type Server struct {
	client *Client
	opts   Options
	tools  []Tool
}

// NewServer 构造 server；tools 由 newTools 一次性生成（无运行期可变状态）。
func NewServer(client *Client, opts Options) *Server {
	if opts.ServerName == "" {
		opts.ServerName = "sitelens"
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 512 << 10
	}
	s := &Server{client: client, opts: opts}
	s.tools = newTools(client, opts)
	return s
}

// Tools 返回已注册工具（含未启用的主动工具；测试/自检用）。
func (s *Server) Tools() []Tool { return s.tools }

// Serve 在 in 上读 JSON-RPC、在 out 上写响应，直到 EOF 或 ctx 取消。
// 单管道串行处理（与辰极客户端同语义）；一条请求处理失败不终止会话。
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxRequestBytes)
	bw := bufio.NewWriter(out)
	defer func() { _ = bw.Flush() }()

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil // 取消属于正常收束
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			// 解析失败：id 未知，按规范回 null。
			if werr := writeResponse(bw, rpcResponse{
				JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParseError, Message: "JSON-RPC 解析失败: " + err.Error()},
			}); werr != nil {
				return werr
			}
			continue
		}
		// 通知（无 id）：只处理生命周期通知，不回复。
		if len(req.ID) == 0 {
			continue
		}
		if werr := writeResponse(bw, s.handle(ctx, req)); werr != nil {
			return werr
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("读取 stdio 失败: %w", err)
	}
	return nil
}

// handle 分发单条请求。
func (s *Server) handle(ctx context.Context, req rpcRequest) rpcResponse {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    s.opts.ServerName,
				"version": s.opts.Version,
			},
			"instructions": "SiteLens 是验证型 Web 扫描器。先调 capabilities 确认 API 可达；" +
				"scan 提交任务后轮询 scan_status，done 后 scan_result 取带证据链的验证发现；" +
				"graph 取攻击链事实图，export 导出 SARIF/JSON；triage 标记复核结论。",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": s.toolDefs()}
	case "tools/call":
		result, err := s.callTool(ctx, req.Params)
		if err != nil {
			var re *rpcError
			if asRPCError(err, &re) {
				resp.Error = re
			} else {
				resp.Error = &rpcError{Code: codeInternalError, Message: err.Error()}
			}
			return resp
		}
		resp.Result = result
	default:
		resp.Error = &rpcError{Code: codeMethodNotFound, Message: "未知方法: " + req.Method}
	}
	return resp
}

// callTool 解析 tools/call 参数并执行。工具执行错误走 result.isError，
// 协议/参数错误走 JSON-RPC error（与 MCP 语义一致）。
func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(bytes.TrimSpace(params)) == 0 {
		return nil, &rpcError{Code: codeInvalidParams, Message: "tools/call 缺少 params"}
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "tools/call params 非法: " + err.Error()}
	}
	if p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "tools/call 缺少工具名"}
	}
	t := s.findTool(p.Name)
	if t == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "未知工具: " + p.Name}
	}
	if t.Active && !s.opts.Active {
		return toolError("主动工具未启用：请以 sitelens mcp --allow-active 启动（或设置 SITELENS_MCP_ACTIVE=1）后重试"), nil
	}
	v, err := t.Handler(ctx, p.Arguments)
	if err != nil {
		return toolError(err.Error()), nil
	}
	return toolContent(v, s.opts.MaxBytes), nil
}

// findTool 按名查找。
func (s *Server) findTool(name string) *Tool {
	for i := range s.tools {
		if s.tools[i].Name == name {
			return &s.tools[i]
		}
	}
	return nil
}

// toolDefs tools/list 输出（主动工具未启用时整条不出现，避免模型误调用）。
func (s *Server) toolDefs() []map[string]any {
	out := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		if t.Active && !s.opts.Active {
			continue
		}
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			"annotations": t.Annotations,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	return out
}

// toolContent 把 handler 返回值序列化成 MCP tool 结果。
// 超限时返回合法 JSON 包装（含 prefix），不吐半截 JSON。
func toolContent(v any, maxBytes int) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return toolError("结果序列化失败: " + err.Error())
	}
	if maxBytes <= 0 {
		maxBytes = 512 << 10
	}
	text := string(b)
	if len(b) > maxBytes {
		prefix := clipString(text, 8192)
		wrapped := map[string]any{
			"truncated":      true,
			"original_bytes": len(b),
			"note":           "结果超过单次响应上限；缩小参数（如 max_findings）或改用 export 取文件",
			"prefix":         prefix,
		}
		if wb, werr := json.Marshal(wrapped); werr == nil {
			text = string(wb)
		}
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}
}

// toolError 工具级错误（isError=true，会话继续）。
func toolError(msg string) map[string]any {
	b, _ := json.Marshal(map[string]any{"error": msg})
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": true,
	}
}

// asRPCError 判断 err 是否为 *rpcError。
func asRPCError(err error, out **rpcError) bool {
	if re, ok := err.(*rpcError); ok {
		*out = re
		return true
	}
	return false
}

// writeResponse 写一行响应并 flush（stdio 下每行一次刷新，不能攒）。
func writeResponse(w *bufio.Writer, resp rpcResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}
