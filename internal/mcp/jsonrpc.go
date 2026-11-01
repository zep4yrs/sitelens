// Package mcp：SiteLens 的 MCP（Model Context Protocol）stdio server。
//
// 定位：给渗透智能体（辰极 Lodestar 等）预留的生态调用面。只做 JSON-RPC 2.0
// over stdio（每行一个 JSON，与辰极 mcpgate 客户端一致），把 SiteLens 本地
// HTTP API 桥接成 MCP 工具；不复制引擎逻辑、不绕过既有安全闸。
//
// 设计边界：
//   - 只支持 stdio 传输（与辰极客户端同窄面；不做 HTTP/SSE、OAuth、resources）；
//   - 协议面只做 initialize / ping / tools/list / tools/call 四个方法，
//     未知方法回 -32601；
//   - 通知（无 id）收到即忽略，不回复；
//   - stdout 只写协议行，日志一律走 stderr（stdio 传输下 stdout 被协议独占）。
package mcp

import "encoding/json"

// protocolVersion 与辰极 internal/mcpgate 客户端声明一致。
// 对端声明更高版本时不作为拒绝理由：协议面不兼容会在 tools/list 上暴露。
const protocolVersion = "2024-11-05"

// JSON-RPC 2.0 标准错误码。
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// rpcRequest JSON-RPC 请求/通知。ID 为空即通知（不期待响应）。
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcError JSON-RPC 错误体。
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

// rpcResponse JSON-RPC 响应。ID 原样回显请求 id（数字/字符串均不重编码）。
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}
