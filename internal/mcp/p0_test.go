package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- 确认令牌单元测试 ----

func TestConfirmerIssueConsume(t *testing.T) {
	c, err := newConfirmer()
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"url":"https://example.com/","level":"quick"}`)
	token, ttl, err := c.Issue("scan", params)
	if err != nil || token == "" || ttl <= 0 {
		t.Fatalf("签发失败 token=%q ttl=%d err=%v", token, ttl, err)
	}
	if err := c.Consume("scan", params, token); err != nil {
		t.Fatalf("首次核销应成功：%v", err)
	}
	if err := c.Consume("scan", params, token); err == nil {
		t.Fatal("令牌应单次有效，重放必须失败")
	}
}

func TestConfirmerBindsParamsAndTool(t *testing.T) {
	c, _ := newConfirmer()
	token, _, _ := c.Issue("scan", json.RawMessage(`{"url":"https://example.com/"}`))
	if err := c.Consume("scan", json.RawMessage(`{"url":"https://evil.com/"}`), token); err == nil {
		t.Fatal("参数被修改时令牌必须失效")
	}
	if err := c.Consume("assets", json.RawMessage(`{"url":"https://example.com/"}`), token); err == nil {
		t.Fatal("工具名不匹配时令牌必须失效")
	}
}

func TestConfirmerRejectsTamperedToken(t *testing.T) {
	c, _ := newConfirmer()
	token, _, _ := c.Issue("scan", json.RawMessage(`{"url":"https://example.com/"}`))
	if err := c.Consume("scan", json.RawMessage(`{"url":"https://example.com/"}`), token+"x"); err == nil {
		t.Fatal("被篡改的令牌必须拒绝")
	}
}

// ---- Pre-flight 范围检查 ----

func TestPreflightScope(t *testing.T) {
	params := json.RawMessage(`{"url":"https://sub.example.com/a"}`)
	if _, err := preflightScope("scan", nil, params); err == nil ||
		!strings.Contains(err.Error(), "allow_hosts") {
		t.Fatalf("未配置 allow_hosts 必须拒绝：%v", err)
	}
	if _, err := preflightScope("scan", []string{"example.com"}, json.RawMessage(`{}`)); err == nil {
		t.Fatal("参数无目标必须拒绝")
	}
	if _, err := preflightScope("scan", []string{"other.com"}, params); err == nil ||
		!strings.Contains(err.Error(), "白名单") {
		t.Fatalf("越权目标必须拒绝：%v", err)
	}
	hosts, err := preflightScope("scan", []string{"*.example.com"}, params)
	if err != nil || len(hosts) != 1 || hosts[0] != "sub.example.com" {
		t.Fatalf("通配白名单应放行 sub.example.com：hosts=%v err=%v", hosts, err)
	}
}

// ---- 端到端：危险工具必须带一次性令牌 ----

func newConfirmServer(t *testing.T, apiURL string, allow []string) *Server {
	t.Helper()
	c, err := NewClient(apiURL, "", 5e9)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(c, Options{Version: "test", Active: true, MaxBytes: 512 << 10, AllowHosts: allow})
}

func TestDangerousToolRequiresToken(t *testing.T) {
	f := newFakeAPI(t)
	s := newConfirmServer(t, f.srv.URL, []string{"example.com"})

	// 无令牌 → 拒绝，并提示先调 confirm_action。
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "scan", map[string]any{"url": "https://example.com/"}))[0])
	if !isErr || !strings.Contains(text, "confirm_token") {
		t.Fatalf("无令牌调用应被拒绝并提示 confirm_token：isErr=%v text=%s", isErr, text)
	}

	// 越权目标签发 → 拒绝。
	text, isErr = toolResult(t, runRPC(t, s, toolCallReq(1, "confirm_action", map[string]any{
		"tool": "scan", "params": map[string]any{"url": "https://evil.com/"},
	}))[0])
	if !isErr || !strings.Contains(text, "白名单") {
		t.Fatalf("越权目标签发应被拒绝：isErr=%v text=%s", isErr, text)
	}

	// 合法签发 → 带令牌调用成功 → 令牌重放失败。
	text, isErr = toolResult(t, runRPC(t, s, toolCallReq(1, "confirm_action", map[string]any{
		"tool": "scan", "params": map[string]any{"url": "https://example.com/"},
	}))[0])
	if isErr {
		t.Fatalf("合法签发不应失败：%s", text)
	}
	var issued map[string]any
	if err := json.Unmarshal([]byte(text), &issued); err != nil {
		t.Fatalf("签发结果不是 JSON：%v %s", err, text)
	}
	token, _ := issued["confirm_token"].(string)
	if token == "" {
		t.Fatalf("签发结果缺少 confirm_token：%s", text)
	}
	text, isErr = toolResult(t, runRPC(t, s, toolCallReq(1, "scan", map[string]any{
		"url": "https://example.com/", "confirm_token": token,
	}))[0])
	if isErr {
		t.Fatalf("带合法令牌的调用不应失败：%s", text)
	}
	// 重放同一令牌 → 拒绝。
	text, isErr = toolResult(t, runRPC(t, s, toolCallReq(1, "scan", map[string]any{
		"url": "https://example.com/", "confirm_token": token,
	}))[0])
	if !isErr || !strings.Contains(text, "已被使用") {
		t.Fatalf("令牌重放应被拒绝：isErr=%v text=%s", isErr, text)
	}
}

func TestDangerousToolRefusedWithoutAllowHosts(t *testing.T) {
	f := newFakeAPI(t)
	s := newConfirmServer(t, f.srv.URL, nil)
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(1, "confirm_action", map[string]any{
		"tool": "scan", "params": map[string]any{"url": "https://example.com/"},
	}))[0])
	if !isErr || !strings.Contains(text, "allow_hosts") {
		t.Fatalf("未配置 allow_hosts 时危险工具必须拒绝：isErr=%v text=%s", isErr, text)
	}
}

// withConfirm 走 confirm_action 拿一次性令牌并合并进参数（危险工具测试用）。
func withConfirm(t *testing.T, s *Server, tool string, args map[string]any) map[string]any {
	t.Helper()
	text, isErr := toolResult(t, runRPC(t, s, toolCallReq(99, "confirm_action", map[string]any{"tool": tool, "params": args}))[0])
	if isErr {
		t.Fatalf("confirm_action 失败: %s", text)
	}
	var issued map[string]any
	if err := json.Unmarshal([]byte(text), &issued); err != nil {
		t.Fatalf("confirm_action 结果不是 JSON: %v %s", err, text)
	}
	tok, _ := issued["confirm_token"].(string)
	if tok == "" {
		t.Fatalf("confirm_action 缺少 confirm_token: %s", text)
	}
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out["confirm_token"] = tok
	return out
}
