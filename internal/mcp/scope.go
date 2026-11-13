package mcp

// 危险工具 Pre-flight 范围检查 + 确认令牌签发工具（5.3 P0）。
//
// 与引擎同一份 allow_hosts 语义（target.Allowed：精确域名 / "*.example.com" 后缀）。
// 设计取舍（fail-closed）：
//   - 未配置 allow_hosts → 拒绝签发令牌（没有可核验的授权范围，就不给危险操作授权）；
//   - 参数里找不到可识别的目标（url/endpoint/host…）→ 拒绝（无法做范围校验）；
//   - 任一目标不在白名单 → 拒绝，并指明具体 host。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// targetArgKeys 参数中可能携带扫描/探测目标的键。
var targetArgKeys = []string{"url", "endpoint", "host", "base_url", "target"}

// normalizeScopeTarget 把用户输入的脏目标（hxxp/[.]/全角括号/缺协议）归一为可解析 URL。
func normalizeScopeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "[.]", ".")
	s = strings.ReplaceAll(s, "(.)", ".")
	s = strings.ReplaceAll(s, "hxxps", "https")
	s = strings.ReplaceAll(s, "hxxp", "http")
	s = strings.Trim(s, "。，,;； \t")
	return s
}

// hostOfTarget 从参数值提取 host（支持 URL / host:port / 纯域名）。
func hostOfTarget(raw string) string {
	s := normalizeScopeTarget(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	// 无协议：按 //host[:port] 解析，失败再退回原串去端口。
	if u, err := url.Parse("//" + s); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(strings.Trim(h, "[]"))
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}

// extractTargets 从工具参数里提取所有目标（含数组型 urls/targets/hosts）。
func extractTargets(raw json.RawMessage) []string {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	var out []string
	for _, k := range targetArgKeys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	for _, k := range []string{"urls", "targets", "hosts"} {
		if arr, ok := m[k].([]any); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// preflightScope 危险操作范围检查：allow_hosts 为空 → 拒绝；目标缺失/越权 → 拒绝。
func preflightScope(toolName string, allow []string, raw json.RawMessage) ([]string, error) {
	if len(allow) == 0 {
		return nil, fmt.Errorf("危险工具 %s 需要先配置 allow_hosts（启动参数 --allow-hosts 或环境变量 SITELENS_MCP_ALLOW_HOSTS，如 example.com,*.corp.example）；未配置授权范围时一律拒绝", toolName)
	}
	targets := extractTargets(raw)
	if len(targets) == 0 {
		return nil, fmt.Errorf("危险工具 %s 必须显式给出目标（url/endpoint/host），无法做 allow_hosts 范围校验", toolName)
	}
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		h := hostOfTarget(t)
		if h == "" {
			return nil, fmt.Errorf("无法从目标 %q 解析主机名，已拒绝（fail-closed）", t)
		}
		if !target.Allowed(h, allow) {
			return nil, fmt.Errorf("目标 %s 不在 allow_hosts 授权白名单内（已拒绝，未发出任何请求）", h)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// confirmTool 危险操作确认令牌签发工具（只读、不触达目标）。
func (t *toolbox) confirmTool() Tool {
	return Tool{
		Name: "confirm_action",
		Description: "为危险工具（scan / graphql_introspect / assets）签发一次性确认令牌。" +
			"先做 allow_hosts Pre-flight 范围检查，再对「工具名 + 规范化参数」做 HMAC 绑定；令牌 TTL 60s、单次有效。" +
			"调用危险工具时把返回的 confirm_token 放进参数即可。未配置 allow_hosts 时拒绝签发。",
		InputSchema: objectSchema(map[string]any{
			"tool":   strProp("要授权的危险工具名（scan / graphql_introspect / assets）"),
			"params": map[string]any{"type": "object", "description": "该工具将要使用的完整参数（必须与实际调用一致，否则令牌不匹配）", "additionalProperties": true},
		}, "tool", "params"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: false},
		Handler: func(_ context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			name, err := argString(m, "tool", true)
			if err != nil {
				return nil, err
			}
			var tool *Tool
			for i := range t.all {
				if t.all[i].Name == name {
					tool = &t.all[i]
					break
				}
			}
			if tool == nil || !tool.Dangerous {
				return nil, fmt.Errorf("%q 不是危险工具，无需确认令牌", name)
			}
			if !t.active {
				return nil, fmt.Errorf("主动工具未启用：请以 sitelens mcp --allow-active 启动后再签发令牌")
			}
			paramsRaw, _ := json.Marshal(m["params"])
			if m["params"] == nil {
				paramsRaw = json.RawMessage("{}")
			}
			hosts, err := preflightScope(tool.Name, t.scope, paramsRaw)
			if err != nil {
				return nil, err
			}
			if t.conf == nil {
				return nil, fmt.Errorf("确认令牌服务不可用（fail-closed），危险工具已拒绝")
			}
			token, ttl, err := t.conf.Issue(tool.Name, paramsRaw)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"confirm_token":       token,
				"expires_in_seconds":  ttl,
				"tool":                tool.Name,
				"scope_checked_hosts": hosts,
				"note":                "令牌单次有效、60s 过期，且与 params 绑定；参数任何改动都需要重新签发。",
			}, nil
		},
	}
}
