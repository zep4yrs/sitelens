package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// specRoot 返回本地 API 描述文件的可读根目录（V-16）。
//
// MCP 是给智能体调用的工具面：若允许任意绝对路径，模型可被页面/文档里的
// 提示注入诱导读取 ~/.ssh/id_rsa、浏览器 Cookie 库等任意文件再 POST 给本机
// API（confused deputy）。默认根 = 环境变量 SITELENS_SPEC_ROOT，未设置时
// 回落到进程当前工作目录（与「从项目根启动」的既有约定一致）。
func specRoot() string {
	if root := strings.TrimSpace(os.Getenv("SITELENS_SPEC_ROOT")); root != "" {
		return root
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

// resolveSpecPath 校验描述文件路径位于允许根目录内，返回绝对路径。
// 判定用 filepath.Rel（而非字符串前缀）：Windows 卷标大小写与 / \ 分隔符
// 差异会让 HasPrefix 误判（同 internal/server settings.resolveOverridesPath）。
func resolveSpecPath(path string) (string, error) {
	root := specRoot()
	if root == "" {
		return "", fmt.Errorf("无法确定描述文件根目录（请设置 SITELENS_SPEC_ROOT）")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("根目录不可解析: %w", err)
	}
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("路径不可解析: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("描述文件必须位于允许目录内（%s）；可用 SITELENS_SPEC_ROOT 指定根目录", absRoot)
	}
	return absPath, nil
}

// ToolAnnotations MCP 工具注解（辰极 mcpgate 侧据此推断审批元组；
// 注意对端 DeriveTuple 的 fail-closed 口径：注解只是声明，不构成信任）。
type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint,omitempty"`
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	IdempotentHint  bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   bool `json:"openWorldHint,omitempty"`
}

// Tool 一个 MCP 工具：描述 + 输入 schema + 注解 + 执行体。
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Annotations ToolAnnotations
	// Active 主动工具：未以 --allow-active 启动时不出现在 tools/list，
	// 被直接调用也返回 isError（与 SiteLens「主动能力默认关」一致）。
	Active  bool
	Handler func(context.Context, json.RawMessage) (any, error)
}

// toolbox 工具集共享的依赖。
type toolbox struct {
	c        *Client
	active   bool
	maxBytes int
	all      []Tool
}

// newTools 构造全套工具。工具字段只读，handler 通过 toolbox 调 API。
func newTools(c *Client, opts Options) []Tool {
	tb := &toolbox{c: c, active: opts.Active, maxBytes: opts.MaxBytes}
	tools := []Tool{
		tb.capabilitiesTool(),
		tb.scanTool(),
		tb.scanStatusTool(),
		tb.scanResultTool(),
		tb.scanCancelTool(),
		tb.historyTool(),
		tb.historyGetTool(),
		tb.graphTool(),
		tb.exportTool(),
		tb.triageTool(),
		tb.apispecTool(),
		tb.graphqlTool(),
		tb.assetsTool(),
	}
	tb.all = tools
	return tools
}

// ---- 工具定义 ----

func (t *toolbox) capabilitiesTool() Tool {
	return Tool{
		Name:        "capabilities",
		Description: "探测 SiteLens API 是否可达、版本、扫描统计、主动工具是否启用，以及可用工具清单。智能体接入后的第一个调用。",
		InputSchema: objectSchema(map[string]any{}),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			out := map[string]any{
				"server":         "sitelens",
				"mcp_protocol":   protocolVersion,
				"active_enabled": t.active,
				"api":            t.c.base.Redacted(),
				"guards": []string{
					"target.Validate（SSRF/DNS rebinding/云 metadata）",
					"allow_hosts 授权白名单",
					"gov.cn 代码级硬拒",
					"主动工具默认关闭，需 --allow-active",
					"响应文本上限 " + strconv.Itoa(t.maxBytes) + " 字节",
				},
			}
			if ver, err := t.c.getJSON(ctx, "/api/version", nil); err != nil {
				out["api_reachable"] = false
				out["api_error"] = err.Error()
			} else {
				out["api_reachable"] = true
				out["api_version"] = ver["version"]
			}
			if stats, err := t.c.getJSON(ctx, "/api/stats", nil); err == nil {
				out["stats"] = stats
			}
			names := make([]string, 0, len(t.all))
			for _, tool := range t.all {
				if tool.Active && !t.active {
					continue
				}
				names = append(names, tool.Name)
			}
			out["tools"] = names
			return out, nil
		},
	}
}

func (t *toolbox) scanTool() Tool {
	return Tool{
		Name:        "scan",
		Description: "对授权目标提交一次 SiteLens 扫描（异步）。返回 job_id；用 scan_status 轮询，完成后用 scan_result 取验证发现与证据链。URL 可粘贴脏地址（缺协议/hxxp/[.]/全角），服务端会做格式归一并在响应回传 input_url/normalized_url/url_corrections。",
		Active:      true,
		InputSchema: objectSchema(map[string]any{
			"url":   strProp("目标 URL（可含缺协议/hxxp/[.]/全角等脏形式，服务端自动归一；必须已获授权，且通过 SiteLens allow_hosts / gov.cn 硬闸门）"),
			"level": enumProp("扫描档位预设；缺省由 options 决定", "quick", "standard", "deep", "full", "assets", "stealth", "apocalypse", "exhaustive"),
			"options": map[string]any{
				"type":                 "object",
				"description":          "透传 SiteLens /api/scan 的扫描选项（如 deep/dast/checks/passive/netsec/graph 等）；服务端做白名单映射",
				"additionalProperties": true,
			},
		}, "url"),
		Annotations: ToolAnnotations{OpenWorldHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			target, err := argString(m, "url", true)
			if err != nil {
				return nil, err
			}
			// 不在 MCP 层预判 URL 形态：服务端会做 URL 自动修正（补协议/hxxp/[.]/
			// 全角/默认端口等），并把 input_url/normalized_url/url_corrections 回传。
			// 这里只要求非空，格式错误由服务端返回可读错误。
			if strings.TrimSpace(target) == "" {
				return nil, fmt.Errorf("url 不能为空")
			}
			body := map[string]any{"url": target}
			if v, ok := m["options"]; ok && v != nil {
				om, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("options 必须是 JSON 对象")
				}
				for k, vv := range om {
					body[k] = vv
				}
			}
			if lv, _ := argString(m, "level", false); lv != "" {
				if !oneOf(lv, "quick", "standard", "deep", "full", "assets", "stealth", "apocalypse", "exhaustive") {
					return nil, fmt.Errorf("level 非法: %q", lv)
				}
				body["level"] = lv
			}
			out, err := t.c.postJSON(ctx, "/api/scan", nil, body)
			if err != nil {
				return nil, err
			}
			res := map[string]any{
				"job_id": out["job_id"],
				"status": "submitted",
				"hint":   "轮询 scan_status；status=done 后调 scan_result（用返回的 scan_id 或 job_id）",
			}
			// 输入 URL 自动修正（后端只改格式不改目标）：把修正回传给智能体，
			// 让它在结论里如实记录“实际扫的是哪个地址”。
			if v, ok := out["input_url"]; ok {
				res["input_url"] = v
			}
			if v, ok := out["normalized_url"]; ok {
				res["normalized_url"] = v
			}
			if v, ok := out["url_corrections"]; ok {
				res["url_corrections"] = v
			}
			return res, nil
		},
	}
}

func (t *toolbox) scanStatusTool() Tool {
	return Tool{
		Name:        "scan_status",
		Description: "查询扫描任务状态（status/progress/done/total/message/live 实时统计）；finished=true 时可用 scan_result 取结果。",
		InputSchema: objectSchema(map[string]any{
			"job_id": strProp("scan 返回的 job_id"),
		}, "job_id"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			jobID, err := argString(m, "job_id", true)
			if err != nil {
				return nil, err
			}
			out, err := t.c.getJSON(ctx, "/api/job/"+url.PathEscape(jobID), nil)
			if err != nil {
				return nil, err
			}
			status, _ := out["status"].(string)
			out["finished"] = status == "done" || status == "error" || status == "cancelled" || status == "partial"
			return out, nil
		},
	}
}

func (t *toolbox) scanResultTool() Tool {
	return Tool{
		Name:        "scan_result",
		Description: "取一次已完成扫描的验证发现（含证据链、复现命令、严重度）与技术栈摘要。未完成时返回 finished=false，不报错。",
		InputSchema: objectSchema(map[string]any{
			"job_id":           strProp("scan 返回的 job_id"),
			"max_findings":     intProp("返回发现条数上限（默认 200）"),
			"include_evidence": boolProp("是否带 request/response 原始证据（默认 true）"),
		}, "job_id"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			jobID, err := argString(m, "job_id", true)
			if err != nil {
				return nil, err
			}
			maxFindings, err := argInt(m, "max_findings", 200)
			if err != nil {
				return nil, err
			}
			if maxFindings <= 0 {
				maxFindings = 200
			}
			includeEvidence, err := argBool(m, "include_evidence", true)
			if err != nil {
				return nil, err
			}
			job, err := t.c.getJSON(ctx, "/api/job/"+url.PathEscape(jobID), nil)
			if err != nil {
				return nil, err
			}
			status, _ := job["status"].(string)
			if status != "done" {
				job["finished"] = false
				job["hint"] = "扫描未完成；先轮询 scan_status"
				return job, nil
			}
			scanID := intOf(job["scan_id"])
			if scanID <= 0 {
				return job, nil
			}
			rec, err := t.c.getJSON(ctx, fmt.Sprintf("/api/history/%d", scanID), nil)
			if err != nil {
				return nil, err
			}
			return normalizeScanRecord(rec, maxFindings, includeEvidence), nil
		},
	}
}

func (t *toolbox) scanCancelTool() Tool {
	return Tool{
		Name:        "scan_cancel",
		Description: "取消一个进行中的扫描任务（只停任务，不回滚已采结果；已采结果按 partial 落库）。",
		InputSchema: objectSchema(map[string]any{
			"job_id": strProp("要取消的 job_id"),
		}, "job_id"),
		Annotations: ToolAnnotations{IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			jobID, err := argString(m, "job_id", true)
			if err != nil {
				return nil, err
			}
			return t.c.postJSON(ctx, "/api/job/"+url.PathEscape(jobID)+"/cancel", nil, map[string]any{})
		},
	}
}

func (t *toolbox) historyTool() Tool {
	return Tool{
		Name:        "history",
		Description: "列出历史扫描记录（摘要：id/url/等级/分数/漏洞数/时间），用于让智能体选择目标记录。",
		InputSchema: objectSchema(map[string]any{
			"limit": intProp("返回条数上限（默认 20，最大 200）"),
		}),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			limit, err := argInt(m, "limit", 20)
			if err != nil {
				return nil, err
			}
			if limit <= 0 || limit > 200 {
				limit = 20
			}
			return t.c.getJSON(ctx, "/api/history", url.Values{"limit": {strconv.Itoa(limit)}})
		},
	}
}

func (t *toolbox) historyGetTool() Tool {
	return Tool{
		Name:        "history_get",
		Description: "取一条历史扫描的完整记录（含 options 与 result）。默认剔除体积大的 graph 字段；需要攻击链请用 graph。",
		InputSchema: objectSchema(map[string]any{
			"scan_id":        intProp("历史记录 id（history 或 scan_result 返回的 scan_id）"),
			"include_result": boolProp("是否带 result 明细（默认 true；false 只回摘要）"),
		}, "scan_id"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			scanID, err := argInt(m, "scan_id", 0)
			if err != nil {
				return nil, err
			}
			if scanID <= 0 {
				return nil, fmt.Errorf("scan_id 必须为正整数")
			}
			includeResult, err := argBool(m, "include_result", true)
			if err != nil {
				return nil, err
			}
			rec, err := t.c.getJSON(ctx, fmt.Sprintf("/api/history/%d", scanID), nil)
			if err != nil {
				return nil, err
			}
			if !includeResult {
				delete(rec, "result")
				return rec, nil
			}
			if res, ok := rec["result"].(map[string]any); ok {
				delete(res, "graph")
			}
			return rec, nil
		},
	}
}

func (t *toolbox) graphTool() Tool {
	return Tool{
		Name:        "graph",
		Description: "取扫描的结构化事实图/攻击链（证据驱动：入口/发现/证据/影响/权限五类节点）。view=chain 取攻击链，full 取完整事实图。",
		InputSchema: objectSchema(map[string]any{
			"scan_id": intProp("扫描记录 id"),
			"view":    enumProp("视图：chain（默认）或 full", "chain", "full"),
		}, "scan_id"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			scanID, err := argInt(m, "scan_id", 0)
			if err != nil {
				return nil, err
			}
			if scanID <= 0 {
				return nil, fmt.Errorf("scan_id 必须为正整数")
			}
			view, err := argString(m, "view", false)
			if err != nil {
				return nil, err
			}
			if view == "" {
				view = "chain"
			}
			if view != "chain" && view != "full" {
				return nil, fmt.Errorf("view 只能是 chain 或 full")
			}
			path := fmt.Sprintf("/api/graph/%d", scanID)
			if view == "chain" {
				path += "/chain"
			}
			return t.c.getJSON(ctx, path, nil)
		},
	}
}

func (t *toolbox) exportTool() Tool {
	return Tool{
		Name:        "export",
		Description: "导出扫描结果为文本（json/csv/md/html/sarif）。SARIF 2.1.0 供 CI/代码扫描平台消费；内容超限会截断并标记 truncated。",
		InputSchema: objectSchema(map[string]any{
			"scan_id": intProp("扫描记录 id"),
			"format":  enumProp("导出格式（默认 json）", "json", "csv", "md", "html", "sarif"),
		}, "scan_id"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			scanID, err := argInt(m, "scan_id", 0)
			if err != nil {
				return nil, err
			}
			if scanID <= 0 {
				return nil, fmt.Errorf("scan_id 必须为正整数")
			}
			format, err := argString(m, "format", false)
			if err != nil {
				return nil, err
			}
			if format == "" {
				format = "json"
			}
			if !oneOf(format, "json", "csv", "md", "html", "sarif") {
				return nil, fmt.Errorf("format 非法: %q", format)
			}
			body, _, err := t.c.do(ctx, "GET", fmt.Sprintf("/api/export/%d", scanID), url.Values{"fmt": {format}}, nil, "")
			if err != nil {
				return nil, err
			}
			content := string(body)
			truncated := false
			if t.maxBytes > 0 && len(content) > t.maxBytes {
				content = clipString(content, t.maxBytes)
				truncated = true
			}
			out := map[string]any{
				"scan_id":   scanID,
				"format":    format,
				"bytes":     len(body),
				"truncated": truncated,
				"content":   content,
			}
			if truncated {
				out["hint"] = "内容已截断；可调大 --max-bytes，或直接在 SiteLens 控制台导出文件"
			}
			return out, nil
		},
	}
}

func (t *toolbox) triageTool() Tool {
	return Tool{
		Name:        "triage",
		Description: "标记一条发现的复核结论（false_positive/confirmed/ignored），写入 SiteLens 本地 triage 存储；用于智能体把验证结论回流给人工复核。",
		InputSchema: objectSchema(map[string]any{
			"scan_id":     intProp("扫描记录 id"),
			"fingerprint": strProp("发现的稳定指纹（取自 export format=sarif 的 partialFingerprints，或 SiteLens 结果页；与 triage 存储同源）"),
			"verdict":     enumProp("复核结论", "false_positive", "confirmed", "ignored"),
			"note":        strProp("可选备注"),
		}, "scan_id", "fingerprint", "verdict"),
		Annotations: ToolAnnotations{},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			scanID, err := argInt(m, "scan_id", 0)
			if err != nil {
				return nil, err
			}
			if scanID <= 0 {
				return nil, fmt.Errorf("scan_id 必须为正整数")
			}
			fp, err := argString(m, "fingerprint", true)
			if err != nil {
				return nil, err
			}
			verdict, err := argString(m, "verdict", true)
			if err != nil {
				return nil, err
			}
			if !oneOf(verdict, "false_positive", "confirmed", "ignored") {
				return nil, fmt.Errorf("verdict 非法: %q", verdict)
			}
			note, _ := argString(m, "note", false)
			body := map[string]any{"fingerprint": fp, "verdict": verdict}
			if note != "" {
				body["note"] = note
			}
			return t.c.postJSON(ctx, fmt.Sprintf("/api/triage/%d", scanID), nil, body)
		},
	}
}

func (t *toolbox) apispecTool() Tool {
	return Tool{
		Name:        "apispec",
		Description: "导入并解析 OpenAPI 3.x / Swagger 2.0 / HAR 描述文件（本地文件路径或内联 JSON），返回端点清单，供后续 API 扫描规划。当前为解析面，尚未自动并入扫描管线。",
		InputSchema: objectSchema(map[string]any{
			"path":   strProp("本地描述文件绝对路径（优先于 spec；上限 8MB）"),
			"spec":   strProp("内联描述 JSON 字符串（无文件时使用）"),
			"format": enumProp("格式提示（默认 auto）", "auto", "openapi", "har"),
		}),
		Annotations: ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			format, err := argString(m, "format", false)
			if err != nil {
				return nil, err
			}
			if format == "" {
				format = "auto"
			}
			if !oneOf(format, "auto", "openapi", "har") {
				return nil, fmt.Errorf("format 非法: %q", format)
			}
			var body []byte
			if path, _ := argString(m, "path", false); path != "" {
				const maxSpec = 8 << 20
				// V-16：路径必须落在允许根目录内（SITELENS_SPEC_ROOT，默认 cwd），
				// 防止模型被提示注入诱导读取任意本地文件。
				safePath, perr := resolveSpecPath(path)
				if perr != nil {
					return nil, perr
				}
				st, serr := os.Stat(safePath)
				if serr != nil {
					return nil, fmt.Errorf("读取描述文件失败: %w", serr)
				}
				if st.IsDir() {
					return nil, fmt.Errorf("描述文件路径是目录: %s", safePath)
				}
				if st.Size() > maxSpec {
					return nil, fmt.Errorf("描述文件超过 8MB 上限")
				}
				body, serr = os.ReadFile(safePath)
				if serr != nil {
					return nil, fmt.Errorf("读取描述文件失败: %w", serr)
				}
			} else if inline, _ := argString(m, "spec", false); inline != "" {
				body = []byte(inline)
			} else {
				return nil, fmt.Errorf("path 与 spec 至少提供一个")
			}
			rawOut, _, err := t.c.do(ctx, "POST", "/api/apispec", url.Values{"fmt": {format}}, body, "application/json")
			if err != nil {
				return nil, err
			}
			var out map[string]any
			if err := json.Unmarshal(rawOut, &out); err != nil {
				return nil, fmt.Errorf("解析接口响应失败: %w", err)
			}
			out["note"] = "当前为解析面：端点尚未自动并入扫描管线；后续版本会把 endpoints 转成 DAST 目标"
			return out, nil
		},
	}
}

func (t *toolbox) graphqlTool() Tool {
	return Tool{
		Name:        "graphql_introspect",
		Description: "对一个 GraphQL 端点做一次只读 introspection（POST 固定 query），返回类型名清单。受 SiteLens SSRF 校验与 allow_hosts 白名单约束。",
		Active:      true,
		InputSchema: objectSchema(map[string]any{
			"endpoint": strProp("GraphQL 端点 URL（http/https）"),
		}, "endpoint"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			endpoint, err := argString(m, "endpoint", true)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
				return nil, fmt.Errorf("endpoint 必须是 http(s) 绝对地址")
			}
			return t.c.postJSON(ctx, "/api/apispec/graphql", nil, map[string]any{"endpoint": endpoint})
		},
	}
}

func (t *toolbox) assetsTool() Tool {
	return Tool{
		Name:        "assets",
		Description: "查询目标资产线索：证书到期/SAN（kind=cert）或端口暴露（kind=ports）。只读网络探测，受 target.Validate 与 allow_hosts 约束。",
		Active:      true,
		InputSchema: objectSchema(map[string]any{
			"kind": enumProp("查询类型", "cert", "ports"),
			"host": strProp("目标主机（可带 :port）"),
		}, "kind", "host"),
		Annotations: ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: true},
		Handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			m, err := decodeArgs(raw)
			if err != nil {
				return nil, err
			}
			kind, err := argString(m, "kind", true)
			if err != nil {
				return nil, err
			}
			host, err := argString(m, "host", true)
			if err != nil {
				return nil, err
			}
			var path string
			switch kind {
			case "cert":
				path = "/api/assets/cert-expiry"
			case "ports":
				path = "/api/assets/ports"
			default:
				return nil, fmt.Errorf("kind 只能是 cert 或 ports")
			}
			return t.c.getJSON(ctx, path, url.Values{"host": {host}})
		},
	}
}

// ---- 结果归一 ----

// normalizeScanRecord 把 /api/history/{id} 记录压成智能体友好的摘要：
// 保留摘要字段、技术栈 Top50、发现（verified 在前、intel 在后），
// 默认保留证据（request/response/replay）；单条发现内文本做限长。
func normalizeScanRecord(rec map[string]any, maxFindings int, includeEvidence bool) map[string]any {
	out := map[string]any{}
	for _, k := range []string{
		"id", "url", "host", "title", "status", "security_grade", "security_score",
		"tech_count", "vuln_count", "scanned_at", "duration",
	} {
		if v, ok := rec[k]; ok {
			out[k] = v
		}
	}
	out["scan_id"] = rec["id"]
	res, _ := rec["result"].(map[string]any)
	if res == nil {
		if v, ok := rec["result"]; ok {
			out["result"] = v
		}
		return out
	}
	for _, k := range []string{"error", "response_time_ms", "partial", "interrupted_phase"} {
		if v, ok := res[k]; ok {
			out[k] = v
		}
	}
	if techs, ok := res["technologies"].([]any); ok {
		limit := len(techs)
		if limit > 50 {
			limit = 50
			out["technologies_truncated"] = true
		}
		out["technologies"] = techs[:limit]
	}
	findings := make([]any, 0, maxFindings)
	truncated := false

	appendFinding := func(v any, source string) {
		if len(findings) >= maxFindings {
			truncated = true
			return
		}
		fm, ok := v.(map[string]any)
		if !ok {
			findings = append(findings, v)
			return
		}
		cp := make(map[string]any, len(fm)+1)
		for k, vv := range fm {
			if !includeEvidence && (k == "request" || k == "response") {
				continue
			}
			cp[k] = clipValue(vv)
		}
		cp["source"] = source
		findings = append(findings, cp)
	}
	if vs, ok := res["verified"].([]any); ok {
		for _, v := range vs {
			appendFinding(v, "verified")
		}
	}
	if vs, ok := res["vulnerabilities"].([]any); ok {
		for _, v := range vs {
			appendFinding(v, "intel")
		}
	}
	out["findings"] = findings
	out["finding_count"] = len(findings)
	if truncated {
		out["findings_truncated"] = true
	}
	if sec, ok := res["security"]; ok {
		out["security"] = sec
	}
	return out
}

// clipValue 对 finding 内字符串做限长（4KB），防止单条证据撑爆响应。
func clipValue(v any) any {
	switch x := v.(type) {
	case string:
		return clipString(x, 4096)
	case map[string]any:
		cp := make(map[string]any, len(x))
		for k, vv := range x {
			cp[k] = clipValue(vv)
		}
		return cp
	case []any:
		cp := make([]any, 0, len(x))
		for _, vv := range x {
			cp = append(cp, clipValue(vv))
		}
		return cp
	default:
		return v
	}
}

// ---- 参数与 schema 辅助 ----

func decodeArgs(raw json.RawMessage) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("arguments 不是 JSON 对象: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func argString(m map[string]any, key string, required bool) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("缺少必填参数 %q", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("参数 %q 必须是字符串", key)
	}
	s = strings.TrimSpace(s)
	if required && s == "" {
		return "", fmt.Errorf("参数 %q 不能为空", key)
	}
	return s, nil
}

func argInt(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return def, nil
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("参数 %q 不是整数", key)
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("参数 %q 必须是整数", key)
	}
}

func argBool(m map[string]any, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("参数 %q 必须是布尔值", key)
	}
	return b, nil
}

// intOf JSON 数字转 int（float64 / int / json.Number）。
func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

func oneOf(v string, vals ...string) bool {
	for _, s := range vals {
		if v == s {
			return true
		}
	}
	return false
}

func objectSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		s["required"] = req
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func enumProp(desc string, vals ...string) map[string]any {
	items := make([]any, len(vals))
	for i, v := range vals {
		items[i] = v
	}
	return map[string]any{"type": "string", "description": desc, "enum": items}
}
