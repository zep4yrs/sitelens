package apispec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// graphqlIntrospectionQuery 唯一允许发出的 GraphQL 请求：只读 introspection，
// 只取类型名。常量写死——绝不允许外部传入任意 query，从根上排除 mutation。
const graphqlIntrospectionQuery = "{__schema{types{name}}}"

// graphqlTimeout DiscoverGraphQL 的端到端超时（连接 + 发送 + 读取）。
const graphqlTimeout = 3 * time.Second

// gqlResponse introspection 响应最小结构。
type gqlResponse struct {
	Data *struct {
		Schema *struct {
			Types []struct {
				Name string `json:"name"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// DiscoverGraphQL 对 GraphQL 端点发 1 次只读 introspection
// （POST {"query":"{__schema{types{name}}}"}，3s 超时），解析类型名并返回。
//
// 安全约束（硬编码，不接受调用方 query）：只读、单次请求、绝不发送
// mutation；3s 超时；响应体 ≤8MB；端点必须是 http/https 绝对 URL。
// 失败（网络/非 2xx/GraphQL errors/坏 JSON）返回错误，不返回半成品。
func DiscoverGraphQL(endpoint string) (*Spec, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("apispec: GraphQL 端点 URL 非法: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("apispec: GraphQL 端点必须是 http/https: %q", endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("apispec: GraphQL 端点缺少主机: %q", endpoint)
	}

	reqBody, err := json.Marshal(map[string]string{"query": graphqlIntrospectionQuery})
	if err != nil {
		return nil, fmt.Errorf("apispec: 构造 introspection 请求失败: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("apispec: 构造 introspection 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: graphqlTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apispec: GraphQL introspection 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 响应体限读：多读 1 字节用于判定超限。
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("apispec: 读取 GraphQL 响应失败: %w", err)
	}
	if len(raw) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("apispec: GraphQL 端点返回 HTTP %d", resp.StatusCode)
	}

	var gr gqlResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		return nil, fmt.Errorf("apispec: GraphQL 响应不是合法 JSON: %w", err)
	}
	if len(gr.Errors) > 0 {
		msg := gr.Errors[0].Message
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return nil, fmt.Errorf("apispec: GraphQL introspection 返回错误: %s", msg)
	}
	if gr.Data == nil || gr.Data.Schema == nil {
		return nil, fmt.Errorf("apispec: GraphQL 响应缺少 data.__schema")
	}

	spec := &Spec{Source: "graphql", Title: u.Host}
	for _, t := range gr.Data.Schema.Types {
		name := strings.TrimSpace(t.Name)
		if name == "" || strings.HasPrefix(name, "__") {
			continue // 跳过 GraphQL 内建 introspection 元类型
		}
		spec.addType(name)
	}
	if len(spec.types) == 0 {
		return nil, fmt.Errorf("apispec: introspection 未返回任何类型名")
	}
	return spec, nil
}
