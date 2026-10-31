// Package apispec 解析 API 规格与请求记录，抽取可被扫描器消费的端点清单。
//
// 本包零外部依赖（仅标准库），全部解析离线进行：不执行任何内容，不抓取
// 外部 $ref（$ref 只记录名称），不访问网络（DiscoverGraphQL 例外——它按
// 协议发 1 次只读 introspection，绝不发送 mutation）。
package apispec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxInputBytes 单次解析允许的最大输入（8MB）。OpenAPI/HAR 文档与 GraphQL
// 响应都受此上限约束，防止超大文档拖垮内存。
const MaxInputBytes = 8 << 20

var (
	// ErrTooLarge 输入超过 MaxInputBytes。
	ErrTooLarge = errors.New("apispec: 输入超过 8MB 上限")
	// ErrUnsupportedYAML 输入看起来是 YAML。本包零依赖、标准库无 YAML
	// 解析器，因此明确返回 unsupported 而不是静默失败或自行实现半吊子
	// YAML。（保留扩展点：调用方可自行转 JSON 后重试。）
	ErrUnsupportedYAML = errors.New("apispec: 不支持 YAML（仅支持 JSON；本包零依赖）")
	// ErrUnsupportedSpec 不是 OpenAPI 3.x / Swagger 2.0 规格。
	ErrUnsupportedSpec = errors.New("apispec: 不支持的规格版本（需要 OpenAPI 3.x 或 Swagger 2.0）")
)

// Endpoint 一个 API 端点：方法 + 路径 + 参数名候选（query/body/路径参数名）。
type Endpoint struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Params []string `json:"params,omitempty"`
}

// Spec 一次解析的产物。内容只读语义：Endpoints/Types/Refs 均返回副本，
// 调用方无法反向篡改内部集合。
type Spec struct {
	Source   string `json:"source"`              // openapi3 / swagger2 / har / graphql
	Version  string `json:"version,omitempty"`   // 原始版本号（如 "3.0.3" / "2.0"）
	Title    string `json:"title,omitempty"`     // info.title
	BasePath string `json:"base_path,omitempty"` // Swagger2 basePath / OpenAPI servers 基路径

	endpoints []Endpoint
	types     []string // GraphQL 类型名
	refs      []string // 仅记录名称的 $ref（从不抓取）
}

// Endpoints 返回端点清单副本（顺序即解析时的稳定顺序）。
func (s *Spec) Endpoints() []Endpoint {
	if s == nil || len(s.endpoints) == 0 {
		return nil
	}
	out := make([]Endpoint, len(s.endpoints))
	for i, e := range s.endpoints {
		cp := e
		cp.Params = append([]string(nil), e.Params...)
		out[i] = cp
	}
	return out
}

// Types 返回 GraphQL 类型名副本（非 GraphQL 规格返回 nil）。
func (s *Spec) Types() []string {
	if s == nil || len(s.types) == 0 {
		return nil
	}
	return append([]string(nil), s.types...)
}

// Refs 返回解析过程中遇到的 $ref 名称副本（如
// "#/components/schemas/Pet"）。只记录、从不抓取外部内容。
func (s *Spec) Refs() []string {
	if s == nil || len(s.refs) == 0 {
		return nil
	}
	return append([]string(nil), s.refs...)
}

// Len 端点数量。
func (s *Spec) Len() int {
	if s == nil {
		return 0
	}
	return len(s.endpoints)
}

// AddEndpoint 追加一个端点（method 统一大写、path 去首尾空白；空 path 忽略）。
// 参数名按出现顺序去重合并。供解析器与调用方构造 Spec 使用。
func (s *Spec) AddEndpoint(method, path string, params ...string) {
	if s == nil {
		return
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	s.endpoints = append(s.endpoints, Endpoint{
		Method: method,
		Path:   path,
		Params: dedupStrings(params),
	})
}

// Dedup 按 (method, path) 去重端点，合并同键端点的参数名（保持首次出现
// 顺序）。解析器在返回前已调用；调用方追加端点后可再次调用。
func (s *Spec) Dedup() {
	if s == nil || len(s.endpoints) < 2 {
		return
	}
	idx := make(map[string]int, len(s.endpoints))
	out := s.endpoints[:0]
	for _, e := range s.endpoints {
		key := e.Method + "\x00" + e.Path
		if i, ok := idx[key]; ok {
			out[i].Params = mergeParams(out[i].Params, e.Params)
			continue
		}
		idx[key] = len(out)
		cp := e
		cp.Params = append([]string(nil), e.Params...)
		out = append(out, cp)
	}
	s.endpoints = out
}

// addType 内部使用：追加 GraphQL 类型名（去重、跳过空名）。
func (s *Spec) addType(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	for _, t := range s.types {
		if t == name {
			return
		}
	}
	s.types = append(s.types, name)
}

// addRef 内部使用：记录 $ref 名称（去重、跳过空名），从不解析/抓取。
func (s *Spec) addRef(ref string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return
	}
	for _, r := range s.refs {
		if r == ref {
			return
		}
	}
	s.refs = append(s.refs, ref)
}

// dedupStrings 按出现顺序去重并剔除空串。
func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeParams 把 add 中未出现过的参数名追加到 base 末尾。
func mergeParams(base, add []string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]string, 0, len(base)+len(add))
	for _, v := range base {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, v := range add {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// checkSize 输入大小门禁（所有解析入口共用）。
func checkSize(data []byte) error {
	if len(data) > MaxInputBytes {
		return fmt.Errorf("%w: %d 字节", ErrTooLarge, len(data))
	}
	return nil
}

// trimBOM 去掉 UTF-8 BOM 与首尾空白。
func trimBOM(data []byte) []byte {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return data
}

// looksJSON 首字符为 '{' 或 '[' 视为 JSON；否则按 YAML/未知处理。
func looksJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// sortedKeys 返回 map 键的字典序拷贝（JSON 对象无序，输出必须确定）。
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 小集合插入排序即可，避免额外依赖 sort 之外的东西（stdlib sort 也 OK）。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// jsonDecodeStrict 解析 JSON；用于需要"非法 JSON 明确报错"的场景。
func jsonDecodeStrict(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("apispec: JSON 解析失败: %w", err)
	}
	return nil
}
