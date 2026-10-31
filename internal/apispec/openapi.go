package apispec

import (
	"fmt"
	"strings"
)

// oaDoc OpenAPI 3.x / Swagger 2.0 的最小公共结构（只声明本包需要的字段；
// 未声明字段忽略，不追求完整规格覆盖）。
type oaDoc struct {
	OpenAPI string `json:"openapi"`
	Swagger string `json:"swagger"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	BasePath string `json:"basePath"` // Swagger 2.0
	Servers  []struct {
		URL string `json:"url"`
	} `json:"servers"` // OpenAPI 3.x
	Paths map[string]oaPathItem `json:"paths"`
}

type oaPathItem struct {
	Ref        string       `json:"$ref"`
	Get        *oaOperation `json:"get"`
	Put        *oaOperation `json:"put"`
	Post       *oaOperation `json:"post"`
	Delete     *oaOperation `json:"delete"`
	Options    *oaOperation `json:"options"`
	Head       *oaOperation `json:"head"`
	Patch      *oaOperation `json:"patch"`
	Trace      *oaOperation `json:"trace"`
	Parameters []oaParam    `json:"parameters"` // 路径级公共参数
}

type oaOperation struct {
	Parameters  []oaParam      `json:"parameters"`
	RequestBody *oaBody        `json:"requestBody"`
	Deprecated  bool           `json:"deprecated"`
	Responses   map[string]any `json:"responses"`
}

type oaBody struct {
	Ref     string                 `json:"$ref"`
	Content map[string]oaMediaType `json:"content"`
}

type oaMediaType struct {
	Schema *oaSchema `json:"schema"`
}

type oaParam struct {
	Ref    string    `json:"$ref"`
	Name   string    `json:"name"`
	In     string    `json:"in"`
	Schema *oaSchema `json:"schema"` // OpenAPI 3.x
	Type   string    `json:"type"`   // Swagger 2.0 非 body 参数
	Items  *oaSchema `json:"items"`
}

// oaSchema 只覆盖字段名提取需要的最小 schema 子集。$ref 只记录不解析。
type oaSchema struct {
	Ref        string               `json:"$ref"`
	Type       string               `json:"type"`
	Properties map[string]*oaSchema `json:"properties"`
	Items      *oaSchema            `json:"items"`
	AllOf      []*oaSchema          `json:"allOf"`
}

// oaMethodOrder 输出方法顺序固定（JSON 对象无序 → 必须显式排序，保证
// 同一文档多次解析得到逐字节一致的结果）。
var oaMethodOrder = []struct {
	name string
	get  func(*oaPathItem) *oaOperation
}{
	{"GET", func(p *oaPathItem) *oaOperation { return p.Get }},
	{"PUT", func(p *oaPathItem) *oaOperation { return p.Put }},
	{"POST", func(p *oaPathItem) *oaOperation { return p.Post }},
	{"DELETE", func(p *oaPathItem) *oaOperation { return p.Delete }},
	{"OPTIONS", func(p *oaPathItem) *oaOperation { return p.Options }},
	{"HEAD", func(p *oaPathItem) *oaOperation { return p.Head }},
	{"PATCH", func(p *oaPathItem) *oaOperation { return p.Patch }},
	{"TRACE", func(p *oaPathItem) *oaOperation { return p.Trace }},
}

// ParseOpenAPI 解析 OpenAPI 3.x / Swagger 2.0 的 JSON 文档。
//
// 支持的抽取项：paths 下的方法、路径/query/formData 参数名、requestBody
// （或 Swagger2 body 参数）schema 的顶层字段名。$ref 只记录名称，绝不解析
// 或抓取外部文档。YAML 输入返回 ErrUnsupportedYAML（本包零依赖，标准库
// 没有 YAML 解析器，不引入新依赖）。
func ParseOpenAPI(data []byte) (*Spec, error) {
	if err := checkSize(data); err != nil {
		return nil, err
	}
	body := trimBOM(data)
	if len(body) == 0 {
		return nil, fmt.Errorf("apispec: 空输入")
	}
	if !looksJSON(body) {
		return nil, ErrUnsupportedYAML
	}
	var doc oaDoc
	if err := jsonDecodeStrict(body, &doc); err != nil {
		return nil, err
	}

	var spec *Spec
	switch {
	case doc.OpenAPI != "":
		if !strings.HasPrefix(doc.OpenAPI, "3.") {
			return nil, fmt.Errorf("%w: openapi=%q", ErrUnsupportedSpec, doc.OpenAPI)
		}
		spec = &Spec{Source: "openapi3", Version: doc.OpenAPI, Title: doc.Info.Title}
		// OpenAPI 3.x 的 servers[0].url 可能含基路径（如 /api/v3）：只作为
		// BasePath 展示，端点 Path 保持文档原样，避免拼接歧义。
		if len(doc.Servers) > 0 {
			if base := serverBasePath(doc.Servers[0].URL); base != "" {
				spec.BasePath = base
			}
		}
	case doc.Swagger != "":
		if doc.Swagger != "2.0" {
			return nil, fmt.Errorf("%w: swagger=%q", ErrUnsupportedSpec, doc.Swagger)
		}
		spec = &Spec{Source: "swagger2", Version: doc.Swagger, Title: doc.Info.Title,
			BasePath: doc.BasePath}
	default:
		return nil, ErrUnsupportedSpec
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("apispec: 文档没有 paths")
	}

	for _, path := range sortedKeys(doc.Paths) {
		item := doc.Paths[path]
		if item.Ref != "" {
			// 路径项本身是 $ref：只记录名称，不解析（防外部引用抓取）。
			spec.addRef(item.Ref)
		}
		if p := normalizePath(path); p != "" {
			for _, m := range oaMethodOrder {
				op := m.get(&item)
				if op == nil {
					continue
				}
				spec.AddEndpoint(m.name, p, oaEndpointParams(item.Parameters, op, spec)...)
			}
		}
	}
	spec.Dedup()
	return spec, nil
}

// serverBasePath 从 server URL 中抽取路径部分（忽略协议/主机），失败返回空。
func serverBasePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return strings.TrimRight(rest[j:], "/")
		}
		return ""
	}
	return ""
}

// normalizePath 路径统一以 "/" 开头；空路径丢弃。
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// oaEndpointParams 提取一个端点的参数名候选：
//  1. path 级 parameters + operation 级 parameters（任意 in，包含 query/header/
//     path/cookie/formData；$ref 只登记名称）；
//  2. operation.requestBody（OpenAPI3）或 body 参数（Swagger2）的 schema 顶层
//     字段名；数组取 item 对象字段。
//
// 顺序：参数按声明顺序，body 字段按字母序（JSON 对象无序，需确定输出）。
func oaEndpointParams(pathParams []oaParam, op *oaOperation, spec *Spec) []string {
	var raw []string
	collect := func(ps []oaParam) {
		for _, p := range ps {
			if p.Ref != "" {
				spec.addRef(p.Ref)
				continue
			}
			if p.In == "body" {
				// Swagger2 的 body 参数名（如 "body"）不是请求体字段，只取 schema 字段。
				if p.Schema != nil {
					raw = append(raw, schemaFieldNames(p.Schema, spec)...)
				}
				continue
			}
			if p.Name != "" {
				raw = append(raw, p.Name)
			}
		}
	}
	collect(pathParams)
	collect(op.Parameters)
	if op.RequestBody != nil {
		if op.RequestBody.Ref != "" {
			spec.addRef(op.RequestBody.Ref)
		}
		for _, mt := range sortedKeys(op.RequestBody.Content) {
			if sch := op.RequestBody.Content[mt].Schema; sch != nil {
				raw = append(raw, schemaFieldNames(sch, spec)...)
			}
		}
	}
	return dedupStrings(raw)
}

// schemaFieldNames 抽取 schema 的顶层字段名；$ref 只记录、不解析。
// 仅下钻一层：对象字段直接计入，数组取 item 对象字段（够 DAST 复用即可，
// 不递归展开嵌套对象，避免超大 schema 爆炸）。
func schemaFieldNames(sch *oaSchema, spec *Spec) []string {
	if sch == nil {
		return nil
	}
	if sch.Ref != "" {
		spec.addRef(sch.Ref)
		return nil
	}
	var out []string
	add := func(m map[string]*oaSchema) {
		for _, name := range sortedKeys(m) {
			out = append(out, name)
		}
	}
	if len(sch.Properties) > 0 {
		add(sch.Properties)
		// 数组字段（如 tags: [{id}]）的 item 对象字段名也纳入：它们同样是
		// 可被注入的请求体字段。只下钻一层，不递归展开任意深度。
		for _, name := range sortedKeys(sch.Properties) {
			p := sch.Properties[name]
			if p == nil {
				continue
			}
			if p.Ref != "" {
				spec.addRef(p.Ref)
			}
			if p.Items != nil {
				if p.Items.Ref != "" {
					spec.addRef(p.Items.Ref)
				}
				if len(p.Items.Properties) > 0 {
					add(p.Items.Properties)
				}
			}
		}
	}
	if sch.Items != nil {
		if sch.Items.Ref != "" {
			spec.addRef(sch.Items.Ref)
		}
		if len(sch.Items.Properties) > 0 {
			add(sch.Items.Properties)
		}
	}
	for _, sub := range sch.AllOf {
		out = append(out, schemaFieldNames(sub, spec)...)
	}
	return out
}
