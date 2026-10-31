package apispec

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const openapiV3Sample = `{
  "openapi": "3.0.3",
  "info": {"title": "Pet API", "version": "1.0.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/pets": {
      "get": {
        "parameters": [
          {"name": "limit", "in": "query", "schema": {"type": "integer"}},
          {"$ref": "#/components/parameters/Offset"}
        ],
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "tags": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}}}}
                }
              }
            }
          }
        },
        "responses": {"201": {"description": "created"}}
      }
    },
    "/pets/{petId}": {
      "get": {
        "parameters": [
          {"name": "petId", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "X-Trace", "in": "header"}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

const swaggerV2Sample = `{
  "swagger": "2.0",
  "info": {"title": "Legacy API", "version": "2.0"},
  "basePath": "/api",
  "paths": {
    "/login": {
      "post": {
        "parameters": [
          {"name": "username", "in": "formData", "type": "string"},
          {"name": "password", "in": "formData", "type": "string"}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/users": {
      "get": {
        "parameters": [{"name": "page", "in": "query", "type": "integer"}],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/orders": {
      "post": {
        "parameters": [{"name": "body", "in": "body", "schema": {"$ref": "#/definitions/Order"}}],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func TestParseOpenAPIv3(t *testing.T) {
	spec, err := ParseOpenAPI([]byte(openapiV3Sample))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if spec.Source != "openapi3" || spec.Version != "3.0.3" || spec.Title != "Pet API" {
		t.Fatalf("头部字段异常: source=%q version=%q title=%q", spec.Source, spec.Version, spec.Title)
	}
	if spec.BasePath != "/v1" {
		t.Fatalf("BasePath 应取 servers 路径: %q", spec.BasePath)
	}
	want := []Endpoint{
		{Method: "GET", Path: "/pets", Params: []string{"limit"}},
		{Method: "POST", Path: "/pets", Params: []string{"name", "tags", "id"}},
		{Method: "GET", Path: "/pets/{petId}", Params: []string{"petId", "X-Trace"}},
	}
	if got := spec.Endpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("端点不符:\n got=%+v\nwant=%+v", got, want)
	}
	if refs := spec.Refs(); !reflect.DeepEqual(refs, []string{"#/components/parameters/Offset"}) {
		t.Fatalf("$ref 应只记录不解析: %v", refs)
	}

	// 同一文档多次解析必须逐字节一致（JSON 对象无序，输出需稳定）。
	again, err := ParseOpenAPI([]byte(openapiV3Sample))
	if err != nil {
		t.Fatalf("二次解析: %v", err)
	}
	if !reflect.DeepEqual(spec, again) {
		t.Fatal("解析结果不确定（顺序不稳定）")
	}
}

func TestParseSwagger2(t *testing.T) {
	spec, err := ParseOpenAPI([]byte(swaggerV2Sample))
	if err != nil {
		t.Fatalf("ParseOpenAPI(swagger2): %v", err)
	}
	if spec.Source != "swagger2" || spec.Version != "2.0" || spec.BasePath != "/api" {
		t.Fatalf("swagger2 头部异常: %+v", spec)
	}
	want := []Endpoint{
		{Method: "POST", Path: "/login", Params: []string{"username", "password"}},
		{Method: "POST", Path: "/orders"}, // body 参数名不算字段，只记录 $ref
		{Method: "GET", Path: "/users", Params: []string{"page"}},
	}
	if got := spec.Endpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("端点不符:\n got=%+v\nwant=%+v", got, want)
	}
	if refs := spec.Refs(); !reflect.DeepEqual(refs, []string{"#/definitions/Order"}) {
		t.Fatalf("body $ref 应只记录: %v", refs)
	}
}

func TestParseOpenAPIYAMLUnsupported(t *testing.T) {
	_, err := ParseOpenAPI([]byte("openapi: 3.0.0\ninfo:\n  title: X\npaths: {}\n"))
	if !errors.Is(err, ErrUnsupportedYAML) {
		t.Fatalf("YAML 应返回 ErrUnsupportedYAML，实际: %v", err)
	}
	// HAR 入口同样对 YAML 明确 unsupported。
	if _, err := ParseHAR([]byte("log:\n  entries: []\n")); !errors.Is(err, ErrUnsupportedYAML) {
		t.Fatalf("HAR YAML 应返回 ErrUnsupportedYAML，实际: %v", err)
	}
}

func TestParseOpenAPIInvalid(t *testing.T) {
	if _, err := ParseOpenAPI([]byte("{not json")); err == nil || errors.Is(err, ErrUnsupportedYAML) {
		t.Fatalf("坏 JSON 应返回解析错误而非 YAML unsupported: %v", err)
	}
	if _, err := ParseOpenAPI(nil); err == nil {
		t.Fatal("空输入应报错")
	}
	if _, err := ParseOpenAPI([]byte(`{"openapi":"4.0.0","paths":{"/x":{}}}`)); !errors.Is(err, ErrUnsupportedSpec) {
		t.Fatalf("未知版本应返回 ErrUnsupportedSpec: %v", err)
	}
	if _, err := ParseOpenAPI([]byte(`{"openapi":"3.0.0"}`)); err == nil {
		t.Fatal("无 paths 应报错")
	}
}

func TestOversizeRejected(t *testing.T) {
	data := append([]byte(`{"openapi":"3.0.0","paths":{}}`), bytes.Repeat([]byte(" "), MaxInputBytes)...)
	if _, err := ParseOpenAPI(data); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超大 OpenAPI 输入应返回 ErrTooLarge: %v", err)
	}
	if _, err := ParseHAR(data); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超大 HAR 输入应返回 ErrTooLarge: %v", err)
	}
}

const harSample = `{
  "log": {
    "version": "1.2",
    "entries": [
      {"request": {"method": "GET", "url": "https://shop.example.com/api/items?page=2&size=20",
        "query": [{"name": "page"}, {"name": "size"}]}},
      {"request": {"method": "GET", "url": "https://shop.example.com/api/items?size=20&page=2",
        "query": [{"name": "size"}, {"name": "page"}]}},
      {"request": {"method": "POST", "url": "https://shop.example.com/api/items",
        "postData": {"mimeType": "application/x-www-form-urlencoded",
          "params": [{"name": "name"}, {"name": "price"}]}}},
      {"request": {"method": "POST", "url": "https://shop.example.com/api/login",
        "postData": {"mimeType": "application/json", "text": "{\"username\":\"u\",\"password\":\"p\"}"}}},
      {"request": {"method": "POST", "url": "https://shop.example.com/oauth/token",
        "postData": {"mimeType": "application/x-www-form-urlencoded",
          "text": "grant_type=password&scope=all"}}},
      {"request": {"method": "GET", "url": "not-a-url", "query": []}}
    ]
  }
}`

func TestParseHAR(t *testing.T) {
	spec, err := ParseHAR([]byte(harSample))
	if err != nil {
		t.Fatalf("ParseHAR: %v", err)
	}
	if spec.Source != "har" || spec.Version != "1.2" {
		t.Fatalf("HAR 头部异常: %+v", spec)
	}
	want := []Endpoint{
		{Method: "GET", Path: "/api/items", Params: []string{"page", "size"}},
		{Method: "POST", Path: "/api/items", Params: []string{"name", "price"}},
		{Method: "POST", Path: "/api/login", Params: []string{"password", "username"}},
		{Method: "POST", Path: "/oauth/token", Params: []string{"grant_type", "scope"}},
	}
	if got := spec.Endpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("HAR 端点不符（含去重/参数合并）:\n got=%+v\nwant=%+v", got, want)
	}
	// 重复 GET 条目合并后仍只有一条 GET /api/items。
	n := 0
	for _, e := range spec.Endpoints() {
		if e.Method == "GET" && e.Path == "/api/items" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("重复条目应去重，GET /api/items 出现 %d 次", n)
	}
}

func TestSpecAddEndpointAndDedup(t *testing.T) {
	s := &Spec{Source: "test"}
	s.AddEndpoint("get", "/x", "a")
	s.AddEndpoint("GET", "/x", "b", "a")
	s.AddEndpoint("post", "/x", "c")
	s.Dedup()
	eps := s.Endpoints()
	if len(eps) != 2 {
		t.Fatalf("去重后端点数应为 2: %+v", eps)
	}
	if eps[0].Method != "GET" || !reflect.DeepEqual(eps[0].Params, []string{"a", "b"}) {
		t.Fatalf("参数合并/顺序不符: %+v", eps[0])
	}
	// Endpoints 返回副本：外部修改不得影响内部状态。
	eps[0].Params[0] = "HACKED"
	if got := s.Endpoints()[0].Params[0]; got != "a" {
		t.Fatalf("Endpoints 应返回副本，内部被外部篡改: %q", got)
	}
}

func TestDiscoverGraphQLSuccessAndReadOnly(t *testing.T) {
	var calls int32
	var gotMethod, gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"__schema":{"types":[
			{"name":"Query"},{"name":"User"},{"name":"__Type"},{"name":"Query"}]}}}`)
	}))
	defer srv.Close()

	spec, err := DiscoverGraphQL(srv.URL + "/graphql")
	if err != nil {
		t.Fatalf("DiscoverGraphQL: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("introspection 只应发 1 次请求，实际 %d", calls)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("introspection 应为 POST，实际 %s", gotMethod)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("Content-Type 异常: %q", gotCT)
	}
	if !strings.Contains(gotBody, "__schema") {
		t.Fatalf("请求体不是只读 introspection: %s", gotBody)
	}
	if strings.Contains(strings.ToLower(gotBody), "mutation") {
		t.Fatalf("绝不发送 mutation: %s", gotBody)
	}
	if spec.Source != "graphql" {
		t.Fatalf("Source 应为 graphql: %q", spec.Source)
	}
	if got, want := spec.Types(), []string{"Query", "User"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("类型名不符（应去重并跳过 __ 元类型）: got=%v want=%v", got, want)
	}
}

func TestDiscoverGraphQLFailures(t *testing.T) {
	base := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
	}
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http-500", 500, `{"data":null}`},
		{"bad-json", 200, `not json`},
		{"graphql-errors", 200, `{"errors":[{"message":"introspection disabled"}]}`},
		{"missing-data", 200, `{}`},
		{"empty-types", 200, `{"data":{"__schema":{"types":[]}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := base(tc.status, tc.body)
			defer srv.Close()
			if _, err := DiscoverGraphQL(srv.URL + "/graphql"); err == nil {
				t.Fatalf("%s 应返回错误", tc.name)
			}
		})
	}
}

func TestDiscoverGraphQLBadEndpoint(t *testing.T) {
	for _, ep := range []string{"", "ftp://example.com/graphql", "not-a-url", "http://"} {
		if _, err := DiscoverGraphQL(ep); err == nil {
			t.Fatalf("非法端点 %q 应返回错误", ep)
		}
	}
}

// TestDiscoverGraphQLTimeout 3s 超时生效：服务端一直挂起，客户端必须按时返回错误。
func TestDiscoverGraphQLTimeout(t *testing.T) {
	// 服务端 handler 阻塞在 release 上：DiscoverGraphQL 超时返回后由测试放行，
	// 避免 httptest.Server.Close 等待挂起 handler（客户端超时不会取消服务端
	// 请求上下文，这是 net/http 的已知行为，不能依赖它收尾）。
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	start := time.Now()
	_, err := DiscoverGraphQL(srv.URL + "/graphql")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("挂起端点应超时返回错误")
	}
	if elapsed < 2500*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("超时应约 3s，实际 %v", elapsed)
	}
}
