package nuclei

import (
	"strings"
	"testing"
)

func TestConvertAfrogSingleRule(t *testing.T) {
	poc := `
id: example-panel
info:
  name: 示例后台面板暴露
  author: sl
  severity: medium
  tags: exposure,panel
http:
  - path: /admin/login
    method: GET
rules:
  r0:
    request:
      path: /admin/login
      method: GET
    response:
      status_code: 200
      body:
        - admin-login
        - 管理后台
expression: r0()
`
	cs := ConvertAfrog([]byte(poc))
	if len(cs) != 1 {
		t.Fatalf("应转出 1 条 check, got %d", len(cs))
	}
	c := cs[0]
	if c.ID != "afrog-example-panel" {
		t.Fatalf("ID = %q", c.ID)
	}
	if c.Path != "/admin/login" || c.Match.Status != 200 {
		t.Fatalf("请求语义不符: %+v", c)
	}
	if !strings.Contains(strings.Join(c.Match.Contains, ","), "admin-login") ||
		!strings.Contains(strings.Join(c.Match.Contains, ","), "管理后台") {
		t.Fatalf("AND 关键词缺失: %+v", c.Match.Contains)
	}
	if !strings.Contains(c.Advice, "afrog 社区模板") {
		t.Fatalf("Advice 出处应标明 afrog: %q", c.Advice)
	}
}

func TestConvertAfrogAndSameRequestMerges(t *testing.T) {
	poc := `
id: dual-rule
info:
  name: 双规则同请求
  severity: high
rules:
  r0:
    request:
      path: /actuator/heapdump
      method: GET
    response:
      status_code: 200
      body: ["java.hprof"]
  r1:
    request:
      path: /actuator/heapdump
      method: GET
    response:
      body: ["JAVA PROFILE"]
expression: r0() && r1()
`
	cs := ConvertAfrog([]byte(poc))
	if len(cs) != 1 {
		t.Fatalf("同请求 AND 应合并为 1 条, got %d", len(cs))
	}
	got := strings.Join(cs[0].Match.Contains, ",")
	if !strings.Contains(got, "java.hprof") || !strings.Contains(got, "java profile") {
		t.Fatalf("合并后应含两组关键词(小写): %q", got)
	}
}

func TestConvertAfrogAndDifferentRequestsRejected(t *testing.T) {
	poc := `
id: chain-poc
info:
  name: 两步链
  severity: critical
rules:
  r0:
    request:
      path: /step1
    response:
      status_code: 200
      body: ["token"]
  r1:
    request:
      path: /step2
    response:
      status_code: 200
      body: ["done"]
expression: r0() && r1()
`
	if cs := ConvertAfrog([]byte(poc)); cs != nil {
		t.Fatalf("多请求 AND 链应拒收, got %+v", cs)
	}
}

func TestConvertAfrogOrSplits(t *testing.T) {
	poc := `
id: or-poc
info:
  name: 双路径任一命中
  severity: low
rules:
  r0:
    request:
      path: /a
    response:
      status_code: 200
      body: ["aaa"]
  r1:
    request:
      path: /b
    response:
      status_code: 200
      body: ["bbb"]
expression: r0() || r1()
`
	cs := ConvertAfrog([]byte(poc))
	if len(cs) != 2 {
		t.Fatalf("OR 应拆为 2 条, got %d", len(cs))
	}
	ids := cs[0].ID + "|" + cs[1].ID
	if !strings.Contains(ids, "-r0") || !strings.Contains(ids, "-r1") {
		t.Fatalf("拆分 ID 应带 rule 名: %s", ids)
	}
}

func TestConvertAfrogMixedExprRejected(t *testing.T) {
	poc := `
id: mixed
info:
  name: 混合逻辑
  severity: high
rules:
  r0:
    request:
      path: /a
    response:
      body: ["a"]
  r1:
    request:
      path: /b
    response:
      body: ["b"]
expression: r0() && r1() || r0()
`
	if cs := ConvertAfrog([]byte(poc)); cs != nil {
		t.Fatalf("混合逻辑应拒收: %+v", cs)
	}
}

func TestConvertAfrogFunctionExprRejected(t *testing.T) {
	poc := `
id: fexpr
info:
  name: 函数表达式
  severity: high
rules:
  r0:
    request:
      path: /a
    response:
      body: ["a"]
expression: contains(to_lower(r0()), 'x')
`
	if cs := ConvertAfrog([]byte(poc)); cs != nil {
		t.Fatalf("函数表达式应拒收: %+v", cs)
	}
}

func TestConvertRawBasic(t *testing.T) {
	tpl := `
id: raw-sqli-error
info:
  name: SQL 注入报错回显
  severity: high
http:
  - raw:
      - |
        POST {{BaseURL}}/api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"admin'","pass":"x"}
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 500
      - type: word
        words:
          - "SQL syntax"
          - "SQLException"
        condition: or
`
	cs := ConvertRaw([]byte(tpl))
	if len(cs) != 1 {
		t.Fatalf("raw 模板应转出 1 条, got %d", len(cs))
	}
	c := cs[0]
	if c.Match.Method != "POST" || c.Path != "/api/login" {
		t.Fatalf("raw 请求语义不符: %+v", c.Match)
	}
	if c.Match.ContentType != "application/json" {
		t.Fatalf("Content-Type 应从 raw 头提取: %q", c.Match.ContentType)
	}
	if !strings.Contains(c.Match.Body, "admin'") {
		t.Fatalf("请求体应保留: %q", c.Match.Body)
	}
	if len(c.Match.StatusAny) != 1 || c.Match.StatusAny[0] != 500 {
		t.Fatalf("status 组缺失: %+v", c.Match)
	}
	if !strings.Contains(strings.Join(c.Match.ContainsAny, ","), "sql syntax") {
		t.Fatalf("or 词组缺失: %+v", c.Match.ContainsAny)
	}
}

func TestConvertPathShapeStillWorks(t *testing.T) {
	tpl := `
id: path-shape
info:
  name: 传统 path 形态
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/readme.txt"
    matchers:
      - type: word
        words:
          - "readme"
`
	cs := Convert([]byte(tpl))
	if len(cs) != 1 || cs[0].Path != "/readme.txt" {
		t.Fatalf("path 形态回归破坏: %+v", cs)
	}
}
