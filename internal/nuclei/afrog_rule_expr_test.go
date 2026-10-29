package nuclei

// afrog rule 级 expression 接线测试（BUG-016）。
//
// 背景：afrog 经典模板的判定写在 **rule 级 expression** 上（真实语料
// 1,687/1,699 条有 rule 级 expression，0 条写 response 块）。此前漏斗
// 没有这个字段，导致整个 afrog 来源（1,699 条）通过率为 0。
// 本文件覆盖：编译准入（不可判定必须整条拒收）、内容判定闸门
// （纯状态码/纯响应头不放行）、AND 合并、OR 拆分、以及 12 条**真实
// 模板夹具**的判定结果断言。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/afrogx"
	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

func convertOneAfrog(t *testing.T, poc string) checks.Check {
	t.Helper()
	cs := ConvertAfrog([]byte(poc))
	if len(cs) != 1 {
		t.Fatalf("应转出 1 条 check, got %d", len(cs))
	}
	return cs[0]
}

// evalExpr 按 runner 的评法求值（afrogx 运行时求值 + 响应上下文）。
func evalExpr(t *testing.T, expr string, status int, body string, headers map[string]string) bool {
	t.Helper()
	prog, err := afrogx.Get(expr)
	if err != nil {
		t.Fatalf("表达式应可编译 %q: %v", expr, err)
	}
	ok, _ := prog.Eval(afrogx.Response{Status: status, Body: body, Headers: headers})
	return ok
}

// TestConvertAfrogRuleExpression 最基本形态：判定全在 rule 级 expression。
func TestConvertAfrogRuleExpression(t *testing.T) {
	poc := `
id: rule-expr
info:
  name: rule 级表达式
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /poc/check.php
    expression: response.status == 200 && response.body.bcontains(b"POC-OK")
expression: r0()
`
	c := convertOneAfrog(t, poc)
	if c.ID != "afrog-rule-expr" || c.Path != "/poc/check.php" || c.Match.Method != "GET" {
		t.Fatalf("转出语义不符: %+v", c)
	}
	if !strings.Contains(c.Match.Expr, "POC-OK") {
		t.Fatalf("Match.Expr 应携带 rule 级表达式, got %q", c.Match.Expr)
	}
	if !evalExpr(t, c.Match.Expr, 200, "xx POC-OK xx", nil) {
		t.Errorf("命中响应应判定为真")
	}
	if evalExpr(t, c.Match.Expr, 200, "not here", nil) {
		t.Errorf("不命中响应应判定为假")
	}
	if evalExpr(t, c.Match.Expr, 404, "POC-OK", nil) {
		t.Errorf("状态码不符应判定为假")
	}
	if c.Match.Status != 0 || len(c.Match.Contains) != 0 {
		t.Errorf("表达式形态不应再合成静态 matcher: %+v", c.Match)
	}
}

// TestConvertAfrogRuleExpressionRejected 不可判定 / 无内容判定的表达式
// 必须**整条拒收**（宁少报不误报）。
func TestConvertAfrogRuleExpressionRejected(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"带外探测", `oobCheck(oob.ProtocolHTTP, 3)`},
		{"时延判定", `response.latency >= 100`},
		{"随机标记", `response.body.bcontains(bytes(randbody))`},
		{"纯状态码", `response.status == 200`},
		{"状态码区间", `response.status >= 200 && response.status < 300`},
		{"纯响应头", `response.raw_header.bcontains(b"Set-Cookie")`},
		{"纯取反", `!response.body.bcontains(b"notfound")`},
	}
	for _, c := range cases {
		poc := fmt.Sprintf(`
id: reject-%s
info:
  name: 拒收
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /reject
    expression: %q
expression: r0()
`, c.name, c.expr)
		if cs := ConvertAfrog([]byte(poc)); cs != nil {
			t.Errorf("%s: 应整条拒收, got %+v", c.name, cs)
		}
	}
}

// TestConvertAfrogAndMergesExpressions 同请求的 AND 链：表达式按 && 合并。
func TestConvertAfrogAndMergesExpressions(t *testing.T) {
	poc := `
id: and-merge
info:
  name: 同请求 AND 合并
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /merge
    expression: response.body.bcontains(b"AA")
  r1:
    request:
      method: GET
      path: /merge
    expression: response.status == 200 && response.body.bcontains(b"BB")
expression: r0() && r1()
`
	c := convertOneAfrog(t, poc)
	expr := c.Match.Expr
	if !strings.Contains(expr, "AA") || !strings.Contains(expr, "BB") || !strings.Contains(expr, "&&") {
		t.Fatalf("AND 链应合并两条表达式: %q", expr)
	}
	if !evalExpr(t, expr, 200, "AA and BB", nil) {
		t.Errorf("两条都满足应命中")
	}
	if evalExpr(t, expr, 200, "AA only", nil) {
		t.Errorf("缺少 BB 不应命中")
	}
	if evalExpr(t, expr, 500, "AA and BB", nil) {
		t.Errorf("状态码不满足不应命中")
	}
}

// TestConvertAfrogAndMixedExpressionAndMatcher AND 链里 rule 表达式与
// response 块 matcher 并存：两者都必须满足。
func TestConvertAfrogAndMixedExpressionAndMatcher(t *testing.T) {
	poc := `
id: and-mixed
info:
  name: 表达式 + 静态 matcher
  severity: medium
rules:
  r0:
    request:
      method: GET
      path: /mixed
    response:
      status_code: 200
      body: ["MAGIC-WORD"]
  r1:
    request:
      method: GET
      path: /mixed
    expression: response.body.bcontains(b"EXPR-OK")
expression: r0() && r1()
`
	c := convertOneAfrog(t, poc)
	if !strings.Contains(c.Match.Expr, "EXPR-OK") {
		t.Fatalf("表达式应保留: %q", c.Match.Expr)
	}
	if len(c.Match.Contains) != 1 || c.Match.Contains[0] != "magic-word" {
		t.Fatalf("静态 matcher 应保留（小写）: %+v", c.Match.Contains)
	}
	if !(len(c.Match.StatusAny) == 1 && c.Match.StatusAny[0] == 200) {
		t.Fatalf("status matcher 应保留: %+v", c.Match)
	}
}

// TestConvertAfrogAndDifferentRequestsRejectedWithExpressions 多请求 AND
// 链无法诚实降为单请求 → 整条拒收。
func TestConvertAfrogAndDifferentRequestsRejectedWithExpressions(t *testing.T) {
	poc := `
id: and-diff
info:
  name: 多请求 AND
  severity: critical
rules:
  r0:
    request:
      method: GET
      path: /step1
    expression: response.body.bcontains(b"TOKEN")
  r1:
    request:
      method: GET
      path: /step2
    expression: response.body.bcontains(b"DONE")
expression: r0() && r1()
`
	if cs := ConvertAfrog([]byte(poc)); cs != nil {
		t.Fatalf("多请求 AND 链应拒收: %+v", cs)
	}
}

// TestConvertAfrogOrSplitsExpressions OR 链：每条 rule 独立成 check，
// 各自携带自己的表达式。
func TestConvertAfrogOrSplitsExpressions(t *testing.T) {
	poc := `
id: or-split
info:
  name: 双路径任一命中
  severity: low
rules:
  r0:
    request:
      method: GET
      path: /a
    expression: response.status == 200 && response.body.bcontains(b"AAA")
  r1:
    request:
      method: GET
      path: /b
    expression: response.body.bcontains(b"BBB")
expression: r0() || r1()
`
	cs := ConvertAfrog([]byte(poc))
	if len(cs) != 2 {
		t.Fatalf("OR 应拆为 2 条, got %d", len(cs))
	}
	byID := map[string]checks.Check{}
	for _, c := range cs {
		byID[c.ID] = c
	}
	a, ok := byID["afrog-or-split-r0"]
	if !ok {
		t.Fatalf("缺少 afrog-or-split-r0: %+v", cs)
	}
	b := byID["afrog-or-split-r1"]
	if a.Path != "/a" || b.Path != "/b" {
		t.Fatalf("拆分后路径不符: %q / %q", a.Path, b.Path)
	}
	if !strings.Contains(a.Match.Expr, "AAA") || strings.Contains(a.Match.Expr, "BBB") {
		t.Fatalf("r0 表达式不应串味: %q", a.Match.Expr)
	}
	if !strings.Contains(b.Match.Expr, "BBB") {
		t.Fatalf("r1 表达式缺失: %q", b.Match.Expr)
	}
	if !evalExpr(t, a.Match.Expr, 200, "AAA", nil) || evalExpr(t, a.Match.Expr, 200, "BBB", nil) {
		t.Errorf("r0 判定不符")
	}
	if !evalExpr(t, b.Match.Expr, 500, "BBB", nil) {
		t.Errorf("r1 无状态码条件应命中")
	}
}

// TestConvertAfrogDocExpressionStillRequired 文档级 expression 仍是纯 rN()
// 布尔链；函数形态整体拒收（不能诚实求值）。
func TestConvertAfrogDocExpressionStillRequired(t *testing.T) {
	poc := `
id: doc-fn
info:
  name: 函数形态文档表达式
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /a
    expression: response.body.bcontains(b"a")
expression: contains(to_lower(r0()), 'x')
`
	if cs := ConvertAfrog([]byte(poc)); cs != nil {
		t.Fatalf("函数形态文档表达式应拒收: %+v", cs)
	}
}

// ---------- 真实模板夹具（来自 packs/nuclei-templates.tar.gz 的 afrog 来源） ----------

type afrogFixture struct {
	file    string
	method  string
	path    string
	sev     string
	status  int
	body    string
	headers map[string]string
	hit     bool
}

var afrogFixtures = []afrogFixture{
	{
		file: "CNVD-2018-13393.yaml", method: "GET", sev: "high",
		path:   `/include/thumb.php?dir=http\..\admin\login\login_check.php`,
		status: 200, body: `<html><?php echo 1; ?> login_met_cookie($metinfo_admin_name);</html>`, hit: true,
	},
	{
		file: "CNVD-2018-13393.yaml", method: "GET", sev: "high",
		path:   `/include/thumb.php?dir=http\..\admin\login\login_check.php`,
		status: 200, body: `<html>hello</html>`, hit: false,
	},
	{
		file: "CNVD-2019-16798.yaml", method: "GET", sev: "high",
		path:   `/mailsms/s?func=ADMIN:appState&dumpConfig=/`,
		status: 200, body: `<object name="cm_md_db">`, hit: true,
	},
	{
		file: "CNVD-2019-16798.yaml", method: "GET", sev: "high",
		path:   `/mailsms/s?func=ADMIN:appState&dumpConfig=/`,
		status: 200, body: `object name=other`, hit: false,
	},
	{
		file: "CNVD-2019-06255.yaml", method: "GET", sev: "critical",
		path:   `/s=set&_method=__construct&method=*&filter[]=system`,
		status: 200, body: "OS=Linux\nPATH=/bin:/usr/bin\nSHELL=/bin/sh\nUSER=root", hit: true,
	},
	{
		file: "CNVD-2019-06255.yaml", method: "GET", sev: "critical",
		path:   `/s=set&_method=__construct&method=*&filter[]=system`,
		status: 200, body: "OS=Linux", hit: false,
	},
	{
		file: "CNVD-2020-57264.yaml", method: "GET", sev: "high",
		path:   `/iclock/ccccc/windows/win.ini`,
		status: 200, body: "[fonts]\r\nx=1\r\n[extensions]\r\ny=2", hit: true,
	},
	{
		file: "CNVD-2020-57264.yaml", method: "GET", sev: "high",
		path:   `/iclock/ccccc/windows/win.ini`,
		status: 200, body: "[fonts]", hit: false,
	},
	{
		file: "CNVD-2021-14536.yaml", method: "GET", sev: "high",
		path:   `/login.php`,
		status: 200, body: `get_dkey_passwd "password":"0123456789abcdef0123456789abcdef"`, hit: true,
	},
	{
		file: "CNVD-2021-14536.yaml", method: "GET", sev: "high",
		path:   `/login.php`,
		status: 200, body: `get_dkey_passwd "password":"short"`, hit: false,
	},
	{
		file: "CNVD-2021-46825.yaml", method: "GET", sev: "critical",
		path:   `/api/v1/cluster/summary`,
		status: 200, body: `{"totalMem": 1, "stormVersion": "2.4.0"}`, hit: true,
	},
	{
		file: "CNVD-2021-46825.yaml", method: "GET", sev: "critical",
		path:   `/api/v1/cluster/summary`,
		status: 200, body: `{"nginxVersion": "1.2"}`, hit: false,
	},
	{
		file: "CNVD-2021-42789.yaml", method: "GET", sev: "high",
		path:   `/admin/admin/admin_list.html`,
		status: 200, body: `添加 首页 管理员列表 导航元素`, hit: true,
	},
	{
		file: "CNVD-2021-42789.yaml", method: "GET", sev: "high",
		path:   `/admin/admin/admin_list.html`,
		status: 200, body: `添加 首页`, hit: false,
	},
	{
		file: "CVE-2017-16894.yaml", method: "GET", sev: "high",
		path:   `/.env`,
		status: 200, body: "APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:abc=", hit: true,
	},
	{
		file: "CVE-2017-16894.yaml", method: "GET", sev: "high",
		path:   `/.env`,
		status: 200, body: "APP_NAME=Other", hit: false,
	},
	{
		file: "CVE-2018-13379.yaml", method: "GET", sev: "critical",
		path:   `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession`,
		status: 200, body: `var fgt_lang = { "EN": "English" };`, hit: true,
	},
	{
		file: "CVE-2018-13379.yaml", method: "GET", sev: "critical",
		path:   `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession`,
		status: 404, body: `not found`, hit: false,
	},
	{
		file: "CVE-2018-8770.yaml", method: "GET", sev: "medium",
		path:   `/tests/generate.php`,
		status: 200, body: "Fatal error: Class 'PHPUnit_Framework_TestCase' not found in /application/third_party/CIUnit/libraries/CIUnitTestCase.php on line 12", hit: true,
	},
	{
		file: "CVE-2018-8770.yaml", method: "GET", sev: "medium",
		path:   `/tests/generate.php`,
		status: 200, body: "Fatal error: something else", hit: false,
	},
	{
		file: "CVE-2018-11759.yaml", method: "GET", sev: "high",
		path:   `/jkstatus%3b`,
		status: 200, body: `<html><title>JK Status Manager</title></html>`, hit: true,
	},
	{
		file: "CVE-2018-11759.yaml", method: "GET", sev: "high",
		path:   `/jkstatus%3b`,
		status: 200, body: `<html>Tomcat</html>`, hit: false,
	},
	{
		file: "CVE-2019-16097.yaml", method: "POST", sev: "medium",
		path:   `/api/users`,
		status: 201, body: `{"error":"username has already been used"}`, hit: true,
	},
	{
		file: "CVE-2019-16097.yaml", method: "POST", sev: "medium",
		path:   `/api/users`,
		status: 200, body: `{"ok":true}`, hit: false,
	},
}

// TestConvertAfrogRealTemplates 12 条真实模板夹具：转换通过 + 判定结果。
func TestConvertAfrogRealTemplates(t *testing.T) {
	seen := map[string]bool{}
	for _, fx := range afrogFixtures {
		data, err := os.ReadFile(filepath.Join("testdata", "afrog", fx.file))
		if err != nil {
			t.Fatalf("读夹具失败 %s: %v", fx.file, err)
		}
		cs := ConvertAfrog(data)
		if len(cs) != 1 {
			t.Errorf("%s: 应转出 1 条 check, got %d", fx.file, len(cs))
			continue
		}
		c := cs[0]
		if seen[fx.file] && c.Match.Expr == "" {
			t.Errorf("%s: 表达式缺失", fx.file)
		}
		seen[fx.file] = true
		if c.Match.Method != fx.method {
			t.Errorf("%s: method = %q, want %q", fx.file, c.Match.Method, fx.method)
		}
		if c.Path != fx.path {
			t.Errorf("%s: path = %q, want %q", fx.file, c.Path, fx.path)
		}
		if c.Sev != fx.sev {
			t.Errorf("%s: sev = %q, want %q", fx.file, c.Sev, fx.sev)
		}
		if c.Match.Expr == "" {
			t.Errorf("%s: rule 级表达式未落到 Match.Expr", fx.file)
			continue
		}
		got := evalExpr(t, c.Match.Expr, fx.status, fx.body, fx.headers)
		if got != fx.hit {
			t.Errorf("%s: 判定 = %v, want %v（expr=%q）", fx.file, got, fx.hit, c.Match.Expr)
		}
	}
	if len(seen) != 12 {
		t.Errorf("夹具应覆盖 12 个真实模板文件, got %d", len(seen))
	}
}

// TestTemplateSourceCoverage 来源覆盖门禁：nuclei path / raw / afrog 三种
// 前端各至少能转出 1 条 check。任一来源通过率为 0 即失败——BUG-016 这类
// "整源失效"靠单条模板测试发现不了。
func TestTemplateSourceCoverage(t *testing.T) {
	sources := map[string]string{
		// path 形态（官方 nuclei-templates）
		"nuclei-path": `
id: coverage-path
info:
  name: 来源覆盖 path
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/readme.txt"
    matchers:
      - type: word
        words: ["readme"]
`,
		// raw 请求形态（官方库 / TscanPlus）
		"nuclei-raw": `
id: coverage-raw
info:
  name: 来源覆盖 raw
  severity: medium
http:
  - raw:
      - |
        GET {{BaseURL}}/api/ping HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: ["pong"]
`,
		// afrog 经典形态
		"afrog": `
id: coverage-afrog
info:
  name: 来源覆盖 afrog
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /afrog/check
    expression: response.status == 200 && response.body.bcontains(b"AFROG-OK")
expression: r0()
`,
	}
	var failed []string
	for name, data := range sources {
		if cs := convertAny([]byte(data)); len(cs) == 0 {
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		t.Fatalf("以下模板来源通过率为 0（整源失效）: %v", failed)
	}
}
