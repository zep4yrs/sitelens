package checks

import "testing"

// 回归：Match.Status 必须与实际响应状态码比较（此前从未比较，
// 纯状态码 check 会对任何响应命中）。
func TestMatchBodyStatusComparison(t *testing.T) {
	m := Match{Status: 200}
	if matchBody(m, 404, "anything", nil, "") {
		t.Fatal("404 不应命中 Status=200 的 check")
	}
	if !matchBody(m, 200, "anything", nil, "") {
		t.Fatal("200 应命中")
	}
	// 状态码不匹配时即使正文包含关键词也不命中
	m2 := Match{Status: 200, Contains: []string{"wp"}}
	if matchBody(m2, 500, "wp", nil, "") {
		t.Fatal("状态不符时正文命中也不应通过")
	}
	// StatusAny 任一语义
	m3 := Match{StatusAny: []int{200, 301}}
	if !matchBody(m3, 301, "", nil, "") {
		t.Fatal("301 应命中 StatusAny")
	}
	if matchBody(m3, 500, "", nil, "") {
		t.Fatal("500 不应命中 StatusAny")
	}
	// ContainsAny 任一语义
	m4 := Match{Status: 200, ContainsAny: []string{"a", "b"}}
	if !matchBody(m4, 200, "has b here", nil, "") {
		t.Fatal("ContainsAny 应任一命中")
	}
	if matchBody(m4, 200, "nothing", nil, "") {
		t.Fatal("ContainsAny 全不包含不应命中")
	}
	// Contains AND 语义保持
	m5 := Match{Status: 200, Contains: []string{"a", "b"}}
	if matchBody(m5, 200, "only a", nil, "") {
		t.Fatal("Contains AND 语义被破坏")
	}
}

// TestMatchDSL dsl 表达式条件：与既有条件并存、AND 语义、host 取值、失败不命中。
func TestMatchDSL(t *testing.T) {
	headers := map[string]string{"Content-Type": "text/html", "Server": "nginx"}
	// 状态 + dsl 双条件都须成立
	m := Match{Status: 200, DSL: []string{`contains(tolower(body), "phpmyadmin")`}}
	if !matchBody(m, 200, "Welcome to phpMyAdmin", headers, "db.local") {
		t.Fatal("dsl 命中 + 状态码命中应通过")
	}
	if matchBody(m, 403, "Welcome to phpMyAdmin", headers, "db.local") {
		t.Fatal("dsl 命中但状态不符不应通过")
	}
	if matchBody(m, 200, "nothing here", headers, "db.local") {
		t.Fatal("状态命中但 dsl 不中不应通过")
	}
	// host 变量取值（排除式写法）
	m2 := Match{DSL: []string{`!contains(host,"1password.com") && contains(body, "x")`}}
	if !matchBody(m2, 200, "x", headers, "target.local") {
		t.Fatal("host 排除 + 正文命中应通过")
	}
	if matchBody(m2, 200, "x", headers, "1password.com") {
		t.Fatal("host 命中排除式不应通过")
	}
	// 多条 dsl 全部须为真
	m3 := Match{DSL: []string{`status_code == 200`, `contains(body, "a")`}}
	if !matchBody(m3, 200, "a", headers, "h") {
		t.Fatal("两条 dsl 都命中应通过")
	}
	if matchBody(m3, 200, "b", headers, "h") {
		t.Fatal("第二条 dsl 不中不应通过")
	}
	// 求值错误（类型不符）不命中
	m4 := Match{DSL: []string{`contains(status_code, "200")`}}
	if matchBody(m4, 200, "a", headers, "h") {
		t.Fatal("dsl 类型错误应不命中（宁少报不误报）")
	}
	// 头下标大小写不敏感
	m5 := Match{DSL: []string{`contains(header['content-type'], "html")`}}
	if !matchBody(m5, 200, "", headers, "h") {
		t.Fatal("dsl 头下标应大小写不敏感命中")
	}
}
