package checks

import "testing"

// 回归：Match.Status 必须与实际响应状态码比较（此前从未比较，
// 纯状态码 check 会对任何响应命中）。
func TestMatchBodyStatusComparison(t *testing.T) {
	m := Match{Status: 200}
	if matchBody(m, 404, "anything", nil) {
		t.Fatal("404 不应命中 Status=200 的 check")
	}
	if !matchBody(m, 200, "anything", nil) {
		t.Fatal("200 应命中")
	}
	// 状态码不匹配时即使正文包含关键词也不命中
	m2 := Match{Status: 200, Contains: []string{"wp"}}
	if matchBody(m2, 500, "wp", nil) {
		t.Fatal("状态不符时正文命中也不应通过")
	}
	// StatusAny 任一语义
	m3 := Match{StatusAny: []int{200, 301}}
	if !matchBody(m3, 301, "", nil) {
		t.Fatal("301 应命中 StatusAny")
	}
	if matchBody(m3, 500, "", nil) {
		t.Fatal("500 不应命中 StatusAny")
	}
	// ContainsAny 任一语义
	m4 := Match{Status: 200, ContainsAny: []string{"a", "b"}}
	if !matchBody(m4, 200, "has b here", nil) {
		t.Fatal("ContainsAny 应任一命中")
	}
	if matchBody(m4, 200, "nothing", nil) {
		t.Fatal("ContainsAny 全不包含不应命中")
	}
	// Contains AND 语义保持
	m5 := Match{Status: 200, Contains: []string{"a", "b"}}
	if matchBody(m5, 200, "only a", nil) {
		t.Fatal("Contains AND 语义被破坏")
	}
}
