package checks

import "testing"

// 头匹配：Nuclei 模板 word part=header 转换产物（全包含语义）。
func TestMatchBodyHeaderContains(t *testing.T) {
	headers := map[string]string{
		"Server":       "nginx/1.24.0",
		"X-Powered-By": "PHP/8.2",
		"Content-Type": "text/html",
	}
	m := Match{Status: 200, HeaderContains: []string{"nginx", "PHP"}}
	if !matchBody(m, 200, "body", headers, "") {
		t.Fatal("两处头关键词均存在应命中")
	}
	m2 := Match{Status: 200, HeaderContains: []string{"nginx", "apache"}}
	if matchBody(m2, 200, "body", headers, "") {
		t.Fatal("缺少 apache 不应命中")
	}
	// 无头条件时行为不变（含正/反用例）
	if !matchBody(Match{Status: 200, Contains: []string{"ok"}}, 200, "ok!", headers, "") {
		t.Fatal("无头条件时正文命中应通过")
	}
}
