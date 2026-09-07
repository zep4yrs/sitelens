package dsl

import (
	"strings"
	"testing"
)

// FuzzCompileEval 用随机输入轰击词法/解析/求值全程——模板库来自互联网
// （不可信输入），任何 panic/挂起都是缺陷。种子取真实模板形态。
func FuzzCompileEval(f *testing.F) {
	seeds := []string{
		`status_code == 200`,
		`status_code == 200 && contains(tolower(body), "<title>ackee")`,
		`!contains(host,"1password.com")`,
		`contains_any(body, "a", "b", "c")`,
		`regex("(?i)wordpress [0-9.]+", body)`,
		`contains(header['content-type'], "json")`,
		`len(body) > 30`,
		`r'^powered' && status_code != 404`,
		`((a` + strings.Repeat(` || (b`, 60),
		"'''\"",
		`\`,
	}
	for _, s := range seeds {
		f.Add(s, 200, "body text", "example.com")
	}
	fixedHeaders := map[string]string{"Server": "nginx", "Content-Type": "text/html"}
	f.Fuzz(func(t *testing.T, expr string, status int, body string, host string) {
		p, err := Compile(expr)
		if err != nil {
			return // 准入拒绝是合法结果
		}
		env := testEnv{status: status, body: body, headers: fixedHeaders, host: host}
		_, _ = p.Eval(env) // 只求不 panic；求值错误合法
		_ = p.PositiveGround()
	})
}
