package dsl

import (
	"strings"
	"testing"
)

type testEnv struct {
	status  int
	body    string
	headers map[string]string
	host    string
}

func (e testEnv) StatusCode() int { return e.status }
func (e testEnv) Body() string    { return e.body }
func (e testEnv) Header(n string) string {
	for k, v := range e.headers {
		if strings.EqualFold(k, n) {
			return v
		}
	}
	return ""
}
func (e testEnv) HeaderValues() []string {
	var out []string
	for _, v := range e.headers {
		out = append(out, v)
	}
	return out
}
func (e testEnv) Host() string { return e.host }

func mustEval(t *testing.T, expr string, env testEnv) (bool, error) {
	t.Helper()
	p, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	return p.Eval(env)
}

func TestStatusComparisons(t *testing.T) {
	env := testEnv{status: 200}
	for expr, want := range map[string]bool{
		"status_code == 200":                       true,
		"status_code == 301":                       false,
		"status_code != 301":                       true,
		"status_code == 200 || status_code == 301": true,
		"status_code == 301 || status_code == 302": false,
		"status_code == 200 && status_code < 300":  true,
		"status_code >= 200 && status_code <= 299": true,
		"status_code == 500":                       false,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

func TestContainsFamily(t *testing.T) {
	env := testEnv{status: 200, body: "<title>Ackee Server</title>"}
	for expr, want := range map[string]bool{
		`contains(body, "<title>Ackee")`:          true,
		`contains(body, "ackee")`:                 false, // nuclei contains 区分大小写
		`contains(tolower(body), "<title>ackee")`: true,  // 真实模板 6b9 成语
		`contains(to_lower(body), "ackee")`:       true,
		`icontains(body, "ACKEE")`:                true,
		`contains_all(body, "Ackee", "Server")`:   true,
		`contains_all(body, "Ackee", "Missing")`:  false,
		`contains_any(body, "Missing", "Server")`: true,
		`starts_with(body, "<title>")`:            true,
		`ends_with(body, "</title>")`:             true,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

func TestRegexFunction(t *testing.T) {
	env := testEnv{status: 200, body: "powered by WordPress 6.4.2"}
	for expr, want := range map[string]bool{
		`regex("(?i)wordpress [0-9.]+", body)`: true,
		`regex("powered by .*", body)`:         true,
		`regex("wordpress", body)`:             false, // 无 (?i) 区分大小写
		`regex(r"^powered", body)`:             true,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

func TestHeaderAccess(t *testing.T) {
	env := testEnv{status: 200, headers: map[string]string{
		"Content-Type": "application/json",
		"Server":       "nginx",
	}}
	for expr, want := range map[string]bool{
		`contains(header['content-type'], "json")`: true, // 头名大小写不敏感
		`contains(header['Content-Type'], "json")`: true,
		`contains(header['x-missing'], "json")`:    false,
		`header['server'] == "nginx"`:              true,
		`contains(headers['server'], "nginx")`:     true, // headers 别名
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

func TestNegationAndPrecedence(t *testing.T) {
	env := testEnv{status: 200, body: "hello", host: "example.com"}
	for expr, want := range map[string]bool{
		`!contains(body, "missing")`:                                               true,
		`!contains(body, "hello")`:                                                 false,
		`!contains(host,"evil.com") && contains(body, "hello")`:                    true,
		`contains(body,"nope") || (status_code == 200 && !contains(host,"x.com"))`: true,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

func TestCompileRejections(t *testing.T) {
	// 子集外 / 多请求 / extract 绑定变量 / 哈希函数 / 算术拼接：一律准入拒绝
	for _, expr := range []string{
		`bcontains(base64("abc"))`,           // 字节函数
		`status_code_2 == 200`,               // 多请求解包变量
		`compare_versions(version, "<=2.2")`, // extract 绑定变量 + 不支持函数
		`duration >= 6`,                      // 时序变量
		`sha1(body) == "abc"`,                // 哈希函数
		`contains(body, "a") + "x" == "ax"`,  // 算术拼接
		`body == `,                           // 悬空比较
		`contains(body, "未闭合`,                // 字符串未闭合
		`contains(body, "a") &&`,             // 悬空 &&（&& 后无记号）
		`len(body) >`,                        // 悬空比较
		`("a" == "b"`,                        // 括号未闭合
		`status_code == 200 extra)`,          // 尾部多余内容
		`interactsh_protocol == "dns"`,       // OOB 变量
	} {
		if p, err := Compile(expr); err == nil {
			t.Errorf("Compile(%q) 应被拒绝，得到 %v", expr, p)
		}
	}
}

func TestEvalTypeErrorsFailClosed(t *testing.T) {
	// 准入通过但运行期类型不匹配 → 求值错误（调用方按不命中处理）
	env := testEnv{status: 200, body: "x"}
	for _, expr := range []string{
		`contains(status_code, "200")`, // int 当字符串用
		`body && contains(body, "a")`,  // 裸字符串当布尔（左支即错）
		`status_code == "200"`,         // int 与字符串比较
		`regex("(", body)`,             // 坏正则
		`len(status_code) > 3`,         // len 非 str
	} {
		p, err := Compile(expr)
		if err != nil {
			continue // 准入拒绝也可以（更严）
		}
		if ok, err := p.Eval(env); err == nil {
			t.Errorf("Eval(%q) 应报错，得到 %v", expr, ok)
		}
	}
}

func TestPositiveGround(t *testing.T) {
	for expr, want := range map[string]bool{
		`status_code == 200`:                             true,
		`contains(body, "x")`:                            true,
		`contains(tolower(body), "x")`:                   true,
		`regex("pat", body)`:                             true,
		`!contains(host,"1password.com")`:                false, // 纯排除式：恒真空转
		`!contains(host,"x.com") && contains(body, "y")`: true,
		`status_code == 200 || !contains(host, "x")`:     true,
		`!contains(body, "y")`:                           false, // 取反下的 body 引用不算依据
		`len(body) > 0`:                                  true,
		`contains(header['server'], "nginx")`:            true,
		`contains(host, "x")`:                            false, // 仅 host 引用不成依据
	} {
		p, err := Compile(expr)
		if err != nil {
			t.Fatalf("Compile(%q): %v", expr, err)
		}
		if got := p.PositiveGround(); got != want {
			t.Errorf("PositiveGround(%q) = %v; want %v", expr, got, want)
		}
	}
}

func TestCompileCached(t *testing.T) {
	a, err := CompileCached(`status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompileCached(`status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("CompileCached 应返回同一份 AST")
	}
	if _, err := CompileCached(`未知变量`); err == nil {
		t.Error("坏表达式不应进入缓存且应报错")
	}
}

func TestLenComparisons(t *testing.T) {
	env := testEnv{status: 200, body: "12345"}
	for expr, want := range map[string]bool{
		`len(body) == 5`:   true,
		`len(body) > 30`:   false,
		`len(body) < 2000`: true,
		`len(body) == 0`:   false,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}

// TestRealLibraryForms 用真实模板库抽样的典型表达式回归（含组合嵌套）。
func TestRealLibraryForms(t *testing.T) {
	env := testEnv{status: 200, body: `{"version":"2.2.34"} <html>phpinfo()</html>`,
		headers: map[string]string{"X-Powered-By": "PHP/5.6.40"}, host: "target.local"}
	for expr, want := range map[string]bool{
		`status_code == 200 && contains(body, "phpinfo()")`:                       true,
		`contains(body, "2.2.34") && status_code == 200`:                          true,
		`regex("(?m)^X-Powered-By: PHP/[0-9.]+", body)`:                           false,
		`status_code != 404 && contains(tolower(body), "<html>")`:                 true,
		`(status_code == 200 || status_code == 403) && contains(body, "version")`: true,
	} {
		got, err := mustEval(t, expr, env)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", expr, got, err, want)
		}
	}
}
