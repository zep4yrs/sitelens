package afrogx

import "testing"

func resp(status int, body string, headers map[string]string) Response {
	if headers == nil {
		headers = map[string]string{}
	}
	return Response{Status: status, Body: body, Headers: headers}
}

func TestEvalSupported(t *testing.T) {
	cases := []struct {
		name string
		expr string
		r    Response
		want bool
	}{
		{"状态码相等", `response.status == 200`, resp(200, "", nil), true},
		{"状态码不等", `response.status == 200`, resp(404, "", nil), false},
		{"状态码范围", `response.status >= 200 && response.status < 300`, resp(206, "", nil), true},
		{"状态码或", `response.status == 200 || response.status == 206`, resp(206, "", nil), true},
		{"取反", `!(response.status == 500)`, resp(200, "", nil), true},
		{"正文包含", `response.body.bcontains(b"<?php")`, resp(200, "x <?php y", nil), true},
		{"正文不包含", `response.body.bcontains(b"<?php")`, resp(200, "plain", nil), false},
		{"正文包含双引号串", `response.body.bcontains("\"password\":")`, resp(200, `{"password":"x"}`, nil), true},
		{"正文忽略大小写", `response.body.ibcontains(b"PHP VERSION")`, resp(200, "php version 5.4", nil), true},
		{"正文大小写敏感不匹配", `response.body.bcontains(b"PHP VERSION")`, resp(200, "php version 5.4", nil), false},
		{"bytes() 包字面量", `response.body.bcontains(bytes("abc"))`, resp(200, "xxabcxx", nil), true},
		{"正则匹配", `"Version: (.*)".bmatches(response.body)`, resp(200, "Version: 5.4", nil), true},
		{"正则不匹配", `"Version: (.*)".bmatches(response.body)`, resp(200, "nothing", nil), false},
		{"raw 正则单引号", `r'>PHP Version <\/td>'.bmatches(response.body)`, resp(200, "x >PHP Version </td> y", nil), true},
		{"响应头包含", `response.headers["Server"].contains("nginx")`,
			resp(200, "", map[string]string{"Server": "nginx/1.2"}), true},
		{"响应头不包含", `response.headers["Server"].contains("nginx")`,
			resp(200, "", map[string]string{"Server": "apache"}), false},
		{"响应头大小写不敏感取值", `response.headers["content-type"].contains("json")`,
			resp(200, "", map[string]string{"Content-Type": "application/json"}), true},
		{"content_type 包含", `response.content_type.contains("json")`,
			resp(200, "", map[string]string{"Content-Type": "application/json"}), true},
		{"恒真", `true`, resp(200, "", nil), true},
		{"恒假", `false`, resp(200, "", nil), false},
		{"组合与", `response.status == 200 && response.body.bcontains(b"ok")`, resp(200, "ok", nil), true},
		{"组合与不满足", `response.status == 200 && response.body.bcontains(b"ok")`, resp(200, "no", nil), false},
		{"组合或", `response.body.bcontains(b"a") || response.body.bcontains(b"b")`, resp(200, "zzbzz", nil), true},
		{"括号组合", `(response.status == 200 || response.status == 206) && response.body.bcontains(b"x")`,
			resp(206, "x", nil), true},
	}
	for _, c := range cases {
		p, err := Compile(c.expr)
		if err != nil {
			t.Errorf("%s: 编译失败 %q: %v", c.name, c.expr, err)
			continue
		}
		got, _ := p.Eval(c.r)
		if got != c.want {
			t.Errorf("%s: Eval(%q) = %v, want %v", c.name, c.expr, got, c.want)
		}
	}
}

// TestCompileRejectsUnsupported 不支持的原子必须**编译期**报错——
// 调用方据此整条拒收（宁少报不误报），不能等到运行期才发现。
func TestCompileRejectsUnsupported(t *testing.T) {
	unsupported := []string{
		`oobCheck(oob.ProtocolDNS, 5)`,
		`oobCheck(oob.ProtocolHTTP, 3)`,
		`response.status == 200 && oobCheck(oob.ProtocolHTTP, 3)`,
		`response.body.bcontains(bytes(randbody))`,
		`response.body.bcontains(bytes(string(r1 * r2)))`,
		`response.body.bcontains(bytes(md5str))`,
		`response.status == 200 && response.latency <= 100`,
		`response.latency >= 100`,
		`md5(string(rand))`,
		`response.unknown.thing == 1`,
		`response.body.bcontains(`,
		`&&`,
	}
	for _, e := range unsupported {
		if _, err := Compile(e); err == nil {
			t.Errorf("表达式 %q 应编译失败（不可判定必须拒收）", e)
		}
	}
}

// TestGetCaches 编译结果缓存：同表达式重复取应返回同一指针，且错误也缓存。
func TestGetCaches(t *testing.T) {
	p1, err1 := Get(`response.status == 200`)
	p2, err2 := Get(`response.status == 200`)
	if err1 != nil || err2 != nil {
		t.Fatalf("编译失败: %v / %v", err1, err2)
	}
	if p1 != p2 {
		t.Errorf("同表达式应命中缓存")
	}
	_, e1 := Get(`oobCheck(oob.ProtocolDNS, 5)`)
	_, e2 := Get(`oobCheck(oob.ProtocolDNS, 5)`)
	if e1 == nil || e2 == nil {
		t.Fatalf("不支持的表达式应报错")
	}
	if e1.Error() != e2.Error() {
		t.Errorf("错误信息应稳定: %v vs %v", e1, e2)
	}
}
