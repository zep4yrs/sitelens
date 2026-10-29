package dast

import (
	"net/url"
	"strings"
	"testing"
)

// parseShellArgs 解析 POSIX 单引号串（支持 '\” 转义），返回参数列表。
//
// 用于验证 shellQuote 的**可逆性**：真转义才能把原内容原样还原；
// 若注入成功逃出了引号，解析结果会多出参数（如 ";" "id"）。
func parseShellArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote {
			switch {
			case c == '\'':
				inQuote = true
			case c == ' ':
				if cur.Len() > 0 {
					out = append(out, cur.String())
					cur.Reset()
				}
			default:
				cur.WriteByte(c)
			}
			continue
		}
		if c == '\'' {
			// '\'' 形式：闭合引号 + 转义单引号 + 重新开引号
			if i+3 < len(s) && s[i+1] == '\\' && s[i+2] == '\'' && s[i+3] == '\'' {
				cur.WriteByte('\'')
				i += 3
				continue
			}
			inQuote = false
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// TestFormReplayShellQuoted 复现命令中的表单地址/字段名/载荷必须整体在引号内。
//
// 这三者全部来自被扫站点的 HTML——恶意站点放
// `<form action="/x' ;id > /tmp/pwn;echo '">` 即可把命令执行权
// 交给复制粘贴复现命令的分析员（BUG-002）。
func TestFormReplayShellQuoted(t *testing.T) {
	cases := []struct{ name, action, field, payload string }{
		{"action 含注入", "/x' ;id > /tmp/pwn;echo '", "q", "1"},
		{"字段名含注入", "/x", "q' ;id ;echo '", "1"},
		{"载荷含引号", "/x", "q", "' OR 1=1--"},
		{"三者同时含注入", "/a' ;id ;echo '", "b' ;id ;echo '", "c' ;id ;echo '"},
	}
	for _, tc := range cases {
		cmd := formReplay(tc.action, tc.field, tc.payload)
		args := parseShellArgs(cmd)
		// 期望：curl -sk --path-as-is -d <body> <action> —— 恰好 6 个参数。
		// 若注入逃出引号，这里会出现额外参数。
		if len(args) != 6 {
			t.Errorf("%s: 参数数应为 6（注入逃逸?），实际 %d：%q", tc.name, len(args), cmd)
			continue
		}
		if args[0] != "curl" || args[1] != "-sk" || args[2] != "--path-as-is" || args[3] != "-d" {
			t.Errorf("%s: 命令前缀被破坏：%q", tc.name, cmd)
		}
		if args[5] != tc.action {
			t.Errorf("%s: action 未原样还原：%q != %q", tc.name, args[5], tc.action)
		}
		form, err := url.ParseQuery(args[4])
		if err != nil {
			t.Errorf("%s: 请求体不是合法表单编码：%v（%q）", tc.name, err, args[4])
			continue
		}
		if form.Get(tc.field) != tc.payload {
			t.Errorf("%s: 载荷未原样还原：%q != %q", tc.name, form.Get(tc.field), tc.payload)
		}
	}
}

// TestFormReplayIsPostSemantics 复现命令必须与真实请求一致（POST 表单）。
func TestFormReplayIsPostSemantics(t *testing.T) {
	cmd := formReplay("https://a.com/login", "user", "admin")
	if !strings.Contains(cmd, "-d ") {
		t.Errorf("复现命令应带 -d（表单体）：%q", cmd)
	}
	if !strings.Contains(cmd, "'https://a.com/login'") {
		t.Errorf("复现命令应含被引号包裹的目标地址：%q", cmd)
	}
}

// TestChainEvidenceKeepsExisting 表单通道已构造好 POST 语义的复现命令，
// chainEvidence 不得再覆盖（BUG-018：此前被无条件覆盖成 GET 语义）。
func TestChainEvidenceKeepsExisting(t *testing.T) {
	f := &Finding{
		Request: "POST https://a.com/login HTTP/1.1\r\n\r\nuser=admin",
		Replay:  "curl -sk --path-as-is -d 'user=admin' 'https://a.com/login'",
	}
	chainEvidence(f, "https://a.com/login?user=admin", &Resp{Status: 200, Body: "ok"})
	if !strings.HasPrefix(f.Request, "POST ") {
		t.Errorf("Request 被覆盖成非 POST：%q", f.Request)
	}
	if !strings.Contains(f.Replay, "-d ") {
		t.Errorf("Replay 被覆盖成 GET 语义：%q", f.Replay)
	}
	if f.Response == nil || f.Response.Status != 200 {
		t.Errorf("响应快照未填充：%+v", f.Response)
	}
}

// TestChainEvidenceFillsMissing 空字段仍应被填充（URL 通道语义不变）。
func TestChainEvidenceFillsMissing(t *testing.T) {
	f := &Finding{}
	chainEvidence(f, "https://a.com/p?q=1", &Resp{Status: 200, Body: "ok"})
	if !strings.HasPrefix(f.Request, "GET ") {
		t.Errorf("URL 通道 Request 应为 GET 语义：%q", f.Request)
	}
	if !strings.Contains(f.Replay, "https://a.com/p?q=1") {
		t.Errorf("URL 通道 Replay 应含目标 URL：%q", f.Replay)
	}
}
