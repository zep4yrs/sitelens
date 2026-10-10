package dast

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 低熵形态判定
// ---------------------------------------------------------------------------

func TestLowEntropyShape(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"1", true},                                 // DVWA dvwaSession 这类短整数
		{"42", true},                                // 短整数
		{"1700000000", true},                        // 10 位秒级时间戳
		{"1700000000000", true},                     // 13 位毫秒时间戳
		{"12345678", true},                          // 8 位纯数字
		{"123456789018", true},                      // 近全数字短十六进制
		{"9f8e7d6c5b4a", false},                     // 十六进制但非近全数字 → 不报
		{"a1b2c3d4e5f60718293a4b5c6d7e8f90", false}, // 强随机 → 不报
		{"", false},
		{"John Doe", false}, // 业务值
	}
	for _, c := range cases {
		got, _ := lowEntropyShape(c.v)
		if got != c.want {
			t.Errorf("lowEntropyShape(%q) = %v，期望 %v", c.v, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 随机差分：时间戳型标识命中 / 强随机不报 / 稳定标识不报
// ---------------------------------------------------------------------------

// diffFetcher 同一 URL 的连续取样返回不同的会话载体值（模拟"每次刷新都变"）。
// 通过 seen 计数只对同一个 URL 的重复请求轮转，其余路径固定返回 ok。
type diffFetcher struct {
	bodies []string
	seen   map[string]int
}

func (f *diffFetcher) GetSmall(u string) *Resp {
	if f.seen == nil {
		f.seen = map[string]int{}
	}
	n := f.seen[u]
	f.seen[u]++
	if len(f.bodies) > 0 {
		b := f.bodies[n%len(f.bodies)]
		if n > 0 {
			b = f.bodies[n%len(f.bodies)]
		}
		return &Resp{Status: 200, Body: b}
	}
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}
func (f *diffFetcher) PostFormSmall(u string, d map[string]string) *Resp { return &Resp{Status: 200} }
func (f *diffFetcher) PostRawSmall(u, ct, b string) *Resp                { return nil }
func (f *diffFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}

func TestRandomDiffWeakTimestamp(t *testing.T) {
	f := &diffFetcher{bodies: []string{
		`<html><input type="hidden" name="csrf_token" value="1700000000"></html>`,
		`<html><input type="hidden" name="csrf_token" value="1700000001"></html>`,
	}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/session?x=1"})
	if !hasCheck(hits, "weak-random-id") {
		t.Fatalf("时间戳型随机标识应命中: %+v", hits)
	}
}

func TestRandomDiffStrongNoHit(t *testing.T) {
	f := &diffFetcher{bodies: []string{
		`<html><input type="hidden" name="csrf_token" value="9f8e7d6c5b4a39281706f5e4d3c2b1a0"></html>`,
		`<html><input type="hidden" name="csrf_token" value="0a1b2c3d4e5f60718293a4b5c6d7e8f9"></html>`,
	}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/session?x=1"})
	if hasCheck(hits, "weak-random-id") {
		t.Fatalf("强随机标识不应报: %+v", hits)
	}
}

func TestRandomDiffStableNoHit(t *testing.T) {
	f := &diffFetcher{bodies: []string{
		`<html><input type="hidden" name="csrf_token" value="1700000000"></html>`,
		`<html><input type="hidden" name="csrf_token" value="1700000000"></html>`,
	}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/session?x=1"})
	if hasCheck(hits, "weak-random-id") {
		t.Fatalf("稳定标识不应报: %+v", hits)
	}
}

func TestRandomDiffOff(t *testing.T) {
	f := &diffFetcher{bodies: []string{
		`<html><input type="hidden" name="csrf_token" value="1700000000"></html>`,
		`<html><input type="hidden" name="csrf_token" value="1700000001"></html>`,
	}}
	opts := DefaultOptions()
	opts.RandomDiff = false
	opts.TimeBlind = false
	opts.BoolBlind = false
	if hits := New(f, opts).Run([]string{"https://a.com/session?x=1"}); hasCheck(hits, "weak-random-id") {
		t.Fatalf("总闸关闭时不应报: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 命令注入回显通道
// ---------------------------------------------------------------------------

func TestCmdEchoHit(t *testing.T) {
	f := &fakeFetch{rules: []func(u string) *Resp{func(u string) *Resp {
		if strings.Contains(u, "echo+15846") || strings.Contains(u, "echo%2015846") ||
			strings.Contains(u, "echo+15846") || strings.Contains(u, "15846") {
			// 模拟 shell 执行 echo 后回显结果
			if strings.Contains(u, "%3Becho") || strings.Contains(u, ";echo") ||
				strings.Contains(u, "%7Cecho") || strings.Contains(u, "|echo") {
				return &Resp{Status: 200, Body: "<html>15846</html>"}
			}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	}}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/ping?ip=127.0.0.1"})
	if !hasCheck(hits, "cmd-inject") {
		t.Fatalf("回显型命令注入应命中: %+v", hits)
	}
}

func TestCmdEchoNoHitOnLiteralEcho(t *testing.T) {
	// 参数被原样回显（未执行）时，出现的是算式文本而非结果 → 不报
	f := &fakeFetch{rules: []func(u string) *Resp{func(u string) *Resp {
		return &Resp{Status: 200, Body: "<html>" + u + "</html>"}
	}}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/ping?ip=127.0.0.1"})
	if hasCheck(hits, "cmd-inject") {
		t.Fatalf("算式文本回显不应报: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 存储型 XSS
// ---------------------------------------------------------------------------

// storedFetcher 模拟留言板：POST 写入的内容会在响应里原样列出。
type storedFetcher struct {
	body  string // 未转义回显
	plain bool   // 只回显纯文本（无可执行上下文）
}

func (f *storedFetcher) GetSmall(u string) *Resp { return &Resp{Status: 200, Body: "<html>ok</html>"} }
func (f *storedFetcher) PostFormSmall(u string, d map[string]string) *Resp {
	v := ""
	for _, x := range d {
		v = x
		break
	}
	if f.plain {
		return &Resp{Status: 200, Body: "<html><pre>" + v + "</pre></html>"}
	}
	return &Resp{Status: 200, Body: `<html><script>var m="` + v + `";</script></html>`}
}
func (f *storedFetcher) PostRawSmall(u, ct, b string) *Resp { return nil }
func (f *storedFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}

func TestStoredXSSScriptContext(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(&storedFetcher{}, opts).RunForms([]FormTarget{
		{Action: "https://a.com/guestbook", Fields: []string{"mtxMessage", "txtName"}},
	})
	if !hasCheck(hits, "xss-stored") {
		t.Fatalf("存储型 XSS（脚本上下文）应命中: %+v", hits)
	}
}

func TestStoredXSSRawOnly(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(&storedFetcher{plain: true}, opts).RunForms([]FormTarget{
		{Action: "https://a.com/guestbook", Fields: []string{"mtxMessage"}},
	})
	if hasCheck(hits, "xss-stored") {
		t.Fatalf("纯文本回显不应判可执行存储型 XSS: %+v", hits)
	}
	if !hasCheck(hits, "xss-stored-raw") {
		t.Fatalf("未过滤存储应报前置项: %+v", hits)
	}
}

func TestStoredXSSFilteredNoHit(t *testing.T) {
	f := &fakeFetch{postRules: []func(u string, d map[string]string) *Resp{
		func(u string, d map[string]string) *Resp {
			return &Resp{Status: 200, Body: "<html>ok (filtered)</html>"}
		},
	}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).RunForms([]FormTarget{
		{Action: "https://a.com/guestbook", Fields: []string{"msg"}},
	})
	if hasCheck(hits, "xss-stored") || hasCheck(hits, "xss-stored-raw") {
		t.Fatalf("被过滤的写入不应报: %+v", hits)
	}
}

func TestStoredXSSOff(t *testing.T) {
	opts := DefaultOptions()
	opts.StoredXSS = false
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(&storedFetcher{}, opts).RunForms([]FormTarget{
		{Action: "https://a.com/guestbook", Fields: []string{"msg"}},
	})
	if hasCheck(hits, "xss-stored") || hasCheck(hits, "xss-stored-raw") {
		t.Fatalf("总闸关闭时不应报: %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 状态变更表单下发弱会话 Cookie
// ---------------------------------------------------------------------------

// weakCookieFetcher 模拟 DVWA weak_id：POST 后下发递增整数会话 Cookie。
type weakCookieFetcher struct{ n int }

func (f *weakCookieFetcher) GetSmall(u string) *Resp {
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}
func (f *weakCookieFetcher) PostFormSmall(u string, d map[string]string) *Resp {
	f.n++
	return &Resp{Status: 200,
		SetCookies: []string{"dvwaSession=" + itoaTest(f.n)},
		Body:       "<html>new session</html>"}
}
func (f *weakCookieFetcher) PostRawSmall(u, ct, b string) *Resp { return nil }
func (f *weakCookieFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestWeakCookieStateChangeForm(t *testing.T) {
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(&weakCookieFetcher{}, opts).RunForms([]FormTarget{
		{Action: "https://a.com/weak_id/", Method: "post"},
	})
	if !hasCheck(hits, "weak-session-id") {
		t.Fatalf("弱会话 Cookie 应命中: %+v", hits)
	}
}

func TestWeakCookieStrongNoHit(t *testing.T) {
	f := &strongCookieFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).RunForms([]FormTarget{{Action: "https://a.com/x/", Method: "post"}})
	if hasCheck(hits, "weak-session-id") {
		t.Fatalf("强随机会话 Cookie 不应报: %+v", hits)
	}
}

type strongCookieFetcher struct{}

func (strongCookieFetcher) GetSmall(u string) *Resp { return &Resp{Status: 200} }
func (strongCookieFetcher) PostFormSmall(u string, d map[string]string) *Resp {
	return &Resp{Status: 200,
		SetCookies: []string{"PHPSESSID=9f8e7d6c5b4a39281706f5e4d3c2b1a0"},
		Body:       "<html>ok</html>"}
}
func (strongCookieFetcher) PostRawSmall(u, ct, b string) *Resp { return nil }
func (strongCookieFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}

func TestWeakCookieGateOff(t *testing.T) {
	opts := DefaultOptions()
	opts.WeakCookie = false
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(&weakCookieFetcher{}, opts).RunForms([]FormTarget{
		{Action: "https://a.com/weak_id/", Method: "post"},
	})
	if hasCheck(hits, "weak-session-id") {
		t.Fatalf("总闸关闭时不应报: %+v", hits)
	}
}
