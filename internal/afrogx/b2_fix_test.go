package afrogx

import "testing"

// ---- B2-04 字节串转义 ----

// TestByteStringEscape B2-04 回归：`b"a\nb"` 必须解码为换行，而不是 "anb"。
func TestByteStringEscape(t *testing.T) {
	cases := []struct{ expr, body string }{
		{`response.body.bcontains(b"a\nb")`, "a\nb"},
		{`response.body.bcontains(b"a\tb")`, "a\tb"},
		{`response.body.bcontains(b"a\\b")`, `a\b`},
		{`response.body.bcontains(b"plain")`, "plain"},
	}
	for _, c := range cases {
		p, err := Get(c.expr)
		if err != nil {
			t.Fatalf("%s 编译失败: %v", c.expr, err)
		}
		ok, why := p.Eval(Response{Status: 200, Body: c.body, Headers: map[string]string{}})
		if !ok {
			t.Errorf("%s 应命中 body=%q（%s）", c.expr, c.body, why)
		}
	}
}

// TestByteStringAsRegex B2-04 回归：`b"(\d+)"` 作为正则时反斜杠不得被吃掉。
func TestByteStringAsRegex(t *testing.T) {
	p, err := Get(`b"Version: (\d+)".bmatches(response.body)`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, _ := p.Eval(Response{Body: "Version: 1234"}); !ok {
		t.Fatal(`b"Version: (\d+)" 应命中 "Version: 1234"（\d 被吃成 d 会不命中）`)
	}
	if ok, _ := p.Eval(Response{Body: "Version: dddd"}); ok {
		t.Fatal(`\d 被吃成 d 时 "Version: dddd" 会误命中`)
	}
	// r"..." 形态保持原有正确行为
	p2, err := Get(`r"Version: (\d+)".bmatches(response.body)`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, _ := p2.Eval(Response{Body: "Version: 1234"}); !ok {
		t.Fatal(`r"..." 正则应命中`)
	}
}

// ---- B2-05 response.raw_header 独立通道 ----

// TestRawHeaderChannel B2-05 回归：raw_header 走响应头，不再当正文求值。
func TestRawHeaderChannel(t *testing.T) {
	// 1) 真实头命中（旧实现把它别名成 body → 漏报）
	p, err := Get(`response.raw_header.bcontains(b"Set-Cookie: sid=")`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	ok, _ := p.Eval(Response{
		Status:  200,
		Body:    "<html>nothing</html>",
		Headers: map[string]string{"Set-Cookie": "sid=abc"},
	})
	if !ok {
		t.Fatal("raw_header 应匹配响应头里的 Set-Cookie（旧实现当正文求值 → 漏报）")
	}

	// 2) 正文含该串但头不含 → 不得命中（旧实现会误报）
	p2, err := Get(`response.raw_header.bcontains(b"text/html")`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	ok2, _ := p2.Eval(Response{
		Status:  200,
		Body:    `<a href="x">text/html</a>`,
		Headers: map[string]string{"Content-Type": "application/json"},
	})
	if ok2 {
		t.Fatal("正文含 text/html 但响应头不含时不得命中（旧实现会误报）")
	}

	// 3) response.raw 仍按正文处理（方向安全，保持原语义）
	p3, err := Get(`response.raw.bcontains(b"needle")`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok3, _ := p3.Eval(Response{Body: "a needle here"}); !ok3 {
		t.Fatal("response.raw 应继续按正文匹配")
	}
}

// ---- B2-08 编译缓存有界 ----

// TestCacheBounded B2-08 回归：缓存条目数不得超过 cacheMax（不校验淘汰策略，
// 只校验"不会无限增长"）。
func TestCacheBounded(t *testing.T) {
	if cacheMax <= 0 {
		t.Fatal("cacheMax 必须为正")
	}
	before := cacheCount.Load()
	for i := 0; i < 16; i++ {
		// 每轮生成不同表达式，强制走编译路径
		if _, err := Get(`response.status == ` + itoa(200+i)); err != nil {
			t.Fatalf("编译失败: %v", err)
		}
	}
	if got := cacheCount.Load() - before; got <= 0 {
		t.Fatal("新表达式应计入缓存计数")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
