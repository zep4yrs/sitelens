package dast

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeFetch 按注册规则响应探测请求；未命中规则时回显参数值（模拟反射页面）。
type fakeFetch struct {
	rules   []func(u string) *Resp
	delay   time.Duration
	request int
}

func (f *fakeFetch) GetSmall(rawURL string) *Resp {
	f.request++
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	for _, r := range f.rules {
		if resp := r(rawURL); resp != nil {
			return resp
		}
	}
	// 默认：把 query 值 URL 解码后回显进 HTML（模拟真实应用的反射行为，不转义 → XSS 必中）
	if u, err := url.Parse(rawURL); err == nil && u.RawQuery != "" {
		var parts []string
		for k, vs := range u.Query() {
			parts = append(parts, k+"="+strings.Join(vs, ","))
		}
		return &Resp{Status: 200, Body: "<html>q=" + strings.Join(parts, "&") + "</html>"}
	}
	return &Resp{Status: 200, Body: "<html>index</html>"}
}

func newRunner(f Fetcher) *Runner {
	r := New(f, DefaultOptions())
	return r
}

func TestCollectParams(t *testing.T) {
	links := []string{
		"https://a.com/list?page=1&q=x",
		"https://a.com/list?page=2",       // page 重复：去重
		"https://a.com/list?page=3&cat=5", // cat 新参数
		"https://b.com/search?kw=z",       // 不同主机
		"https://c.com/noparam",           // 无参数：跳过
		"://bad",                          // 解析失败：跳过
	}
	targets := collectParams(links, 100)
	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.Param] = true
	}
	if len(targets) != 4 || !got["page"] || !got["q"] || !got["cat"] || !got["kw"] {
		t.Fatalf("collectParams 去重/过滤失败: %+v", targets)
	}
	capped := collectParams(links, 2)
	if len(capped) != 2 {
		t.Fatalf("cap 上限未生效: %+v", capped)
	}
}

func TestSetParamKeepsOthers(t *testing.T) {
	out := setParam("https://a.com/p?x=1&y=2", "y", "INJ")
	if !strings.Contains(out, "x=1") || !strings.Contains(out, "y=INJ") {
		t.Fatalf("setParam 应保留其余参数: %s", out)
	}
}

func TestXSSReflected(t *testing.T) {
	hits := newRunner(&fakeFetch{}).Run([]string{"https://a.com/list?q=1"})
	found := false
	for _, h := range hits {
		if h.Check == "xss-reflect" && h.Param == "q" {
			found = true
		}
	}
	if !found {
		t.Fatalf("反射 XSS 未命中: %+v", hits)
	}
}

func TestSQLiBaselineSuppression(t *testing.T) {
	// 页面本来就含 "postgresql"：注入单引号不应命中（基线剔除）
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			return &Resp{Status: 200, Body: "powered by postgresql v15"}
		},
	}}
	hits := newRunner(f).Run([]string{"https://a.com/list?id=1"})
	for _, h := range hits {
		if h.Check == "sqli-error" {
			t.Fatalf("基线已有特征不应命中: %+v", h)
		}
	}
	// 基线干净、注入后报错：应命中
	f2 := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "%27") || strings.Contains(u, "'") {
				return &Resp{Status: 500, Body: "Warning: mysql_fetch_array() expects"}
			}
			return nil
		},
	}}
	hits = newRunner(f2).Run([]string{"https://a.com/list?id=1"})
	ok := false
	for _, h := range hits {
		if h.Check == "sqli-error" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("报错 SQLi 未命中: %+v", hits)
	}
}

func TestOpenRedirect(t *testing.T) {
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "sitelens-dt.example.com") {
				return &Resp{Status: 302,
					Headers: map[string]string{"Location": "https://sitelens-dt.example.com/ok"},
					Body:    ""}
			}
			return nil
		},
	}}
	hits := newRunner(f).Run([]string{"https://a.com/go?to=/home"})
	ok := false
	for _, h := range hits {
		if h.Check == "open-redirect" && h.Severity == "medium" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("开放重定向未命中: %+v", hits)
	}
}

func TestTraversalBaseline(t *testing.T) {
	// 回显 ../ 但不回显文件内容：不命中（正文无 root:x:0:0:）
	hits := newRunner(&fakeFetch{}).Run([]string{"https://a.com/dl?f=readme.txt"})
	for _, h := range hits {
		if h.Check == "lfi-passwd" {
			t.Fatalf("无文件内容不应命中遍历: %+v", h)
		}
	}
	// 注入后返回 passwd 内容：命中
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "etc%2Fpasswd") || strings.Contains(u, "etc/passwd") {
				return &Resp{Status: 200, Body: "root:x:0:0:root:/root:/bin/bash"}
			}
			return nil
		},
	}}
	hits = newRunner(f).Run([]string{"https://a.com/dl?f=readme.txt"})
	ok := false
	for _, h := range hits {
		if h.Check == "lfi-passwd" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("目录遍历未命中: %+v", hits)
	}
}

func TestTimeBlindDoubleConfirm(t *testing.T) {
	// 注入 SLEEP 后延迟超过阈值且复测一致 → 命中；基线快（0 延迟）
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "SLEEP") {
				return &Resp{Status: 200, Body: "ok"}
			}
			return nil
		},
	}}
	f.delay = 20 * time.Millisecond // 全局慢一点，SLEEP 无额外延迟 → 不该命中
	opts := DefaultOptions()
	opts.BlindThresholdMS = 100
	hits := New(f, opts).Run([]string{"https://a.com/list?id=1"})
	for _, h := range hits {
		if h.Check == "sqli-blind-time" {
			t.Fatalf("未注入延迟不应命中盲注: %+v", h)
		}
	}
}

func TestCancelStops(t *testing.T) {
	calls := 0
	r := newRunner(&fakeFetch{})
	r.SetCancel(func() bool { calls++; return calls > 2 })
	hits := r.Run([]string{
		"https://a.com/a?x=1", "https://a.com/b?y=1", "https://a.com/c?z=1",
	})
	_ = hits // 取消后应提前返回，不 panic 即可
}

func TestMaxParamsCap(t *testing.T) {
	f := &fakeFetch{}
	opts := DefaultOptions()
	opts.MaxParams = 1
	hits := New(f, opts).Run([]string{
		"https://a.com/a?x=1", "https://a.com/b?y=1",
	})
	if f.request > 20 { // 1 目标 × 8 请求上限，余量给取消检查
		t.Fatalf("MaxParams=1 应只探测 1 个参数，实际请求 %d", f.request)
	}
	_ = hits
}
