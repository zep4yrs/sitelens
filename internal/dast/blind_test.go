package dast

import (
	"fmt"
	"strings"
	"testing"
)

// routeFetcher 按 payload 关键词路由响应尺寸：
// AND 1=1 → 与基线同尺寸（1000B），AND 1=2 → 偏离（400B）。
type routeFetcher struct{}

func (f *routeFetcher) GetSmall(u string) *Resp {
	switch {
	case strings.Contains(u, "AND 1=1"):
		return &Resp{Status: 200, Body: repeatStr("x", 1000)}
	case strings.Contains(u, "AND 1=2"):
		return &Resp{Status: 200, Body: repeatStr("x", 400)}
	default:
		return &Resp{Status: 200, Body: repeatStr("x", 1000)}
	}
}

func (f *routeFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return f.GetSmall(u)
}

// randomFetcher 每次请求尺寸随机漂移（内容随机化站点模型）。
type randomFetcher struct{ n int }

func (f *randomFetcher) GetSmall(u string) *Resp {
	f.n++
	return &Resp{Status: 200, Body: repeatStr("x", 1000+f.n*137)}
}

func (f *randomFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return f.GetSmall(u)
}

func repeatStr(s string, n int) string {
	return strings.Repeat(s, n)
}

func TestBoolBlindDetectsDifferential(t *testing.T) {
	r := New(&routeFetcher{}, DefaultOptions())
	f := r.boolBlind(Target{URL: "http://t/v?id=1", Param: "id"}, new(int), 0)
	if f == nil {
		t.Fatal("差分成立应命中")
	}
	if f.Check != "bool-blind-sqli" || f.Severity != "high" {
		t.Fatalf("Finding 字段不符: %+v", f)
	}
	if f.Param != "id" || !strings.Contains(f.Evidence, "双确认") {
		t.Fatalf("Finding 证据不符: %+v", f)
	}
}

func TestBoolBlindRandomSiteNoHit(t *testing.T) {
	// 内容随机化站点（真相似不成立）→ 不命中
	r := New(&randomFetcher{}, DefaultOptions())
	if f := r.boolBlind(Target{URL: "http://t/v?id=1", Param: "id"}, new(int), 0); f != nil {
		t.Fatalf("随机内容站点不应命中: %+v", f)
	}
}

func TestBoolPayloads(t *testing.T) {
	tn, fn := boolPayloads("7")
	if tn != "7 AND 1=1" || fn != "7 AND 1=2" {
		t.Fatalf("数字型 payload 不符: %q / %q", tn, fn)
	}
	ts, fs := boolPayloads("abc")
	if ts != "abc' AND '1'='1" || fs != "abc' AND '1'='2" {
		t.Fatalf("字符串型 payload 不符: %q / %q", ts, fs)
	}
	te, fe := boolPayloads("")
	if te != "1 AND 1=1" || fe != "1 AND 1=2" {
		t.Fatalf("空值应回退数字型: %q / %q", te, fe)
	}
}
