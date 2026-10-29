package sitelens

// Evidence 正文小写惰性缓存（evidence.go）的回归：
// 缓存不得改变「同一证据内容 → 同一匹配结果」的语义，Body 改写后必须失效。

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func TestEvidenceLowerBodyCache(t *testing.T) {
	ev := &Evidence{Body: "Hello WORLD"}
	if got := ev.lowerBody(); got != "hello world" {
		t.Fatalf("lowerBody = %q, want %q", got, "hello world")
	}
	if ev.bodyLow != "hello world" || ev.bodyLowSrc != ev.Body {
		t.Fatalf("缓存字段未正确写入: low=%q src=%q", ev.bodyLow, ev.bodyLowSrc)
	}
	// 重复取用复用缓存（同一字符串值）
	if got := ev.lowerBody(); got != "hello world" {
		t.Fatalf("重复调用 lowerBody 结果不一致: %q", got)
	}
	// Body 被改写：缓存必须失效重算，否则匹配语义会被污染
	ev.Body = "BYE"
	if got := ev.lowerBody(); got != "bye" {
		t.Fatalf("Body 改写后 lowerBody = %q, want %q", got, "bye")
	}
	// 空正文
	empty := &Evidence{}
	if got := empty.lowerBody(); got != "" {
		t.Fatalf("空正文 lowerBody = %q", got)
	}
}

func TestExtractPrecomputesLowerBody(t *testing.T) {
	body := "<html><head><title>T</title></head><body>Hello WORLD</body></html>"
	resp := &httpx.Response{
		Status: 200, Headers: map[string]string{"Server": "nginx"},
		Body: body, FinalURL: "http://x/",
	}
	ev := Extract(resp)
	if ev.bodyLow != strings.ToLower(body) {
		t.Fatalf("Extract 未预计算小写正文: %q", ev.bodyLow)
	}
	if ev.bodyLowSrc != body {
		t.Fatalf("Extract 未记录缓存来源正文")
	}
	if got := ev.lowerBody(); got != strings.ToLower(body) {
		t.Fatalf("lowerBody = %q", got)
	}
}

// TestMatchSeesBodyMutation 缓存不得让改写后的 Body 沿用旧的小写正文。
func TestMatchSeesBodyMutation(t *testing.T) {
	techs, err := LoadTechnologiesFrom(mustRules(t, map[string]any{
		"html": []string{"wordpress"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	ev := &Evidence{Headers: map[string]string{}, Metas: map[string]string{}, Body: "Powered by WordPress"}
	if hits := Match(techs, ev); len(hits) != 1 {
		t.Fatalf("首次匹配应命中: %+v", hits)
	}
	ev.Body = "nothing relevant here"
	if hits := Match(techs, ev); len(hits) != 0 {
		t.Fatalf("Body 改写后不应沿用旧缓存命中: %+v", hits)
	}
	ev.Body = "wordpress again"
	if hits := Match(techs, ev); len(hits) != 1 {
		t.Fatalf("再次改写后应重新命中: %+v", hits)
	}
}
