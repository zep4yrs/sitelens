package sitelens

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// BenchmarkMatch 全库指纹匹配基准：13,727 条规则 × 模拟真实页面证据
// （40KB HTML + 常见响应头/meta/脚本）。文档性能口径的实测来源。
func BenchmarkMatch(b *testing.B) {
	path := "../../data/go/technologies.json"
	if _, err := os.Stat(path); err != nil {
		b.Skip("指纹库不在本地")
	}
	m, err := LoadMatcher(path)
	if err != nil {
		b.Fatal(err)
	}
	var body strings.Builder
	body.WriteString("<!DOCTYPE html><html><head><title>Example Domain</title>")
	body.WriteString(`<meta name="generator" content="WordPress 6.4">`)
	body.WriteString(`<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>`)
	body.WriteString(`<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">`)
	body.WriteString(`</head><body>`)
	para := "<p>The example page renders content for benchmark payload sizing.</p>"
	for body.Len() < 40*1024 {
		body.WriteString(para)
	}
	body.WriteString("</body></html>")
	ev := &Evidence{
		URL:      "https://bench.example/",
		Status:   200,
		Headers:  map[string]string{"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.0"},
		Body:     body.String(),
		Title:    "Example Domain",
		Metas:    map[string]string{"generator": "WordPress 6.4"},
		CookieNames: []string{"wordpress_test_cookie"},
	}
	b.ResetTimer()
	var hitCount int
	for i := 0; i < b.N; i++ {
		hitCount = len(m.Match(ev))
	}
	if hitCount == 0 {
		fmt.Fprintln(os.Stderr, "警告：基准页零命中（规则或证据形状变了？）")
	}
}
