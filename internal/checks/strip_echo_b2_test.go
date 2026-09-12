package checks

import (
	"strings"
	"testing"
)

// B2 复扫收口回归：catch-all 回显站的软 404 基线与目标侧必须落在
// 同一比对窗口。此前探针侧路径无前导 '/'、主循环侧有，基线残留
// "/<html>…" 而目标侧为 "<html>…"，前缀比对失配 → 生产可达误报。
func TestStripEchoSameWindow(t *testing.T) {
	// catch-all 站模板：正文回显请求路径（真实站 "404: /path" 形态）
	tpl := "<html><h1>Not Found</h1><p>404: /{EP}</p></html>"
	want := "<html><h1>Not Found</h1><p>404: </p></html>"

	// 基线侧：请求 /__sitelens_probe_none__，回显带前导 '/'
	baseBody := strings.ReplaceAll(tpl, "{EP}", "__sitelens_probe_none__")
	base := stripEcho(baseBody, "https://t.com/__sitelens_probe_none__", "__sitelens_probe_none__")

	// 目标侧：请求 /admin，回显带前导 '/'
	targetBody := strings.ReplaceAll(tpl, "{EP}", "admin")
	target := stripEcho(targetBody, "https://t.com/admin", "/admin")

	if base != want || target != want {
		t.Fatalf("回显未剔净:\n  base   = %q\n  target = %q\n  want   = %q", base, target, want)
	}
	// 前缀比对（processGroup 同逻辑）此前必 false，现在必须 true
	if !strings.HasPrefix(strings.ToLower(target), strings.ToLower(base)) {
		t.Fatalf("前缀比对应成立（软 404 应被识别）: base=%q target=%q", base, target)
	}
}

// 无前导 '/' 与有前导 '/' 的路径形态必须等价；且只剔「/路径」回显形态，
// 正文里与路径同名的裸词（通常是内容而非回显）不受牵连。
func TestStripEchoPathFormsEquivalent(t *testing.T) {
	body := "<p>/admin</p><p>admin</p>"
	a := stripEcho(body, "https://t.com/admin", "/admin")
	b := stripEcho(body, "https://t.com/admin", "admin")
	if a != b {
		t.Fatalf("路径形态不等价: %q vs %q", a, b)
	}
	if a != "<p></p><p>admin</p>" {
		t.Fatalf("剔除结果不符（裸词应保留）: %q", a)
	}
}
