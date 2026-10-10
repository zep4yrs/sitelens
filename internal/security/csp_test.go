package security

import (
	"strings"
	"testing"
)

func weaknessesByDirective(ws []Weakness) map[string]bool {
	m := map[string]bool{}
	for _, w := range ws {
		m[w.Directive] = true
	}
	return m
}

// DVWA CSP Bypass 的典型策略：script-src 'self' + unsafe-inline，
// 头在但可绕过——只判「头在不在」会漏掉这类。
func TestCSPWeakDirectivesDetected(t *testing.T) {
	h := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
	}
	rep := Assess(h)
	d := weaknessesByDirective(rep.Weaknesses)
	for _, want := range []string{"script-src", "object-src", "base-uri", "frame-ancestors"} {
		if !d[want] {
			t.Fatalf("应报 %s 弱点，实际 %+v", want, rep.Weaknesses)
		}
	}
	hasSelf, hasInline := false, false
	for _, w := range rep.Weaknesses {
		if w.Directive != "script-src" {
			continue
		}
		if w.Evidence == "" {
			t.Fatal("弱点应有证据串")
		}
		if strings.Contains(w.Evidence, "unsafe-inline") {
			hasInline = true
		}
		if strings.Contains(w.Evidence, "self") {
			hasSelf = true
		}
	}
	if !hasSelf || !hasInline {
		t.Fatalf("应分别报 unsafe-inline 与 'self' 弱点：%+v", rep.Weaknesses)
	}
}

// 严格策略（nonce + 全指令）不得报任何弱点。
func TestCSPSecureNoWeakness(t *testing.T) {
	h := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'nonce-abc123'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
	}
	if ws := Assess(h).Weaknesses; len(ws) != 0 {
		t.Fatalf("严格 CSP 不应报弱点：%+v", ws)
	}
}

// 无 CSP 头时不报「指令弱点」（那是缺头，属评分项，不是弱点）。
func TestCSPAbsentNoWeakness(t *testing.T) {
	if ws := Assess(map[string]string{}).Weaknesses; len(ws) != 0 {
		t.Fatalf("无 CSP 时不应报指令弱点：%+v", ws)
	}
}
