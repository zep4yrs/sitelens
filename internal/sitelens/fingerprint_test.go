package sitelens

import (
	"encoding/json"
	"testing"
)

func TestCompilePatsLiteralFastPath(t *testing.T) {
	pats := compilePats([]string{"wp-content", "", `WordPress[\s-]?([\d.]+)?`})
	if len(pats) != 2 {
		t.Fatalf("空模式应被丢弃: %d", len(pats))
	}
	if !pats[0].isLit || pats[0].lit != "wp-content" {
		t.Fatalf("纯字面量应走快路径: %+v", pats[0])
	}
	if pats[1].isLit || pats[1].gate != "wordpress" {
		t.Fatalf("正则应带字面量门控: %+v", pats[1])
	}
}

func TestLiteralGate(t *testing.T) {
	cases := []struct{ in, want string }{
		{`WordPress[\s-]?([\d.]+)?`, "wordpress"},
		{`jquery[.-]?([0-9.]+)?\.js`, "jquery"}, // 点号转义并入运行
		{`(?:^|\/)vendor\/`, "vendor/"},         // 非捕获组跳过后，转义斜杠并入运行
		{`^nginx`, "nginx"},                     // ^ 后的运行有效
		{`a|b`, ""},                             // 交替：不设门
		{`.{2}`, ""},                            // 短运行不设门
		{`Symfony`, "symfony"},
	}
	for _, c := range cases {
		if got := literalGate(c.in); got != c.want {
			t.Errorf("literalGate(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestGateDoesNotSkipRealMatches(t *testing.T) {
	// 门控后正则通道仍要能命中并抽版本
	raw := mustRules(t, map[string]any{
		"html": []string{`SiteLens[ /]?v?([\d.]+)`},
	})
	techs, err := LoadTechnologiesFrom(raw)
	if err != nil {
		t.Fatal(err)
	}
	ev := &Evidence{
		Headers: map[string]string{},
		Metas:   map[string]string{},
		Body:    "<p>powered by SiteLens v3.2.1 today</p>",
	}
	hits := Match(techs, ev)
	if len(hits) != 1 || hits[0].Version != "3.2.1" {
		t.Fatalf("门控不应影响命中与版本抽取: %+v", hits)
	}
	// 门控字面量不在正文：正则必须被跳过且不误命中
	ev.Body = "<p>nothing relevant</p>"
	if hits := Match(techs, ev); len(hits) != 0 {
		t.Fatalf("无门控字面量不应命中: %+v", hits)
	}
}

func mustRules(t *testing.T, rules map[string]any) json.RawMessage {
	t.Helper()
	box := map[string]any{
		"technologies": []map[string]any{
			{"name": "TestTech", "cats": []string{"misc"}, "conf": 50, "rules": rules},
		},
	}
	b, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// LoadTechnologiesFrom 供测试从内存 JSON 加载（绕开文件路径）。
func LoadTechnologiesFrom(data json.RawMessage) ([]*compiledTech, error) {
	return loadFrom(data)
}
