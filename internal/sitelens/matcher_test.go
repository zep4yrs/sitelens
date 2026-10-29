package sitelens

// Matcher.find 由线性扫全库改为 name → 指纹查表（matcher.go）的回归：
// 命中后的元数据补全行为必须与旧线性查找一致（取首个同名指纹）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestTechJSON(t *testing.T, techs []map[string]any) string {
	t.Helper()
	box := map[string]any{"technologies": techs}
	b, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "technologies.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMatcherFindByNameMap(t *testing.T) {
	path := writeTestTechJSON(t, []map[string]any{
		{"name": "Alpha", "cats": []string{"cms"}, "conf": 60,
			"rules": map[string]any{"html": []string{"alpha-marker"}}},
		{"name": "Beta", "cats": []string{"js"}, "conf": 50,
			"rules": map[string]any{"html": []string{"beta-marker"}}},
	})
	m, err := LoadMatcher(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Count() != 2 {
		t.Fatalf("Count = %d, want 2", m.Count())
	}
	// 查表必须返回同一份 *Technology（与旧线性查找一致，取首个同名）
	if got := m.find("Alpha"); got != m.techs[0].tech {
		t.Fatalf("find(Alpha) 未返回首条指纹的 *Technology: %+v", got)
	}
	if got := m.find("Beta"); got != m.techs[1].tech {
		t.Fatalf("find(Beta) 未返回对应指纹: %+v", got)
	}
	if got := m.find("不存在"); got != nil {
		t.Fatalf("未知技术应返回 nil: %+v", got)
	}
	// Match 的元数据补全路径：命中 Alpha 时 Cats 应带出
	hits := m.Match(&Evidence{Body: "alpha-marker", Headers: map[string]string{}, Metas: map[string]string{}})
	if len(hits) != 1 || hits[0].Name != "Alpha" || len(hits[0].Cats) != 1 || hits[0].Cats[0] != "cms" {
		t.Fatalf("Match 元数据补全不符: %+v", hits)
	}
}

// TestMatcherFindFirstDuplicate 同名指纹取首条（与旧线性查找语义一致）。
func TestMatcherFindFirstDuplicate(t *testing.T) {
	path := writeTestTechJSON(t, []map[string]any{
		{"name": "Dup", "cats": []string{"a"}, "conf": 10,
			"rules": map[string]any{"html": []string{"dup-first"}}},
		{"name": "Dup", "cats": []string{"b"}, "conf": 20,
			"rules": map[string]any{"html": []string{"dup-second"}}},
	})
	m, err := LoadMatcher(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.find("Dup"); got != m.techs[0].tech {
		t.Fatalf("同名应取首条: got=%+v", got)
	}
}

// TestMatcherZeroValue 零值 Matcher（引擎热替换降级用）行为不变。
func TestMatcherZeroValue(t *testing.T) {
	m := &Matcher{}
	if m.Count() != 0 {
		t.Fatalf("零值 Matcher Count = %d", m.Count())
	}
	if got := m.find("WordPress"); got != nil {
		t.Fatalf("零值 Matcher find 应为 nil: %+v", got)
	}
	hits := m.Match(&Evidence{Body: "wordpress", Headers: map[string]string{}, Metas: map[string]string{}})
	if len(hits) != 0 {
		t.Fatalf("零值 Matcher Match 应为空: %+v", hits)
	}
}
