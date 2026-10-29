package nuclei

// BUG-022：path 列表展开的回归断言。
//
// 旧实现 `path = req.Path[0]` 只探测第一项，其余候选路径全丢（wordfence
// 类模板最多 4 条候选，官库/40k 来源长尾最长 64 条）。现按 maxPathExpand
// 展开为多条 check（id 带 ~pN 后缀），长尾截断是覆盖率损失、不是误报来源。

import (
	"fmt"
	"strings"
	"testing"
)

func TestConvertPathListExpanded(t *testing.T) {
	poc := `
id: multi-path
info:
  name: 多路径候选
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/a/readme.txt"
      - "{{BaseURL}}/wp-content/plugins/b/readme.txt"
      - "{{BaseURL}}/wp-content/plugins/c/readme.txt"
    matchers:
      - type: word
        words: ["stable tag"]
`
	cs := Convert([]byte(poc))
	if len(cs) != 3 {
		t.Fatalf("3 条候选路径应展开为 3 条 check, got %d", len(cs))
	}
	wantPaths := []string{
		"/wp-content/plugins/a/readme.txt",
		"/wp-content/plugins/b/readme.txt",
		"/wp-content/plugins/c/readme.txt",
	}
	for i, c := range cs {
		if c.Path != wantPaths[i] {
			t.Errorf("check[%d].Path = %q, want %q", i, c.Path, wantPaths[i])
		}
		wantID := fmt.Sprintf("nuclei-multi-path~p%d", i+1)
		if c.ID != wantID {
			t.Errorf("check[%d].ID = %q, want %q", i, c.ID, wantID)
		}
	}
}

func TestConvertPathListCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`
id: long-path-list
info:
  name: 长路径列表
  severity: low
http:
  - method: GET
    path:
`)
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&b, "      - \"{{BaseURL}}/p/%d\"\n", i)
	}
	b.WriteString(`
    matchers:
      - type: word
        words: ["hello"]
`)
	cs := Convert([]byte(b.String()))
	if len(cs) != maxPathExpand {
		t.Fatalf("长路径列表应截断到 %d 条, got %d", maxPathExpand, len(cs))
	}
	if cs[0].Path != "/p/0" || cs[maxPathExpand-1].Path != fmt.Sprintf("/p/%d", maxPathExpand-1) {
		t.Fatalf("展开顺序不符: %q .. %q", cs[0].Path, cs[maxPathExpand-1].Path)
	}
}

func TestConvertPathListDedupAndSkipUnusable(t *testing.T) {
	poc := `
id: dedup-path
info:
  name: 重复与不可用路径
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/same"
      - "{{BaseURL}}/same"
      - "{{BaseURL}}/x/{{var}}"
      - "relative/no-base"
    matchers:
      - type: word
        words: ["hello"]
`
	cs := Convert([]byte(poc))
	if len(cs) != 1 {
		t.Fatalf("去重/跳过不可用路径后应只剩 1 条, got %d", len(cs))
	}
	if cs[0].Path != "/same" {
		t.Fatalf("Path = %q", cs[0].Path)
	}
	if cs[0].ID != "nuclei-dedup-path" {
		t.Fatalf("单路径不应带 ~pN 后缀: %q", cs[0].ID)
	}
}

func TestConvertPathListSalvagesLaterPath(t *testing.T) {
	poc := `
id: salvage-path
info:
  name: 首项不可用但次项可用
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/x/{{var}}"
      - "{{BaseURL}}/usable"
    matchers:
      - type: word
        words: ["hello"]
`
	cs := Convert([]byte(poc))
	if len(cs) != 1 || cs[0].Path != "/usable" {
		t.Fatalf("应保留可用路径 /usable, got %+v", cs)
	}
}
