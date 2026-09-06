package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

const goodTpl = `id: CVE-2020-26876
info:
  name: WP Courses Information Disclosure
  severity: high
  tags: cve,wordpress,wp-plugin
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-json/wp/v2/lesson/1"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "lesson"
          - "content"
        condition: and
`

const unsupportedTpl = `id: needs-dsl
info:
  name: DSL Template
  severity: medium
http:
  - path:
      - "{{BaseURL}}/x"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
`

const multiGroupTpl = `id: multi-or
info:
  name: Multi OR Groups
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status: [200, 301]
      - type: word
        words: ["dashboard"]
`

func TestConvertGoodTemplate(t *testing.T) {
	cs := Convert([]byte(goodTpl))
	if len(cs) != 1 {
		t.Fatalf("应转换出 1 条: %d", len(cs))
	}
	c := cs[0]
	if c.ID != "nuclei-CVE-2020-26876" || c.Path != "/wp-json/wp/v2/lesson/1" {
		t.Fatalf("字段转换失败: %+v", c)
	}
	if c.Sev != "high" || c.Lv != 1 {
		t.Fatalf("严重度/等级失败: %+v", c)
	}
	// and 条件：status 200 + 两个词全包含
	if c.Match.Status != 200 || len(c.Match.Contains) != 2 {
		t.Fatalf("matchers-and 合并失败: %+v", c.Match)
	}
}

func TestConvertUnsupportedSkipped(t *testing.T) {
	if cs := Convert([]byte(unsupportedTpl)); len(cs) != 0 {
		t.Fatalf("dsl 模板应跳过: %+v", cs)
	}
}

func TestConvertMultiGroupSplit(t *testing.T) {
	cs := Convert([]byte(multiGroupTpl))
	if len(cs) != 2 {
		t.Fatalf("or 多组应拆成 2 条: %d", len(cs))
	}
	if cs[0].ID != "nuclei-multi-or~g1" || cs[1].ID != "nuclei-multi-or~g2" {
		t.Fatalf("拆分 id 异常: %s %s", cs[0].ID, cs[1].ID)
	}
	// status 组：200/301 任一
	if len(cs[0].Match.StatusAny) != 2 {
		t.Fatalf("StatusAny 转换失败: %+v", cs[0].Match)
	}
	// word or 组：ContainsAny
	if len(cs[1].Match.ContainsAny) != 1 {
		t.Fatalf("ContainsAny 转换失败: %+v", cs[1].Match)
	}
}

func TestSelectTagPriorityAndRotation(t *testing.T) {
	entries := []Entry{
		{Path: "a.yaml", Tags: []string{"wordpress"}, Sev: "high"},
		{Path: "b.yaml", Tags: []string{"nginx"}, Sev: "critical"},
		{Path: "c.yaml", Tags: []string{"misc"}, Sev: "low"},
		{Path: "d.yaml", Tags: []string{"misc"}, Sev: "info"},
	}
	cursor := 0
	sel := Select(entries, map[string]bool{"wordpress": true}, 2, &cursor)
	if len(sel) != 2 || sel[0].Path != "a.yaml" {
		t.Fatalf("tag 置顶失败: %+v", sel)
	}
	// 无 tag 命中时轮转：两次选择起点不同
	sel1 := Select(entries, map[string]bool{}, 2, &cursor)
	sel2 := Select(entries, map[string]bool{}, 2, &cursor)
	if sel1[0].Path == sel2[0].Path {
		t.Fatalf("游标应轮转: %s vs %s", sel1[0].Path, sel2[0].Path)
	}
}

func TestIndexAndLoadRealLibrary(t *testing.T) {
	dir := "../../data/nuclei"
	if _, err := os.Stat(dir); err != nil {
		t.Skip("模板库不在本地")
	}
	entries, err := Index(dir, filepath.Join(t.TempDir(), "idx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 1000 {
		t.Fatalf("索引条目异常: %d", len(entries))
	}
	// 抽一条真实模板转换
	sel := Select(entries, map[string]bool{"wordpress": true}, 5, nil)
	if len(sel) == 0 {
		t.Fatal("wordpress tag 应命中")
	}
	loaded := 0
	for _, e := range sel {
		if cs, err := LoadFile(filepath.Join(dir, filepath.FromSlash(e.Path))); err == nil && len(cs) > 0 {
			loaded++
		}
	}
	if loaded == 0 {
		t.Fatal("真实模板至少应转换出 1 条")
	}
}
