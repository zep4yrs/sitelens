package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func yamlUnmarshalForTest(in string, out *map[string]any) error {
	return yaml.Unmarshal([]byte(in), out)
}

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
		var probe map[string]any
		if err := yamlUnmarshalForTest(goodTpl, &probe); err != nil {
			t.Fatalf("yaml 解析失败: %v", err)
		}
		t.Fatalf("应转换出 1 条: %d", len(cs))
	}
	c := cs[0]
	if c.ID != "nuclei-CVE-2020-26876" || c.Path != "/wp-json/wp/v2/lesson/1" {
		t.Fatalf("字段转换失败: %+v", c)
	}
	if c.Sev != "high" || c.Lv != 1 {
		t.Fatalf("严重度/等级失败: %+v", c)
	}
	// and 条件多组合并：有词组时按"宁少报"丢弃 status，仅保留全包含词
	if c.Match.Status != 0 || len(c.Match.Contains) != 2 {
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
	sel := Select(entries, map[string]bool{"wordpress": true}, "", 2, &cursor)
	if len(sel) != 2 || sel[0].Path != "a.yaml" {
		t.Fatalf("tag 置顶失败: %+v", sel)
	}
	// 无 tag 命中时轮转：两次选择起点不同
	sel1 := Select(entries, map[string]bool{}, "", 2, &cursor)
	sel2 := Select(entries, map[string]bool{}, "", 2, &cursor)
	if sel1[0].Path == sel2[0].Path {
		t.Fatalf("游标应轮转: %s vs %s", sel1[0].Path, sel2[0].Path)
	}
}

func TestSelectRelevanceRanking(t *testing.T) {
	entries := []Entry{
		{Path: "z-unrelated.yaml", Name: "Something Else", Tags: []string{"misc"}, Sev: "low"},
		{Path: "m-wp-firewall.yaml", Name: "WordPress Firewall Detect", Tags: []string{"wp-plugin"}, Sev: "medium"},
		{Path: "k-wp-backup.yaml", Name: "WordPress Backup Exposure", Tags: []string{"wp-plugin"}, Sev: "high"},
		{Path: "a-other.yaml", Name: "Other Thing", Tags: []string{"misc"}, Sev: "info"},
	}
	cursor := 0
	// 无 tag 硬命中，但查询词 "wordpress backup" 与两条 wp 模板词面重合，
	// 应排到最前，且 high 严重度的 backup 在前
	sel := Select(entries, map[string]bool{}, "wordpress backup 泄露", 2, &cursor)
	if len(sel) < 2 || sel[0].Path != "k-wp-backup.yaml" || sel[1].Path != "m-wp-firewall.yaml" {
		t.Fatalf("相关度排序失败: %+v", sel)
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
	// 回归断言：Index 必须提取 tags（此前重构曾静默丢失，tag 路由整条失效）
	withTags := 0
	for _, e := range entries {
		if len(e.Tags) > 0 {
			withTags++
		}
	}
	if withTags < len(entries)/2 {
		t.Fatalf("带 tags 的条目占比异常低: %d/%d", withTags, len(entries))
	}
	// tag 路由：wordpress tag 应命中真实模板
	wpSel := Select(entries, map[string]bool{"wordpress": true}, "", 20, nil)
	if len(wpSel) == 0 {
		t.Fatal("wordpress tag 应命中模板")
	}
	wpHit := false
	for _, e := range wpSel {
		for _, tg := range e.Tags {
			if tg == "wordpress" {
				wpHit = true
			}
		}
	}
	if !wpHit {
		t.Fatalf("选中结果应含 wordpress tag: %+v", wpSel[:2])
	}
	// 抽 200 条转换：漏斗会按 Python 版同款规则拒绝相当比例
	//（OSINT/外部 URL/interactsh/dsl 等），但应有可观的成功数
	sel := Select(entries, map[string]bool{}, "", 200, nil)
	if len(sel) == 0 {
		t.Fatal("选择器应返回条目")
	}
	loaded := 0
	for _, e := range sel {
		if cs, err := LoadFile(filepath.Join(dir, filepath.FromSlash(e.Path))); err == nil && len(cs) > 0 {
			loaded++
		}
	}
	t.Logf("抽样 %d 条，漏斗通过 %d 条", len(sel), loaded)
	if loaded < 10 {
		t.Fatalf("漏斗通过数异常偏低: %d/%d", loaded, len(sel))
	}
}
