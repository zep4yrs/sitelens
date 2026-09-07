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

// dsl 安全子集：状态比较 + tolower 包含（真实库占比最高的形态）
const dslTpl = `id: dsl-combo
info:
  name: DSL Combo
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && contains(tolower(body), "<title>ackee")'
`

// 纯排除式：对任意响应可能恒真，准入必须拒绝（防空转 check）
const dslExclusionOnlyTpl = `id: dsl-excl
info:
  name: DSL Exclusion Only
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - '!contains(host,"1password.com")'
`

// 子集外函数 / extract 绑定变量 / 多请求变量：准入拒绝
const dslExoticTpl = `id: dsl-exotic
info:
  name: DSL Exotic
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "bcontains(base64('abc'))"
          - "compare_versions(version, '<=2.2.34')"
          - "status_code_2 == 200"
`

// regex 匹配器：装配修复回归——此前 g.rx 从未写入 Match.RegexBody，
// 纯 regex 模板会转成无条件 check（对任意响应恒真）
const regexOnlyTpl = `id: regex-only
info:
  name: Regex Only
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        regex:
          - "powered by WordPress [0-9.]+"
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

// TestConvertDslSafeSubset dsl 安全子集准入：正向子集转换并写入
// Match.DSL；纯排除式与子集外形态整模板跳过。
func TestConvertDslSafeSubset(t *testing.T) {
	cs := Convert([]byte(dslTpl))
	if len(cs) != 1 {
		t.Fatalf("dsl 正向模板应转换出 1 条: %d", len(cs))
	}
	if len(cs[0].Match.DSL) != 1 {
		t.Fatalf("Match.DSL 未装配: %+v", cs[0].Match)
	}
	if cs[0].Match.DSL[0] != `status_code == 200 && contains(tolower(body), "<title>ackee")` {
		t.Fatalf("dsl 表达式原文应原样保留: %q", cs[0].Match.DSL[0])
	}

	if cs := Convert([]byte(dslExclusionOnlyTpl)); len(cs) != 0 {
		t.Fatalf("纯排除式 dsl 应跳过（恒真空转）: %+v", cs)
	}
	if cs := Convert([]byte(dslExoticTpl)); len(cs) != 0 {
		t.Fatalf("子集外 dsl（bcontains/extract 绑定/多请求变量）应跳过: %+v", cs)
	}
}

// TestConvertRegexBodyAttached 锁定装配修复：regex 匹配器必须落到
// Match.RegexBody（此前 g.rx 丢失导致纯 regex 模板对任意响应恒真）。
func TestConvertRegexBodyAttached(t *testing.T) {
	cs := Convert([]byte(regexOnlyTpl))
	if len(cs) != 1 {
		t.Fatalf("纯 regex 模板应转换出 1 条: %d", len(cs))
	}
	if len(cs[0].Match.RegexBody) != 1 || cs[0].Match.RegexBody[0] != "(?i)powered by WordPress [0-9.]+" {
		t.Fatalf("Match.RegexBody 未装配: %+v", cs[0].Match)
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
