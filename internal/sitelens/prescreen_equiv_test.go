package sitelens

// 预筛 / 正则缓存 / 门控的等价性回归：
//  1. 加载期正则 intern：同 raw 串共享同一 *regexp.Regexp（结果缓存能跨技术命中）；
//  2. 语法树门控只做「确定不可能命中」的跳过——与旧实现（仅 literalGate 门控）
//     的命中集合与命中证据文本必须逐字段一致；
//  3. 带预筛的 MatchPrescreen 与无预筛的 Match 的命中（名称/版本/置信）一致。

import (
	"encoding/json"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

func corpusEvidence(body string) *Evidence {
	doc := htmlx.Parse(body)
	return &Evidence{
		URL: "http://corpus.example/", FinalURL: "http://corpus.example/", Status: 200,
		Headers: map[string]string{
			"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.0", "Content-Type": "text/html",
		},
		Body: body, Title: doc.Title, ScriptSrcs: doc.ScriptSrcs, Metas: doc.Metas,
		CookieNames: []string{"wordpress_test_cookie"},
	}
}

// TestRegexInternSharesCompiledPattern 同一指纹库内相同 raw 正则只编译一次。
func TestRegexInternSharesCompiledPattern(t *testing.T) {
	raw := `SiteLens[ /]?v?([\d.]+)`
	techs, err := LoadTechnologiesFrom(mustRules2(t,
		map[string]any{"html": []string{raw}},
		map[string]any{"html": []string{raw}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(techs) != 2 || len(techs[0].html) != 1 || len(techs[1].html) != 1 {
		t.Fatalf("规则加载不符: %d", len(techs))
	}
	p0, p1 := techs[0].html[0], techs[1].html[0]
	if p0.re == nil || p1.re == nil {
		t.Fatalf("正则未编译: %+v %+v", p0, p1)
	}
	if p0.re != p1.re {
		t.Fatal("相同 raw 正则未复用同一 *regexp.Regexp（intern 失效，结果缓存无法跨技术命中）")
	}
	if p0.gate != p1.gate || p0.raw != p1.raw {
		t.Fatalf("intern 后 pattern 字段不一致: %+v %+v", p0, p1)
	}
	// 命中仍正常并抽版本
	ev := &Evidence{Headers: map[string]string{}, Metas: map[string]string{}, Body: "powered by SiteLens v3.2.1"}
	hits := Match(techs, ev)
	if len(hits) != 2 || hits[0].Version != "3.2.1" {
		t.Fatalf("intern 后匹配/版本抽取异常: %+v", hits)
	}
}

// TestPrescreenGateEquivalenceOldSemantics 新门控（旧 literalGate + 语法树条件树）
// 与旧语义（仅 literalGate）在全库 × 语料上命中集合、命中证据文本完全一致。
func TestPrescreenGateEquivalenceOldSemantics(t *testing.T) {
	techs := loadTestTechs(t)
	ps := buildLitPrescreen(techs)
	// 参照实现：清空语法树门控，其余（旧门控/预筛/正则）完全相同
	refTechs := cloneTechsNoGateTree(techs)
	refPS := buildLitPrescreen(refTechs)

	corpus := testCorpusBodies(t)
	for _, name := range sortedCorpusNames(corpus) {
		ev := corpusEvidence(corpus[name])
		got := MatchPrescreen(techs, ev, ps)
		want := MatchPrescreen(refTechs, ev, refPS)
		if len(got) != len(want) {
			t.Fatalf("%s: 命中数不一致 new=%d old=%d", name, len(got), len(want))
		}
		for i := range want {
			if !sameHit(got[i], want[i]) {
				t.Fatalf("%s: 第 %d 条命中不一致\n new=%+v\n old=%+v", name, i, got[i], want[i])
			}
		}
	}
}

// TestMatchPrescreenHitsSubsetOfPlainMatch 预筛不得新增命中：
// 带预筛路径的每条命中都必须能在无预筛路径（Match）里找到同名同版本的命中。
//
// 注意：反向不成立是**旧实现既有语义**——无预筛的 Match 对 html 字面量模式
// 直接 Contains 即命中，而带预筛的路径还叠了 weakKeyword/productNameOnly
// 双重闸门（见 fingerprint.go 注释），所以 Match 可能多报。本测试只保证
// 「预筛不改变/不新增命中」，历史差异不在此测试范围内。
func TestMatchPrescreenHitsSubsetOfPlainMatch(t *testing.T) {
	techs := loadTestTechs(t)
	ps := buildLitPrescreen(techs)
	corpus := testCorpusBodies(t)
	for _, name := range sortedCorpusNames(corpus) {
		ev := corpusEvidence(corpus[name])
		got := MatchPrescreen(techs, ev, ps)
		plain := Match(techs, ev)
		plainSet := make(map[string]string, len(plain))
		for _, h := range plain {
			plainSet[h.Name] = h.Version
		}
		for _, h := range got {
			v, ok := plainSet[h.Name]
			if !ok {
				t.Fatalf("%s: 预筛命中 %q 在无预筛路径不存在（预筛新增了命中）", name, h.Name)
			}
			if v != h.Version {
				t.Fatalf("%s: %q 版本不一致 prescreen=%q plain=%q", name, h.Name, h.Version, v)
			}
		}
	}
}

// mustRules2 生成含多条指纹的内存指纹库（与 fingerprint_test.go 的 mustRules 区分）。
func mustRules2(t *testing.T, ruleSets ...map[string]any) json.RawMessage {
	t.Helper()
	techs := make([]map[string]any, 0, len(ruleSets))
	for i, rules := range ruleSets {
		techs = append(techs, map[string]any{
			"name": "TestTech" + string(rune('A'+i)), "cats": []string{"misc"},
			"conf": 50, "rules": rules,
		})
	}
	b, err := json.Marshal(map[string]any{"technologies": techs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sameHit 命中逐字段比较（Cats 为切片，不能直接用 !=）。
func sameHit(a, b Hit) bool {
	if a.Name != b.Name || a.Conf != b.Conf || a.Evidence != b.Evidence || a.Version != b.Version {
		return false
	}
	if len(a.Cats) != len(b.Cats) {
		return false
	}
	for i := range a.Cats {
		if a.Cats[i] != b.Cats[i] {
			return false
		}
	}
	return true
}
