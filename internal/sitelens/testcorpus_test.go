package sitelens

// 指纹匹配优化（5.2）的回归测试共用语料/辅助。
//
// 语料来源：仓库内真实页面（web/*.html）、HTML 解析器 fuzz 语料、以及若干
// 典型站点形状的合成页——用于验证「优化前后命中集合/证据文本完全一致」。

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

const testTechLibPath = "../../data/go/technologies.json"

var (
	testLibOnce sync.Once
	testLib     []*compiledTech
	testLibErr  error
)

// loadTestTechs 全库指纹（包内只加载一次，避免每个测试重复解析 3.4MB JSON）。
func loadTestTechs(t *testing.T) []*compiledTech {
	t.Helper()
	if _, err := os.Stat(testTechLibPath); err != nil {
		t.Skipf("指纹库不在本地，跳过: %v", err)
	}
	testLibOnce.Do(func() {
		testLib, testLibErr = LoadTechnologies(testTechLibPath)
	})
	if testLibErr != nil {
		t.Fatalf("加载指纹库失败: %v", testLibErr)
	}
	return testLib
}

// testBenchBody 40KB 拟真页（与 BenchmarkMatch 同形状，含 WordPress/jQuery 特征）。
func testBenchBody() string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><title>Example Domain</title>")
	b.WriteString(`<meta name="generator" content="WordPress 6.4">`)
	b.WriteString(`<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>`)
	b.WriteString(`<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">`)
	b.WriteString(`</head><body>`)
	para := "<p>The example page renders content for benchmark payload sizing.</p>"
	for b.Len() < 40*1024 {
		b.WriteString(para)
	}
	b.WriteString("</body></html>")
	return b.String()
}

// testCorpusBodies 真实 + fuzz + 合成页面语料（按名字排序，保证测试确定性）。
func testCorpusBodies(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{"bench": testBenchBody()}
	files, _ := filepath.Glob("../../web/*.html")
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			out["web/"+filepath.Base(f)] = string(b)
		}
	}
	fuzzFiles, _ := filepath.Glob("../../internal/htmlx/testdata/fuzz/*/*")
	for _, f := range fuzzFiles {
		if b, err := os.ReadFile(f); err == nil && len(b) <= 256*1024 {
			out["fuzz/"+filepath.Base(f)] = string(b)
		}
	}
	syn := map[string]string{
		"wordpress": `<!DOCTYPE html><html><head><title>WP</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body><div class="wp-block-group">hello</div></body></html>`,
		"nginx-php": `<html><body><a href="/index.php">home</a><p>Powered by PHP 8.2.0</p></body></html>`,
		"pelican":   `<html><body><p>Powered by <a href="https://getpelican.com/">Pelican</a></p></body></html>`,
		"xenforo":   `<html id="XenForo"><body><a>Forum software by XenForo</a></body></html>`,
		"tilda":     `<html><head><link rel="stylesheet" href="https://static.tildacdn.com/x.css"></head><body></body></html>`,
		"empty":     ``,
		"short":     `abc`,
		"unicode":   `<html><body>ĲSSELMEER İstanbul KELVIN ſoftware STRASSE</body></html>`,
		"nul":       "a\x00b\x00c\x00d\x00e",
	}
	for k, v := range syn {
		out["syn/"+k] = v
	}
	return out
}

// sortedCorpusNames 语料名排序（map 遍历顺序随机会让测试输出不稳定）。
func sortedCorpusNames(corpus map[string]string) []string {
	names := make([]string, 0, len(corpus))
	for n := range corpus {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// corpusInputs 语料里的「正文 + meta 内容」全部待匹配文本（门控健全性校验用）。
func corpusInputs(t *testing.T) map[string][]string {
	t.Helper()
	corpus := testCorpusBodies(t)
	out := make(map[string][]string, len(corpus))
	for name, body := range corpus {
		inputs := []string{body}
		if len(body) > 0 {
			for _, v := range htmlx.Parse(body).Metas {
				if v != "" {
					inputs = append(inputs, v)
				}
			}
		}
		out[name] = inputs
	}
	return out
}

// cloneTechsNoGateTree 复制指纹库但清空语法树门控（还原「旧实现」语义参照）：
// 只保留旧的 literalGate 门控，用于验证新门控不改变任何命中/证据文本。
func cloneTechsNoGateTree(techs []*compiledTech) []*compiledTech {
	out := make([]*compiledTech, len(techs))
	for i, ct := range techs {
		c := *ct
		if ct.html != nil {
			c.html = append([]pattern(nil), ct.html...)
			for j := range c.html {
				c.html[j].gateTree = nil
			}
		}
		if ct.inline != nil {
			c.inline = append([]pattern(nil), ct.inline...)
			for j := range c.inline {
				c.inline[j].gateTree = nil
			}
		}
		if ct.meta != nil {
			c.meta = make(map[string]pattern, len(ct.meta))
			for k, p := range ct.meta {
				p.gateTree = nil
				c.meta[k] = p
			}
		}
		out[i] = &c
	}
	return out
}

// libraryGateTreePatterns 库里全部挂语法树门控的正则模式（健全性校验用）。
func libraryGateTreePatterns(techs []*compiledTech) []pattern {
	var out []pattern
	for _, ct := range techs {
		for _, p := range ct.html {
			if !p.isLit && p.gateTree != nil {
				out = append(out, p)
			}
		}
		for _, p := range ct.inline {
			if !p.isLit && p.gateTree != nil {
				out = append(out, p)
			}
		}
		for _, p := range ct.meta {
			if p.gateTree != nil {
				out = append(out, p)
			}
		}
	}
	return out
}
