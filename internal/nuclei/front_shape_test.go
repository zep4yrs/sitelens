package nuclei

// 前端形状预筛的安全性测试：scanFrontShape 是「排除法」，返回位图必须是
// 实际可能命中前端集合的超集——任何一条前端真的转换成功了，对应位必须
// 已置位。这是预筛能跳过解析的前提；宁可多解析一次，不可漏转换。

import (
	"bytes"
	"strings"
	"testing"
)

// shapeCase 形状预筛用例：文档 + 期望的精确位图（-1 表示只校验超集关系）。
type shapeCase struct {
	name    string
	doc     []byte
	exact   frontShape
	exactOK bool
}

func frontShapeCases(tb testing.TB) []shapeCase {
	tb.Helper()
	cases := []shapeCase{
		{name: "path", doc: []byte(goodTpl), exact: frontHTTP, exactOK: true},
		{name: "raw", doc: []byte(`
id: raw-shape
info:
  name: raw
http:
  - raw:
      - |
        GET {{BaseURL}}/r HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: ["r"]
`), exact: frontHTTP, exactOK: true},
		{name: "requests", doc: []byte(`
id: req-shape
info:
  name: req
requests:
  - method: GET
    path: ["{{BaseURL}}/r"]
    matchers:
      - type: word
        words: ["r"]
`), exact: frontHTTP, exactOK: true},
		{name: "afrog", doc: []byte(`
id: afrog-shape
info:
  name: afrog
rules:
  r0:
    request:
      path: /a
    response:
      body: ["a"]
expression: r0()
`), exact: frontAfrog, exactOK: true},
		{name: "tcp", doc: []byte(`
id: tcp-shape
info:
  name: tcp
tcp:
  - matchers:
      - type: word
        words: ["PONG"]
`), exact: frontNet, exactOK: true},
		{name: "dns", doc: []byte("id: d\ninfo:\n  name: d\ndns:\n  - matchers:\n      - type: word\n        words: [x]\n"), exact: frontNet, exactOK: true},
		{name: "ssl", doc: []byte("id: s\ninfo:\n  name: s\nssl:\n  - matchers:\n      - type: word\n        words: [x]\n"), exact: frontNet, exactOK: true},
		{name: "hybrid", doc: []byte(`
id: hybrid-shape
info:
  name: h
http:
  - method: GET
    path: /ignored
rules:
  r0:
    request:
      path: /a
    response:
      body: ["a"]
expression: r0()
`), exact: frontHTTP | frontAfrog, exactOK: true},
		// ---- 键写法变体：必须仍能识别 ----
		{name: "quoted-http", doc: []byte("id: q\ninfo:\n  name: q\n\"http\":\n  - method: GET\n    path: \"{{BaseURL}}/q\"\n    matchers:\n      - type: word\n        words: [q]\n"), exact: frontHTTP, exactOK: true},
		{name: "single-quoted-rules", doc: []byte("id: q\ninfo:\n  name: q\n'rules':\n  r0:\n    request:\n      path: /a\n    response:\n      body: [a]\nexpression: r0()\n"), exact: frontAfrog, exactOK: true},
		{name: "space-before-colon", doc: []byte("id: q\ninfo:\n  name: q\nhttp :\n  - method: GET\n    path: \"{{BaseURL}}/q\"\n    matchers:\n      - type: word\n        words: [q]\n"), exact: frontHTTP, exactOK: true},
		{name: "indented-root", doc: []byte("  id: q\n  info:\n    name: q\n  http:\n    - method: GET\n      path: \"{{BaseURL}}/q\"\n      matchers:\n        - type: word\n          words: [q]\n"), exact: frontHTTP, exactOK: true},
		{name: "crlf", doc: bytes.ReplaceAll([]byte(goodTpl), []byte("\n"), []byte("\r\n")), exact: frontHTTP, exactOK: true},
		// YAML 的换行集合不止 \n：CR / NEL(#x85) / LS(#x2028) / PS(#x2029)
		// 都是行分隔符。只看 \n 会把这些行误当成嵌套内容而漏掉顶层键
		// （fuzz 实测案例，已收入 testdata/fuzz 回归语料）。
		{name: "cr-only-break", doc: []byte("id: cr\ninfo:\n  name: cr\rhttp:\n  - method: GET\n    path: \"{{BaseURL}}/cr\"\n    matchers:\n      - type: word\n        words: [cr]\n"), exact: frontHTTP, exactOK: true},
		{name: "nel-break", doc: []byte("id: nel\ninfo:\n  name: nel\u0085http:\n  - method: GET\n    path: \"{{BaseURL}}/nel\"\n    matchers:\n      - type: word\n        words: [nel]\n"), exact: frontHTTP, exactOK: true},
		{name: "ls-break", doc: []byte("id: ls\ninfo:\n  name: ls\u2028rules:\n  r0:\n    request:\n      path: /ls\n    response:\n      body: [ls]\nexpression: r0()\n"), exact: frontAfrog, exactOK: true},
		{name: "ps-break", doc: []byte("id: ps\ninfo:\n  name: ps\u2029tcp:\n  - matchers:\n      - type: word\n        words: [ps]\n"), exact: frontNet, exactOK: true},
		{name: "bom", doc: append([]byte{0xEF, 0xBB, 0xBF}, []byte(goodTpl)...), exact: frontHTTP, exactOK: true},
		{name: "doc-marker", doc: []byte("---\nid: q\ninfo:\n  name: q\nhttp:\n  - method: GET\n    path: \"{{BaseURL}}/q\"\n    matchers:\n      - type: word\n        words: [q]\n"), exact: frontHTTP, exactOK: true},
		{name: "leading-comments", doc: []byte("# c\n---\n# http:\nid: q\ninfo:\n  name: q\nrules:\n  r0:\n    request:\n      path: /a\n    response:\n      body: [a]\nexpression: r0()\n"), exact: frontAfrog, exactOK: true},
		{name: "nested-key-not-top", doc: []byte("id: q\ninfo:\n  name: q\n  description: |\n    http:\n      - path: x\n"), exact: 0, exactOK: true},
		// ---- 无法廉价确认的形态：必须保守返回超集（不校验精确值）----
		{name: "flow-root", doc: []byte(`{"id":"f","info":{"name":"f"},"http":[{"method":"GET","path":"{{BaseURL}}/f","matchers":[{"type":"word","words":["f"]}]}]}`)},
		{name: "merge-key", doc: []byte("base: &b\n  http:\n    - method: GET\n      path: \"{{BaseURL}}/m\"\n      matchers:\n        - type: word\n          words: [m]\nid: m\ninfo:\n  name: m\n<<: *b\n")},
		{name: "tagged-key", doc: []byte("!!str http:\n  - method: GET\n    path: \"{{BaseURL}}/t\"\n    matchers:\n      - type: word\n        words: [t]\n")},
		{name: "anchored-key", doc: []byte("&a http:\n  - method: GET\n    path: \"{{BaseURL}}/a\"\n    matchers:\n      - type: word\n        words: [a]\n")},
		{name: "explicit-key", doc: []byte("? http\n: []\nid: x\ninfo:\n  name: x\n")},
		{name: "escaped-quoted-key", doc: []byte("\"ht\\x74p\": []\nid: x\ninfo:\n  name: x\n")},
		{name: "multi-doc", doc: []byte("id: a\ninfo:\n  name: a\n---\nhttp:\n  - method: GET\n    path: \"{{BaseURL}}/b\"\n    matchers:\n      - type: word\n        words: [b]\n")},
		{name: "root-seq", doc: []byte("- id: x\n  info:\n    name: y\n"), exact: 0, exactOK: true},
		{name: "scalar-root", doc: []byte("just text\n"), exact: 0, exactOK: true},
		{name: "empty", doc: nil, exact: 0, exactOK: true},
		{name: "invalid-tab", doc: []byte("id: x\nhttp:\n\t- broken\n")},
		{name: "interactsh", doc: []byte("id: x\ninfo:\n  name: x\nhttp:\n  - method: GET\n    path: \"{{BaseURL}}/oob\"\n    matchers:\n      - type: word\n        words: [interactsh-url]\n"), exact: 0, exactOK: true},
		{name: "oversize", doc: append([]byte(goodTpl), bytes.Repeat([]byte("# pad\n"), 100*1024)...), exact: 0, exactOK: true},
	}
	return cases
}

// TestScanFrontShapeSuperset 逐用例校验「超集安全」与代表性形态的精确位图。
func TestScanFrontShapeSuperset(t *testing.T) {
	for _, c := range frontShapeCases(t) {
		c := c
		t.Run(c.name, func(t *testing.T) {
			shape := scanFrontShape(c.doc)
			if c.exactOK && shape != c.exact {
				t.Fatalf("scanFrontShape=%03b, want %03b", shape, c.exact)
			}
			// 实际命中 → 位图必须置位（漏位 = 会漏转换，红线）
			if len(Convert(c.doc)) > 0 && shape&frontHTTP == 0 {
				t.Fatalf("Convert 命中但 frontHTTP 未置位: shape=%03b", shape)
			}
			if len(ConvertRaw(c.doc)) > 0 && shape&frontHTTP == 0 {
				t.Fatalf("ConvertRaw 命中但 frontHTTP 未置位: shape=%03b", shape)
			}
			if len(ConvertAfrog(c.doc)) > 0 && shape&frontAfrog == 0 {
				t.Fatalf("ConvertAfrog 命中但 frontAfrog 未置位: shape=%03b", shape)
			}
			if ConvertNetwork(c.doc) != nil && shape&frontNet == 0 {
				t.Fatalf("ConvertNetwork 命中但 frontNet 未置位: shape=%03b", shape)
			}
		})
	}
}

// FuzzScanFrontShapeSuperset 用随机字节轰击超集安全性质（种子覆盖全部
// 形状用例；常规 go test 只跑种子，-fuzz 时才扩展）。
func FuzzScanFrontShapeSuperset(f *testing.F) {
	for _, c := range frontShapeCases(f) {
		f.Add(c.doc)
	}
	f.Add([]byte(goodTpl))
	f.Add([]byte(dslTpl))
	f.Fuzz(func(t *testing.T, data []byte) {
		shape := scanFrontShape(data)
		if len(Convert(data)) > 0 && shape&frontHTTP == 0 {
			t.Fatalf("Convert 命中但 frontHTTP 未置位: shape=%03b, data=%q", shape, data)
		}
		if len(ConvertRaw(data)) > 0 && shape&frontHTTP == 0 {
			t.Fatalf("ConvertRaw 命中但 frontHTTP 未置位: shape=%03b", shape)
		}
		if len(ConvertAfrog(data)) > 0 && shape&frontAfrog == 0 {
			t.Fatalf("ConvertAfrog 命中但 frontAfrog 未置位: shape=%03b, data=%q", shape, data)
		}
		if ConvertNetwork(data) != nil && shape&frontNet == 0 {
			t.Fatalf("ConvertNetwork 命中但 frontNet 未置位: shape=%03b", shape)
		}
	})
}

// TestScanFrontShapeSkipsWastedParses 锁定优化收益本身：afrog 形状只走
// afrog 前端（不再白解析 path/raw 两次），path 形状只走 HTTP 前端。
func TestScanFrontShapeSkipsWastedParses(t *testing.T) {
	afrogOnly := []byte(`
id: afrog-only
info:
  name: afrog only
rules:
  r0:
    request:
      path: /a
    response:
      body: ["a"]
expression: r0()
`)
	if got := scanFrontShape(afrogOnly); got != frontAfrog {
		t.Fatalf("afrog 形状应只含 frontAfrog: %03b", got)
	}
	if got := scanFrontShape([]byte(goodTpl)); got != frontHTTP {
		t.Fatalf("path 形状应只含 frontHTTP: %03b", got)
	}
	if got := scanFrontShape([]byte("id: x\ninfo:\n  name: x\nhttp: []\nrules: {}\ntcp: []\n")); got != frontHTTP|frontAfrog|frontNet {
		t.Fatalf("三键并存应置全部位: %03b", got)
	}
	if strings.Contains(string(afrogOnly), "http:") {
		t.Fatal("用例构造有误")
	}
}
