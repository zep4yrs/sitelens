package nuclei

// 模板索引并行的等价性对照测试。
//
// 生产实现把「逐文件转换」并行化，并加了前端形状预筛；本文件用旧实现的
// 快照（convertAnyLegacy / indexLegacyForTest，逐行复制自 e0afe65 的
// 顺序版本）做差分对照，保证转换产物与 entries 顺序/去重语义逐条不变。
// 旧实现快照是「参考真值」，不随生产代码演进——生产逻辑若改动，差异会
// 在测试里显性暴露，必须同步更新这里并说明理由。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// convertAnyLegacy 旧 convertAny：三前端依次尝试，每个前端各自全量解析。
func convertAnyLegacy(data []byte) []checks.Check {
	if cs := Convert(data); len(cs) > 0 {
		return cs
	}
	if cs := ConvertRaw(data); len(cs) > 0 {
		return cs
	}
	return ConvertAfrog(data)
}

// indexLegacyForTest 旧 Index：单 goroutine 顺序 walk + 转换（e0afe65 快照）。
//
// 快照冻结在 e0afe65 语义：缓存 schema 硬编码 9（当时的版本）——后续
// schema bump 不应改变这份"旧实现"的定义。
func indexLegacyForTest(dir, cachePath string) ([]Entry, error) {
	const legacyCacheSchema = 9
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if data, rerr := os.ReadFile(cachePath); rerr == nil {
			var cached cacheFile
			if json.Unmarshal(data, &cached) == nil && cached.Schema == legacyCacheSchema &&
				cached.Files == len(files) {
				return cached.Entries, nil
			}
		}
	}

	legacyPrefix := "legacy/"
	var first, second []string
	for _, f := range files {
		rel := f
		if r, err := filepath.Rel(dir, f); err == nil {
			rel = filepath.ToSlash(r)
		}
		if strings.HasPrefix(rel, legacyPrefix) {
			second = append(second, f)
		} else {
			first = append(first, f)
		}
	}
	entries := make([]Entry, 0, len(files))
	seenName := map[string]bool{}
	for pi, pass := range [][]string{first, second} {
		for _, f := range pass {
			st, serr := os.Stat(f)
			if serr != nil || st.Size() > 512*1024 {
				continue
			}
			rel, rerr := filepath.Rel(dir, f)
			if rerr != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			data, rerr2 := os.ReadFile(f)
			if rerr2 != nil {
				continue
			}
			var proto string
			cs := convertAnyLegacy(data)
			if len(cs) == 0 {
				if nc := ConvertNetwork(data); nc != nil {
					proto = nc.Proto
				} else {
					continue
				}
			}
			name, sev, tags, cves := convertMeta(string(data))
			if pi == 1 && seenName[name] {
				continue
			}
			seenName[name] = true
			entries = append(entries, Entry{
				Path:        rel,
				Name:        name,
				Sev:         sev,
				Tags:        tags,
				CVEs:        cves,
				Source:      NormalizeSource(rel),
				Proto:       proto,
				MTime:       st.ModTime().Unix(),
				Size:        st.Size(),
				Convertible: true,
			})
		}
	}
	if cachePath != "" {
		if data, jerr := json.Marshal(cacheFile{Schema: 9, Files: len(files), Entries: entries}); jerr == nil {
			_ = os.WriteFile(cachePath, data, 0o644)
		}
	}
	return entries, nil
}

// equivTemplateDocs 差分对照语料：三种前端 + 协议模板 + flow/JSON 形态 +
// 旧顺序多前端同文件（http+rules 混合）+ 非法/被拒形态。
func equivTemplateDocs(tb testing.TB) map[string][]byte {
	tb.Helper()
	docs := map[string][]byte{
		"path":     []byte(goodTpl),
		"dsl":      []byte(dslTpl),
		"dsl-excl": []byte(dslExclusionOnlyTpl),
		"dsl-exot": []byte(dslExoticTpl),
		"regex":    []byte(regexOnlyTpl),
		"multi-or": []byte(multiGroupTpl),
		"raw": []byte(`
id: raw-diff
info:
  name: raw 差分
  severity: high
http:
  - raw:
      - |
        POST {{BaseURL}}/api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"admin'"}
    matchers-condition: and
    matchers:
      - type: status
        status: [500]
      - type: word
        words: ["SQL syntax"]
        condition: or
`),
		"requests": []byte(`
id: req-key
info:
  name: requests 键形态
  severity: medium
requests:
  - method: GET
    path:
      - "{{BaseURL}}/req"
    matchers:
      - type: word
        words: ["reqok"]
`),
		"afrog": []byte(`
id: afrog-diff
info:
  name: afrog 差分
  severity: high
rules:
  r0:
    request:
      method: GET
      path: /afrog/diff
    response:
      status_code: 200
      body: ["AFROG-DIFF"]
expression: r0()
`),
		"hybrid-http-rules": []byte(`
id: hybrid-diff
info:
  name: 混合形态
  severity: high
http:
  - method: GET
    path: /not-a-suffix
rules:
  r0:
    request:
      method: GET
      path: /hybrid/ok
    expression: response.status == 200 && response.body.bcontains(b"HYBRID-OK")
expression: r0()
`),
		// 同一文件同时满足 path 与 afrog 两个前端：首命中必须是 path
		"both-path-afrog": []byte(`
id: both-path-afrog
info:
  name: Path 与 Afrog 双命中
  severity: medium
http:
  - method: GET
    path: "{{BaseURL}}/path-wins"
    matchers:
      - type: word
        words: ["pathwins"]
rules:
  r0:
    request:
      method: GET
      path: /afrog-loses
    expression: response.status == 200 && response.body.bcontains(b"AFROG")
expression: r0()
`),
		// 同一文件同时满足 raw 与 afrog 两个前端：首命中必须是 raw
		"both-raw-afrog": []byte(`
id: both-raw-afrog
info:
  name: Raw 与 Afrog 双命中
  severity: medium
http:
  - raw:
      - |
        POST {{BaseURL}}/raw-wins HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: ["rawwins"]
rules:
  r0:
    request:
      method: GET
      path: /afrog-loses
    expression: response.status == 200 && response.body.bcontains(b"AFROG")
expression: r0()
`),
		"flow-json": []byte(`{"id":"flow-diff","info":{"name":"flow 形态","severity":"low"},"http":[{"method":"GET","path":"{{BaseURL}}/flow","matchers":[{"type":"word","words":["flowok"]}]}]}`),
		"tcp": []byte(`
id: tcp-diff
info:
  name: tcp 差分
  severity: info
tcp:
  - inputs:
      - data: "PING\r\n"
    matchers:
      - type: word
        words: ["PONG"]
`),
		"dns": []byte(`
id: dns-diff
info:
  name: dns 差分
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["1.2.3.4"]
`),
		"ssl": []byte(`
id: ssl-diff
info:
  name: ssl 差分
  severity: info
ssl:
  - address: "{{Host}}:443"
    matchers:
      - type: word
        words: ["example"]
`),
		"multi-path": []byte(`
id: multi-path-diff
info:
  name: 多路径展开
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
      - "{{BaseURL}}/b"
      - "{{BaseURL}}/c"
    matchers:
      - type: word
        words: ["hit"]
`),
		"noisy": []byte(`
id: acme-xss
info:
  name: 噪声模板
  severity: high
rules:
  r0:
    request:
      path: /x
    response:
      body: ["xss"]
expression: r0()
`),
		"interactsh": []byte(`
id: interactsh-diff
info:
  name: 外部回调
  severity: high
http:
  - method: GET
    path: "{{BaseURL}}/oob"
    matchers:
      - type: word
        words: ["interactsh-url"]
`),
		"invalid":   []byte("id: [unclosed\nhttp:\n\t- broken\n"),
		"empty":     {},
		"root-seq":  []byte("- id: x\n  info:\n    name: y\n"),
		"scalar":    []byte("just a scalar\n"),
		"comments":  []byte("# only comments\n\n# http:\nrules: {}\n"),
		"crlf":      bytes.ReplaceAll([]byte(goodTpl), []byte("\n"), []byte("\r\n")),
		"bom":       append([]byte{0xEF, 0xBB, 0xBF}, []byte(goodTpl)...),
		"merge-key": []byte("base: &b\n  http:\n    - method: GET\n      path: \"{{BaseURL}}/m\"\n      matchers:\n        - type: word\n          words: [m]\nid: merge-diff\ninfo:\n  name: merge 形态\n<<: *b\n"),
	}
	// 12 条 afrog 真实夹具一并纳入
	afrogFiles, err := filepath.Glob(filepath.Join("testdata", "afrog", "*.yaml"))
	if err != nil {
		tb.Fatal(err)
	}
	if len(afrogFiles) != 12 {
		tb.Fatalf("afrog 真实夹具应为 12 条: %d", len(afrogFiles))
	}
	for _, f := range afrogFiles {
		data, rerr := os.ReadFile(f)
		if rerr != nil {
			tb.Fatalf("读夹具失败 %s: %v", f, rerr)
		}
		docs["fixture/"+filepath.Base(f)] = data
	}
	return docs
}

// TestConvertAnyLegacyEquivalent 差分对照：新 convertAny 与旧三前端顺序
// 实现对同一语料逐条相等（全字段，0 差异）。
func TestConvertAnyLegacyEquivalent(t *testing.T) {
	docs := equivTemplateDocs(t)
	converted := 0
	for name, data := range docs {
		want := convertAnyLegacy(data)
		got := convertAny(data)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: convertAny 与旧实现不等价\n got=%+v\nwant=%+v", name, got, want)
		}
		// 同一份形状位图喂给 convertAnyShape 必须得到同一结果
		if got2 := convertAnyShape(data, scanFrontShape(data)); !reflect.DeepEqual(got2, want) {
			t.Fatalf("%s: convertAnyShape 与旧实现不等价", name)
		}
		if len(want) > 0 {
			converted++
		}
	}
	if converted < 15 {
		t.Fatalf("差分语料覆盖面不足，仅 %d/%d 条转换成功", converted, len(docs))
	}
}

// TestConvertAnyFirstFrontWins 锁定「首个成功前端」优先级：同一文件同时
// 满足多个前端时，path 形态优先于 raw，raw 优先于 afrog（与旧三联顺序
// 一致）——预筛只允许跳过必然为空的前端，不允许改变胜者。
func TestConvertAnyFirstFrontWins(t *testing.T) {
	docs := equivTemplateDocs(t)
	cases := []struct{ doc, wantID, wantPath string }{
		{"both-path-afrog", "nuclei-both-path-afrog", "/path-wins"},
		{"both-raw-afrog", "nuclei-both-raw-afrog", "/raw-wins"},
	}
	for _, c := range cases {
		data, ok := docs[c.doc]
		if !ok {
			t.Fatalf("缺少差分语料 %q", c.doc)
		}
		cs := convertAny(data)
		if len(cs) != 1 {
			t.Fatalf("%s: 应转出 1 条, got %d", c.doc, len(cs))
		}
		if cs[0].ID != c.wantID || cs[0].Path != c.wantPath {
			t.Fatalf("%s: 首命中前端不对: id=%q path=%q（want %q %q）",
				c.doc, cs[0].ID, cs[0].Path, c.wantID, c.wantPath)
		}
		// 旧实现同样如此（差分对照已覆盖，这里再显式钉住语义）
		old := convertAnyLegacy(data)
		if !reflect.DeepEqual(old, cs) {
			t.Fatalf("%s: 与旧实现首命中不一致", c.doc)
		}
	}
}

// FuzzConvertAnyLegacyEquivalent 随机字节轰击差分对照（种子覆盖三种前端、
// 协议模板、混合形态、非法 YAML）。
func FuzzConvertAnyLegacyEquivalent(f *testing.F) {
	for _, data := range equivTemplateDocs(f) {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		want := convertAnyLegacy(data)
		got := convertAny(data)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("差分不一致: got=%+v want=%+v", got, want)
		}
	})
}

// writeEquivCorpus 构造等价性测试语料目录：三种前端、协议模板、混合形态、
// flow/JSON、legacy 两轮同名去重、非法与被拒形态。
func writeEquivCorpus(t *testing.T, dir string) {
	t.Helper()
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 非 legacy pass（走 WalkDir 字典序）
	write("http/cves/path-one.yaml", []byte(`
id: path-one
info:
  name: Path Form One
  severity: high
http:
  - method: GET
    path: "{{BaseURL}}/one"
    matchers:
      - type: word
        words: ["one"]
`))
	write("http/raw/raw-one.yaml", []byte(`
id: raw-one
info:
  name: Raw Form One
  severity: medium
http:
  - raw:
      - |
        GET {{BaseURL}}/raw HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: ["rawok"]
`))
	write("http/requests/requests-one.yaml", []byte(`
id: requests-one
info:
  name: Requests Form One
  severity: low
requests:
  - method: GET
    path: ["{{BaseURL}}/req"]
    matchers:
      - type: word
        words: ["reqok"]
`))
	write("http/misc/hybrid.yaml", []byte(`
id: hybrid-one
info:
  name: Hybrid One
  severity: critical
http:
  - method: GET
    path: /ignored
rules:
  r0:
    request:
      method: GET
      path: /hybrid/one
    expression: response.status == 200 && response.body.bcontains(b"HYBRID")
expression: r0()
`))
	write("http/misc/flow.yaml", []byte(`{"id":"flow-one","info":{"name":"Flow One","severity":"info"},"http":[{"method":"GET","path":"{{BaseURL}}/flow","matchers":[{"type":"word","words":["flowok"]}]}]}`))
	write("network/redis.yaml", []byte(`
id: tcp-one
info:
  name: Tcp One
  severity: info
tcp:
  - inputs:
      - data: "PING\r\n"
    matchers:
      - type: word
        words: ["PONG"]
`))
	write("dns/zone.yaml", []byte(`
id: dns-one
info:
  name: Dns One
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["1.2.3.4"]
`))
	write("ssl/cipher.yaml", []byte(`
id: ssl-one
info:
  name: Ssl One
  severity: info
ssl:
  - address: "{{Host}}:443"
    matchers:
      - type: word
        words: ["example"]
`))
	write("http/misc/interactsh.yaml", []byte(`
id: oob-one
info:
  name: Oob One
  severity: high
http:
  - method: GET
    path: "{{BaseURL}}/oob"
    matchers:
      - type: word
        words: ["interactsh-url"]
`))
	write("http/misc/invalid.yaml", []byte("id: [unclosed\nhttp:\n\t- broken\n"))
	write("http/misc/noisy.yaml", []byte(`
id: acme-xss
info:
  name: Noisy One
  severity: high
rules:
  r0:
    request:
      path: /x
    response:
      body: ["xss"]
expression: r0()
`))
	write("http/misc/plain.yml", []byte(`
id: yml-one
info:
  name: Yml One
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/yml"
    matchers:
      - type: word
        words: ["yml"]
`))
	// afrog 真实夹具（两条不同来源目录深度）
	for _, fx := range []string{"CNVD-2018-13393.yaml", "CVE-2018-13379.yaml"} {
		data, err := os.ReadFile(filepath.Join("testdata", "afrog", fx))
		if err != nil {
			t.Fatal(err)
		}
		write("afrog/CNVD/2018/"+fx, data)
	}
	// legacy pass：与 pass1 同名 → 跳过；legacy 内部同名 → 只留先者；唯一名 → 保留
	write("legacy/path-one-legacy.yaml", []byte(`
id: path-one-legacy
info:
  name: Path Form One
  severity: info
http:
  - method: GET
    path: "{{BaseURL}}/legacy-dupe"
    matchers:
      - type: word
        words: ["legacydupe"]
`))
	write("legacy/dup-a.yaml", []byte(`
id: legacy-dup-a
info:
  name: Legacy Dup Name
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/dup-a"
    matchers:
      - type: word
        words: ["dupa"]
`))
	write("legacy/dup-b.yaml", []byte(`
id: legacy-dup-b
info:
  name: Legacy Dup Name
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/dup-b"
    matchers:
      - type: word
        words: ["dupb"]
`))
	write("legacy/unique-old.yaml", []byte(`
id: legacy-unique
info:
  name: Legacy Unique Name
  severity: medium
http:
  - method: GET
    path: "{{BaseURL}}/unique"
    matchers:
      - type: word
        words: ["unique"]
`))
	// 批量模板：把单 pass 文件数推过并行阈值（<32 走顺序），确保差分对照
	// 真的覆盖 worker pool 的并行路径与结果下标回填。
	for i := 0; i < 40; i++ {
		write(fmt.Sprintf("http/bulk/tpl-%02d.yaml", i), []byte(fmt.Sprintf(`
id: bulk-%02d
info:
  name: Bulk Template %02d
  severity: low
http:
  - method: GET
    path: "{{BaseURL}}/bulk/%02d"
    matchers:
      - type: word
        words: ["bulk%02d"]
`, i, i, i, i)))
	}
}

// TestIndexParallelEquivalent 索引差分对照：并行 + 形状预筛的 Index 与旧
// 顺序实现在同一语料上 entries 逐字段相等（含顺序与 legacy 两轮去重）。
func TestIndexParallelEquivalent(t *testing.T) {
	dir := t.TempDir()
	writeEquivCorpus(t, dir)
	want, err := indexLegacyForTest(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Index(dir, filepath.Join(t.TempDir(), "idx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Index 与旧顺序实现不等价\n got=%d 条: %+v\nwant=%d 条: %+v", len(got), got, len(want), want)
	}
	// 覆盖断言：语料必须真的覆盖到两轮去重与协议模板，否则对照没有意义
	paths := map[string]bool{}
	for _, e := range got {
		paths[e.Path] = true
	}
	for _, must := range []string{
		"http/cves/path-one.yaml", "http/raw/raw-one.yaml", "http/requests/requests-one.yaml",
		"http/misc/hybrid.yaml", "network/redis.yaml", "dns/zone.yaml", "ssl/cipher.yaml",
		"legacy/dup-a.yaml", "legacy/unique-old.yaml",
	} {
		if !paths[must] {
			t.Fatalf("语料覆盖不足，缺失条目 %q（entries=%v）", must, paths)
		}
	}
	for _, never := range []string{
		"legacy/path-one-legacy.yaml", // 与 pass1 同名，legacy 去重跳过
		"legacy/dup-b.yaml",           // legacy 内部同名，只留字典序先者
		"http/misc/interactsh.yaml",   // interactsh 拒绝
		"http/misc/invalid.yaml",      // 非法 YAML
		"http/misc/noisy.yaml",        // 靶场定谳噪声模板
	} {
		if paths[never] {
			t.Fatalf("不应入索引的条目出现了: %q", never)
		}
	}
}

// TestIndexCacheRoundTripAndDeterministic 缓存命中返回同一份 entries；
// 多次重建（并行）结果稳定可比。
func TestIndexCacheRoundTripAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeEquivCorpus(t, dir)
	cache := filepath.Join(t.TempDir(), "idx.json")
	first, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := Index(dir, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, cached) {
		t.Fatalf("缓存命中结果与冷构建不一致")
	}
	for i := 0; i < 3; i++ {
		again, err := Index(dir, filepath.Join(t.TempDir(), "idx-again.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("第 %d 次重建结果与首次不一致（并行非确定性）", i+1)
		}
	}
}
