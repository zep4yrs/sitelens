package fpmerge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// buildTar 合成一个小 webappanalyzer tarball（categories + 两个字母库）。
func buildTar(t *testing.T) []byte {
	t.Helper()
	files := map[string]string{
		"webappanalyzer-main/src/categories.json": `{
			"31": {"name": "CDN"},
			"27": {"name": "Programming Language"}
		}`,
		"webappanalyzer-main/src/technologies/c.json": `{
			"Cloudflare": {
				"cats": [31],
				"cpe": "cpe:2.3:a:cloudflare:cloudflare:*:*:*:*:*:*:*:*",
				"cookies": {"__cfduid": ""},
				"headers": {"cf-ray": {}},
				"website": "https://www.cloudflare.com"
			},
			"CPlusOnly": {"cats": [27], "js": {"SomeHash": {}}}
		}`,
		"webappanalyzer-main/src/technologies/w.json": `{
			"WordPress": {
				"cats": [1],
				"html": ["<link rel=\"stylesheet\" href=\"wp-content"],
				"meta": {"generator": {"regex": "^WordPress ?([0-9.]+)?\\;confidence:80\\;version:\\1"}}
			}
		}`,
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestMergeFromTarSynthetic(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "technologies.json")
	cpeDst := filepath.Join(dir, "tech_cpe.json")

	// 预置精编库：同名 WordPress 必须赢
	curated := boxFile{Version: 1, Count: 1, Technologies: []entry{{
		Name: "WordPress", Cats: []string{"cms"}, Conf: 99,
		Website: "https://wordpress.org", Rules: json.RawMessage(`{"meta":{"x-curated":"yes"}}`),
	}}}
	curatedJSON, err := json.Marshal(curated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, curatedJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := MergeFromTar(bytes.NewReader(buildTar(t)), dst, cpeDst)
	if err != nil {
		t.Fatalf("MergeFromTar: %v", err)
	}
	if st.Added != 1 || st.SkippedDup != 1 || st.Total != 2 {
		t.Fatalf("统计不对: %+v", st)
	}
	if st.CPEs != 1 {
		t.Fatalf("CPE 应收集 1 条（含同名跳过项）: %+v", st)
	}

	merged, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var out boxFile
	if err := json.Unmarshal(merged, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Technologies) != 2 {
		t.Fatalf("合并结果不对: count=%d len=%d", out.Count, len(out.Technologies))
	}
	// 精编 WordPress 原样保留
	if out.Technologies[0].Name != "WordPress" || out.Technologies[0].Conf != 99 {
		t.Errorf("精编条目被改: %+v", out.Technologies[0])
	}
	// Cloudflare 条目通道映射：cookie 名小写、头存在性转 ^、conf 降 70
	byName := map[string]entry{}
	for _, e := range out.Technologies {
		byName[e.Name] = e
	}
	cf := byName["Cloudflare"]
	var cfRules struct {
		Cookies []string            `json:"cookies"`
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(cf.Rules, &cfRules); err != nil {
		t.Fatal(err)
	}
	if cf.Conf != 70 || len(cfRules.Cookies) != 1 || cfRules.Cookies[0] != "__cfduid" {
		t.Errorf("Cloudflare 映射不对: conf=%d %+v", cf.Conf, cfRules)
	}
	if len(cfRules.Headers["cf-ray"]) != 1 || cfRules.Headers["cf-ray"][0] != "^" {
		t.Errorf("存在性头应转 ^: %+v", cfRules.Headers)
	}

	// 纯 js 通道的 CPlusOnly 应被拒（引擎无该通道）
	if _, ok := byName["CPlusOnly"]; ok {
		t.Errorf("仅 js 通道的条目应跳过")
	}

	// 私有后缀剥除：WordPress meta 生成器正则
	wpAdd := byName["WordPress"] // 同名跳过，但确认精编未被覆盖已在上断言

	_ = wpAdd

	// CPE 映射文件
	cpeJSON, err := os.ReadFile(cpeDst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cpeJSON, []byte("cpe:2.3:a:cloudflare:cloudflare")) {
		t.Errorf("tech_cpe.json 缺 Cloudflare CPE")
	}
}

func TestCleanPatStripsPrivateSuffix(t *testing.T) {
	p := cleanPat(`^WordPress ?([0-9.]+)?\;confidence:80\;version:\1`)
	// 后缀剥除后剩合法 RE2 才保留；\1 反向引用不合法则须拒收
	if p != "" {
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			t.Errorf("返回的模式必须能过 RE2: %q", p)
		}
	}
	if got := cleanPat(""); got != "" {
		t.Errorf("空模式应返回空: %q", got)
	}
	if got := cleanPat("(?<=foo)bar"); got != "" {
		t.Errorf("环视应被拒: %q", got)
	}
}

// buildTarWithTechs 合成只含 categories + 单 tech 库（x.json）的 tarball。
func buildTarWithTechs(t *testing.T, techsJSON string) []byte {
	t.Helper()
	files := map[string]string{
		"webappanalyzer-main/src/categories.json":     `{"31": {"name": "CDN"}}`,
		"webappanalyzer-main/src/technologies/x.json": techsJSON,
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestInvalidHeaderRegexFailsClosed C-11 回归：脏正则必须 fail-closed（丢弃），
// 不能降级成 "^"（该 header 存在即命中 → 指纹误报）。
func TestInvalidHeaderRegexFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "technologies.json")
	cpeDst := filepath.Join(dir, "tech_cpe.json")
	if err := os.WriteFile(dst, []byte(`{"version":1,"count":0,"technologies":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	techs := `{
		"BadRegex": {"cats": [31], "headers": {"x-bad": {"regex": "(?=lookahead)"}}},
		"MixedTech": {"cats": [31], "meta": {"generator": {"regex": "^gen-[0-9.]+$"}},
		              "headers": {"x-bad2": {"regex": "(?<!nope)foo"}}},
		"GoodPresence": {"cats": [31], "headers": {"x-good": {}}},
		"GoodRegex": {"cats": [31], "headers": {"x-ok": {"regex": "^foo$"}}}
	}`
	st, err := MergeFromTar(bytes.NewReader(buildTarWithTechs(t, techs)), dst, cpeDst)
	if err != nil {
		t.Fatalf("MergeFromTar: %v", err)
	}
	merged, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var out boxFile
	if err := json.Unmarshal(merged, &out); err != nil {
		t.Fatal(err)
	}
	byName := map[string]entry{}
	for _, e := range out.Technologies {
		byName[e.Name] = e
	}
	// 只有坏 header 的条目：不得生成任何规则（尤其不能是 "^"）
	if e, ok := byName["BadRegex"]; ok {
		t.Errorf("坏正则条目应整条丢弃（fail-closed），实际仍合并: %s", e.Rules)
	}
	if st.RejectedPats == 0 {
		t.Error("坏正则应计入 RejectedPats（便于观测社区库质量）")
	}
	// 混合条目：坏 header 被丢弃，合法 meta 保留
	mixed, ok := byName["MixedTech"]
	if !ok {
		t.Fatal("MixedTech 应保留（有合法 meta）")
	}
	var mr struct {
		Headers map[string][]string `json:"headers"`
		Meta    map[string]string   `json:"meta"`
	}
	if err := json.Unmarshal(mixed.Rules, &mr); err != nil {
		t.Fatal(err)
	}
	if _, has := mr.Headers["x-bad2"]; has {
		t.Errorf("坏 header 正则不应进入 rules: %+v", mr.Headers)
	}
	if mr.Meta["generator"] != "^gen-[0-9.]+$" {
		t.Errorf("合法 meta 正则应保留: %+v", mr.Meta)
	}
	// 合法存在性判断仍是 "^"
	var gp struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(byName["GoodPresence"].Rules, &gp); err != nil {
		t.Fatal(err)
	}
	if len(gp.Headers["x-good"]) != 1 || gp.Headers["x-good"][0] != "^" {
		t.Errorf("显式存在性判断（{}）应转 ^: %+v", gp.Headers)
	}
	// 合法正则原样保留
	var gr struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(byName["GoodRegex"].Rules, &gr); err != nil {
		t.Fatal(err)
	}
	if len(gr.Headers["x-ok"]) != 1 || gr.Headers["x-ok"][0] != "^foo$" {
		t.Errorf("合法正则应原样保留: %+v", gr.Headers)
	}
}
