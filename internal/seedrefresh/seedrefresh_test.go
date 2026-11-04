package seedrefresh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write 造一个文件（含中间目录）。
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// read 读回文件内容（不存在返回 ""）。
func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// newTree 造一份「包内置种子」树。root 即安装目录里的 data 目录本身
// （桌面壳传的是 <engine>/data），所以相对路径不带 data/ 前缀。
func newTree(t *testing.T, root string) {
	t.Helper()
	write(t, filepath.Join(root, "nvd_cves.json.gz"), "nvd-new")
	write(t, filepath.Join(root, "tpl_intel.json.gz"), "tpl-new")
	write(t, filepath.Join(root, "intel_dump.json.gz"), "dump-new")
	write(t, filepath.Join(root, "affected_ranges.json"), "ranges-new")
	write(t, filepath.Join(root, "go", "technologies.json"), "fp-new")
	write(t, filepath.Join(root, "go", "ml_assets", "vocab.json"), "vocab-new")
	write(t, filepath.Join(root, "wordlists", "dirs.txt"), "words-new")
	write(t, filepath.Join(root, "onnxruntime", "onnxruntime.dll"), "dll-new")
}

func TestBuildCoversSeedsAndKeepsUserData(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	// 用户区：同路径种子是旧值，另有历史/模板池/插件
	write(t, filepath.Join(user, "data", "nvd_cves.json.gz"), "nvd-old")
	write(t, filepath.Join(user, "data", "go", "technologies.json"), "fp-old")
	write(t, filepath.Join(user, "state", "history.json"), "history")
	write(t, filepath.Join(user, "pools", "nuclei", "x.yaml"), "tpl-pool")

	plan, err := Build(seed, user, "5.1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Skipped {
		t.Fatal("首次交付不应跳过")
	}
	// 白名单内的种子必须进 Copy（含 wordlists 之外的 data 根文件）
	copySet := map[string]bool{}
	for _, it := range plan.Copy {
		copySet[it.Rel] = true
	}
	for _, want := range []string{
		"data/nvd_cves.json.gz", "data/tpl_intel.json.gz", "data/intel_dump.json.gz",
		"data/affected_ranges.json", "data/go/technologies.json",
		"data/go/ml_assets/vocab.json", "data/onnxruntime/onnxruntime.dll",
	} {
		if !copySet[want] {
			t.Errorf("应覆盖 %s，实际未列入", want)
		}
	}
	// 用户成果不在白名单
	for _, banned := range []string{"data/wordlists/dirs.txt"} {
		if copySet[banned] {
			t.Errorf("不得覆盖用户词表 %s", banned)
		}
	}

	n, err := Apply(plan, user)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(plan.Copy) {
		t.Fatalf("覆盖份数 = %d，期望 %d", n, len(plan.Copy))
	}
	if got := read(filepath.Join(user, "data", "nvd_cves.json.gz")); got != "nvd-new" {
		t.Errorf("NVD 种子未覆盖为包内版本，实际 %q", got)
	}
	if got := read(filepath.Join(user, "data", "go", "technologies.json")); got != "fp-new" {
		t.Errorf("指纹种子未覆盖，实际 %q", got)
	}
	// 用户成果原位存活
	if read(filepath.Join(user, "state", "history.json")) != "history" {
		t.Error("扫描历史被改动")
	}
	if read(filepath.Join(user, "pools", "nuclei", "x.yaml")) != "tpl-pool" {
		t.Error("模板池被改动")
	}
	// 词表是包内新增（用户区没有）→ 不覆盖路径不创建它
	if read(filepath.Join(user, "data", "wordlists", "dirs.txt")) != "" {
		t.Error("词表不应由本通道交付")
	}
}

func TestSameVersionSkips(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	write(t, filepath.Join(user, "data", "nvd_cves.json.gz"), "nvd-old")

	plan, err := Build(seed, user, "5.0.0", "5.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Skipped || len(plan.Copy) != 0 {
		t.Fatalf("版本一致应整批跳过，实际 %+v", plan)
	}
}

func TestVersionChangeOverwritesAgain(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	// 上一版已交付 5.0.0，用户又跑过 update-nvd（内容标记为 online）
	write(t, filepath.Join(user, "data", "nvd_cves.json.gz"), "nvd-online")

	plan, err := Build(seed, user, "5.1.0", "5.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Skipped {
		t.Fatal("版本变化应重新交付")
	}
	if _, err := Apply(plan, user); err != nil {
		t.Fatal(err)
	}
	// 包内快照是权威源：升级即覆盖（用户随时可再 update-nvd）
	if got := read(filepath.Join(user, "data", "nvd_cves.json.gz")); got != "nvd-new" {
		t.Errorf("升级未覆盖快照，实际 %q", got)
	}
	// 清单落地：版本 + 摘要
	m := LoadManifest(user)
	if m.Version != "5.1.0" {
		t.Errorf("清单版本 = %q，期望 5.1.0", m.Version)
	}
	if len(m.Files["data/nvd_cves.json.gz"]) != 64 {
		t.Errorf("清单缺 sha256：%+v", m.Files)
	}
}

func TestSecondRunSameVersionIsNoop(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	plan, _ := Build(seed, user, "5.1.0", "")
	if _, err := Apply(plan, user); err != nil {
		t.Fatal(err)
	}
	// 用户随后手动更新了 NVD 快照
	write(t, filepath.Join(user, "data", "nvd_cves.json.gz"), "nvd-online")
	// 同版本再启动：清单说已交付 → 不得再覆盖用户的新快照
	m := LoadManifest(user)
	plan2, err := Build(seed, user, "5.1.0", m.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !plan2.Skipped {
		t.Fatal("同版本二次启动应跳过")
	}
	if got := read(filepath.Join(user, "data", "nvd_cves.json.gz")); got != "nvd-online" {
		t.Errorf("同版本二次启动覆盖了用户快照，实际 %q", got)
	}
}

func TestApplyIsAtomicOnMissingSource(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	plan, _ := Build(seed, user, "5.1.0", "")
	// 抽掉一份源文件，模拟出包不完整
	target := filepath.Join(user, "data", "nvd_cves.json.gz")
	write(t, target, "nvd-old")
	for i := range plan.Copy {
		if plan.Copy[i].Rel == "data/nvd_cves.json.gz" {
			plan.Copy[i].Src = filepath.Join(seed, "not-exist")
		}
	}
	if _, err := Apply(plan, user); err == nil {
		t.Fatal("源缺失应报错")
	}
	if got := read(target); got != "nvd-old" {
		t.Errorf("失败拷贝留下了半截文件，实际 %q", got)
	}
}

func TestCoveredRejectsEscapes(t *testing.T) {
	if covered("../data/nvd_cves.json.gz") {
		t.Error("路径逃逸不得进白名单")
	}
	if covered("data/wordlists/x.txt") {
		t.Error("词表不得进白名单")
	}
	if !covered("data/nvd_cves.json.gz") || !covered("data/go/a.json") {
		t.Error("种子应进白名单")
	}
}

// 白名单边界：逐条钉住「哪些能覆盖、哪些绝不能」。
// 白名单写宽一格就会抹掉用户成果，写窄一格则包内快照进不来——两边都要有断言。
func TestCoveredWhitelistBoundary(t *testing.T) {
	cases := map[string]bool{
		// 可由本通道覆盖（update-* 会整体重建同一文件）
		"data/nvd_cves.json.gz":            true,
		"data/affected_ranges.json":        true,
		"data/intel_dump.json.gz":          true,
		"data/tpl_intel.json.gz":           true,
		"data/go/technologies.json":        true,
		"data/go/ml_assets/sev.onnx":       true,
		"data/onnxruntime/onnxruntime.dll": true,
		// 绝不覆盖（用户成果 / 用户可增删的资产）
		"data/asset-extras/site-dark.png": false,
		"data/asset-extras/icons/a.png":   false,
		"data/wordlists/dirs.txt":         false,
		"data/wordlists/sub/x.txt":        false,
		"state/history.json":              false,
		"pools/nuclei/x.yaml":             false,
		"plugins/x.json":                  false,
		// 逃逸路径
		"../evil":   false,
		"/abs/evil": false,
	}
	for rel, want := range cases {
		if got := covered(rel); got != want {
			t.Errorf("covered(%q)=%v，期望 %v", rel, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// C-16：清单原子写 + sha256 差分（升级只拷变化文件）
// ---------------------------------------------------------------------------

// TestBuildDiffSkipsUnchangedOnUpgrade 已交付过的版本升级：包内种子没变 →
// 全部归入 Unchanged（不拷贝），Apply 后清单仍记录完整基线。
func TestBuildDiffSkipsUnchangedOnUpgrade(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)

	// 首轮交付 5.1.0
	plan1, err := Build(seed, user, "5.1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Apply(plan1, user); err != nil || n != len(plan1.Copy) {
		t.Fatalf("首轮 Apply: n=%d err=%v", n, err)
	}
	// 记录一份文件的 mtime：差分命中时不应被重写
	target := filepath.Join(user, "data", "nvd_cves.json.gz")
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	// 升级到 5.2.0：包内内容与用户区一致 → 不拷贝
	plan2, err := Build(seed, user, "5.2.0", "5.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if plan2.Skipped {
		t.Fatal("版本变化不应整批跳过")
	}
	if len(plan2.Copy) != 0 {
		t.Fatalf("包内种子未变，不该再拷贝任何文件（差分失效）: %+v", plan2.Copy)
	}
	if len(plan2.Unchanged) == 0 {
		t.Fatal("应把摘要一致的文件列入 Unchanged")
	}
	if n, err := Apply(plan2, user); err != nil || n != 0 {
		t.Fatalf("升级 Apply 应拷贝 0 份: n=%d err=%v", n, err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("摘要一致的种子被重写（mtime 变化）: %v → %v", before.ModTime(), after.ModTime())
	}
	// 清单：版本更新 + 仍保留全部白名单文件摘要（差分基线不丢）
	m := LoadManifest(user)
	if m.Version != "5.2.0" {
		t.Fatalf("清单版本 = %q，期望 5.2.0", m.Version)
	}
	if len(m.Files) != len(plan2.Unchanged) {
		t.Fatalf("清单应记录全部白名单文件（%d），实际 %d: %+v", len(plan2.Unchanged), len(m.Files), m.Files)
	}
	if len(m.Files["data/nvd_cves.json.gz"]) != 64 {
		t.Fatalf("清单缺 sha256: %+v", m.Files)
	}
}

// TestBuildDiffReCopiesWhenDestinationModified 用户手动 update-* 改过的大资产
// （dst 摘要 != 包内摘要）在版本升级时仍被包内快照覆盖（权威源语义不变）。
func TestBuildDiffReCopiesWhenDestinationModified(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	plan1, _ := Build(seed, user, "5.1.0", "")
	if _, err := Apply(plan1, user); err != nil {
		t.Fatal(err)
	}
	// 用户手动更新 NVD（内容变化）
	write(t, filepath.Join(user, "data", "nvd_cves.json.gz"), "nvd-online")

	plan2, err := Build(seed, user, "5.2.0", "5.1.0")
	if err != nil {
		t.Fatal(err)
	}
	var reCopy bool
	for _, it := range plan2.Copy {
		if it.Rel == "data/nvd_cves.json.gz" {
			reCopy = true
		}
	}
	if !reCopy {
		t.Fatalf("用户改过的种子应重新覆盖（差分只看摘要，不看版本号）: copy=%+v", plan2.Copy)
	}
	// 其余未变文件仍应复用
	if len(plan2.Unchanged) == 0 {
		t.Error("其余摘要一致文件应复用")
	}
	if _, err := Apply(plan2, user); err != nil {
		t.Fatal(err)
	}
	if got := read(filepath.Join(user, "data", "nvd_cves.json.gz")); got != "nvd-new" {
		t.Errorf("包内快照应覆盖用户改动，实际 %q", got)
	}
}

// TestManifestAtomicWrite 清单原子写：内容合法、无临时文件残留、可被再次读取。
func TestManifestAtomicWrite(t *testing.T) {
	seed := t.TempDir()
	user := t.TempDir()
	newTree(t, seed)
	plan, err := Build(seed, user, "5.1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(plan, user); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(user, ManifestName))
	if err != nil {
		t.Fatalf("清单应可读: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("清单必须是完整 JSON（非半截写入）: %v\n%s", err, data)
	}
	if m.Version != "5.1.0" || len(m.Files) == 0 {
		t.Fatalf("清单内容不完整: %+v", m)
	}
	entries, err := os.ReadDir(user)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.Contains(e.Name(), ".seedtmp") {
			t.Fatalf("原子写残留临时文件: %s", e.Name())
		}
	}
}
