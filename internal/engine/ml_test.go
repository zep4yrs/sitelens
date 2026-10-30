package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// TestSevAssetsDirResolvesRepoModels BUG-019 回归：ONNX 资产路径曾只用
// cfg.ML.AssetsDir（默认 data/go/ml_assets，仓内不存在），而资产随
// 「模型进仓库本体」迁到 models/go/ml_assets → glob 恒落空 → sev_onnx
// 通道恒不可用并静默回退 NVD 先验。现与线性模型路径同源经
// ml.LocateAssetsDir 解析。工作树无 ONNX 资产时 skip。
func TestSevAssetsDirResolvesRepoModels(t *testing.T) {
	t.Chdir("../..") // 运行时约定：模型资产相对路径相对进程 cwd（仓库根）
	e := &Engine{cfg: config.Default()}
	if st, err := os.Stat(e.cfg.ML.AssetsDir); err == nil && st.IsDir() {
		// 未来若仓内补了默认目录，配置优先语义本就指向它，无需求解候选
		t.Skipf("默认资产目录已存在（%s），本回归前提不再成立", e.cfg.ML.AssetsDir)
	}
	got := e.sevAssetsDir()
	want := filepath.Join("models", "go", "ml_assets")
	if got != want {
		t.Fatalf("sev 资产目录 = %q，期望同源候选 %q", got, want)
	}
	// 解析到的目录必须真能定位 sev-prior ONNX 资产与词表（默认构建下
	// NewSevScorer 由 onnx 构建标签提供，这里断言资产可发现性）。
	for _, pat := range []string{"sev-prior-v3.1-[ab].onnx", "sev-prior-v3.1-[ab]-int8.onnx"} {
		m, err := filepath.Glob(filepath.Join(got, pat))
		if err != nil || len(m) == 0 {
			t.Fatalf("资产目录 %q 下未找到 %q（ONNX 通道将不可用）", got, pat)
		}
	}
	if _, err := os.Stat(filepath.Join(got, "sev-prior-v3.1.vocab.txt")); err != nil {
		t.Fatalf("资产目录 %q 缺 sev-prior 词表: %v", got, err)
	}
}

// TestSevAssetsDirFallbackToConfigured 自定义部署可能只投放 ONNX 文件
// （不成套线性模型资产）：候选全不合格时保持配置值原语义，不得静默改道。
func TestSevAssetsDirFallbackToConfigured(t *testing.T) {
	t.Chdir(t.TempDir()) // 默认候选（data/go、models/go）在此均不存在
	e := &Engine{cfg: config.Default()}
	custom := "custom-onnx-only"
	e.cfg.ML.AssetsDir = custom
	if got := e.sevAssetsDir(); got != custom {
		t.Fatalf("候选全缺失时应退回配置值 %q，实得 %q", custom, got)
	}
}

// TestMLNormRelevance 归一键与交集标记三档：hit / related / 空。
func TestMLNormRelevance(t *testing.T) {
	if mlNorm("Apache Tomcat") != "apachetomcat" || mlNorm("php/php") != "phpphp" {
		t.Fatalf("mlNorm 归一口径错误: %q %q", mlNorm("Apache Tomcat"), mlNorm("php/php"))
	}
	keys := mlTechKeys([]Tech{
		{Name: "Apache Tomcat"}, {Name: "PHP"}, {Name: "Microsoft Windows"},
	})
	if got := mlRelevance("apache/tomcat", keys); got != ml.RelHit {
		t.Errorf("apache/tomcat → %q, 期望 hit", got)
	}
	if got := mlRelevance("php/php", keys); got != ml.RelRelated {
		t.Errorf("php/php → %q, 期望 related", got)
	}
	if got := mlRelevance("oracle/mysql", keys); got != "" {
		t.Errorf("oracle/mysql → %q, 期望空", got)
	}
	if got := mlRelevance("apache/tomcat", nil); got != "" {
		t.Errorf("无检出技术时应为空, got %q", got)
	}
}

// TestMLForSilentSemantics mlFor 的两种静默出口：
// 目录缺失 → nil 不死；资产损坏 → nil 且本进程禁用。
func TestMLForSilentSemantics(t *testing.T) {
	// 目录不存在：nil，且不置死标记（资产可能后补）
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "no-such-dir")
	if a := e.mlFor(); a != nil {
		t.Fatalf("目录缺失应返回 nil, got %v", a)
	}
	if e.mlDead {
		t.Error("目录缺失不应置死标记")
	}

	// 资产损坏（meta 合法、coef 字节数不足）：nil 且永久禁用
	bad := t.TempDir()
	meta := `{"name":"cve-tech","classes":["x"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`
	for fn, b := range map[string][]byte{
		"cve-tech.meta.json": []byte(meta),
		"cve-tech.vocab.txt": []byte("aa\nbb\ncc"),
		"cve-tech.idf.f32":   make([]byte, 12),
		"cve-tech.coef.f32":  make([]byte, 4), // 期望 1×3×4=12 字节，故意短
		"cwe-type.meta.json": []byte(`{"name":"cwe-type","classes":["CWE-79"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`),
		"cwe-type.vocab.txt": []byte("aa\nbb\ncc"),
		"cwe-type.idf.f32":   make([]byte, 12),
		"cwe-type.coef.f32":  make([]byte, 12),
	} {
		if err := os.WriteFile(filepath.Join(bad, fn), b, 0o644); err != nil {
			t.Fatalf("写 %s: %v", fn, err)
		}
	}
	e2 := &Engine{cfg: config.Default()}
	e2.cfg.ML.AssetsDir = bad
	if a := e2.mlFor(); a != nil {
		t.Fatalf("损坏资产应返回 nil, got %v", a)
	}
	if !e2.mlDead {
		t.Error("损坏资产应置死标记（本进程静默禁用）")
	}
	if a := e2.mlFor(); a != nil {
		t.Error("禁用后再次请求仍应为 nil")
	}
}

// TestMLEnrichSilentSkip mlEnrich 全链静默语义：资产缺失时 predictions
// 缺席（nil），既不 panic 也不产生空数组。
func TestMLEnrichSilentSkip(t *testing.T) {
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "absent")
	res := &Result{Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-1234"}}}
	e.mlEnrich(res, nil)
	if res.Predictions != nil {
		t.Errorf("资产缺失时 predictions 应缺席, got %v", res.Predictions)
	}
	// 无 CVE 的结果在 CVE 收集阶段即返回，连资产目录都不触碰
	res2 := &Result{}
	e2 := &Engine{cfg: config.Default()}
	e2.mlEnrich(res2, nil)
	if res2.Predictions != nil {
		t.Errorf("无 CVE 时 predictions 应缺席, got %v", res2.Predictions)
	}
}

// writeTinyMLAssets 写一套完整合法的小维度双模型资产（各 1 类×3 特征），
// 供 mlFor/mlEnrich 包内测试；返回后再断言加载/禁用语义。
func writeTinyMLAssets(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"name":"%s","classes":["C1"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`
	idf123 := []byte{0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63} // float32 [1,1,1]
	for _, name := range []string{"cve-tech", "cwe-type"} {
		files := map[string][]byte{
			name + ".meta.json": []byte(fmt.Sprintf(meta, name)),
			name + ".vocab.txt": []byte("alpha\nbravo\ncharlie"),
			name + ".idf.f32":   idf123,
			name + ".coef.f32":  make([]byte, 12), // 1 类×3 特征全零系数
		}
		for fn, b := range files {
			if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
				t.Fatalf("写 %s: %v", fn, err)
			}
		}
	}
}

// TestMLForPartialAssetsNotDead 回归：任一关键文件缺失都算「资产未就绪」，
// 返回 nil 且**不置死**——此前只 Stat cve-tech.coef.f32，其余文件缺失会
// 被当作「损坏」永久禁用到进程重启；资产分步部署窗口内一次扫描就打死 ML。
func TestMLForPartialAssetsNotDead(t *testing.T) {
	dir := t.TempDir()
	// 只写 cve-tech 四件：文件级缺失（非损坏）→ nil 且不置死
	for fn, b := range map[string][]byte{
		"cve-tech.meta.json": []byte(`{"name":"cve-tech","classes":["C1"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`),
		"cve-tech.vocab.txt": []byte("alpha\nbravo\ncharlie"),
		"cve-tech.idf.f32":   {0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63},
		"cve-tech.coef.f32":  make([]byte, 12),
	} {
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	if a := e.mlFor(); a != nil {
		t.Fatalf("缺 cwe-type 四件应返回 nil, got %v", a)
	}
	if e.mlDead {
		t.Fatal("缺 cwe-type（文件缺失而非损坏）不应置死标记")
	}

	// 补齐 cwe-type 后同一进程立即可用（资产随后补齐的语义）
	writeTinyMLAssets(t, dir) // 覆写 cve-tech 并补全 cwe-type
	if a := e.mlFor(); a == nil {
		t.Fatal("补齐资产后 mlFor 应成功返回")
	}
	if e.mlDead || e.mlAssets == nil {
		t.Fatal("补齐资产后不应置死且应缓存资产")
	}

	// 对照：文件齐全但内容截断（损坏）→ 置死
	bad := t.TempDir()
	writeTinyMLAssets(t, bad)
	if err := os.WriteFile(filepath.Join(bad, "cve-tech.coef.f32"), make([]byte, 4), 0o644); err != nil {
		t.Fatal(err)
	}
	e2 := &Engine{cfg: config.Default()}
	e2.cfg.ML.AssetsDir = bad
	if a := e2.mlFor(); a != nil {
		t.Fatal("截断损坏应返回 nil")
	}
	if !e2.mlDead {
		t.Fatal("损坏资产应置死（本进程禁用）")
	}
}

// TestMLEnrichNoCVENotTouchAssets 回归：发现列表非空但无任何 CVE 时，
// mlEnrich 在 CVE 收集阶段即返回，不加载资产（cve-tech coef 94MB 读入
// 后无卸载路径，不能为空结果白付常驻）。
func TestMLEnrichNoCVENotTouchAssets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "assets")
	writeTinyMLAssets(t, dir)
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	res := &Result{Vulnerabilities: []intel.Finding{{Tech: "some-tech", Title: "无 CVE 情报行"}}}
	e.mlEnrich(res, nil)
	if e.mlAssets != nil {
		t.Fatal("无 CVE 的结果不应加载 ML 资产")
	}
	if e.mlDead {
		t.Fatal("无 CVE 不应置死标记")
	}
	// 对照：有合法 CVE 才加载
	res2 := &Result{Vulnerabilities: []intel.Finding{
		{Tech: "some-tech", CVE: "CVE-2024-1234", Desc: "alpha bravo charlie delta echo"},
	}}
	e.mlEnrich(res2, nil)
	if e.mlAssets == nil {
		t.Fatal("有 CVE 的结果应加载资产并产出预测")
	}
	if len(res2.Predictions) == 0 {
		t.Fatal("有 CVE 且有描述应产出预测")
	}
}

// TestMLEnrichCVEShape 回归：CVE 收集做整体形态校验（CVE-年份-序号），
// 并以首次出现的原始形态输出（与 vulnerabilities.cve 一致，消费方按 cve
// 精确关联不 miss）。此前只验 CVE- 前缀，"CVE-2021-1002 (PoC)" 这类带尾
// 杂质会进 predictions，小写 CVE 还会被归一成大写导致关联 miss。
func TestMLEnrichCVEShape(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "assets")
	writeTinyMLAssets(t, dir)
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	descr := "alpha bravo charlie delta echo" // 命中词表，走 fallback 描述
	res := &Result{Vulnerabilities: []intel.Finding{
		{CVE: "cve-2021-1001", Desc: descr},       // 小写：收集并保留原始形态
		{CVE: "CVE-2021-1001", Desc: descr},       // 大小写重复：按归一键去重
		{CVE: "CVE-2021-1002 (PoC)", Desc: descr}, // 带尾巴：拒收
		{CVE: "GHSA-xxxx-xxxx-xxxx", Desc: descr}, // 非 CVE 前缀：拒收
		{CVE: "MS17-010", Desc: descr},            // 非 CVE 前缀：拒收
		{CVE: "  CVE-2021-1003  ", Desc: descr},   // 首尾空白：Trim 后合法
		{CVE: "CVE-21-1", Desc: descr},            // 位数不足：拒收
		{CVE: "CVE-2021-1004", Desc: ""},          // 无描述：跳过（不臆造）
	}}
	e.mlEnrich(res, nil)
	if len(res.Predictions) != 2 {
		t.Fatalf("应产出 2 条预测, got %d: %v", len(res.Predictions), res.Predictions)
	}
	want := []string{"cve-2021-1001", "CVE-2021-1003"} // 原始形态
	for i, p := range res.Predictions {
		if p.CVE != want[i] {
			t.Errorf("predictions[%d].cve = %q, 期望 %q（原始形态）", i, p.CVE, want[i])
		}
		if p.CVE == "CVE-2021-1002 (POC)" || strings.Contains(p.CVE, "(") {
			t.Errorf("带尾巴的杂质 id 不应进入 predictions: %q", p.CVE)
		}
	}
}

// TestMLDescrDoesNotWakeNVD 回归：mlDescr 只在 NVD 索引已解码常驻时顺带
// 查询（NVDLoaded 不触发加载），否则回退 findings 自带描述——扫描收尾
// 不能首次拉起全量索引（实测 3.46s / 37 万条 / ≈1.7GB 常驻，同步阻塞
// Scan 返回并改变后续降档行为）。
func TestMLDescrDoesNotWakeNVD(t *testing.T) {
	// ① 仅挂路径（未拉起）：回退 findings，且不得触发加载
	kb := &intel.KB{}
	kb.AttachNVDPath(filepath.Join(t.TempDir(), "no-such-nvd.json.gz"))
	findings := []intel.Finding{{CVE: "CVE-2024-1234", Desc: "alpha bravo charlie", CVSSScore: 7.5}}
	descr, sev := mlDescr(kb, findings, "CVE-2024-1234")
	if descr != "alpha bravo charlie" || sev != 7.5 {
		t.Fatalf("未拉起时应回退 findings 自带描述, got %q %v", descr, sev)
	}
	if kb.NVDLoaded() {
		t.Fatal("mlDescr 不得拉起 NVD 索引（NVDLoaded 应仍为 false）")
	}
	_ = kb.NVDCount() // 存在性口径复核：仍不应加载
	if kb.NVDLoaded() {
		t.Fatal("存在性查询不应触发加载")
	}

	// ② 已挂载索引：正常命中 NVD 描述与评分
	gz := filepath.Join(t.TempDir(), "nvd_cves.json.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(map[string]any{
		"cves": []map[string]any{{
			"cve": "CVE-2024-1234", "score": 9.9, "descr": "nvd descr alpha bravo",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gz, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := intel.LoadNVD(gz)
	if err != nil || store == nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	kb2 := &intel.KB{}
	kb2.AttachNVD(store)
	d2, s2 := mlDescr(kb2, findings, "CVE-2024-1234")
	if d2 != "nvd descr alpha bravo" || s2 != 9.9 {
		t.Fatalf("已拉起时应命中 NVD, got %q %v", d2, s2)
	}

	// ③ kb=nil 安全回退 findings
	if d3, _ := mlDescr(nil, findings, "CVE-2024-1234"); d3 != "alpha bravo charlie" {
		t.Fatalf("kb=nil 应回退 findings, got %q", d3)
	}
}

// writeTinySevLinear 写一个 1 类×3 特征的线性严重度回归资产（系数全零，
// 分数 = intercept），供 mlEnrich 严重度后端优先级测试。
func writeTinySevLinear(t *testing.T, dir string, intercept float64) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := fmt.Sprintf(`{"name":"sev-linear","classes":["cvss-score"],"n_features":3,"n_classes":1,
"intercept":[%g],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`, intercept)
	files := map[string][]byte{
		"sev-linear.meta.json": []byte(meta),
		"sev-linear.vocab.txt": []byte("alpha\nbravo\ncharlie"),
		"sev-linear.idf.f32":   {0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63},
		"sev-linear.coef.f32":  make([]byte, 12), // 1 类×3 特征全零系数
	}
	for fn, b := range files {
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatalf("写 %s: %v", fn, err)
		}
	}
}

// TestMLEnrichSevSourcePriority 5.2 阶段 1 严重度后端优先级：
// NVD/情报行查表（nvd）→ sev-linear（linear）→ 无可选 ONNX 时留空。
// 同时覆盖 sev_linear 开关关闭的行为（不臆造分数）。
func TestMLEnrichSevSourcePriority(t *testing.T) {
	dir := t.TempDir()
	writeTinyMLAssets(t, dir)
	writeTinySevLinear(t, dir, 5.5)

	if !config.Default().ML.SevLinear {
		t.Fatal("默认配置 ml.sev_linear 应为 true（5.2 阶段 1 默认后端）")
	}

	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	descr := "alpha bravo charlie delta"
	res := &Result{Vulnerabilities: []intel.Finding{
		{CVE: "CVE-2024-0001", Desc: descr, CVSSScore: 7.5}, // 查表优先
		{CVE: "CVE-2024-0002", Desc: descr},                 // 无分 → 线性兜底
	}}
	e.mlEnrich(res, nil)
	if len(res.Predictions) != 2 {
		t.Fatalf("应产出 2 条预测, got %d: %v", len(res.Predictions), res.Predictions)
	}
	if p := res.Predictions[0]; p.SevSource != "nvd" || p.SevScore != 7.5 {
		t.Fatalf("查表优先失效: source=%q score=%v", p.SevSource, p.SevScore)
	}
	if p := res.Predictions[1]; p.SevSource != "linear" || p.SevScore != 5.5 {
		t.Fatalf("线性兜底失效: source=%q score=%v", p.SevSource, p.SevScore)
	}
	info, ok := res.Extras["ml_sev"].(map[string]any)
	if !ok {
		t.Fatalf("extras.ml_sev 缺失: %v", res.Extras)
	}
	if info["nvd"] != 1 || info["linear"] != 1 || info["none"] != 0 {
		t.Fatalf("ml_sev 来源计数不对: %v", info)
	}
	if info["active"] != true {
		t.Fatalf("linear 生效时 active 应为 true: %v", info)
	}

	// 关闭 sev_linear：无 NVD 分的条目不给分数（不臆造），来源留空。
	e2 := &Engine{cfg: config.Default()}
	e2.cfg.ML.AssetsDir = dir
	e2.cfg.ML.SevLinear = false
	res2 := &Result{Vulnerabilities: []intel.Finding{
		{CVE: "CVE-2024-0003", Desc: descr},
	}}
	e2.mlEnrich(res2, nil)
	if len(res2.Predictions) != 1 {
		t.Fatalf("应产出 1 条预测, got %d", len(res2.Predictions))
	}
	if p := res2.Predictions[0]; p.SevScore != 0 || p.SevSource != "" {
		t.Fatalf("关闭 sev_linear 后不应给分: source=%q score=%v", p.SevSource, p.SevScore)
	}
}

// TestSevLinearOptionalLoadSemantics 可选 sev-linear 资产的两类降级：
// 缺文件 = 未就绪（不报错、不影响 cve-tech/cwe-type）；损坏 = 仅禁用该后端。
func TestSevLinearOptionalLoadSemantics(t *testing.T) {
	dir := t.TempDir()
	writeTinyMLAssets(t, dir) // 只有 cve-tech/cwe-type
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	a := e.mlFor()
	if a == nil {
		t.Fatal("缺 sev-linear 不应影响必备线性模型加载")
	}
	if a.Sev != nil || a.SevErr != "" {
		t.Fatalf("缺 sev-linear 应为未就绪（nil, \"\"）: Sev=%v SevErr=%q", a.Sev, a.SevErr)
	}

	bad := t.TempDir()
	writeTinyMLAssets(t, bad)
	writeTinySevLinear(t, bad, 5.5)
	if err := os.WriteFile(filepath.Join(bad, "sev-linear.coef.f32"), make([]byte, 4), 0o644); err != nil {
		t.Fatal(err)
	}
	e2 := &Engine{cfg: config.Default()}
	e2.cfg.ML.AssetsDir = bad
	a2 := e2.mlFor()
	if a2 == nil {
		t.Fatal("可选 sev-linear 损坏不应置死整个 ML 资产")
	}
	if a2.Sev != nil || a2.SevErr == "" {
		t.Fatalf("损坏 sev-linear 应仅禁用该后端: Sev=%v SevErr=%q", a2.Sev, a2.SevErr)
	}
	if e2.mlDead {
		t.Fatal("可选 sev-linear 损坏不应置死标记")
	}
}

// writeNVDKB 写一个内存 NVD 镜像（gzip JSON）并挂载到 KB，供查表优先用例。
func writeNVDKB(t *testing.T, entries []map[string]any) *intel.KB {
	t.Helper()
	gz := filepath.Join(t.TempDir(), "nvd_cves.json.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(map[string]any{"cves": entries}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gz, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := intel.LoadNVD(gz)
	if err != nil || store == nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	kb := &intel.KB{}
	kb.AttachNVD(store)
	return kb
}

// TestMLEnrichLookupOnlyWithoutAssets 5.2 阶段 2：查表字段（CPE/CWE/score）
// 齐全时，即使完全没有模型资产也能产出预测，且不读 94MB cve-tech。
func TestMLEnrichLookupOnlyWithoutAssets(t *testing.T) {
	kb := writeNVDKB(t, []map[string]any{{
		"cve": "CVE-2024-1234", "pub": "2024-01-02", "score": 9.8,
		"descr": "WordPress plugin allows remote code execution",
		"prods": []map[string]any{{"vp": "wordpress/wordpress"}},
		"cwes":  []string{"CWE-79", "CWE-20"},
	}})
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "absent")
	res := &Result{Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-1234"}}}
	e.mlEnrich(res, kb)

	if len(res.Predictions) != 1 {
		t.Fatalf("查表齐全应产出预测, got %v", res.Predictions)
	}
	p := res.Predictions[0]
	if p.TechSource != "nvd" || len(p.TechTop5) != 1 ||
		p.TechTop5[0].Product != "wordpress/wordpress" || p.TechTop5[0].Prob != 1 {
		t.Fatalf("产品查表结果不对: source=%q top5=%+v", p.TechSource, p.TechTop5)
	}
	if p.CWESource != "nvd" || p.CWEType != "CWE-79" {
		t.Fatalf("CWE 查表结果不对: source=%q cwe=%q", p.CWESource, p.CWEType)
	}
	if p.SevSource != "nvd" || p.SevScore != 9.8 {
		t.Fatalf("严重度查表结果不对: source=%q score=%v", p.SevSource, p.SevScore)
	}
	if e.mlAssets != nil {
		t.Fatal("查表全覆盖时应保持惰性，不加载模型资产（94MB）")
	}
}

// TestMLEnrichLookupBeatsModel 查表优先于模型：有 CPE/CWE/score 时，
// 即使模型资产可用也直接出查表结论，且不加载资产。
func TestMLEnrichLookupBeatsModel(t *testing.T) {
	dir := t.TempDir()
	writeTinyMLAssets(t, dir)
	writeTinySevLinear(t, dir, 5.5)
	kb := writeNVDKB(t, []map[string]any{{
		"cve": "CVE-2024-5678", "pub": "2024-02-02", "score": 7.5,
		"descr": "alpha bravo charlie delta",
		"prods": []map[string]any{{"vp": "apache/tomcat"}},
		"cwes":  []string{"CWE-22"},
	}})
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	res := &Result{Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-5678"}}}
	e.mlEnrich(res, kb)

	if len(res.Predictions) != 1 {
		t.Fatalf("应产出 1 条预测, got %v", res.Predictions)
	}
	p := res.Predictions[0]
	if p.TechSource != "nvd" || p.TechTop5[0].Product != "apache/tomcat" {
		t.Fatalf("查表应优先于模型: source=%q top5=%+v", p.TechSource, p.TechTop5)
	}
	if p.CWESource != "nvd" || p.CWEType != "CWE-22" {
		t.Fatalf("CWE 查表应优先于模型: source=%q cwe=%q", p.CWESource, p.CWEType)
	}
	if p.SevSource != "nvd" || p.SevScore != 7.5 {
		t.Fatalf("严重度查表应优先: source=%q score=%v", p.SevSource, p.SevScore)
	}
	if e.mlAssets != nil {
		t.Fatal("查表全覆盖时不应加载模型资产")
	}
}

// TestMLEnrichModelFallback 盲区回退：无查表字段时按 descr 走模型，
// 来源标注为 model/linear（阶段 1+2 契约）。
func TestMLEnrichModelFallback(t *testing.T) {
	dir := t.TempDir()
	writeTinyMLAssets(t, dir)
	writeTinySevLinear(t, dir, 5.5)
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = dir
	res := &Result{Vulnerabilities: []intel.Finding{{
		CVE: "CVE-2024-9999", Desc: "alpha bravo charlie delta echo",
	}}}
	e.mlEnrich(res, nil)

	if len(res.Predictions) != 1 {
		t.Fatalf("应产出 1 条预测, got %v", res.Predictions)
	}
	p := res.Predictions[0]
	if p.TechSource != "model" || len(p.TechTop5) == 0 {
		t.Fatalf("产品应走模型兜底: source=%q top5=%+v", p.TechSource, p.TechTop5)
	}
	if p.CWESource != "model" || p.CWEType == "" {
		t.Fatalf("CWE 应走模型兜底: source=%q cwe=%q", p.CWESource, p.CWEType)
	}
	if p.SevSource != "linear" {
		t.Fatalf("严重度应走 sev-linear: source=%q", p.SevSource)
	}
}

// TestMLEnrichIntelProductSource finding 自带 product 的回退（无 NVD 索引）：
// 产品来源标 intel，CWE 来源空、严重度走 finding CVSS。
func TestMLEnrichIntelProductSource(t *testing.T) {
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "absent")
	res := &Result{Vulnerabilities: []intel.Finding{{
		CVE: "CVE-2023-0001", Product: "wordpress/wordpress", CVSSScore: 8.0,
	}}}
	e.mlEnrich(res, nil)

	if len(res.Predictions) != 1 {
		t.Fatalf("finding 自带 product 应产出预测, got %v", res.Predictions)
	}
	p := res.Predictions[0]
	if p.TechSource != "intel" || len(p.TechTop5) != 1 || p.TechTop5[0].Product != "wordpress/wordpress" {
		t.Fatalf("产品来源应为 intel: source=%q top5=%+v", p.TechSource, p.TechTop5)
	}
	if p.CWESource != "" || p.CWEType != "" {
		t.Fatalf("无 CWE 查表时不应臆造: source=%q cwe=%q", p.CWESource, p.CWEType)
	}
	if p.SevSource != "nvd" || p.SevScore != 8.0 {
		t.Fatalf("严重度应取 finding CVSS: source=%q score=%v", p.SevSource, p.SevScore)
	}
	if e.mlAssets != nil {
		t.Fatal("无模型资产且查表覆盖产品/严重度时不应报错或加载资产")
	}
}

// TestMLPriorFingerprintFirst 5.2 阶段 2：指纹技术名 → 产品映射优先，
// 不加载模型资产、不读正文；无指纹命中且无资产时无先验。
func TestMLPriorFingerprintFirst(t *testing.T) {
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "absent")
	res := &Result{Technologies: []Tech{{Name: "WordPress"}, {Name: "Apache Tomcat"}}}
	prior, _, info := e.mlPrior(res, nil, "core", []string{"wp-login"})
	if prior == nil {
		t.Fatal("指纹命中应产出先验")
	}
	for _, id := range []string{"wp-users", "tomcat-manager"} {
		if _, ok := prior.Boost[id]; !ok {
			t.Errorf("指纹先验应提权 %s，实得 %v", id, prior.Boost)
		}
	}
	if info["source"] != "fingerprint" {
		t.Fatalf("先验来源应为 fingerprint, got %v", info["source"])
	}
	if e.mlAssets != nil {
		t.Fatal("指纹先验不应加载模型资产（94MB）")
	}

	// 无指纹命中：无资产时静默无先验，且保持不加载资产。
	res2 := &Result{Technologies: []Tech{{Name: "Nginx"}}}
	if p, _, _ := e.mlPrior(res2, nil, "core", nil); p != nil {
		t.Fatalf("无映射且无资产应无先验, got %+v", p)
	}
	if e.mlAssets != nil {
		t.Fatal("无先验时也不应加载模型资产")
	}
}
