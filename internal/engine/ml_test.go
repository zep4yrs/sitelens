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
		"cve-tech.meta.json":  []byte(meta),
		"cve-tech.vocab.txt":  []byte("aa\nbb\ncc"),
		"cve-tech.idf.f32":    make([]byte, 12),
		"cve-tech.coef.f32":   make([]byte, 4), // 期望 1×3×4=12 字节，故意短
		"cwe-type.meta.json":  []byte(`{"name":"cwe-type","classes":["CWE-79"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`),
		"cwe-type.vocab.txt":  []byte("aa\nbb\ncc"),
		"cwe-type.idf.f32":    make([]byte, 12),
		"cwe-type.coef.f32":   make([]byte, 12),
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
		{CVE: "cve-2021-1001", Desc: descr},                              // 小写：收集并保留原始形态
		{CVE: "CVE-2021-1001", Desc: descr},                              // 大小写重复：按归一键去重
		{CVE: "CVE-2021-1002 (PoC)", Desc: descr},                        // 带尾巴：拒收
		{CVE: "GHSA-xxxx-xxxx-xxxx", Desc: descr},                        // 非 CVE 前缀：拒收
		{CVE: "MS17-010", Desc: descr},                                   // 非 CVE 前缀：拒收
		{CVE: "  CVE-2021-1003  ", Desc: descr},                          // 首尾空白：Trim 后合法
		{CVE: "CVE-21-1", Desc: descr},                                   // 位数不足：拒收
		{CVE: "CVE-2021-1004", Desc: ""},                                 // 无描述：跳过（不臆造）
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
