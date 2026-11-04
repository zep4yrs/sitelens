package engine

// Wave-1 修复回归（C2-02 / C2-04）。
//
// C2-02：graph 收尾路径不得隐式拉起 NVD 全量索引（≈1.7GB/数秒）。
// C2-04：CVSS 0.0 与"缺失"区分——查表命中 0.0 分时 ML 不得兜底抬分。

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// writeTinyNVDForEngine 写一份最小 NVD 索引（gz），供 Engine 侧用例读取。
// 0 分条必须带 score_set 标记，才能表达"真实 0 分"而非"缺失"（C2-04）。
func writeTinyNVDForEngine(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nvd.json.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建临时 NVD: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	box := map[string]any{"cves": []map[string]any{
		{"cve": "CVE-2099-0001", "score": 0, "score_set": true, "sev": "none",
			"descr": "zero impact issue"},
		{"cve": "CVE-2099-0002", "descr": "unscored issue"},
	}}
	if err := json.NewEncoder(gz).Encode(box); err != nil {
		t.Fatalf("写临时 NVD: %v", err)
	}
	return path
}

// TestGraphNVDEnrichNeverLoadsNVD C2-02 回归：nvdLookup / annotatePriorsFromKB
// 在 NVD 索引未常驻时只能跳过，绝不能触发懒加载。
func TestGraphNVDEnrichNeverLoadsNVD(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-nvd.json.gz")
	kb := intel.LoadLazy("", "") // 纯内存构造（无可解码源）
	kb.AttachNVDPath(missing)
	if kb.NVDLoaded() {
		t.Fatal("前置：NVD 不应已加载")
	}

	col := newCollector("scan-c2-02")
	ev := model.NewEvidence("response", model.OriginBlackbox, "dast", "", "http://t/", "", 0, "x")
	col.g.Add(ev)
	vn := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "", "http://t/?q=1", "q", "", 0,
		model.ObsPositive, "detected", model.ConfProbable, []string{ev.ID})
	vn.CVE = "CVE-2020-0001"
	col.g.Add(vn)
	col.g.Add(model.NewImpact("disclosure", "proven", vn.ID, "", nil,
		model.ConfProbable, []string{ev.ID}))

	// 旧代码会触发 KB.NVD() 的路径：cwe 适配器 + impact 先验标注。
	lookup := nvdLookup{kb}
	_ = lookup.CWEsFor("CVE-2020-0001")
	col.annotatePriorsFromKB(kb)

	if kb.NVDLoaded() {
		t.Fatal("graph 收尾路径隐式拉起了 NVD 全量索引（C2-02 回归）")
	}
	if kb.LoadError() != "" {
		t.Fatalf("不应产生加载错误（说明根本没有尝试加载）: %s", kb.LoadError())
	}
}

// TestMLCVEInfoZeroScoreIsAuthoritative C2-04 回归：NVD 查表命中 0.0 分时，
// mlCVEInfoOf 必须报"有评分"，mlEnrich 才不会用 sev-linear 抬分。
func TestMLCVEInfoZeroScoreIsAuthoritative(t *testing.T) {
	nvd, err := intel.LoadNVD(writeTinyNVDForEngine(t))
	if err != nil || nvd == nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	kb := intel.LoadLazy("", "")
	kb.AttachNVD(nvd)
	info := mlCVEInfoOf(kb, nil, "CVE-2099-0001")
	if !info.HasScore {
		t.Fatal("0.0 分查表命中应标记 HasScore（否则 ML 会兜底抬分）")
	}
	if info.Score != 0 {
		t.Fatalf("分数应为 0.0，实得 %v", info.Score)
	}
	if mlCVEInfoOf(kb, nil, "CVE-2099-0002").HasScore {
		t.Fatal("无评分条不应标记 HasScore")
	}
}
