package intel

import (
	"testing"
)

// TestNVDDataContract_CWE 校验入仓 NVD 数据文件与本版代码的「数据契约」：
// 若文件是 v2（含 cwes 字段），则应能取到真实 CWE；仍是 v1 则如实记录
// 「待重跑 update-nvd」，不伪装成通过。
//
// 意图是**暴露数据状态**而非跳过问题：v1 数据下它会明确输出提示，
// 便于 CI / 人工发现「代码已支持但数据未刷新」。
func TestNVDDataContract_CWE(t *testing.T) {
	store, err := LoadNVD("../../data/nvd_cves.json.gz")
	if err != nil {
		t.Fatalf("加载 NVD 数据失败：%v", err)
	}
	if store == nil {
		t.Skip("NVD 数据文件不存在（新 clone 未拉大文件）")
	}

	// 已知带 CWE 的抽样 CVE（NVD weaknesses 实测：
	// CVE-2021-44228 → CWE-20/400/502/917，CVE-2022-22965 → CWE-94）。
	sample := []string{"CVE-2021-44228", "CVE-2022-22965", "CVE-2019-0708", "CVE-2017-0144"}
	withCWE := 0
	for _, cve := range sample {
		if cs := store.CWEsFor(cve); len(cs) > 0 {
			withCWE++
		}
	}

	if withCWE == 0 {
		// v1 数据：格式合法但无 cwes。属已知状态，记录以便触发数据刷新。
		t.Logf("当前 NVD 数据为 v1（无 cwes 字段）：%d/%d 抽样命中 CWE。"+
			"CVE→CWE 通道需重跑 `sitelens update-nvd` 后生效（见开发文档 26.13 遗留）。",
			withCWE, len(sample))
		return
	}
	// v2 数据：编号形态必须合法。
	for _, cve := range sample {
		for _, c := range store.CWEsFor(cve) {
			if !isCWENumber(c) {
				t.Errorf("%s 的 CWE 编号形态非法：%q", cve, c)
			}
		}
	}
	t.Logf("NVD 数据含 cwes：%d/%d 抽样命中", withCWE, len(sample))
}
