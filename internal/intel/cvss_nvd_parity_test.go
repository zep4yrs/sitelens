package intel

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// CVSS 计分对拍门禁：用仓库自带的 NVD CVE 字典（data/nvd_cves.json.gz，
// 内含 NVD 官方发布的向量与基础分）**逐条重算并比对**。
//
// 为什么必须有这道门禁：
// CVSS 计分的三处缺陷（AV:L 权重误用 v2 值、漏 ×1.08 系数、PR 权重依赖
// 向量串书写顺序）此前全部**不报错、不崩溃**，而仓库里的单元测试又恰好把
// 错误输出写成了期望值——于是 CI 全绿，41.42% 的向量分数与官方分不符。
// 抽样测试发现不了这类"整体偏移"；只有逐条全量比对能。
//
// 规模：29 万条 v3 向量，重算耗时 <2s。字典不在仓库时跳过（不误伤干净 clone）。
var nvdVecV3 = regexp.MustCompile(`^(CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$`)

func TestCVSS3MatchesNVDOfficialScores(t *testing.T) {
	const path = "../../data/nvd_cves.json.gz"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("NVD 字典不在本地（%v），跳过对拍", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("打开 gzip 失败：%v", err)
	}
	defer zr.Close()

	var dump struct {
		CVEs []struct {
			CVE   string   `json:"cve"`
			Score *float64 `json:"score"`
			Vec   string   `json:"vec"`
		} `json:"cves"`
	}
	if err := json.NewDecoder(zr).Decode(&dump); err != nil {
		t.Fatalf("解析 NVD 字典失败：%v", err)
	}

	var checked, mismatched int
	for _, e := range dump.CVEs {
		if e.Score == nil || !nvdVecV3.MatchString(e.Vec) {
			continue
		}
		got, label, err := CVSS3Score(e.Vec)
		if err != nil {
			t.Fatalf("%s（%s）不应解析失败：%v", e.CVE, e.Vec, err)
		}
		checked++
		// 官方分是 1 位小数；比较到 0.1 粒度（规范取整的最终粒度）。
		if diff := got - *e.Score; diff > 0.05 || diff < -0.05 {
			mismatched++
			if mismatched <= 10 {
				t.Errorf("%s：向量 %s → 算出 %.1f（%s），NVD 官方 %.1f",
					e.CVE, e.Vec, got, label, *e.Score)
			}
		}
	}
	if checked == 0 {
		t.Skip("NVD 字典中无 v3 向量，跳过对拍")
	}
	if mismatched > 0 {
		t.Fatalf("CVSS 计分与 NVD 官方分不符：%d/%d 条不一致", mismatched, checked)
	}
	t.Logf("CVSS 计分与 NVD 官方分逐条一致：%d 条", checked)
}
