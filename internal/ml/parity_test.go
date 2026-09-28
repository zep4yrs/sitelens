package ml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixturesDir：internal/ml 相对主仓 data/go/ml_assets（export_go_assets.py 导出物）。
const fixturesDir = ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "data" + string(filepath.Separator) + "go" + string(filepath.Separator) + "ml_assets"

type fixtureProduct struct {
	Product string  `json:"product"`
	Prob    float64 `json:"prob"`
}

type fixture struct {
	Cve      string           `json:"cve"`
	Descr    string           `json:"descr"`
	TechTop5 []fixtureProduct `json:"tech_top5"`
	CwePred  string           `json:"cwe_pred"`
	CweProb  float64          `json:"cwe_prob"`
}

// TestParityWithPythonFixtures 对拍 Python 侧基准：500 条真实 CVE 描述，
// Go 推理 vs export_go_assets.py 侧 predict_proba 排序结果：
//   - 产品 Top-1 一致率 >= 99.5%
//   - 产品 Top-5 平均重叠 >= 4.5/5
//   - CWE 类型一致率 >= 99.5%
func TestParityWithPythonFixtures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "fixtures.json"))
	if err != nil {
		t.Fatalf("读取 fixtures.json 失败（%s）: %v", fixturesDir, err)
	}
	var fx []fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("解析 fixtures.json: %v", err)
	}
	if len(fx) != 500 {
		t.Fatalf("期望 500 条 fixtures, 实际 %d 条", len(fx))
	}

	assets, err := LoadAssets(fixturesDir)
	if err != nil {
		t.Fatalf("加载模型资产: %v", err)
	}
	ncT, nfT := assets.Tech.Dims()
	ncC, nfC := assets.Cwe.Dims()
	t.Logf("cve-tech: %d 类 × %d 特征; cwe-type: %d 类 × %d 特征", ncT, nfT, ncC, nfC)

	top1OK, cweOK, overlapSum := 0, 0, 0.0
	var top1Miss, cweMiss []string
	start := time.Now()
	for _, f := range fx {
		top5 := assets.Tech.TopK(f.Descr, 5)

		// 1) Top-1 产品一致
		if top5[0].Class == f.TechTop5[0].Product {
			top1OK++
		} else if len(top1Miss) < 5 {
			top1Miss = append(top1Miss, f.Cve+" go="+top5[0].Class+" py="+f.TechTop5[0].Product)
		}

		// 2) Top-5 重叠（集合交 / 5）
		goSet := make(map[string]bool, 5)
		for _, p := range top5 {
			goSet[p.Class] = true
		}
		ov := 0
		for _, p := range f.TechTop5 {
			if goSet[p.Product] {
				ov++
			}
		}
		overlapSum += float64(ov)

		// 3) CWE 类型一致
		if cwe, _ := assets.Cwe.ArgMax(f.Descr); cwe == f.CwePred {
			cweOK++
		} else if len(cweMiss) < 5 {
			cweMiss = append(cweMiss, f.Cve+" go="+cwe+" py="+f.CwePred)
		}
	}
	elapsed := time.Since(start)

	n := float64(len(fx))
	top1Rate := float64(top1OK) / n
	avgOverlap := overlapSum / n
	cweRate := float64(cweOK) / n

	t.Logf("500 条 Go 推理耗时 %v（%.2f 条/秒）", elapsed, n/elapsed.Seconds())
	t.Logf("parity: top-1 产品一致率 = %.4f%% (%d/500), 阈值 99.5%%", top1Rate*100, top1OK)
	t.Logf("parity: top-5 平均重叠 = %.4f/5, 阈值 4.5", avgOverlap)
	t.Logf("parity: cwe_pred 一致率 = %.4f%% (%d/500), 阈值 99.5%%", cweRate*100, cweOK)
	for _, m := range top1Miss {
		t.Logf("top-1 不一致样例: %s", m)
	}
	for _, m := range cweMiss {
		t.Logf("cwe 不一致样例: %s", m)
	}

	if top1Rate < 0.995 {
		t.Errorf("top-1 产品一致率 %.4f%% < 99.5%%", top1Rate*100)
	}
	if avgOverlap < 4.5 {
		t.Errorf("top-5 平均重叠 %.4f < 4.5/5", avgOverlap)
	}
	if cweRate < 0.995 {
		t.Errorf("cwe_pred 一致率 %.4f%% < 99.5%%", cweRate*100)
	}
}
