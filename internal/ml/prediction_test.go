package ml

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbaNormalizedSigmoidRowNorm 验证与 sklearn 实测口径一致：
// 逐类 sigmoid 后行归一（fixtures.json 数值口径，见 prediction.go 注释）。
func TestProbaNormalizedSigmoidRowNorm(t *testing.T) {
	got := probaNormalized([]float64{3.6622776601683795, 0.1324555320336759})
	s0 := 1.0 / (1.0 + math.Exp(-3.6622776601683795))
	s1 := 1.0 / (1.0 + math.Exp(-0.1324555320336759))
	want := []float64{s0 / (s0 + s1), s1 / (s0 + s1)}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-12 {
			t.Errorf("proba[%d] = %v, 期望 %v", i, got[i], want[i])
		}
	}
	var sum float64
	for _, v := range got {
		sum += v
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Errorf("行归一后概率和 = %v, 期望 1", sum)
	}
	// 全饱和负分（分母 0）退回均匀分布，不得出现 NaN
	uniform := probaNormalized([]float64{-1000, -1000})
	if math.Abs(uniform[0]-0.5) > 1e-12 || math.Abs(uniform[1]-0.5) > 1e-12 {
		t.Errorf("全饱和负分应退回均匀分布, got %v", uniform)
	}
}

// TestProbaTopK 验证 ProbaTopK：排序同 TopK，Score 为 sigmoid 行归一概率。
func TestProbaTopK(t *testing.T) {
	m := newTinyModel() // "aa cc" 得分 x=3.6623 > y=0.1325
	top := m.ProbaTopK("aa cc", 2)
	if top[0].Class != "x" || top[1].Class != "y" {
		t.Fatalf("ProbaTopK 顺序 = %s/%s, 期望 x/y", top[0].Class, top[1].Class)
	}
	// 手算：sigmoid(3.6623)=0.974918, sigmoid(0.1325)=0.533064
	// 归一：x = 0.974918/(0.974918+0.533064) = 0.646…, y = 0.353…
	s0 := 1.0 / (1.0 + math.Exp(-3.6622776601683795))
	s1 := 1.0 / (1.0 + math.Exp(-0.1324555320336759))
	wantX, wantY := s0/(s0+s1), s1/(s0+s1)
	if math.Abs(top[0].Score-wantX) > 1e-12 || math.Abs(top[1].Score-wantY) > 1e-12 {
		t.Errorf("概率 = %v/%v, 期望 %v/%v", top[0].Score, top[1].Score, wantX, wantY)
	}
	if math.Abs(top[0].Score+top[1].Score-1) > 1e-12 {
		t.Errorf("两类概率和应为 1, got %v", top[0].Score+top[1].Score)
	}
	// 与 TopK 的线性得分单调一致
	if top[0].Score <= top[1].Score {
		t.Errorf("概率应随线性得分单调: %v <= %v", top[0].Score, top[1].Score)
	}
}

// TestPredictionJSON 确认结果契约键位与开发文档 §10.3 对齐：
// cve / tech_top5(product+prob[+relevance]) / cwe_type / sev_score。
func TestPredictionJSON(t *testing.T) {
	p := Prediction{
		CVE: "CVE-2024-1234",
		TechTop5: []TechPred{
			{Product: "apache/tomcat", Prob: 0.42, Relevance: RelHit},
			{Product: "php/php", Prob: 0.11},
		},
		CWEType:  "CWE-79",
		SevScore: 7.5,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"cve", "tech_top5", "cwe_type", "sev_score"} {
		if _, ok := m[key]; !ok {
			t.Errorf("契约键 %s 缺失: %s", key, raw)
		}
	}
	first := m["tech_top5"].([]any)[0].(map[string]any)
	for _, key := range []string{"product", "prob", "relevance"} {
		if _, ok := first[key]; !ok {
			t.Errorf("tech_top5[0] 键 %s 缺失: %s", key, raw)
		}
	}
	// 无交集条目 relevance 缺席（omitempty）
	second := m["tech_top5"].([]any)[1].(map[string]any)
	if _, ok := second["relevance"]; ok {
		t.Errorf("无交集条目 relevance 应缺席: %v", second)
	}
	// 零值 sev_score（无先验）应缺席
	p2 := Prediction{CVE: "CVE-2024-1"}
	raw2, _ := json.Marshal(p2)
	if strings.Contains(string(raw2), `"sev_score"`) {
		t.Errorf("零值 sev_score 应被 omitempty: %s", raw2)
	}
}

// TestProbaAgainstPythonFixtures 真实资产上与 Python predict_proba 数值
// 对拍：fixtures 首条描述的 Go 概率与导出侧 prob 逐条容差 <=1e-3。
// （排序一致性由 parity_test.go 承担，这里只验概率口径——sigmoid 行归一。）
// 资产目录缺失时跳过（不阻塞无资产环境的单测）。
func TestProbaAgainstPythonFixtures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "fixtures.json"))
	if err != nil {
		t.Skipf("fixtures.json 不可读（未导出资产）: %v", err)
	}
	var fx []fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("解析 fixtures.json: %v", err)
	}
	assets, err := LoadAssets(fixturesDir)
	if err != nil {
		t.Skipf("模型资产不可加载: %v", err)
	}
	// 抽首条 + 末条对拍（口径错则偏差远超 1e-3）
	for _, i := range []int{0, len(fx) - 1} {
		f := fx[i]
		top5 := assets.Tech.ProbaTopK(f.Descr, 5)
		for j, tp := range f.TechTop5 {
			if top5[j].Class != tp.Product {
				t.Errorf("fx[%d] top5[%d] = %s, 期望 %s", i, j, top5[j].Class, tp.Product)
				continue
			}
			if math.Abs(top5[j].Score-tp.Prob) > 1e-3 {
				t.Errorf("fx[%d] %s 概率 = %.5f, Python 侧 %.5f（容差 1e-3）",
					i, tp.Product, top5[j].Score, tp.Prob)
			}
		}
		if top := assets.Cwe.ProbaTopK(f.Descr, 1)[0]; top.Class != f.CwePred {
			t.Errorf("fx[%d] cwe = %s, 期望 %s", i, top.Class, f.CwePred)
		}
	}
}
