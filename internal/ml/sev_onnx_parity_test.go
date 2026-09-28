//go:build onnx

package ml

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestSevOnnxParity Go 推理 vs Python fp32 ONNX 真值（同一模型产物，
// 夹具由 ml/export_sev_fixtures_go.py 生成）。门槛 MAE < 0.03（CVSS 分
// 尺度）：Python 侧 torch↔ONNX 已 <0.02，Go 差异只允许来自分词器微差。
// 资产/DLL 缺失时 t.Skip（开发机形态差异不阻塞无 onnx 环境）。
func TestSevOnnxParity(t *testing.T) {
	root := filepath.Join("..", "..")
	assets := filepath.Join(root, "data", "go", "ml_assets")
	fixPath := filepath.Join(assets, "sev-fixtures.json")
	vocabPath := filepath.Join(assets, "sev-prior-v3.1.vocab.txt")
	onnxA := filepath.Join(assets, "sev-prior-v3.1-a.onnx")
	onnxB := filepath.Join(assets, "sev-prior-v3.1-b.onnx")
	dll := os.Getenv("SITLENS_ORT_DLL")
	if dll == "" {
		dll = filepath.Join(root, "data", "onnxruntime", "onnxruntime.dll")
	}
	for _, p := range []string{fixPath, vocabPath, onnxA, onnxB, dll} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("onnx 对拍资产缺失（%s），跳过", p)
		}
	}
	raw, err := os.ReadFile(fixPath)
	if err != nil {
		t.Fatal(err)
	}
	var fix struct {
		Seq   int `json:"seq"`
		Items []struct {
			Text  string  `json:"text"`
			Score float64 `json:"score"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatal(err)
	}
	scorer, err := NewSevScorer(vocabPath, dll, []string{onnxA, onnxB})
	if err != nil {
		t.Fatalf("scorer 初始化: %v", err)
	}
	var sum, maxd float64
	for i, it := range fix.Items {
		got, err := scorer.Score(it.Text)
		if err != nil {
			t.Fatalf("item %d: %v", i, err)
		}
		d := math.Abs(got - it.Score)
		sum += d
		if d > maxd {
			maxd = d
		}
		if d > 0.15 && i < 5 {
			t.Logf("item %d 大偏差（不判死，看分布）: got %.4f want %.4f", i, got, it.Score)
		}
	}
	mae := sum / float64(len(fix.Items))
	t.Logf("Go vs Python fp32: n=%d MAE=%.5f max=%.5f", len(fix.Items), mae, maxd)
	if mae >= 0.03 {
		t.Fatalf("MAE %.5f >= 0.03 —— 分词器或推理口径与 Python 不一致", mae)
	}
}
