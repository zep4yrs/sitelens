package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestSevLinearFixtures 线性严重度回归（sev-linear）的夹具门禁：
// 资产由 ml/train_sev_linear.py 导出（meta 与 cve-tech 同构、n_classes=1）。
// 夹具真值是 NVD CVSS 分（pub>=2024 截断描述抽样 120 条），实测 MAE≈1.19；
// 这里只做回归守卫（阈值 1.30，防止资产换错/维度错位导致的静默劣化）。
func TestSevLinearFixtures(t *testing.T) {
	dir := testAssetsDir(t)
	model, err := LoadModel(dir, "sev-linear")
	if err != nil {
		t.Fatalf("加载 sev-linear: %v", err)
	}
	if nc, nf := model.Dims(); nc != 1 || nf <= 0 {
		t.Fatalf("sev-linear 维度异常: n_classes=%d n_features=%d（应为 1×N 回归）", nc, nf)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sev-linear-fixtures.json"))
	if err != nil {
		t.Skipf("sev-linear fixtures 缺失，跳过: %v", err)
	}
	var fx struct {
		N     int `json:"n"`
		Items []struct {
			CVE   string  `json:"cve"`
			Text  string  `json:"text"`
			Score float64 `json:"score"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("解析 fixtures: %v", err)
	}
	if fx.N == 0 || len(fx.Items) != fx.N {
		t.Fatalf("fixtures 规模异常: n=%d len=%d", fx.N, len(fx.Items))
	}
	var sum, maxErr float64
	for i, it := range fx.Items {
		got, err := model.RegressionScore(it.Text)
		if err != nil {
			t.Fatalf("fixtures[%d] %s 推理失败: %v", i, it.CVE, err)
		}
		if got < 0 || got > 10 {
			t.Fatalf("fixtures[%d] %s 分数越界: %v", i, it.CVE, got)
		}
		e := math.Abs(got - it.Score)
		sum += e
		if e > maxErr {
			maxErr = e
		}
	}
	mae := sum / float64(len(fx.Items))
	t.Logf("sev-linear fixtures: n=%d MAE=%.4f max=%.4f（守卫阈值 1.30）", len(fx.Items), mae, maxErr)
	if mae > 1.30 {
		t.Fatalf("sev-linear MAE=%.4f > 1.30：资产疑似与训练口径不符或维度错位", mae)
	}
	// 确定性：同一文本两次推理必须逐位一致（无随机性）。
	a, _ := model.RegressionScore(fx.Items[0].Text)
	b, _ := model.RegressionScore(fx.Items[0].Text)
	if a != b {
		t.Fatalf("同一文本两次推理不一致: %v vs %v", a, b)
	}
}

// TestRegressionScoreGuards 回归打分的边界守卫：维度/非有限/clamp。
func TestRegressionScoreGuards(t *testing.T) {
	dir := t.TempDir()
	write := func(name, meta string, coef []byte) {
		t.Helper()
		files := map[string][]byte{
			name + ".meta.json": []byte(meta),
			name + ".vocab.txt": []byte("alpha\nbravo\ncharlie"),
			name + ".idf.f32":   {0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63},
			name + ".coef.f32":  coef,
		}
		for fn, b := range files {
			if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	base := `{"name":"%s","classes":%s,"n_features":3,"n_classes":%d,
"intercept":%s,"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`

	// 多类模型（分类器）不能被当回归打分器用。
	write("sev-multi", `{"name":"sev-multi","classes":["a","b"],"n_features":3,"n_classes":2,
"intercept":[0,0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`, make([]byte, 24))
	m, err := LoadModel(dir, "sev-multi")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RegressionScore("alpha"); err == nil {
		t.Fatal("多类模型调用 RegressionScore 应报错")
	}

	// clamp：intercept=20 → 10；intercept=-5 → 0（零系数，分数=intercept）。
	for _, tc := range []struct {
		name string
		b    string
		want float64
	}{
		{"sev-hi", "20", 10},
		{"sev-lo", "-5", 0},
	} {
		write(tc.name, fmt.Sprintf(base, tc.name, `["cvss-score"]`, 1, "["+tc.b+"]"),
			make([]byte, 12))
		mm, err := LoadModel(dir, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, err := mm.RegressionScore("alpha bravo")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s clamp = %v，期望 %v", tc.name, got, tc.want)
		}
	}

	// NaN 系数（绕过 loader 的损坏拦截，直接构造）→ 推理必须报错而非透传。
	nanModel := &Model{
		name: "sev-nan", classes: []string{"cvss-score"},
		vocab: map[string]int32{"alpha": 0}, idf: []float32{1},
		coef: []float32{float32(math.NaN())}, intercept: []float64{0},
		nFeatures: 1, nClasses: 1,
	}
	if _, err := nanModel.RegressionScore("alpha"); err == nil {
		t.Fatal("NaN 输出应返回错误（不得透传进 Prediction）")
	}

	// nil 模型与 nil 保护
	var nilModel *Model
	if _, err := nilModel.RegressionScore("alpha"); err == nil {
		t.Fatal("nil 模型应返回错误")
	}
}

// TestLoadOptionalSevLinear 可选加载语义：缺文件 = 未就绪（不报错）；
// 文件齐全但损坏 = 返回原因字符串（仅禁用该后端）。
func TestLoadOptionalSevLinear(t *testing.T) {
	dir := t.TempDir()
	if m, reason := loadOptionalModel(dir, "sev-linear"); m != nil || reason != "" {
		t.Fatalf("缺文件应返回 (nil, \"\")，实得 (%v, %q)", m, reason)
	}
	for fn, b := range map[string][]byte{
		"sev-linear.meta.json": []byte(`{"name":"sev-linear","classes":["cvss-score"],
"n_features":3,"n_classes":1,"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`),
		"sev-linear.vocab.txt": []byte("alpha\nbravo\ncharlie"),
		"sev-linear.idf.f32":   {0, 0, 128, 63, 0, 0, 128, 63, 0, 0, 128, 63},
		"sev-linear.coef.f32":  make([]byte, 4), // 期望 1×3×4=12，故意截断
	} {
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if m, reason := loadOptionalModel(dir, "sev-linear"); m != nil || reason == "" {
		t.Fatalf("损坏资产应返回 (nil, 原因)，实得 (%v, %q)", m, reason)
	}
}
