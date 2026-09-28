package ml

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		// 长度>=2 的词字符 run；单字符 run 丢弃（\b\w\w+\b 语义）
		{"The debug command in Sendmail is enabled", []string{"the", "debug", "command", "in", "sendmail", "is", "enabled"}},
		{"CVE-2024-1234", []string{"cve", "2024", "1234"}},
		{"don't", []string{"don"}},                     // ' 断词，t 单字符丢弃
		{"a b c 1 2", nil},                             // 全部单字符
		{"2.4 v1.2.3", []string{"v1"}},                 // 版本号切出 v1；2/4/1/2/3 单字符
		{"foo_bar", []string{"foo_bar"}},               // 下划线是词字符，不断词
		{"", nil},
		{"über café 跨站脚本攻击", []string{"über", "café", "跨站脚本攻击"}}, // Unicode \w
		{"rate limiting (429) via X-Forwarded-For", []string{"rate", "limiting", "429", "via", "forwarded", "for"}},
	}
	for _, c := range cases {
		got := Tokenize(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Tokenize(%q) = %v, 期望 %v", c.in, got, c.want)
		}
	}
}

func newTinyModel() *Model {
	return &Model{
		name:      "tiny",
		classes:   []string{"x", "y"},
		vocab:     map[string]int32{"aa": 0, "bb": 1, "cc": 2},
		idf:       []float32{1, 2, 3},
		coef:      []float32{1, 2, 3, -1, 0, 1}, // 2 类 × 3 特征，行主序
		intercept: []float64{0.5, -0.5},
		nFeatures: 3,
		nClasses:  2,
	}
}

func TestVectorizeTFIDF(t *testing.T) {
	m := newTinyModel()
	ids, vals := m.Vectorize("aa aa bb")
	if !reflect.DeepEqual(ids, []int32{0, 1}) {
		t.Fatalf("ids = %v, 期望 [0 1]（升序）", ids)
	}
	// aa: count=2 → (1+ln2)*1=1.6931…; bb: count=1 → (1+ln1)*2=2
	// L2 归一后 0.6461289150464732 / 0.7632282916276542（Python 预计算）
	wantVals := []float64{0.6461289150464732, 0.7632282916276542}
	for i, want := range wantVals {
		if math.Abs(vals[i]-want) > 1e-12 {
			t.Errorf("vals[%d] = %v, 期望 %v", i, vals[i], want)
		}
	}
	var norm float64
	for _, v := range vals {
		norm += v * v
	}
	if math.Abs(math.Sqrt(norm)-1) > 1e-12 {
		t.Errorf("L2 范数 = %v, 期望 1", math.Sqrt(norm))
	}
	// 无命中 → 空向量（零向量语义）
	if ids2, vals2 := m.Vectorize("zz zz"); ids2 != nil || vals2 != nil {
		t.Errorf("未命中词表应返回空向量, got %v %v", ids2, vals2)
	}
}

func TestVectorizeSublinearVsRaw(t *testing.T) {
	// 子线性 tf：词出现两次的权重应高于一次，但低于线性翻倍（1+ln2≈1.693 < 2）
	m := newTinyModel()
	_, once := m.Vectorize("bb aa")   // once[0] = aa 出现 1 次
	_, twice := m.Vectorize("aa aa bb") // twice[0] = aa 出现 2 次
	if !(twice[0] > once[0] && twice[0] < 2*once[0]) {
		t.Errorf("子线性 tf 未生效: aa 一次权重 %v, 两次权重 %v（应在 (%v, %v) 区间）",
			once[0], twice[0], once[0], 2*once[0])
	}
}

func TestDecisionFunctionTopK(t *testing.T) {
	m := newTinyModel()
	scores := m.DecisionFunction("aa cc")
	// "aa cc"：各出现 1 次，idf=[1,2,3] → 未归一值 [1,3]，L2=√10 → [1/√10, 3/√10]
	// score[0] = 1/√10*1 + 3/√10*3 + 0.5 = 10/√10 + 0.5 = 3.6622776601683795
	// score[1] = 1/√10*(-1) + 3/√10*1 - 0.5 = 2/√10 - 0.5 = 0.1324555320336759
	// （bigram "aa cc" 不在词表，不参与）
	want := []float64{3.6622776601683795, 0.1324555320336759}
	for i, w := range want {
		if math.Abs(scores[i]-w) > 1e-12 {
			t.Errorf("scores[%d] = %v, 期望 %v", i, scores[i], w)
		}
	}
	top := m.TopK("aa cc", 2)
	if top[0].Class != "x" || top[1].Class != "y" {
		t.Errorf("TopK = %v/%v, 期望 x/y", top[0].Class, top[1].Class)
	}
	if cls, sc := m.ArgMax("aa cc"); cls != "x" || math.Abs(sc-want[0]) > 1e-12 {
		t.Errorf("ArgMax = %v,%v; 期望 x,%v", cls, sc, want[0])
	}
	// k 超过类数需截断
	if got := m.TopK("aa", 99); len(got) != 2 {
		t.Errorf("TopK k=99 应截断为 2, got %d", len(got))
	}
}

func TestVectorizeBigram(t *testing.T) {
	// 词表含 bigram（对齐导出资产 ngram_range=(1,2)）：
	// vocab{aa:0, bb:1, "aa bb":2}，idf=[1,1,2]；"aa bb" → 三特征各 1 次
	// 未归一 [1,1,2]，L2=√6 → [0.4082482904638631, 0.4082482904638631, 0.8164965809277261]
	m := &Model{
		name:      "bigram",
		classes:   []string{"z"},
		vocab:     map[string]int32{"aa": 0, "bb": 1, "aa bb": 2},
		idf:       []float32{1, 1, 2},
		coef:      []float32{1, 1, 1},
		intercept: []float64{0},
		nFeatures: 3,
		nClasses:  1,
	}
	ids, vals := m.Vectorize("aa bb")
	if !reflect.DeepEqual(ids, []int32{0, 1, 2}) {
		t.Fatalf("ids = %v, 期望 [0 1 2]（bigram 特征需命中）", ids)
	}
	want := []float64{0.4082482904638631, 0.4082482904638631, 0.8164965809277261}
	for i, w := range want {
		if math.Abs(vals[i]-w) > 1e-12 {
			t.Errorf("vals[%d] = %v, 期望 %v", i, vals[i], w)
		}
	}
	// 非相邻词不成 bigram："aa xx bb" 只命中 aa、bb 两个一元特征
	ids2, _ := m.Vectorize("aa xx bb")
	if !reflect.DeepEqual(ids2, []int32{0, 1}) {
		t.Errorf("非相邻词不应产生 bigram, ids = %v", ids2)
	}
}

// writeTinyAssets 在 dir 写一套完整的小模型资产，供 LoadAssets 单测。
func writeTinyAssets(t *testing.T, dir, name string, coefBytes []byte) {
	t.Helper()
	f32le := func(fs []float32) []byte {
		b := make([]byte, 4*len(fs))
		for i, f := range fs {
			binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(f))
		}
		return b
	}
	meta := fmt.Sprintf(`{"name":%q,"classes":["x","y"],"n_features":3,"n_classes":2,
"intercept":[0.5,-0.5],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`, name)
	files := map[string][]byte{
		name + ".meta.json":  []byte(meta),
		name + ".vocab.txt":  []byte("aa\nbb\ncc"),
		name + ".idf.f32":    f32le([]float32{1, 2, 3}),
		name + ".coef.f32":   coefBytes,
	}
	for fn, b := range files {
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatalf("写 %s: %v", fn, err)
		}
	}
}

func TestLoadModelAndAssets(t *testing.T) {
	dir := t.TempDir()
	writeTinyAssets(t, dir, "tiny", make([]byte, 4*6)) // 2 类×3 特征全零系数

	m, err := LoadModel(dir, "tiny")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	nc, nf := m.Dims()
	if nc != 2 || nf != 3 {
		t.Errorf("Dims = (%d,%d), 期望 (2,3)", nc, nf)
	}
	if !reflect.DeepEqual(m.Classes(), []string{"x", "y"}) {
		t.Errorf("Classes = %v", m.Classes())
	}
	if m.Name() != "tiny" {
		t.Errorf("Name = %q", m.Name())
	}

	// coef 字节数不符必须报错
	bad := t.TempDir()
	writeTinyAssets(t, bad, "tiny", make([]byte, 4*5))
	if _, err := LoadModel(bad, "tiny"); err == nil {
		t.Error("coef 长度不符应报错")
	}

	// meta.name 与请求名不符必须报错
	wrong := t.TempDir()
	writeTinyAssets(t, wrong, "other", make([]byte, 4*6))
	if _, err := LoadModel(wrong, "tiny"); err == nil {
		t.Error("meta.name 不符应报错")
	}

	// LoadAssets 需要 cve-tech/cwe-type 双模型，缺任一应报错
	if _, err := LoadAssets(dir); err == nil {
		t.Error("缺 cve-tech/cwe-type 时 LoadAssets 应报错")
	}
}

// TestTopKNonPositiveK 回归：负数/零 k 返回空而不是 panic。
// 此前 TopK("aa", -1) 直接 make([]Pred, -1) → makeslice panic；
// 导出 API 不能假设调用方只传常量正数（如配置化 Top-N）。
func TestTopKNonPositiveK(t *testing.T) {
	m := newTinyModel()
	for _, k := range []int{-1, -99, 0} {
		if got := m.TopK("aa", k); len(got) != 0 {
			t.Errorf("TopK(k=%d) 应返回空, got %v", k, got)
		}
		if got := m.ProbaTopK("aa", k); len(got) != 0 {
			t.Errorf("ProbaTopK(k=%d) 应返回空, got %v", k, got)
		}
	}
	// 正数 k 行为不回归：超类数截断
	if got := m.ProbaTopK("aa", 99); len(got) != 2 {
		t.Errorf("ProbaTopK k=99 应截断为 2, got %d", len(got))
	}
}

// TestTokenizePythonLowerSpecialCasing 回归：lowercase 步骤对齐 CPython
// str.lower()（sklearn lowercase=True 的口径），而非 Go 的逐 rune 简单映射。
// Python 3.10.10 实测基准：
//   re.findall(r'(?u)\b\w\w+\b', 'İstanbul'.lower()) == ['stanbul']
//   re.findall(r'(?u)\b\w\w+\b', 'ΝΙΚΟΣ'.lower())     == ['νικος']（末字符 0x3C2 ς）
func TestTokenizePythonLowerSpecialCasing(t *testing.T) {
	// İ → "i"+U+0307（组合点上点非 \w，断词，单字符 i 被丢弃）
	if got := Tokenize("İstanbul"); !reflect.DeepEqual(got, []string{"stanbul"}) {
		t.Errorf("Tokenize(İstanbul) = %v, 期望 [stanbul]", got)
	}
	// 词尾 Σ → ς(U+03C2)；非词尾 Σ → σ(U+03C3)
	if got := Tokenize("ΝΙΚΟΣ"); !reflect.DeepEqual(got, []string{"νικος"}) {
		t.Errorf("Tokenize(ΝΙΚΟΣ) = %q, 期望 [νικος]（末字符应为 U+03C2 ς）", got)
	}
	// 词中 Σ（后邻 cased）→ σ；词尾 Σ（后邻非 cased，含空格/串尾）→ ς。
	// 'ΚΟΣΜΟΣ'.lower() = 'κοσμος'（U+03C3 词中 / U+03C2 词尾）。
	if got := Tokenize("ΚΟΣΜΟΣ"); len(got) != 1 || got[0] != "κοσμο"+string(rune(0x3C2)) {
		t.Errorf("Tokenize(ΚΟΣΜΟΣ) = %q, 期望 [κοσμος]（词中 σ/词尾 ς）", got)
	}
	got := Tokenize("ΟΔΟΣ ΟΔΟΣ") // 两处 Σ 后邻都是空格/串尾 → 均为 ς
	if len(got) != 2 || got[0] != "οδο"+string(rune(0x3C2)) || got[1] != "οδο"+string(rune(0x3C2)) {
		t.Errorf("Tokenize(ΟΔΟΣ ΟΔΟΣ) = %q, 期望两处词尾均为 ς", got)
	}
	// 单独的 Σ 前无 cased 字母 → σ
	if pyLower("Σ") != "σ" {
		t.Errorf("pyLower(Σ) = %q, 期望 σ", pyLower("Σ"))
	}
	// ASCII 常规文本不受影响（快路径与 strings.ToLower 等价）
	if got := Tokenize("The DEBUG Command"); !reflect.DeepEqual(got,
		[]string{"the", "debug", "command"}) {
		t.Errorf("ASCII 文本应不受影响, got %v", got)
	}
}

// TestVectorizeZeroIDFNoNaN 回归：命中特征的 idf 权重全 0 时按零向量
// 语义返回，而不是 0/0 产出 NaN。
func TestVectorizeZeroIDFNoNaN(t *testing.T) {
	m := &Model{
		name:      "zeroidf",
		classes:   []string{"z"},
		vocab:     map[string]int32{"aa": 0},
		idf:       []float32{0},
		coef:      []float32{1},
		intercept: []float64{0},
		nFeatures: 1,
		nClasses:  1,
	}
	ids, vals := m.Vectorize("aa aa")
	if ids != nil || vals != nil {
		t.Errorf("idf 全 0 的命中特征应返回零向量, got %v %v", ids, vals)
	}
	for _, s := range m.DecisionFunction("aa aa") {
		if math.IsNaN(s) || math.IsInf(s, 0) {
			t.Errorf("得分出现非有限值 %v", s)
		}
	}
}

// TestLoadModelRejectsCorruptF32 回归：同长度损坏（字节数正常、内容是
// NaN/Inf 位型或 idf 全零）必须在加载期报错——此前静默通过加载，NaN
// 一路透传进 Prediction 后 json.Marshal 直接失败，整份扫描输出丢失。
func TestLoadModelRejectsCorruptF32(t *testing.T) {
	all := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

	// ① coef 全 0xFF（NaN 位型，长度恰为 2 类×3 特征×4B）
	corruptCoef := t.TempDir()
	writeTinyAssets(t, corruptCoef, "tiny", all(24, 0xFF))
	if _, err := LoadModel(corruptCoef, "tiny"); err == nil {
		t.Error("coef 为 NaN 位型应报错")
	}

	// ② idf 全 0xFF（NaN 位型）
	corruptIDF := t.TempDir()
	writeTinyAssets(t, corruptIDF, "tiny", all(24, 0))
	if err := os.WriteFile(filepath.Join(corruptIDF, "tiny.idf.f32"), all(12, 0xFF), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModel(corruptIDF, "tiny"); err == nil {
		t.Error("idf 为 NaN 位型应报错")
	}

	// ③ idf 全 0（有限值但平滑 idf 不可能全零 → 损坏）：命中后 0/0 产 NaN
	zeroIDF := t.TempDir()
	writeTinyAssets(t, zeroIDF, "tiny", all(24, 0))
	if err := os.WriteFile(filepath.Join(zeroIDF, "tiny.idf.f32"), all(12, 0), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModel(zeroIDF, "tiny"); err == nil {
		t.Error("idf 全 0 应报错")
	}

	// ④ Inf 位型（0x7F800000 = +Inf）
	infIDF := t.TempDir()
	writeTinyAssets(t, infIDF, "tiny", all(24, 0))
	if err := os.WriteFile(filepath.Join(infIDF, "tiny.idf.f32"),
		[]byte{0x00, 0x00, 0x80, 0x7F, 0, 0, 0, 0, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModel(infIDF, "tiny"); err == nil {
		t.Error("idf 为 Inf 位型应报错")
	}
}
