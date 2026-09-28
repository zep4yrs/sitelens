package ml

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Model 是一个导出的线性模型（词表 + idf + 系数 + 元信息）。
// coef 为行主序：coef[c*nFeatures+i] 是第 c 类在第 i 特征上的权重。
type Model struct {
	name       string
	classes    []string
	vocab      map[string]int32
	idf        []float32
	coef       []float32
	intercept  []float64
	nFeatures  int
	nClasses   int
}

// Name 返回模型名（cve-tech / cwe-type）。
func (m *Model) Name() string { return m.name }

// Classes 返回类别表（下标与 coef 行一致）。
func (m *Model) Classes() []string { return m.classes }

// Dims 返回 (nClasses, nFeatures)。
func (m *Model) Dims() (int, int) { return m.nClasses, m.nFeatures }

// Assets 内嵌引擎所需的两个模型。
type Assets struct {
	Tech *Model // cve-tech：CVE 描述 → 受影响产品 Top-5（196 类）
	Cwe  *Model // cwe-type：CVE 描述 → CWE 弱点类型（25 类）
}

// LoadAssets 从 dir 加载 cve-tech 与 cwe-type 两套模型资产。
func LoadAssets(dir string) (*Assets, error) {
	tech, err := LoadModel(dir, "cve-tech")
	if err != nil {
		return nil, fmt.Errorf("ml: 加载 cve-tech: %w", err)
	}
	cwe, err := LoadModel(dir, "cwe-type")
	if err != nil {
		return nil, fmt.Errorf("ml: 加载 cwe-type: %w", err)
	}
	return &Assets{Tech: tech, Cwe: cwe}, nil
}

// Predict 一次完成双模型推理：返回产品 Top-5 与 CWE 弱点类型。
func (a *Assets) Predict(descr string) ([]Pred, string) {
	top5 := a.Tech.TopK(descr, 5)
	cwe, _ := a.Cwe.ArgMax(descr)
	return top5, cwe
}

// metaJSON 对齐导出侧 meta.json 字段。
type metaJSON struct {
	Name         string    `json:"name"`
	Classes      []string  `json:"classes"`
	NFeatures    int       `json:"n_features"`
	NClasses     int       `json:"n_classes"`
	Intercept    []float64 `json:"intercept"`
	SublinearTF  bool      `json:"sublinear_tf"`
	Lowercase    bool      `json:"lowercase"`
	TokenPattern string    `json:"token_pattern"`
	L2Norm       bool      `json:"l2_norm"`
}

// LoadModel 从 dir 加载名为 name 的模型（读 <name>.{vocab.txt,idf.f32,coef.f32,meta.json}）。
// 加载时校验维度一致性与导出配置（lowercase/sublinear_tf/l2_norm/token_pattern），
// 配置不符说明资产与本实现的推理口径不一致，直接报错而非静默错推理。
func LoadModel(dir, name string) (*Model, error) {
	if name == "" {
		return nil, errors.New("ml: 模型名为空")
	}
	raw, err := os.ReadFile(filepath.Join(dir, name+".meta.json"))
	if err != nil {
		return nil, err
	}
	var meta metaJSON
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("ml: 解析 %s.meta.json: %w", name, err)
	}
	if meta.Name != name {
		return nil, fmt.Errorf("ml: meta.name=%q 与请求的 %q 不符", meta.Name, name)
	}
	if !meta.Lowercase || !meta.SublinearTF || !meta.L2Norm {
		return nil, fmt.Errorf("ml: %s 导出配置不支持: lowercase=%v sublinear_tf=%v l2_norm=%v",
			name, meta.Lowercase, meta.SublinearTF, meta.L2Norm)
	}
	if meta.TokenPattern != expectedTokenPattern {
		return nil, fmt.Errorf("ml: %s token_pattern=%q 与 Go 切词口径 %q 不符",
			name, meta.TokenPattern, expectedTokenPattern)
	}
	if meta.NFeatures <= 0 || meta.NClasses <= 0 {
		return nil, fmt.Errorf("ml: %s 维度非法: n_features=%d n_classes=%d",
			name, meta.NFeatures, meta.NClasses)
	}
	if len(meta.Classes) != meta.NClasses || len(meta.Intercept) != meta.NClasses {
		return nil, fmt.Errorf("ml: %s 类表/intercept 长度与 n_classes=%d 不符 (%d/%d)",
			name, meta.NClasses, len(meta.Classes), len(meta.Intercept))
	}

	vocab, err := loadVocab(filepath.Join(dir, name+".vocab.txt"), meta.NFeatures)
	if err != nil {
		return nil, err
	}
	idf, err := readF32(filepath.Join(dir, name+".idf.f32"), meta.NFeatures)
	if err != nil {
		return nil, fmt.Errorf("ml: %s idf: %w", name, err)
	}
	coef, err := readF32(filepath.Join(dir, name+".coef.f32"), meta.NClasses*meta.NFeatures)
	if err != nil {
		return nil, fmt.Errorf("ml: %s coef: %w", name, err)
	}
	// idf 全 0 在平滑 idf（sklearn 默认 smooth_idf，idf >= 1）下不可能出现，
	// 只能是等长覆盖写之类的损坏：命中特征权重全 0 会让 Vectorize 除以
	// 零范数产出 NaN。必须在加载期拦下（契约：损坏 → 加载失败 → 静默跳过）。
	var idfHasPositive bool
	for _, v := range idf {
		if v > 0 {
			idfHasPositive = true
			break
		}
	}
	if !idfHasPositive {
		return nil, fmt.Errorf("ml: %s idf 全 0：平滑 idf 不可能全零，资产疑似同长度损坏", name)
	}

	return &Model{
		name:      name,
		classes:   meta.Classes,
		vocab:     vocab,
		idf:       idf,
		coef:      coef,
		intercept: meta.Intercept,
		nFeatures: meta.NFeatures,
		nClasses:  meta.NClasses,
	}, nil
}

// loadVocab 读词表：行号即特征 id（0 起），utf-8。容忍 \r\n 与结尾空行。
func loadVocab(path string, nFeatures int) (map[string]int32, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // 结尾换行
	}
	if len(lines) != nFeatures {
		return nil, fmt.Errorf("ml: %s 词表行数 %d != n_features %d", path, len(lines), nFeatures)
	}
	vocab := make(map[string]int32, len(lines))
	for i, tok := range lines {
		tok = strings.TrimSuffix(tok, "\r")
		if _, dup := vocab[tok]; dup {
			return nil, fmt.Errorf("ml: %s 第 %d 行词重复: %q", path, i, tok)
		}
		vocab[tok] = int32(i)
	}
	return vocab, nil
}

// readF32 读小端 float32 数组并校验：长度恰为 want，且每个值有限。
// NaN/±Inf 位型（0x7F80_0000 掩码内）字节数完全正常，截断型校验拦不住
// 等长损坏（比特翻转/等长覆盖写）；不拦的话 NaN 会静默通过加载、经
// 推理透传进 Prediction，最终让整份扫描输出 JSON 序列化失败。
func readF32(path string, want int) ([]float32, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != want*4 {
		return nil, fmt.Errorf("%s 字节数 %d != 期望 %d×4（float32 LE）", path, len(raw), want)
	}
	out := make([]float32, want)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
		if f := float64(out[i]); math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("%s 第 %d 个值非有限（%v）：资产疑似同长度损坏", path, i, f)
		}
	}
	return out, nil
}
