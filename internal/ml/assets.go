package ml

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Model 是一个导出的线性模型（词表 + idf + 系数 + 元信息）。
// coef 为行主序：coef[c*nFeatures+i] 是第 c 类在第 i 特征上的权重。
//
// 并发（C2-10）：加载完成后推理只读；Unload 需要在途推理与释放互斥，
// 故用 mu 守护全部大块字段。Model 必须按指针使用（含 RWMutex，不可拷贝）。
type Model struct {
	name      string
	classes   []string
	vocab     map[string]int32
	idf       []float32
	coef      []float32
	intercept []float64
	nFeatures int
	nClasses  int
	mu        sync.RWMutex
}

// Name 返回模型名（cve-tech / cwe-type）。模型卸载后仍可读（仅用于日志/错误）。
func (m *Model) Name() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.name
}

// Classes 返回类别表（下标与 coef 行一致）；卸载后返回 nil。
func (m *Model) Classes() []string {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.classes
}

// Dims 返回 (nClasses, nFeatures)；卸载后为 (0, 0)。
func (m *Model) Dims() (int, int) {
	if m == nil {
		return 0, 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nClasses, m.nFeatures
}

// Loaded 报告模型是否仍持有权重（卸载后 false）。
func (m *Model) Loaded() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nClasses > 0 && m.coef != nil
}

// Unload 幂等释放模型的大块内存（classes/vocab/idf/coef/intercept）。
//
// 并发安全（C2-10）：Unload 持写锁，与所有推理方法的读锁互斥——返回后
// 不会再有在途推理读取这些内存。卸载后的模型是"空模型"：
// 推理返回空/零结果、回归返回明确错误，绝不 panic；需要重新使用请重新
// LoadModel / LoadAssets（本方法不负责重建）。
func (m *Model) Unload() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.classes, m.vocab, m.idf, m.coef, m.intercept = nil, nil, nil, nil, nil
	m.nFeatures, m.nClasses = 0, 0
	m.mu.Unlock()
}

// Close 与 Unload 等价（io.Closer 习惯用法，幂等）。
func (m *Model) Close() { m.Unload() }

// Assets 内嵌引擎所需的模型资产。
type Assets struct {
	Tech *Model // cve-tech：CVE 描述 → 受影响产品 Top-5（196 类）
	Cwe  *Model // cwe-type：CVE 描述 → CWE 弱点类型（25 类）
	// Sev 可选 sev-linear：CVE 描述 → CVSS 分数回归（0-10）。5.2 阶段 1 起
	// 为默认严重度后端（NVD 查表优先、查不到用它兜底）；资产缺失时为 nil
	// （未就绪，不报错），文件存在但损坏时 SevErr 记录原因，仅禁用该后端，
	// 不影响 cve-tech/cwe-type。
	Sev    *Model
	SevErr string

	// mu 守护 Tech/Cwe/Sev 指针：Unload 与 Predict 并发时不得读到半卸载状态。
	mu sync.RWMutex
}

// Unload 释放整套模型资产（幂等、并发安全；C2-10）。
//
// 会同时 Unload 各 *Model 的大块数据——即使调用方仍持有旧 *Model 引用，
// 也不会继续占着 94MB 系数；那些引用上的推理退化为空/零结果而非 panic。
// 卸载后需要重新使用时重新 LoadAssets 构造新的 Assets（engine 接线由上层做）。
func (a *Assets) Unload() {
	if a == nil {
		return
	}
	a.mu.Lock()
	tech, cwe, sev := a.Tech, a.Cwe, a.Sev
	a.Tech, a.Cwe, a.Sev = nil, nil, nil
	a.SevErr = ""
	a.mu.Unlock()
	// 先摘指针再释放模型数据：Predict 在 a.mu 读锁下必然看到 nil 或完整指针。
	tech.Unload()
	cwe.Unload()
	sev.Unload()
}

// Close 与 Unload 等价（满足 io.Closer 习惯用法，幂等）。
func (a *Assets) Close() { a.Unload() }

// Loaded 报告资产当前是否可用（未加载/已卸载为 false）。
func (a *Assets) Loaded() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Tech != nil && a.Cwe != nil
}

// LoadAssets 从 dir 加载 cve-tech 与 cwe-type 两套必备模型资产，
// 并尽力加载可选的 sev-linear 严重度回归模型。
func LoadAssets(dir string) (*Assets, error) {
	tech, err := LoadModel(dir, "cve-tech")
	if err != nil {
		return nil, fmt.Errorf("ml: 加载 cve-tech: %w", err)
	}
	cwe, err := LoadModel(dir, "cwe-type")
	if err != nil {
		return nil, fmt.Errorf("ml: 加载 cwe-type: %w", err)
	}
	sev, sevErr := loadOptionalModel(dir, "sev-linear")
	return &Assets{Tech: tech, Cwe: cwe, Sev: sev, SevErr: sevErr}, nil
}

// loadOptionalModel 加载可选模型（5.2 阶段 1：sev-linear）。
//
// 两种失败语义与 mlFor 的静默纪律一致：
//   - 文件不齐（任一缺失）→ (nil, "")：未就绪，不算损坏，后续可补；
//   - 文件齐全但加载失败/不是单输出回归 → (nil, reason)：损坏，仅禁用
//     该后端，不置死整个 ML 资产（cve-tech/cwe-type 仍可用）。
func loadOptionalModel(dir, name string) (*Model, string) {
	for _, ext := range []string{"meta.json", "vocab.txt", "idf.f32", "coef.f32"} {
		if _, err := os.Stat(filepath.Join(dir, name+"."+ext)); err != nil {
			return nil, ""
		}
	}
	m, err := LoadModel(dir, name)
	if err != nil {
		return nil, err.Error()
	}
	if nc, _ := m.Dims(); nc != 1 {
		return nil, fmt.Sprintf("ml: %s 是 %d 类分类模型，线性 severity 需要单输出回归（n_classes=1）",
			name, nc)
	}
	return m, ""
}

// Predict 一次完成双模型推理：返回产品 Top-5 与 CWE 弱点类型。
// 与 Assets.Unload 并发安全：未加载/已卸载时返回空结果（不 panic）。
func (a *Assets) Predict(descr string) ([]Pred, string) {
	if a == nil {
		return nil, ""
	}
	a.mu.RLock()
	tech, cwe := a.Tech, a.Cwe
	a.mu.RUnlock()
	if tech == nil || cwe == nil {
		return nil, ""
	}
	top5 := tech.TopK(descr, 5)
	cweType, _ := cwe.ArgMax(descr)
	return top5, cweType
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
//
// 内存（C2-10）：改用分块流式读，峰值只多一块 64KB 缓冲。旧实现
// os.ReadFile 会同时持有「原始字节 94MB + float32 切片 94MB」≈ 2× 文件
// 大小，cve-tech.coef.f32（94MB）加载峰值额外 ~94MB。
func readF32(path string, want int) ([]float32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() != int64(want)*4 {
		return nil, fmt.Errorf("%s 字节数 %d != 期望 %d×4（float32 LE）", path, st.Size(), want)
	}
	out := make([]float32, want)
	const bufFloats = 16384 // 64KB 块
	buf := make([]byte, bufFloats*4)
	for off := 0; off < want; {
		n := want - off
		if n > bufFloats {
			n = bufFloats
		}
		if _, err := io.ReadFull(f, buf[:n*4]); err != nil {
			return nil, fmt.Errorf("%s 读取失败（第 %d 个值起）: %w", path, off, err)
		}
		for i := 0; i < n; i++ {
			v := math.Float32frombits(binary.LittleEndian.Uint32(buf[i*4:]))
			if fv := float64(v); math.IsNaN(fv) || math.IsInf(fv, 0) {
				return nil, fmt.Errorf("%s 第 %d 个值非有限（%v）：资产疑似同长度损坏", path, off+i, fv)
			}
			out[off+i] = v
		}
		off += n
	}
	// 读完后再确认没有尾部多余字节（文件在 Stat 之后变长时给出明确错误，
	// 而不是静默忽略——截断/拼接型损坏宁可在加载期失败）。
	var tail [1]byte
	if n, _ := f.Read(tail[:]); n > 0 {
		return nil, fmt.Errorf("%s 在读取期间变长（尾部存在多余字节）", path)
	}
	return out, nil
}
