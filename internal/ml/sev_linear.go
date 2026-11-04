// sev_linear.go 线性严重度回归（5.2 阶段 1）：CVE 描述 → CVSS 0-10 分。
//
// 资产 sev-linear.* 由 ml/train_sev_linear.py 训练并导出，格式与
// cve-tech/cwe-type 同构（vocab.txt / idf.f32 / coef.f32 / meta.json），
// 但 n_classes=1：score = x·w + b，其中 x 为与 Go 侧 Vectorize 完全一致的
// sublinear tf-idf + L2 归一向量。
//
// 定位（决策依据见 docs/release-5.2.0/阶段1-线性severity与ONNX下线-5.2.0.md）：
// NVD/情报行查表（误差 0）为第一优先，查不到时用本模型兜底；同一 600 样本
// 实测 MAE 1.19 分（sev-prior ONNX 1.08、手写 CVSS 规则 1.43），资产约
// 0.7MB，替代 ONNX 整链（643MB + onnxruntime.dll）。
package ml

import (
	"fmt"
	"math"
)

// 严重度分数取值范围（CVSS 0-10）。
const (
	sevScoreMin = 0.0
	sevScoreMax = 10.0
)

// RegressionScore 用单输出线性回归模型给文本打分（CVSS 0-10，越界 clamp）。
//
// 仅接受 n_classes==1 的回归资产；输出非有限（NaN/Inf）视为推理失败，
// 由调用方回退下一优先级后端——绝不让 NaN 透传进 Prediction 导致整份
// 扫描 JSON 序列化失败（与 assets.go readF32 的损坏拦截同口径）。
func (m *Model) RegressionScore(text string) (float64, error) {
	if m == nil {
		return 0, fmt.Errorf("ml: 线性 severity 模型未加载")
	}
	// C2-10：与 Unload 互斥；读锁内完成"维度检查 + 推理"，避免卸载后
	// nClasses 变 0 与推理交错产生半状态。
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.nClasses != 1 {
		return 0, fmt.Errorf("ml: %s 不是单输出回归模型（n_classes=%d）", m.name, m.nClasses)
	}
	scores := m.decisionLocked(text)
	if len(scores) != 1 {
		return 0, fmt.Errorf("ml: %s 回归输出维度异常（%d）", m.name, len(scores))
	}
	v := scores[0]
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("ml: %s 回归输出非有限（%v）", m.name, v)
	}
	if v < sevScoreMin {
		return sevScoreMin, nil
	}
	if v > sevScoreMax {
		return sevScoreMax, nil
	}
	return v, nil
}
