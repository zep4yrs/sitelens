// prediction.go 定义 ML 预测的结果契约（Result.Predictions 元素形态），
// 与开发文档-5.0-ML预训练.md §10.3 预测契约对齐：
//
//	cve / tech_top5(product+prob) / cwe_type / sev_score
//
// prob 为 sklearn predict_proba 同口径概率（实测：两个导出模型的
// predict_proba 均为逐类 sigmoid 后行归一，已与 fixtures.json 数值对上）。
package ml

import (
	"math"
	"sort"
)

// Relevance 取值：tech_top5 条目与扫描检出技术的交集标记。
const (
	RelHit     = "hit"     // 归一全串（vendor/product）与检出技术匹配
	RelRelated = "related" // 仅产品段与检出技术匹配（同产品弱证据）
)

// TechPred 受影响产品 Top-5 中的一项。
// Relevance 由引擎在组装时填写（模型本身不输出）：检出技术命中标
// hit/related，无交集留空（omitempty）。
type TechPred struct {
	Product   string  `json:"product"`
	Prob      float64 `json:"prob"`
	Relevance string  `json:"relevance,omitempty"`
}

// Prediction 一条 CVE 的 ML 推理结果（先验参考，不参与扫描判定）。
// SevScore 量级为 CVSS 0-10；阶段 A（纯 Go 线性模型）以 NVD CVSS 先验
// 填充，sev-prior（阶段 B DistilBERT ONNX 回归头，文档 §10.0）接入后
// 替换为模型分数。无先验（NVD 缺该 CVE）时为 0，omitempty 不输出。
type Prediction struct {
	CVE      string     `json:"cve"`
	TechTop5 []TechPred `json:"tech_top5"`
	CWEType  string     `json:"cwe_type,omitempty"`
	SevScore float64    `json:"sev_score,omitempty"`
}

// sigmoid 逐类逻辑斯蒂：p = 1/(1+e^-s)。
func sigmoid(s float64) float64 {
	// 防 overflow：大负数直接取 0（e^-s 溢出），大正数取 1
	if s < -35 {
		return 0
	}
	if s > 35 {
		return 1
	}
	return 1.0 / (1.0 + math.Exp(-s))
}

// probaNormalized 与 sklearn 实测口径一致：逐类 sigmoid 后按行归一
// （cve-tech 的 OneVsRestClassifier.predict_proba 与 cwe-type 多类
// SGDClassifier(loss="log_loss").predict_proba 均为此形态，已用
// fixtures.json 数值验证）。分母非正或非有限时退回均匀分布——
// NaN 对任何比较都判 false，必须写成 !(sum > 0) 才能一并拦住：
// 上游分数若含 NaN，归一结果再透传进 Prediction 会让整份扫描输出
// JSON 序列化失败（json: unsupported value: NaN）。
func probaNormalized(scores []float64) []float64 {
	out := make([]float64, len(scores))
	var sum float64
	for i, s := range scores {
		out[i] = sigmoid(s)
		sum += out[i]
	}
	if !(sum > 0) {
		for i := range out {
			out[i] = 1.0 / float64(len(out))
		}
		return out
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

// ProbaTopK 同 TopK（按线性得分降序的前 k 类），但 Score 换成
// predict_proba 口径概率。排序依据仍是原始得分（概率单调于 sigmoid，
// 排序与 Python 侧 proba.argsort 一致）。
func (m *Model) ProbaTopK(text string, k int) []Pred {
	if k <= 0 { // 与 TopK 同口径：负/零 k 返回空而非 panic
		return nil
	}
	scores := m.DecisionFunction(text)
	probs := probaNormalized(scores)
	if k > len(scores) {
		k = len(scores)
	}
	idx := make([]int, len(scores))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		if scores[idx[a]] != scores[idx[b]] {
			return scores[idx[a]] > scores[idx[b]]
		}
		return idx[a] < idx[b]
	})
	out := make([]Pred, k)
	for i := 0; i < k; i++ {
		out[i] = Pred{Class: m.classes[idx[i]], Score: probs[idx[i]]}
	}
	return out
}

// Proba 返回指定类别的 predict_proba 口径概率（预测单个类别的置信度）。
func (m *Model) Proba(text string, class string) float64 {
	scores := m.DecisionFunction(text)
	probs := probaNormalized(scores)
	for i, c := range m.classes {
		if c == class {
			return probs[i]
		}
	}
	return 0
}
