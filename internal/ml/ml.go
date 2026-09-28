// Package ml 实现站点引擎内嵌的 5.0 ML 线性模型推理（纯 Go，零第三方依赖）。
//
// 模型资产由 sitelens-ml5/ml/export_go_assets.py 导出到 data/go/ml_assets/：
//
//	<name>.vocab.txt  词表，行号=特征 id（utf-8，第 i 行对应 id=i）
//	<name>.idf.f32    idf 权重，n_features 个 float32（小端）
//	<name>.coef.f32   OvR 系数，n_classes×n_features float32（小端，行=类，行主序）
//	<name>.meta.json  类别表 / intercept / 维度
//
// 推理流程与 sklearn TfidfVectorizer(sublinear_tf, lowercase, l2,
// ngram_range=(1,2)) + 线性分类器 decision_function 对齐：
//
//	lowercase → \b\w\w+\b 切词（词字符连续 run 且长度>=2）
//	→ 一元 + 相邻二元组（空格连接，词表含 bigram，见 Vectorize）
//	→ 词频计数 → 子线性 tf (1+ln tf) × idf → L2 归一
//	→ score[c] = x·coef[c] + intercept[c]，按分数排序取 Top-K / argmax。
package ml

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// expectedTokenPattern 与导出侧 sklearn token_pattern 一致（见 meta.json）。
const expectedTokenPattern = `(?u)\b\w\w+\b`

// Tokenize 做 sklearn 兼容切词：先 lowercase（CPython str.lower() 全小写
// 映射，见 pyLower），再按 Unicode 词字符（字母/数字/数字符号/下划线，
// 对应 Python re 的 \w）切连续 run，仅保留长度 >= 2 的 run（对齐
// token_pattern r"(?u)\b\w\w+\b"，贪量词 \w\w+ 匹配的正是完整 run，
// \b 只出现在 run 边界）。
func Tokenize(s string) []string {
	var toks []string
	var run []rune
	flush := func() {
		if len(run) >= 2 {
			toks = append(toks, string(run))
		}
		run = run[:0]
	}
	for _, r := range pyLower(s) {
		if isWordRune(r) {
			run = append(run, r)
		} else {
			flush()
		}
	}
	flush()
	return toks
}

// isWordRune 对齐 Python re（Unicode 模式）的 \w：
// 字母（L*）、数字（Nd）与数字符号（Nl/No，即 str.isalnum() 口径）加下划线。
func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r)
}

// pyLower 对齐 CPython str.lower() 的小写归一（sklearn lowercase=True 用的
// 正是它）。Go strings.ToLower 只做逐 rune 简单映射，缺 Unicode
// SpecialCasing 的两条无条件全映射特例，词元字符串会与 Python 分歧：
//   - 'İ'(U+0130) → "i" + U+0307（组合点上点）。U+0307 不是 \w，会把词
//     断开：Python 'İstanbul' → 词元 ["stanbul"]，简单映射则产出多余的
//     首词元 "istanbul"；
//   - 希腊大写 Σ(U+03A3) 的 Final_Sigma 规则：前邻是 cased 字母且后邻
//     不是（含文本末尾）时 → ς(U+03C2)，否则 → σ(U+03C3)。
//
// 词元不同 → 词表命中不同 → 与 Python 侧推理偏差，故必须对齐。
func pyLower(s string) string {
	// 快路径：不含两个特例字符时与 strings.ToLower 完全等价
	if !strings.ContainsAny(s, "İΣ") {
		return strings.ToLower(s)
	}
	rs := []rune(s)
	var b strings.Builder
	b.Grow(len(s) + len(rs)) // İ 展开成 2 rune，预留增量
	for i, r := range rs {
		switch r {
		case 0x0130:
			b.WriteString("i\u0307")
		case 0x03A3:
			prev := i > 0 && isCasedRune(rs[i-1])
			next := i+1 < len(rs) && isCasedRune(rs[i+1])
			if prev && !next {
				b.WriteRune(0x03C2)
			} else {
				b.WriteRune(0x03C3)
			}
		default:
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}

// isCasedRune Final_Sigma 判定用的 cased 字符近似（CPython 的
// PY_UNICODE_ISCASED = lower | title | upper）。
func isCasedRune(r rune) bool {
	return unicode.IsLower(r) || unicode.IsTitle(r) || unicode.IsUpper(r)
}

// Vectorize 把文本转成与 sklearn TfidfVectorizer(ngram_range=(1,2)) 一致的
// L2 归一稀疏向量。特征 = 一元词 + 相邻二元组（"tok1 tok2"，与 sklearn
// _word_ngrams 的空格连接一致；导出词表 120k 特征中约 10 万个为 bigram）。
// 返回按特征 id 升序排列的 ids 与对应 tf-idf 值 vals；文本无词表命中时
// 返回空切片（sklearn 中为零向量，得分仅剩 intercept）。
//
//	values[i] = (1 + ln(count_i)) * idf[id_i]，随后整行除以 L2 范数。
func (m *Model) Vectorize(text string) (ids []int32, vals []float64) {
	counts := make(map[int32]int, 32)
	featCount := make(map[string]int, 32)
	toks := Tokenize(text)
	for _, tok := range toks {
		featCount[tok]++
	}
	for i := 1; i < len(toks); i++ {
		featCount[toks[i-1]+" "+toks[i]]++
	}
	for feat, n := range featCount {
		if id, ok := m.vocab[feat]; ok {
			counts[id] = n
		}
	}
	if len(counts) == 0 {
		return nil, nil
	}
	ids = make([]int32, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] }) // 累加顺序对齐 scipy csr 逐列序
	vals = make([]float64, len(ids))
	var norm float64
	for i, id := range ids {
		v := (1.0 + math.Log(float64(counts[id]))) * float64(m.idf[id])
		vals[i] = v
		norm += v * v
	}
	norm = math.Sqrt(norm)
	if norm == 0 {
		// 命中特征的 idf 权重全 0：按零向量语义返回（sklearn 中即零向量），
		// 不做 0/0 除法——那会产出 NaN 并一路透传进预测分数。
		return nil, nil
	}
	for i := range vals {
		vals[i] /= norm
	}
	return ids, vals
}

// DecisionFunction 计算 OvR 线性打分 score[c] = x·coef[c] + intercept[c]，
// 返回长度 n_classes 的分数切片（分数与 sklearn decision_function 同序同义）。
func (m *Model) DecisionFunction(text string) []float64 {
	ids, vals := m.Vectorize(text)
	scores := make([]float64, m.nClasses)
	copy(scores, m.intercept)
	nF := m.nFeatures
	for k, id := range ids {
		x := vals[k]
		col := int(id)
		for c := 0; c < m.nClasses; c++ {
			scores[c] += x * float64(m.coef[c*nF+col])
		}
	}
	return scores
}

// Pred 是一次排序预测：类名 + 原始线性得分。
type Pred struct {
	Class string
	Score float64
}

// TopK 返回按得分降序的前 k 个类别（同分时按类别表下标升序，保证确定性）。
// k <= 0 返回空（本包导出 API，不能假设调用方传常量正数——负 k 曾直接
// make 负长度切片 panic 打死整个进程）。
func (m *Model) TopK(text string, k int) []Pred {
	if k <= 0 {
		return nil
	}
	scores := m.DecisionFunction(text)
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
		out[i] = Pred{Class: m.classes[idx[i]], Score: scores[idx[i]]}
	}
	return out
}

// ArgMax 返回得分最高的类别名与得分（空文本等情况下仍有 intercept 支撑）。
func (m *Model) ArgMax(text string) (string, float64) {
	top := m.TopK(text, 1)
	return top[0].Class, top[0].Score
}
