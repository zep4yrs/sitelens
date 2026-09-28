// sev_wordpiece.go sev-prior（DistilBERT）的纯 Go WordPiece 分词器。
// 与 HuggingFace BertTokenizer(distilbert-base-uncased) 对齐：lowercase →
// 标点切分 → 贪心最长匹配（"##" 续片段）→ [CLS] 文本 [SEP] → [PAD] 补齐。
// 不带构建标签：任何构建下都可编译可测试（真实推理在 sev_onnx.go，onnx 标签）。
package ml

import (
	"strings"
	"unicode"
)

// distilbert-base-uncased 的特殊 token id（BERT 词表标准位）。
const (
	wpPadID = 0
	wpUnkID = 100
	wpClsID = 101
	wpSepID = 102
)

// SevTokenizerDistilBERT DistilBERT 分词器（词表 + 序列长度）。
type SevTokenizerDistilBERT struct {
	vocab  map[string]int32
	maxLen int // 192（与导出脚本 SEQ 一致）
}

// NewSevTokenizer 从 vocab.txt（每行一个 token，行号=id）构造分词器。
func NewSevTokenizer(vocabLines []string, maxLen int) *SevTokenizerDistilBERT {
	v := make(map[string]int32, len(vocabLines))
	for i, line := range vocabLines {
		v[strings.TrimSuffix(line, "\r")] = int32(i)
	}
	return &SevTokenizerDistilBERT{vocab: v, maxLen: maxLen}
}

// Encode 文本 → (input_ids, attention_mask)，长度恒为 maxLen。
// 截断保留 [CLS] + 前 maxLen-2 个内容 token + [SEP]。
func (t *SevTokenizerDistilBERT) Encode(text string) (ids []int64, mask []int64) {
	ids = make([]int64, 0, t.maxLen)
	ids = append(ids, wpClsID)
	content := 0
	limit := t.maxLen - 2
	for _, word := range basicWords(text) {
		if content >= limit {
			break
		}
		for _, piece := range t.wordPiece(word) {
			if content >= limit {
				break
			}
			ids = append(ids, piece)
			content++
		}
	}
	ids = append(ids, wpSepID)
	for len(ids) < t.maxLen {
		ids = append(ids, wpPadID)
	}
	mask = make([]int64, t.maxLen)
	for i := range mask {
		if ids[i] != wpPadID {
			mask[i] = 1
		}
	}
	return ids, mask
}

// wordPiece 单词 → 贪心最长匹配的 token id 序列（整词失败返回 [UNK]）。
func (t *SevTokenizerDistilBERT) wordPiece(word string) []int64 {
	if len([]rune(word)) > 100 {
		return []int64{wpUnkID}
	}
	var out []int64
	start := 0
	runes := []rune(word)
	for start < len(runes) {
		end := len(runes)
		var cur string
		for end > start {
			cand := string(runes[start:end])
			if start > 0 {
				cand = "##" + cand
			}
			if _, ok := t.vocab[cand]; ok {
				cur = cand
				break
			}
			end--
		}
		if cur == "" {
			return []int64{wpUnkID}
		}
		out = append(out, int64(t.vocab[cur]))
		start = end
	}
	return out
}

// basicWords HF BasicTokenizer 的近似：lowercase → 连续字母数字 run 为一个
// 词、标点独立成词、CJK 字符逐字成词（CVE 英文描述为主，CJK 为兜底）。
func basicWords(text string) []string {
	var words []string
	var run []rune
	flush := func() {
		if len(run) > 0 {
			words = append(words, string(run))
			run = run[:0]
		}
	}
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.IsSpace(r):
			flush()
		case isCJK(r):
			flush()
			words = append(words, string(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			run = append(run, r)
		default: // 标点/符号独立成词（HF BasicTokenizer 同款切分；词表内
			// 的 -/_/' 等有专属 token，丢弃会让整条 token 流错位）
			flush()
			words = append(words, string(r))
		}
	}
	flush()
	return words
}

func isCJK(r rune) bool {
	for _, rng := range [][2]rune{{0x4E00, 0x9FFF}, {0x3400, 0x4DBF}, {0x3000, 0x303F}} {
		if r >= rng[0] && r <= rng[1] {
			return true
		}
	}
	return false
}
