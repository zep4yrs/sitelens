// sev_onnx.go sev-prior v3.1 的 Go 侧 ONNX 推理（构建标签 onnx）。
// 依赖 github.com/yalue/onnxruntime_go + onnxruntime 共享库（Windows=
// onnxruntime.dll）；无标签构建走 sev_onnx_stub.go（Score 恒错误，引擎
// 自动回退 NVD 先验，见 §10.8）。
// 推理契约（ml5/ml/export_sev_onnx.py）：input_ids/attention_mask int64
// [1,192] → logits 标量（0-1 尺度）×10 = CVSS 分。
// 集成：v3.1 部署形态 = 双种子 ONNX 各跑一次取平均（忠实还原训练侧的
// 预测平均集成），单模型清单同样可用。
//
//go:build onnx

package ml

import (
	"fmt"
	"os"
	"strings"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// SevScorer sev-prior ONNX 打分器（进程内单例语义，构造一次复用）。
type SevScorer struct {
	tok  *SevTokenizerDistilBERT
	sess []*ort.DynamicSession[int64, float32]
	seq  int
}

var (
	ortOnce   sync.Once
	ortInitOK bool
	ortErr    error
)

// NewSevScorer 加载 onnx 模型（一个或多个，多者预测取平均）并初始化
// 运行时。dllPath 为 onnxruntime 共享库路径；初始化进程内只做一次
// （失败后不再重试——损坏不会自愈）。
func NewSevScorer(vocabPath, dllPath string, onnxPaths []string) (*SevScorer, error) {
	if len(onnxPaths) == 0 {
		return nil, fmt.Errorf("ml: sev onnx 模型清单为空")
	}
	for _, p := range onnxPaths {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("ml: sev onnx 模型缺失: %w", err)
		}
	}
	vocabRaw, err := os.ReadFile(vocabPath)
	if err != nil {
		return nil, fmt.Errorf("ml: sev 词表缺失: %w", err)
	}
	const seq = 192
	tok := NewSevTokenizer(strings.Split(string(vocabRaw), "\n"), seq)

	ortOnce.Do(func() {
		if _, err := os.Stat(dllPath); err != nil {
			ortErr = fmt.Errorf("ml: onnxruntime 共享库缺失: %w", err)
			return
		}
		ort.SetSharedLibraryPath(dllPath)
		if err := ort.InitializeEnvironment(); err != nil {
			ortErr = fmt.Errorf("ml: onnxruntime 初始化失败: %w", err)
			return
		}
		ortInitOK = true
	})
	if !ortInitOK {
		return nil, ortErr
	}

	var sess []*ort.DynamicSession[int64, float32]
	for _, p := range onnxPaths {
		s, err := ort.NewDynamicSession[int64, float32](p,
			[]string{"input_ids", "attention_mask"}, []string{"logits"})
		if err != nil {
			return nil, fmt.Errorf("ml: sev session 创建失败（%s）: %w", p, err)
		}
		sess = append(sess, s)
	}
	return &SevScorer{tok: tok, sess: sess, seq: seq}, nil
}

// Score 描述文本 → CVSS 分（0-10，clamp）。logits 为 0-1 尺度（训练
// 目标 = 分数/10），×10 还原；多模型时取各 logits 的算术平均。
func (s *SevScorer) Score(text string) (float64, error) {
	ids, mask := s.tok.Encode(text)
	inIDs, err := ort.NewTensor(ort.NewShape(1, int64(s.seq)), ids)
	if err != nil {
		return 0, err
	}
	defer inIDs.Destroy()
	inMask, err := ort.NewTensor(ort.NewShape(1, int64(s.seq)), mask)
	if err != nil {
		return 0, err
	}
	defer inMask.Destroy()
	var sum float64
	for _, se := range s.sess {
		outT, err := ort.NewTensor(ort.NewShape(1, 1), make([]float32, 1))
		if err != nil {
			return 0, err
		}
		if err := se.Run([]*ort.Tensor[int64]{inIDs, inMask},
			[]*ort.Tensor[float32]{outT}); err != nil {
			outT.Destroy()
			return 0, err
		}
		sum += float64(outT.GetData()[0])
		outT.Destroy()
	}
	score := sum / float64(len(s.sess)) * 10
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}
	return score, nil
}
