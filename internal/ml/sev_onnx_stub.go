// sev_onnx_stub.go 无 onnx 标签构建下的占位实现：sev-prior 推理不可用，
// 引擎按 §10.8 自动回退 NVD CVSS 先验（静态原因可解释，不静默装死）。
//
//go:build !onnx

package ml

import "errors"

// ErrNoONNX 构建未启用 onnx 标签（CGO/onnxruntime 不可用场景：npm 包、
// CI 默认构建）。桌面安装器构建带 -tags onnx 并内嵌共享库。
var ErrNoONNX = errors.New("ml: 本构建未启用 onnx（需 -tags onnx 与 onnxruntime 共享库）")

// SevScorer 占位类型：保持引擎接线代码在两种构建下形态一致。
type SevScorer struct{}

// NewSevScorer 恒返回 ErrNoONNX。
func NewSevScorer(_, _, _ string) (*SevScorer, error) { return nil, ErrNoONNX }

// Score 恒返回 ErrNoONNX。
func (*SevScorer) Score(string) (float64, error) { return 0, ErrNoONNX }
