package model

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
)

// 本文件是 4.0 → 5.0 数据接口的**参考读端**（Go 实现，P9）。
//
// 定位：演示「消费方如何读取 graph JSONL」——打开 → ReadJSONL → Validate → 取字段；
// 并提供契约自检（恒不变式校验）。它**不在任何执行链上**，也不被引擎/API/CI 引用，
// 是纯只读工具（`sitelens graph-read <file>`）。
//
// 语言无关说明：graph JSONL 是普通 JSON，任何语言都能读（Python 示例见
// docs/schema-graph-v1.md §7，仅文档示例）。本实现是 4.0 分支自带的参考读端，
// 保持 4.0 全仓 Go。

// InspectResult 一次图检视的结果（可 JSON 序列化，供 CLI 输出）。
type InspectResult struct {
	Schema      string         `json:"schema"`
	ScanID      string         `json:"scan_id,omitempty"`
	GeneratedAt string         `json:"generated_at,omitempty"`
	Exists      bool           `json:"exists"`
	Counts      map[string]int `json:"counts"`
	Entities    int            `json:"entities"`
	// ObservationDist 观测态分布（5.0 造负样本时只认 negative，故单列）。
	ObservationDist map[string]int `json:"observation_dist,omitempty"`
	// ChainEdgeKinds 攻击链边类型分布。
	ChainEdgeKinds map[string]int `json:"chain_edge_kinds,omitempty"`
	// CWEs 图中出现的 CWE 编号（升序去重）。
	CWEs []string `json:"cwes,omitempty"`
	// Problems 契约违规明细（空 = 通过）。对应 docs/schema-graph-v1.md §8 恒不变式。
	Problems []string `json:"problems,omitempty"`
}

// OK 报告是否无契约违规。
func (r *InspectResult) OK() bool { return r != nil && len(r.Problems) == 0 }

// InspectGraph 读取并检视一个 graph JSONL 文件。
// 文件不存在返回 (Exists:false, nil)（不是错误——调用方自行决定提示）。
func InspectGraph(path string) (*InspectResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &InspectResult{Exists: false}, nil
		}
		return nil, err
	}
	defer f.Close()
	return Inspect(f)
}

// Inspect 从 reader 读取图并产出检视结果（含契约校验）。
// schema 不兼容 / 首行非 header / 非法行 → 返回错误（读端不得静默误读）。
func Inspect(r io.Reader) (*InspectResult, error) {
	g, err := ReadJSONL(r)
	if err != nil {
		return nil, err
	}
	res := &InspectResult{
		Schema: g.Schema, ScanID: g.ScanID, GeneratedAt: g.GeneratedAt,
		Exists: true, Counts: g.Counts(),
	}
	for _, n := range res.Counts {
		res.Entities += n
	}

	// 观测态分布（四态语义，5.0 负样本纪律依赖它）。
	od := map[string]int{}
	for _, v := range g.VulnNodes {
		od[string(v.Observation)]++
	}
	if len(od) > 0 {
		res.ObservationDist = od
	}
	// 攻击链边类型分布。
	ck := map[string]int{}
	for _, e := range g.ChainEdges {
		ck[e.Kind]++
	}
	if len(ck) > 0 {
		res.ChainEdgeKinds = ck
	}
	// CWE 集合。
	seen := map[string]bool{}
	for _, rel := range g.CWERels {
		if rel.CWEID != "" && !seen[rel.CWEID] {
			seen[rel.CWEID] = true
			res.CWEs = append(res.CWEs, rel.CWEID)
		}
	}
	sort.Strings(res.CWEs)

	// 契约自检：复用 Validate（恒不变式的**唯一**权威实现，避免两处规则漂移）。
	res.Problems = validateProblems(g)
	return res, nil
}

// validateProblems 把 Validate 的错误摊平为逐条问题（便于读端逐项展示）。
func validateProblems(g *ScanGraph) []string {
	err := g.Validate()
	if err == nil {
		return nil
	}
	// errors.Join 的返回值支持 Unwrap() []error；摊平后可逐条展示。
	var multi interface{ Unwrap() []error }
	if errors.As(err, &multi) {
		var out []string
		for _, e := range multi.Unwrap() {
			out = append(out, e.Error())
		}
		return out
	}
	return []string{err.Error()}
}

// InspectJSON 检视结果序列化（CLI 输出用）。
func (r *InspectResult) InspectJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
