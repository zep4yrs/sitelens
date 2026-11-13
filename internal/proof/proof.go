package proof

// 目标导向证明链（5.3 P1，设计稿 §4.1）：只读规划，不发任何请求。
//
// 目标（Goal）描述「想证明什么」；规划器读取已收集的事实图（model.ScanGraph）
// 与链视图，把到目标的最短路径翻译成证明链：
//
//	Goal → Hypothesis（假设）→ Probe（探针/证据来源）→ Proof（已证实步骤）
//
// 每个步骤标注 proven / gap：有证据的链节点算 proven，无证据算 gap。
// 规划器不触发扫描、不访问网络，纯函数（同一输入输出稳定）。

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// Level 目标级别。
const (
	LevelReach = "reach" // 证明「可达」：存在一条到目标的路径
	LevelProve = "prove" // 证明「可利用」：路径上每一步都有证据
)

// Goal 一个验证目标（需授权目标，API 层负责 allow_hosts 校验）。
type Goal struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Target    string    `json:"target"` // 主机名（规范化小写）
	Level     string    `json:"level"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"` // active
}

// ProofStep 证明链上的一个步骤。
type ProofStep struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // goal|recon|entry|exploit|impact|priv|gap
	Title       string   `json:"title"`
	Status      string   `json:"status"` // proven|gap|planned
	NodeID      string   `json:"node_id,omitempty"`
	CheckID     string   `json:"check_id,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Hypothesis  string   `json:"hypothesis,omitempty"`
}

// Chain 一条证明链。
type Chain struct {
	ID        string      `json:"id"`
	GoalID    string      `json:"goal_id"`
	Target    string      `json:"target"`
	Level     string      `json:"level"`
	Steps     []ProofStep `json:"steps"`
	Proven    int         `json:"proven"`
	Total     int         `json:"total"`
	Coverage  float64     `json:"coverage"`
	Complete  bool        `json:"complete"`
	CreatedAt time.Time   `json:"created_at"`
}

// NormalizeLevel 归一目标级别（未知值按 reach，fail-safe 不放大语义）。
func NormalizeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case LevelProve, "proof", "proven", "可利用", "证明":
		return LevelProve
	default:
		return LevelReach
	}
}

// Plan 对目标规划证明链（只读；g 为 nil/空时返回一条「证据缺口」链）。
func Plan(goal Goal, g *model.ScanGraph, now time.Time) []Chain {
	if now.IsZero() {
		now = time.Now()
	}
	level := NormalizeLevel(goal.Level)
	if g == nil || len(g.ChainNodes) == 0 {
		return []Chain{{
			ID:        chainID(goal.ID, 0),
			GoalID:    goal.ID,
			Target:    goal.Target,
			Level:     level,
			CreatedAt: now,
			Steps: []ProofStep{
				goalStep(goal),
				{
					ID:         chainID(goal.ID, 0) + "-s1",
					Kind:       "gap",
					Title:      "缺少事实图/攻击链数据",
					Status:     "gap",
					Hypothesis: "先完成一次收集事实图的扫描（graph=true），再重新规划",
				},
			},
			Total: 2, Proven: 1, Coverage: 0.5, Complete: false,
		}}
	}
	view := g.ShortestPaths("", "", 16)
	if len(view.Paths) == 0 {
		// 有事实图但链视图不完整（例如只有入口节点、没有链边）：给出一条
		// 「证据缺口」链，明确下一步该补什么，而不是静默返回空。
		return []Chain{{
			ID:        chainID(goal.ID, 0),
			GoalID:    goal.ID,
			Target:    goal.Target,
			Level:     level,
			CreatedAt: now,
			Steps: []ProofStep{
				goalStep(goal),
				{
					ID:         chainID(goal.ID, 0) + "-s1",
					Kind:       "gap",
					Title:      "攻击链数据不足（无链边）",
					Status:     "gap",
					Hypothesis: "事实图有 " + strconv.Itoa(len(g.ChainNodes)) + " 个链节点但没有链边；需要开启漏洞验证/利用级验证以建立链关系",
				},
			},
			Total: 1, Proven: 0, Coverage: 0, Complete: false,
		}}
	}
	chains := make([]Chain, 0, len(view.Paths))
	for i, p := range view.Paths {
		steps := []ProofStep{goalStep(goal)}
		proven := 0
		for j, nodeID := range p.Nodes {
			n := findChainNode(g, nodeID)
			step := ProofStep{
				ID:     fmt.Sprintf("%s-s%d", chainID(goal.ID, i), j+1),
				NodeID: nodeID,
				Kind:   "recon",
				Status: "gap",
			}
			if n != nil {
				step.Kind = chainKind(n.Kind)
				step.Title = n.Label
				if step.Title == "" {
					step.Title = n.Kind + " " + n.RefID
				}
				step.EvidenceIDs = append([]string(nil), n.EvidenceIDs...)
				if len(n.EvidenceIDs) > 0 {
					step.Status = "proven"
					proven++
				} else {
					step.Hypothesis = "该链节点没有证据来源；需补充验证或人工复核"
				}
			} else {
				step.Title = nodeID
			}
			steps = append(steps, step)
		}
		// 覆盖度只统计链节点（goal 步是上下文，不参与 proven/total）。
		total := len(steps) - 1
		if total <= 0 {
			total = 1
		}
		coverage := float64(proven) / float64(total)
		chains = append(chains, Chain{
			ID:        chainID(goal.ID, i),
			GoalID:    goal.ID,
			Target:    goal.Target,
			Level:     level,
			Steps:     steps,
			Proven:    proven,
			Total:     total,
			Coverage:  round2(coverage),
			Complete:  proven == total && len(p.Nodes) > 0,
			CreatedAt: now,
		})
	}
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Complete != chains[j].Complete {
			return chains[i].Complete // 完整链排前面
		}
		return chains[i].Coverage > chains[j].Coverage
	})
	return chains
}

func goalStep(goal Goal) ProofStep {
	return ProofStep{
		ID:         "goal-" + goal.ID,
		Kind:       "goal",
		Title:      goal.Title,
		Status:     "planned",
		Hypothesis: "目标：" + goal.Title + "（" + NormalizeLevel(goal.Level) + "）",
	}
}

func chainID(goalID string, i int) string {
	return fmt.Sprintf("chain-%s-%d", goalID, i)
}

func chainKind(kind string) string {
	switch kind {
	case "recon", "entry", "exploit", "impact", "priv":
		return kind
	default:
		return "recon"
	}
}

func findChainNode(g *model.ScanGraph, id string) *model.ChainNode {
	for i := range g.ChainNodes {
		if g.ChainNodes[i].ID == id {
			return &g.ChainNodes[i]
		}
	}
	return nil
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
