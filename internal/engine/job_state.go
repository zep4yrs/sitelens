// FE-12 扫描作业状态机（纯逻辑，无 IO）。
//
// 目的：把「扫描任务从创建到结束」的状态与合法迁移集中成一张表，供
// server 侧 job 状态更新、前端状态展示与续扫（partial→running）共用。
// 既有 store.Job.Status 是自由字符串（pending/running/cancelling/cancelled/
// done/error），本文件只新增语义、不改既有存储与调用方——接线由 server
// 落库函数（internal/server/partial.go）负责。
//
// 状态枚举（FE-12）：
//
//	running   执行中
//	paused    暂停（用户暂停/等待资源）
//	blocked   阻塞（WAF/限流/授权等待等外部原因，可恢复）
//	partial   部分完成（取消/中断后已保存部分结果，可续扫）
//	failed    失败（错误终止，可重试）
//	done      完成（终态）
//	cancelled 已取消（连续扫入口：可重新置 running）
//
// 设计口径：
//   - 迁移表是本文件唯一事实来源，非法迁移一律拒绝并记录（StateMachine）；
//   - 同状态重入不算合法迁移（显式拒绝，避免前端重复提示）；
//   - done 是唯一不可离开的终态；failed/cancelled 可通过重试/续扫回到 running。
package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// JobState 扫描作业状态。
type JobState string

// 状态枚举（与前端状态机文案一致）。
const (
	StateRunning   JobState = "running"
	StatePaused    JobState = "paused"
	StateBlocked   JobState = "blocked"
	StatePartial   JobState = "partial"
	StateFailed    JobState = "failed"
	StateDone      JobState = "done"
	StateCancelled JobState = "cancelled"
)

// allJobStates 展示/校验顺序（枚举全集）。
var allJobStates = []JobState{
	StateRunning, StatePaused, StateBlocked, StatePartial,
	StateFailed, StateDone, StateCancelled,
}

// jobTransitions 合法迁移表：from → 允许的 to 集合。
//
// 说明：
//   - running 可进入全部非终态分支：暂停、阻塞、部分完成、失败、完成、取消；
//   - paused 可恢复 running，也可直接取消/失败/保存部分结果；
//   - blocked 解除后回 running，或取消/失败；
//   - partial 可续扫（running）、补完后 done，或再次取消/失败；
//   - failed 仅可重试（running）；
//   - cancelled 仅可续扫（running）；
//   - done 无后继（终态）。
var jobTransitions = map[JobState][]JobState{
	StateRunning:   {StatePaused, StateBlocked, StatePartial, StateFailed, StateDone, StateCancelled},
	StatePaused:    {StateRunning, StatePartial, StateFailed, StateCancelled},
	StateBlocked:   {StateRunning, StateFailed, StateCancelled},
	StatePartial:   {StateRunning, StateDone, StateFailed, StateCancelled},
	StateFailed:    {StateRunning},
	StateDone:      {},
	StateCancelled: {StateRunning},
}

// AllJobStates 返回枚举全集（副本，按展示顺序）。
func AllJobStates() []JobState {
	out := make([]JobState, len(allJobStates))
	copy(out, allJobStates)
	return out
}

// Valid 是否为合法枚举值（空串/未知值返回 false）。
func (s JobState) Valid() bool {
	switch s {
	case StateRunning, StatePaused, StateBlocked, StatePartial,
		StateFailed, StateDone, StateCancelled:
		return true
	}
	return false
}

// Terminal 是否为「本次运行已结束」的终态（done/failed/cancelled）。
// 注意：failed/cancelled 允许重试/续扫，但当前这次运行已经收尾。
func (s JobState) Terminal() bool {
	return s == StateDone || s == StateFailed || s == StateCancelled
}

// String 实现 fmt.Stringer（空值显示为 "<unknown>"，避免日志里出现空洞）。
func (s JobState) String() string {
	if s == "" {
		return "<unknown>"
	}
	return string(s)
}

// ParseJobState 宽松解析（大小写/空白不敏感），失败返回 ("", false)。
func ParseJobState(raw string) (JobState, bool) {
	s := JobState(strings.ToLower(strings.TrimSpace(raw)))
	if !s.Valid() {
		return "", false
	}
	return s, true
}

// JobStateFromLegacy 把既有 store.Job.Status（pending/running/cancelling/
// cancelled/done/error）映射到新枚举。未知非空状态返回 ("", false)。
func JobStateFromLegacy(status string) (JobState, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending", "running", "cancelling":
		// pending=尚未开始、cancelling=取消请求已受理但执行方仍在跑：
		// 执行视角都还是「进行中」，避免把在跑任务误判成终态。
		return StateRunning, true
	case "paused":
		return StatePaused, true
	case "blocked":
		return StateBlocked, true
	case "partial":
		return StatePartial, true
	case "cancelled":
		return StateCancelled, true
	case "done":
		return StateDone, true
	case "error", "failed":
		return StateFailed, true
	}
	return "", false
}

// LegacyJobStatus 新枚举 → store.Job.Status 兼容写法（failed 落 "error"，
// 与既有前端/历史口径一致；其余同名）。
func (s JobState) LegacyJobStatus() string {
	if s == StateFailed {
		return "error"
	}
	return string(s)
}

// NextStates 返回 from 的合法后继（排序副本；未知状态返回空）。
func NextStates(from JobState) []JobState {
	next := jobTransitions[from]
	out := make([]JobState, len(next))
	copy(out, next)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CanTransition 从 from 迁移到 to 是否合法。
func CanTransition(from, to JobState) bool {
	if !from.Valid() || !to.Valid() {
		return false
	}
	for _, candidate := range jobTransitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// TransitionError 非法迁移错误（携带允许的后继，便于日志/前端提示）。
type TransitionError struct {
	From    JobState
	To      JobState
	Allowed []JobState
}

func (e *TransitionError) Error() string {
	allowed := make([]string, 0, len(e.Allowed))
	for _, s := range e.Allowed {
		allowed = append(allowed, string(s))
	}
	hint := strings.Join(allowed, ",")
	if hint == "" {
		hint = "无（终态）"
	}
	return fmt.Sprintf("非法状态迁移：%s → %s（允许：%s）", e.From, e.To, hint)
}

// ValidateTransition 校验迁移；非法返回 *TransitionError。
func ValidateTransition(from, to JobState) error {
	if CanTransition(from, to) {
		return nil
	}
	return &TransitionError{From: from, To: to, Allowed: NextStates(from)}
}

// Transition 纯函数迁移：合法时返回 to，非法返回 from 与错误。
func Transition(from, to JobState) (JobState, error) {
	if err := ValidateTransition(from, to); err != nil {
		return from, err
	}
	return to, nil
}

// StateChange 一次迁移尝试记录（含被拒绝的尝试——"非法迁移拒绝并记录"）。
type StateChange struct {
	From     JobState  `json:"from"`
	To       JobState  `json:"to"`
	Accepted bool      `json:"accepted"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

// StateMachine 带历史的作业状态机（非并发安全：单个 job 内串行使用；
// 跨 goroutine 由调用方加锁，server 侧走 store.JobManager 的锁）。
type StateMachine struct {
	current JobState
	history []StateChange
}

// NewStateMachine 以 initial 初始化。initial 非法时 current 置空并在历史
// 里记录一条被拒绝的初始化；后续需先迁移到 running（空状态 → running 允许）。
func NewStateMachine(initial JobState) *StateMachine {
	m := &StateMachine{}
	if initial.Valid() {
		m.current = initial
		return m
	}
	m.history = append(m.history, StateChange{
		From: "", To: initial, Accepted: false,
		Error: fmt.Sprintf("非法初始状态：%q", string(initial)),
		At:    time.Now(),
	})
	return m
}

// Current 当前状态（可能为空 = 未初始化）。
func (m *StateMachine) Current() JobState { return m.current }

// History 历史副本（含被拒绝的迁移尝试）。
func (m *StateMachine) History() []StateChange {
	out := make([]StateChange, len(m.history))
	copy(out, m.history)
	return out
}

// CanApply to 是否可从当前状态迁移。
func (m *StateMachine) CanApply(to JobState) bool {
	if m.current == "" { // 未初始化：只允许进入 running
		return to == StateRunning
	}
	return CanTransition(m.current, to)
}

// Apply 尝试迁移并记录（成功/失败都记录）。失败时状态不变并返回错误。
func (m *StateMachine) Apply(to JobState) error {
	from := m.current
	change := StateChange{From: from, To: to, At: time.Now()}
	if err := ValidateTransition(from, to); err != nil {
		if from == "" && to == StateRunning {
			// 未初始化机器：允许首迁到 running（NewStateMachine 收到非法
			// 初始值后的恢复路径）。
			change.Accepted = true
			m.current = to
			m.history = append(m.history, change)
			return nil
		}
		change.Error = err.Error()
		m.history = append(m.history, change)
		return err
	}
	change.Accepted = true
	m.current = to
	m.history = append(m.history, change)
	return nil
}
