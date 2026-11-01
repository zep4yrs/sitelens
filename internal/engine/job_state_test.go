// FE-12 状态机回归：迁移表完整性、合法/非法迁移、状态机历史与旧状态映射。
package engine

import (
	"errors"
	"strings"
	"testing"
)

// TestAllJobStatesComplete 枚举全集与迁移表覆盖：7 个状态、全部合法、
// 迁移表给出每个状态的后继（done 为空表项也算显式声明）。
func TestAllJobStatesComplete(t *testing.T) {
	want := []JobState{
		StateRunning, StatePaused, StateBlocked, StatePartial,
		StateFailed, StateDone, StateCancelled,
	}
	got := AllJobStates()
	if len(got) != len(want) {
		t.Fatalf("枚举数量 %d，期望 %d：%v", len(got), len(want), got)
	}
	for i, s := range want {
		if got[i] != s {
			t.Errorf("枚举[%d]=%q，期望 %q", i, got[i], s)
		}
		if !s.Valid() {
			t.Errorf("%q 应为合法状态", s)
		}
	}
	for _, s := range want {
		nexts, ok := jobTransitions[s]
		if !ok {
			t.Errorf("迁移表缺状态 %q 的表项", s)
			continue
		}
		for _, to := range nexts {
			if !to.Valid() {
				t.Errorf("%q 的后继含非法状态 %q", s, to)
			}
		}
	}
	if JobState("weird").Valid() || JobState("").Valid() {
		t.Error("未知/空状态不应合法")
	}
}

// TestTransitionTable 逐对校验迁移矩阵（独立期望表，防实现自证）。
func TestTransitionTable(t *testing.T) {
	expect := map[JobState][]JobState{
		StateRunning: {StatePaused, StateBlocked, StatePartial,
			StateFailed, StateDone, StateCancelled},
		StatePaused:    {StateRunning, StatePartial, StateFailed, StateCancelled},
		StateBlocked:   {StateRunning, StateFailed, StateCancelled},
		StatePartial:   {StateRunning, StateDone, StateFailed, StateCancelled},
		StateFailed:    {StateRunning},
		StateDone:      {},
		StateCancelled: {StateRunning},
	}
	states := AllJobStates()
	for _, from := range states {
		for _, to := range states {
			want := false
			for _, allowed := range expect[from] {
				if allowed == to {
					want = true
				}
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s→%s)=%v，期望 %v", from, to, got, want)
			}
		}
		// 同状态重入不是合法迁移
		if CanTransition(from, from) {
			t.Errorf("%s→%s 同状态不应允许", from, from)
		}
	}
	// 未知状态
	if CanTransition(JobState(""), StateRunning) || CanTransition(StateRunning, JobState("nope")) {
		t.Error("未知状态迁移应拒绝")
	}
}

// TestTransitionError 非法迁移返回带允许后继的结构化错误。
func TestTransitionError(t *testing.T) {
	got, err := Transition(StateDone, StateRunning)
	if err == nil {
		t.Fatal("done→running 应报错")
	}
	if got != StateDone {
		t.Errorf("非法迁移应保持原状态，实际 %q", got)
	}
	var te *TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("错误类型应为 *TransitionError，实际 %T", err)
	}
	if te.From != StateDone || te.To != StateRunning {
		t.Errorf("错误字段 from/to = %s/%s", te.From, te.To)
	}
	if len(te.Allowed) != 0 {
		t.Errorf("done 无合法后继，实际 %v", te.Allowed)
	}
	if !strings.Contains(err.Error(), "非法状态迁移") {
		t.Errorf("错误文案异常：%v", err)
	}
	// 合法迁移返回目标状态
	if got, err := Transition(StatePartial, StateRunning); err != nil || got != StateRunning {
		t.Errorf("partial→running 应合法：%v %v", got, err)
	}
}

// TestNextStates done 终态无后继；running 后继按字典序稳定。
func TestNextStates(t *testing.T) {
	if n := NextStates(StateDone); len(n) != 0 {
		t.Errorf("done 应无后继，实际 %v", n)
	}
	r := NextStates(StateRunning)
	if len(r) != 6 {
		t.Fatalf("running 应有 6 个后继，实际 %v", r)
	}
	for i := 1; i < len(r); i++ {
		if r[i-1] > r[i] {
			t.Errorf("NextStates 应有序：%v", r)
		}
	}
	if len(NextStates(JobState("?"))) != 0 {
		t.Error("未知状态无后继")
	}
}

// TestStateMachineRecordsAcceptedAndRejected 状态机成功/失败都落历史。
func TestStateMachineRecordsAcceptedAndRejected(t *testing.T) {
	m := NewStateMachine(StateRunning)
	if m.Current() != StateRunning {
		t.Fatalf("初始状态 = %s", m.Current())
	}
	path := []JobState{StatePaused, StateRunning, StateBlocked, StateRunning,
		StatePartial, StateRunning, StateDone}
	for _, to := range path {
		if err := m.Apply(to); err != nil {
			t.Fatalf("合法迁移 %s→%s 失败：%v", m.Current(), to, err)
		}
	}
	if m.Current() != StateDone {
		t.Fatalf("末态 = %s，期望 done", m.Current())
	}
	hist := m.History()
	if len(hist) != len(path) {
		t.Fatalf("历史条数 %d，期望 %d", len(hist), len(path))
	}
	for i, h := range hist {
		if !h.Accepted || h.Error != "" {
			t.Errorf("历史[%d] 应为成功迁移：%+v", i, h)
		}
		if h.At.IsZero() {
			t.Errorf("历史[%d] 缺时间戳", i)
		}
	}
	// 非法迁移：拒绝并记录
	if err := m.Apply(StateRunning); err == nil {
		t.Fatal("done→running 应被拒绝")
	}
	hist = m.History()
	last := hist[len(hist)-1]
	if last.Accepted || last.From != StateDone || last.To != StateRunning {
		t.Fatalf("非法迁移未正确记录：%+v", last)
	}
	if !strings.Contains(last.Error, "非法状态迁移") {
		t.Errorf("拒绝原因异常：%q", last.Error)
	}
	if m.Current() != StateDone {
		t.Errorf("拒绝后状态不应变化：%s", m.Current())
	}
	// 历史是副本：外部修改不污染内部
	hist[0].Accepted = false
	if !m.History()[0].Accepted {
		t.Error("History 应返回副本")
	}
}

// TestNewStateMachineInvalidInitial 非法初始状态记录并允许恢复到 running。
func TestNewStateMachineInvalidInitial(t *testing.T) {
	m := NewStateMachine(JobState("boom"))
	if m.Current() != "" {
		t.Fatalf("非法初始状态 current 应为空，实际 %q", m.Current())
	}
	h := m.History()
	if len(h) != 1 || h[0].Accepted || !strings.Contains(h[0].Error, "非法初始状态") {
		t.Fatalf("初始化失败记录异常：%+v", h)
	}
	// 未初始化只允许进入 running
	if err := m.Apply(StateDone); err == nil {
		t.Fatal("空状态→done 应被拒绝")
	}
	if err := m.Apply(StateRunning); err != nil {
		t.Fatalf("空状态→running 应允许：%v", err)
	}
	if m.Current() != StateRunning {
		t.Errorf("恢复后状态 = %s", m.Current())
	}
}

// TestParseJobStateAndLegacy 字符串解析与旧 store.Job.Status 映射。
func TestParseJobStateAndLegacy(t *testing.T) {
	if s, ok := ParseJobState("  RUNNING "); !ok || s != StateRunning {
		t.Errorf("ParseJobState = %v/%v", s, ok)
	}
	if _, ok := ParseJobState("weird"); ok {
		t.Error("未知值应解析失败")
	}
	legacy := map[string]JobState{
		"pending": StateRunning, "running": StateRunning, "cancelling": StateRunning,
		"paused": StatePaused, "blocked": StateBlocked, "partial": StatePartial,
		"cancelled": StateCancelled, "done": StateDone, "error": StateFailed,
		"failed": StateFailed,
	}
	for raw, want := range legacy {
		if got, ok := JobStateFromLegacy(raw); !ok || got != want {
			t.Errorf("legacy %q → %v/%v，期望 %v", raw, got, ok, want)
		}
	}
	if _, ok := JobStateFromLegacy(""); ok {
		t.Error("空 legacy 状态应失败")
	}
	if _, ok := JobStateFromLegacy("weird"); ok {
		t.Error("未知 legacy 状态应失败")
	}
	if got := StateFailed.LegacyJobStatus(); got != "error" {
		t.Errorf("failed→legacy = %q，期望 error", got)
	}
	if got := StatePartial.LegacyJobStatus(); got != "partial" {
		t.Errorf("partial→legacy = %q", got)
	}
	if got := StateDone.LegacyJobStatus(); got != "done" {
		t.Errorf("done→legacy = %q", got)
	}
}

// TestTerminal 终态判定。
func TestTerminal(t *testing.T) {
	terminal := map[JobState]bool{
		StateDone: true, StateFailed: true, StateCancelled: true,
		StateRunning: false, StatePaused: false, StateBlocked: false, StatePartial: false,
	}
	for s, want := range terminal {
		if got := s.Terminal(); got != want {
			t.Errorf("%s.Terminal()=%v，期望 %v", s, got, want)
		}
	}
}

// TestJobStateString 空状态日志可读。
func TestJobStateString(t *testing.T) {
	if got := JobState("").String(); got != "<unknown>" {
		t.Errorf("空状态 String = %q", got)
	}
	if got := StateRunning.String(); got != "running" {
		t.Errorf("running String = %q", got)
	}
}
