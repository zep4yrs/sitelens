package engine

import (
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// LiveStats 扫描进行中的实时统计（additive：服务端 job 状态 → 前端实时面板）。
//
// 数据来源：httpx.Client.Stats()（真实请求数/拦截数）+ 爬虫页计数；Rate 为
// 两次快照之间的瞬时请求速率（req/s），不是配置速率。所有字段只读、无副作用，
// 不参与判定，也不改变扫描行为。
type LiveStats struct {
	Phase     string  `json:"phase"`      // 机器可读阶段：prepare/home/jsmap/crawl/fingerprint/security/checks/nuclei/passive/dast/exploit/active/done
	PhaseName string  `json:"phase_name"` // 中文阶段名（前端直接展示）
	Requests  int64   `json:"requests"`   // 实际发出的 HTTP 请求数（含重定向逐跳，来自 client.Stats）
	Pages     int64   `json:"pages"`      // 已进入分析集的页面数
	Blocked   int64   `json:"blocked"`    // 被 WAF/限流拦截的响应数
	Rate      float64 `json:"rate"`       // 瞬时速率 req/s（两次快照差分；无样本为 0）
	ElapsedMS int64   `json:"elapsed_ms"` // 扫描已用时（毫秒）
}

// liveTracker 扫描实时统计器：节流推送（默认 250ms 一次），避免高频回调拖慢扫描。
type liveTracker struct {
	mu       sync.Mutex
	start    time.Time
	phase    string
	name     string
	pages    int64
	stats    func() httpx.Stats
	emit     func(LiveStats)
	lastEmit time.Time
	lastReq  int64
	lastAt   time.Time
	rate     float64
}

func newLiveTracker(stats func() httpx.Stats, emit func(LiveStats)) *liveTracker {
	if emit == nil {
		return nil
	}
	return &liveTracker{start: time.Now(), stats: stats, emit: emit, phase: "prepare", name: "准备"}
}

// setPhase 切换阶段并立即推送一次（阶段切换对用户是重要信息，不受节流限制）。
func (t *liveTracker) setPhase(phase, name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.phase, t.name = phase, name
	t.pushLocked(true)
	t.mu.Unlock()
}

// notePage 记录一页进入分析集。
func (t *liveTracker) notePage() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.pages++
	t.pushLocked(false)
	t.mu.Unlock()
}

// touch 在每次实际请求后调用：只触发节流推送，请求数从 client.Stats 读取。
func (t *liveTracker) touch() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.pushLocked(false)
	t.mu.Unlock()
}

// done 收尾：推一次最终快照（阶段 done）。
func (t *liveTracker) done() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.phase, t.name = "done", "完成"
	t.pushLocked(true)
	t.mu.Unlock()
}

func (t *liveTracker) pushLocked(force bool) {
	now := time.Now()
	if !force && !t.lastEmit.IsZero() && now.Sub(t.lastEmit) < 250*time.Millisecond {
		return
	}
	t.lastEmit = now
	var st httpx.Stats
	if t.stats != nil {
		st = t.stats()
	}
	// 瞬时速率：两次快照之间的请求增量 / 时间增量（首次快照无速率）。
	if !t.lastAt.IsZero() {
		dt := now.Sub(t.lastAt).Seconds()
		if dt > 0 {
			t.rate = float64(st.Requests-t.lastReq) / dt
		}
	}
	t.lastAt, t.lastReq = now, st.Requests
	t.emit(LiveStats{
		Phase:     t.phase,
		PhaseName: t.name,
		Requests:  st.Requests,
		Pages:     t.pages,
		Blocked:   st.Blocked,
		Rate:      t.rate,
		ElapsedMS: now.Sub(t.start).Milliseconds(),
	})
}
