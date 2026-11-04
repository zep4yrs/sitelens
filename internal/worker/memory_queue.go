// 内存队列实现：mutex 保护状态 + 广播 channel 唤醒阻塞消费者。
//
// 语义与分布式 Queue 实现保持一致（Redis/DB 实现可替换）：
//   - 入队即 pending，FIFO 投递；
//   - Dequeue 授予租约（visible timeout），租约内任务不可被其它 worker 领取；
//   - Ack 完成；Nack 失败——未达重试上限则回到 failed 待重投，达到上限进死信；
//   - Heartbeat 续租；租约到期未确认由下一次 Dequeue/Stats 回收重投；
//   - 同租户 + 幂等键重复入队只保留一条任务并返回首次 ID。
package worker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// QueueOptions MemoryQueue 参数（零值可用）。
type QueueOptions struct {
	DefaultMaxAttempts int              // 默认重试上限（<=0 → 3）
	LeaseTTL           time.Duration    // Dequeue 传 leaseTTL<=0 时的默认租约（<=0 → 30s）
	Now                func() time.Time // 时钟注入（仅测试用；nil = time.Now）
	// MaxTerminalRetained 终态（done/dead）任务快照保留上限（<=0 → 4096）。
	// C-07：完成任务此前永不释放（tasks/idem 只增），长驻服务内存无界；
	// 超过上限后按进入终态的先后淘汰最旧快照（TaskState 查询随之消失）。
	MaxTerminalRetained int
	// MaxDeadLetters 死信快照上限（<=0 → 1024）：超出淘汰最旧。
	MaxDeadLetters int
}

const (
	defaultTerminalRetained = 4096
	defaultDeadLetters      = 1024
)

// MemoryQueue 进程内任务队列（企业版单实例/测试基线实现）。
type MemoryQueue struct {
	mu        sync.Mutex
	opts      QueueOptions
	seq       atomic.Uint64
	tasks     map[string]*taskEntry
	ready     []string // 待投递任务 ID（FIFO；pending/failed 均在此）
	inflight  map[string]*inflightEntry
	idem      map[string]string // tenant\x00key → 首次任务 ID（终态即释放）
	dead      []DeadLetter
	terminal  []string // 终态任务 ID（FIFO，用于按上限回收 tasks 快照）
	closed    bool
	wait      chan struct{} // 状态变更广播（close 后替换）
	enqueued  int64
	delivered int64
}

type taskEntry struct {
	task     Task
	state    State
	attempts int
	lastErr  string
	idemKey  string // 入队时的幂等键（终态时用于释放 q.idem）
}

type inflightEntry struct {
	token    string
	taskID   string
	workerID string
	deadline time.Time
}

// NewMemoryQueue 创建内存队列。
func NewMemoryQueue(opts QueueOptions) *MemoryQueue {
	return &MemoryQueue{
		opts:     opts,
		tasks:    map[string]*taskEntry{},
		inflight: map[string]*inflightEntry{},
		idem:     map[string]string{},
		wait:     make(chan struct{}),
	}
}

// now 当前时间（测试可注入）。
func (q *MemoryQueue) now() time.Time {
	if q.opts.Now != nil {
		return q.opts.Now()
	}
	return time.Now()
}

// broadcastLocked 唤醒全部等待者（调用方须持 q.mu）。
func (q *MemoryQueue) broadcastLocked() {
	close(q.wait)
	q.wait = make(chan struct{})
}

// maxAttemptsFor 任务重试上限：任务显式值 > 队列默认值 > 内置默认。
func (q *MemoryQueue) maxAttemptsFor(t Task) int {
	if t.MaxAttempts > 0 {
		return t.MaxAttempts
	}
	if q.opts.DefaultMaxAttempts > 0 {
		return q.opts.DefaultMaxAttempts
	}
	return defaultMaxAttempts
}

// terminalLimit 终态任务快照保留上限。
func (q *MemoryQueue) terminalLimit() int {
	if q.opts.MaxTerminalRetained > 0 {
		return q.opts.MaxTerminalRetained
	}
	return defaultTerminalRetained
}

// deadLimit 死信快照上限。
func (q *MemoryQueue) deadLimit() int {
	if q.opts.MaxDeadLetters > 0 {
		return q.opts.MaxDeadLetters
	}
	return defaultDeadLetters
}

// dropIdemLocked 释放任务占用的幂等键（C-07）。
// 终态（done/dead）后释放：同一 key 再次入队应作为**新任务**执行，
// 不能被"已完成的旧任务"静默吞掉（旧实现 idem 表只增，返旧 ID 不执行）。
func (q *MemoryQueue) dropIdemLocked(id string, e *taskEntry) {
	if e == nil || e.idemKey == "" {
		return
	}
	if cur, ok := q.idem[e.idemKey]; ok && cur == id {
		delete(q.idem, e.idemKey)
	}
	e.idemKey = ""
}

// markTerminalLocked 把任务置为终态（done/dead），释放幂等键并按上限回收
// 任务快照（C-07：原实现 tasks/idem/dead 随任务数单调增长，内存无界）。
func (q *MemoryQueue) markTerminalLocked(id string, e *taskEntry, st State) {
	e.state = st
	q.dropIdemLocked(id, e)
	q.terminal = append(q.terminal, id)
	for len(q.terminal) > q.terminalLimit() {
		oldest := q.terminal[0]
		q.terminal = q.terminal[1:]
		if oe, ok := q.tasks[oldest]; ok && (oe.state == StateDone || oe.state == StateDead) {
			delete(q.tasks, oldest)
		}
	}
}

// appendDeadLocked 追加死信并按上限淘汰最旧（调用方持锁）。
func (q *MemoryQueue) appendDeadLocked(d DeadLetter) {
	q.dead = append(q.dead, d)
	if over := len(q.dead) - q.deadLimit(); over > 0 {
		q.dead = append([]DeadLetter(nil), q.dead[over:]...)
	}
}

// Enqueue 入队（幂等键命中时返回首次任务 ID，不重复入队）。
func (q *MemoryQueue) Enqueue(ctx context.Context, t Task) (string, error) {
	if ctx != nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return "", ErrQueueClosed
	}
	tenant := strings.TrimSpace(t.TenantID)
	key := strings.TrimSpace(t.IdempotencyKey)
	idemKey := ""
	if key != "" {
		idemKey = tenant + "\x00" + key
		if id, ok := q.idem[idemKey]; ok {
			if e, alive := q.tasks[id]; alive && e.state != StateDone && e.state != StateDead {
				return id, nil // 幂等命中：任务仍在队列/执行中，不重复入队
			}
			// 映射残留（任务已终态但快照已被上限淘汰）：清掉，按新任务处理。
			delete(q.idem, idemKey)
		}
	}
	id := strings.TrimSpace(t.ID)
	if id == "" {
		id = fmt.Sprintf("task-%d", q.seq.Add(1))
	}
	if _, dup := q.tasks[id]; dup {
		return "", fmt.Errorf("worker: 任务 ID 重复：%s", id)
	}
	nt := Task{
		ID: id, TenantID: tenant, Kind: t.Kind,
		Payload:        append([]byte(nil), t.Payload...),
		IdempotencyKey: key,
		MaxAttempts:    q.maxAttemptsFor(t),
		CreatedAt:      t.CreatedAt,
	}
	if nt.CreatedAt.IsZero() {
		nt.CreatedAt = q.now()
	}
	q.tasks[id] = &taskEntry{task: nt, state: StatePending, idemKey: idemKey}
	q.ready = append(q.ready, id)
	if idemKey != "" {
		q.idem[idemKey] = id
	}
	q.enqueued++
	q.broadcastLocked()
	return id, nil
}

// Dequeue 领取一个任务（阻塞直到有可见任务或 ctx 结束）。
// leaseTTL 为本次投递的可见性超时；<=0 用队列默认。
func (q *MemoryQueue) Dequeue(ctx context.Context, workerID string, leaseTTL time.Duration) (*Lease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if leaseTTL <= 0 {
		leaseTTL = q.opts.LeaseTTL
		if leaseTTL <= 0 {
			leaseTTL = defaultLeaseTTL
		}
	}
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return nil, ErrQueueClosed
		}
		now := q.now()
		q.reapLocked(now)
		if id, ok := q.popReadyLocked(); ok {
			lease := q.deliverLocked(id, workerID, leaseTTL, now)
			q.mu.Unlock()
			return lease, nil
		}
		next := q.nextDeadlineLocked()
		wait := q.wait
		q.mu.Unlock()

		// C-13：用 NewTimer 且每个分支都 Stop。原实现 time.After 在每次
		// 循环都新建定时器，被广播唤醒时旧 timer 不可 Stop、要留到租约
		// 到期（默认 30s）才释放；高吞吐/16 worker 下会堆积大量未到期
		// timer，造成堆内存抖动。
		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		if !next.IsZero() {
			d := next.Sub(now)
			if d <= 0 {
				continue // 有租约刚好到期：立刻重查回收
			}
			timer = time.NewTimer(d)
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, ctx.Err()
		case <-wait:
			if timer != nil {
				timer.Stop()
			}
		case <-timerC:
		}
	}
}

// popReadyLocked 取下一个可投递任务（跳过已删除/已终态 ID）。
func (q *MemoryQueue) popReadyLocked() (string, bool) {
	for len(q.ready) > 0 {
		id := q.ready[0]
		q.ready = q.ready[1:]
		e, ok := q.tasks[id]
		if !ok || (e.state != StatePending && e.state != StateFailed) {
			continue
		}
		return id, true
	}
	return "", false
}

// deliverLocked 投递任务：attempts+1、置 running、授予租约。
func (q *MemoryQueue) deliverLocked(id, workerID string, ttl time.Duration, now time.Time) *Lease {
	e := q.tasks[id]
	e.attempts++
	e.state = StateRunning
	token := fmt.Sprintf("%s#%d", id, q.seq.Add(1))
	deadline := now.Add(ttl)
	q.inflight[token] = &inflightEntry{token: token, taskID: id, workerID: workerID, deadline: deadline}
	q.delivered++
	return &Lease{
		Token: token, Task: cloneTask(e.task), TenantID: e.task.TenantID,
		WorkerID: workerID, Deadline: deadline, Attempts: e.attempts,
	}
}

// reapLocked 回收过期租约：未达上限回 failed 待重投，达到上限进死信。
func (q *MemoryQueue) reapLocked(now time.Time) {
	for token, inf := range q.inflight {
		if now.Before(inf.deadline) {
			continue
		}
		delete(q.inflight, token)
		e, ok := q.tasks[inf.taskID]
		if !ok {
			continue
		}
		e.lastErr = "租约过期未确认"
		if e.attempts >= q.maxAttemptsFor(e.task) {
			q.appendDeadLocked(DeadLetter{
				Task: cloneTask(e.task), Reason: e.lastErr,
				Attempts: e.attempts, FailedAt: now,
			})
			q.markTerminalLocked(inf.taskID, e, StateDead)
		} else {
			e.state = StateFailed
			q.ready = append(q.ready, inf.taskID)
		}
		q.broadcastLocked()
	}
}

// nextDeadlineLocked 最近租约到期时间（无租约返回零值）。
func (q *MemoryQueue) nextDeadlineLocked() time.Time {
	var next time.Time
	for _, inf := range q.inflight {
		if next.IsZero() || inf.deadline.Before(next) {
			next = inf.deadline
		}
	}
	return next
}

// Ack 确认任务成功（租约已过期/非本次投递 → ErrLeaseExpired）。
//
// C-14：**先验 token 再 reap**。原实现先 reapLocked 再查 token：租约恰好在
// Ack 前一刻到期时，reap 会把 inflight 删掉并把任务重投（甚至进死信），
// 于是一个**实际已成功**的任务被判 ErrLeaseExpired → 重复执行 + 运维看到
// 假失败。现在先取 token：token 还在（即使 deadline 已过）就认这次确认，
// 只在 token 已被回收（真正的重投已发生）时才返回 ErrLeaseExpired。
func (q *MemoryQueue) Ack(ctx context.Context, lease *Lease) error {
	if err := validateLease(lease); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQueueClosed
	}
	inf, ok := q.inflight[lease.Token]
	if !ok || inf.taskID != lease.Task.ID {
		q.reapLocked(q.now()) // 顺手清理其它过期租约
		return ErrLeaseExpired
	}
	delete(q.inflight, lease.Token)
	if e, ok := q.tasks[inf.taskID]; ok {
		q.markTerminalLocked(inf.taskID, e, StateDone)
	}
	q.reapLocked(q.now())
	q.broadcastLocked()
	return nil
}

// Nack 标记本次尝试失败：未达重试上限回 failed 待重投，否则进死信。
//
// C-14：与 Ack 同理，先验 token 再 reap；只要租约未被回收，本次 Nack 就
// 归属于这次投递，不能被"刚好到期"误判成 ErrLeaseExpired。
func (q *MemoryQueue) Nack(ctx context.Context, lease *Lease, reason string) error {
	if err := validateLease(lease); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQueueClosed
	}
	now := q.now()
	inf, ok := q.inflight[lease.Token]
	if !ok || inf.taskID != lease.Task.ID {
		q.reapLocked(now)
		return ErrLeaseExpired
	}
	delete(q.inflight, lease.Token)
	e, ok := q.tasks[inf.taskID]
	if !ok {
		return ErrLeaseExpired
	}
	e.lastErr = strings.TrimSpace(reason)
	if e.lastErr == "" {
		e.lastErr = "执行失败"
	}
	if e.attempts >= q.maxAttemptsFor(e.task) {
		q.appendDeadLocked(DeadLetter{
			Task: cloneTask(e.task), Reason: e.lastErr,
			Attempts: e.attempts, FailedAt: now,
		})
		q.markTerminalLocked(inf.taskID, e, StateDead)
	} else {
		e.state = StateFailed
		q.ready = append(q.ready, inf.taskID)
	}
	q.reapLocked(now)
	q.broadcastLocked()
	return nil
}

// Heartbeat 续租（extend<=0 用队列默认租约）。
func (q *MemoryQueue) Heartbeat(ctx context.Context, lease *Lease, extend time.Duration) (*Lease, error) {
	if err := validateLease(lease); err != nil {
		return nil, err
	}
	if extend <= 0 {
		extend = q.opts.LeaseTTL
		if extend <= 0 {
			extend = defaultLeaseTTL
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil, ErrQueueClosed
	}
	now := q.now()
	q.reapLocked(now)
	inf, ok := q.inflight[lease.Token]
	if !ok || inf.taskID != lease.Task.ID {
		return nil, ErrLeaseExpired
	}
	inf.deadline = now.Add(extend)
	e, ok := q.tasks[inf.taskID]
	if !ok {
		return nil, ErrLeaseExpired
	}
	return &Lease{
		Token: inf.token, Task: cloneTask(e.task), TenantID: e.task.TenantID,
		WorkerID: inf.workerID, Deadline: inf.deadline, Attempts: e.attempts,
	}, nil
}

// Stats 队列状态快照（会顺带回收过期租约）。
func (q *MemoryQueue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapLocked(q.now())
	st := QueueStats{Leases: len(q.inflight), Enqueued: q.enqueued, Delivered: q.delivered}
	for _, e := range q.tasks {
		switch e.state {
		case StatePending:
			st.Pending++
		case StateRunning:
			st.Running++
		case StateDone:
			st.Done++
		case StateFailed:
			st.Failed++
		case StateDead:
			st.Dead++
		}
	}
	return st
}

// DeadLetters 死信队列快照（副本）。
func (q *MemoryQueue) DeadLetters() []DeadLetter {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]DeadLetter, len(q.dead))
	for i := range q.dead {
		out[i] = q.dead[i]
		out[i].Task = cloneTask(q.dead[i].Task)
	}
	return out
}

// TaskState 查询任务当前状态（不存在返回 false）。
func (q *MemoryQueue) TaskState(id string) (State, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapLocked(q.now())
	e, ok := q.tasks[id]
	if !ok {
		return "", false
	}
	return e.state, true
}

// Close 关闭队列：拒绝新任务并唤醒所有阻塞消费者（ErrQueueClosed）。
func (q *MemoryQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.broadcastLocked()
}

// validateLease 校验租约必填项。
func validateLease(lease *Lease) error {
	if lease == nil || strings.TrimSpace(lease.Token) == "" || strings.TrimSpace(lease.Task.ID) == "" {
		return ErrInvalidLease
	}
	return nil
}

// cloneTask 复制任务（Payload 深拷贝，避免调用方/死信快照互相影响）。
func cloneTask(t Task) Task {
	out := t
	if t.Payload != nil {
		out.Payload = append([]byte(nil), t.Payload...)
	}
	return out
}
