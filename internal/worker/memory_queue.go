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
}

// MemoryQueue 进程内任务队列（企业版单实例/测试基线实现）。
type MemoryQueue struct {
	mu        sync.Mutex
	opts      QueueOptions
	seq       atomic.Uint64
	tasks     map[string]*taskEntry
	ready     []string // 待投递任务 ID（FIFO；pending/failed 均在此）
	inflight  map[string]*inflightEntry
	idem      map[string]string // tenant\x00key → 首次任务 ID
	dead      []DeadLetter
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
			if _, alive := q.tasks[id]; alive {
				return id, nil // 幂等命中：同 key 只执行一次
			}
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
	q.tasks[id] = &taskEntry{task: nt, state: StatePending}
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

		var timer <-chan time.Time
		if !next.IsZero() {
			d := next.Sub(now)
			if d <= 0 {
				continue // 有租约刚好到期：立刻重查回收
			}
			timer = time.After(d)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait:
		case <-timer:
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
			e.state = StateDead
			q.dead = append(q.dead, DeadLetter{
				Task: cloneTask(e.task), Reason: e.lastErr,
				Attempts: e.attempts, FailedAt: now,
			})
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
func (q *MemoryQueue) Ack(ctx context.Context, lease *Lease) error {
	if err := validateLease(lease); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQueueClosed
	}
	q.reapLocked(q.now())
	inf, ok := q.inflight[lease.Token]
	if !ok || inf.taskID != lease.Task.ID {
		return ErrLeaseExpired
	}
	delete(q.inflight, lease.Token)
	if e, ok := q.tasks[inf.taskID]; ok {
		e.state = StateDone
	}
	q.broadcastLocked()
	return nil
}

// Nack 标记本次尝试失败：未达重试上限回 failed 待重投，否则进死信。
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
	q.reapLocked(now)
	inf, ok := q.inflight[lease.Token]
	if !ok || inf.taskID != lease.Task.ID {
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
		e.state = StateDead
		q.dead = append(q.dead, DeadLetter{
			Task: cloneTask(e.task), Reason: e.lastErr,
			Attempts: e.attempts, FailedAt: now,
		})
	} else {
		e.state = StateFailed
		q.ready = append(q.ready, inf.taskID)
	}
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
