// 企业版 6.x 分布式 worker 回归：队列 lease/心跳/重投/幂等键 + WorkerPool
// 并发/优雅停止/重试死信/并发上限。
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor 轮询等待条件成立（测试辅助；避免脆弱 sleep 断言）。
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// dequeueWithTimeout 带超时领取一个任务。
func dequeueWithTimeout(t *testing.T, q *MemoryQueue, workerID string, ttl, timeout time.Duration) *Lease {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	lease, err := q.Dequeue(ctx, workerID, ttl)
	if err != nil {
		t.Fatalf("Dequeue 失败：%v", err)
	}
	return lease
}

// TestEnqueueDequeueAck 基本生命周期：入队 → 投递（租约）→ Ack → done。
func TestEnqueueDequeueAck(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{LeaseTTL: time.Second})
	id, err := q.Enqueue(ctx, Task{TenantID: "t1", Kind: "scan", Payload: []byte("payload")})
	if err != nil || id == "" {
		t.Fatalf("Enqueue: id=%q err=%v", id, err)
	}
	if st := q.Stats(); st.Pending != 1 || st.Running != 0 {
		t.Fatalf("入队后统计异常: %+v", st)
	}
	lease := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if lease.Task.ID != id || lease.TenantID != "t1" || lease.WorkerID != "w1" ||
		lease.Attempts != 1 || !lease.Deadline.After(time.Now()) {
		t.Fatalf("租约字段异常: %+v", lease)
	}
	if st := q.Stats(); st.Running != 1 || st.Leases != 1 || st.Delivered != 1 {
		t.Fatalf("投递后统计异常: %+v", st)
	}
	if err := q.Ack(ctx, lease); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if st := q.Stats(); st.Done != 1 || st.Running != 0 || st.Leases != 0 {
		t.Fatalf("Ack 后统计异常: %+v", st)
	}
	if state, ok := q.TaskState(id); !ok || state != StateDone {
		t.Fatalf("任务状态应为 done: %q %v", state, ok)
	}
	// 无任务时 Dequeue 阻塞到 ctx 超时
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := q.Dequeue(waitCtx, "w1", time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("空队列应阻塞到超时: %v", err)
	}
	// 旧租约再次 Ack 必须失败（防重复确认）
	if err := q.Ack(ctx, lease); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("旧租约 Ack 应 ErrLeaseExpired: %v", err)
	}
}

// TestConcurrentConsumersNoDuplicate 并发消费不重复：每个任务恰好投递一次。
func TestConcurrentConsumersNoDuplicate(t *testing.T) {
	const total, workers = 200, 8
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := 0; i < total; i++ {
		if _, err := q.Enqueue(ctx, Task{Kind: "scan", Payload: []byte(fmt.Sprintf("job-%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := make(map[string]int, total)
	var processed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for {
				lease, err := q.Dequeue(ctx, fmt.Sprintf("w%d", idx), 5*time.Second)
				if err != nil {
					return
				}
				if lease.Attempts != 1 {
					t.Errorf("并发消费出现重复投递: task=%s attempts=%d", lease.Task.ID, lease.Attempts)
				}
				mu.Lock()
				seen[lease.Task.ID]++
				mu.Unlock()
				if err := q.Ack(ctx, lease); err != nil {
					t.Errorf("Ack: %v", err)
				}
				if processed.Add(1) >= total {
					cancel()
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if len(seen) != total {
		t.Fatalf("应消费 %d 个唯一任务，实际 %d", total, len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("任务 %s 被重复消费 %d 次", id, n)
		}
	}
	if st := q.Stats(); st.Done != total || st.Pending != 0 || st.Running != 0 {
		t.Fatalf("最终统计异常: %+v", st)
	}
}

// TestLeaseTimeoutRedelivery 租约到期未确认 → 回收重投（attempts 递增，旧租约失效）。
func TestLeaseTimeoutRedelivery(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 30 * time.Millisecond})
	id, err := q.Enqueue(ctx, Task{Kind: "scan"})
	if err != nil {
		t.Fatal(err)
	}
	first := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if first.Attempts != 1 {
		t.Fatalf("首次投递 attempts 应为 1: %d", first.Attempts)
	}
	// 不 Ack：租约到期后第二个消费者应领到同一任务（重投）
	second := dequeueWithTimeout(t, q, "w2", 0, 2*time.Second)
	if second.Task.ID != id || second.Attempts != 2 || second.Token == first.Token {
		t.Fatalf("租约超时应重投（新令牌/attempts=2）: %+v", second)
	}
	// 旧租约已失效
	if err := q.Ack(ctx, first); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("过期租约 Ack 应失败: %v", err)
	}
	if err := q.Ack(ctx, second); err != nil {
		t.Fatalf("新租约 Ack: %v", err)
	}
	if st := q.Stats(); st.Done != 1 || st.Running != 0 {
		t.Fatalf("最终统计异常: %+v", st)
	}
}

// TestHeartbeatRenewal 心跳续租：原租约到期后仍有效；过期后心跳失败。
func TestHeartbeatRenewal(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 40 * time.Millisecond})
	if _, err := q.Enqueue(ctx, Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	lease := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	time.Sleep(25 * time.Millisecond)
	renewed, err := q.Heartbeat(ctx, lease, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("心跳续租: %v", err)
	}
	if !renewed.Deadline.After(lease.Deadline) {
		t.Fatalf("心跳应延长 deadline: %v → %v", lease.Deadline, renewed.Deadline)
	}
	time.Sleep(60 * time.Millisecond) // 越过原 deadline、未到新 deadline
	if err := q.Ack(ctx, lease); err != nil {
		t.Fatalf("续租后原租约应仍有效: %v", err)
	}
	// 过期后心跳必须失败（任务已被回收）
	if _, err := q.Enqueue(ctx, Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	expired := dequeueWithTimeout(t, q, "w2", 20*time.Millisecond, time.Second)
	time.Sleep(40 * time.Millisecond)
	if _, err := q.Heartbeat(ctx, expired, time.Second); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("过期租约心跳应 ErrLeaseExpired: %v", err)
	}
}

// TestRetryAndDeadLetter 重试上限与死信：attempts 达上限后进死信不再重投。
func TestRetryAndDeadLetter(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{DefaultMaxAttempts: 2, LeaseTTL: time.Second})
	id, err := q.Enqueue(ctx, Task{Kind: "scan"})
	if err != nil {
		t.Fatal(err)
	}
	first := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if err := q.Nack(ctx, first, "boom-1"); err != nil {
		t.Fatalf("Nack: %v", err)
	}
	if st := q.Stats(); st.Failed != 1 || st.Dead != 0 {
		t.Fatalf("首次失败应待重投: %+v", st)
	}
	second := dequeueWithTimeout(t, q, "w2", 0, time.Second)
	if second.Attempts != 2 {
		t.Fatalf("重投 attempts 应为 2: %d", second.Attempts)
	}
	if err := q.Nack(ctx, second, "boom-2"); err != nil {
		t.Fatalf("Nack: %v", err)
	}
	if st := q.Stats(); st.Dead != 1 || st.Failed != 0 || st.Pending != 0 {
		t.Fatalf("达到上限应进死信: %+v", st)
	}
	dead := q.DeadLetters()
	if len(dead) != 1 || dead[0].Task.ID != id || dead[0].Reason != "boom-2" || dead[0].Attempts != 2 {
		t.Fatalf("死信内容异常: %+v", dead)
	}
	if state, ok := q.TaskState(id); !ok || state != StateDead {
		t.Fatalf("任务状态应为 dead: %q %v", state, ok)
	}
	// 不再重投
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := q.Dequeue(waitCtx, "w3", time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("死信任务不应再被投递: %v", err)
	}
	// 旧租约确认失败
	if err := q.Nack(ctx, second, "again"); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("旧租约 Nack 应失败: %v", err)
	}
}

// TestIdempotencyKey 幂等键：同租户同 key 只保留一条任务（完成后再入队也不重复执行）。
func TestIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{LeaseTTL: time.Second})
	id1, err := q.Enqueue(ctx, Task{TenantID: "t1", IdempotencyKey: "k1", Kind: "scan"})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := q.Enqueue(ctx, Task{TenantID: "t1", IdempotencyKey: "k1", Kind: "scan"})
	if err != nil || id2 != id1 {
		t.Fatalf("同 key 应返回首次 ID: %q vs %q err=%v", id1, id2, err)
	}
	if st := q.Stats(); st.Pending != 1 {
		t.Fatalf("幂等去重后应只有 1 条任务: %+v", st)
	}
	// 跨租户同 key 互不影响
	id3, err := q.Enqueue(ctx, Task{TenantID: "t2", IdempotencyKey: "k1", Kind: "scan"})
	if err != nil || id3 == id1 {
		t.Fatalf("跨租户同 key 应独立: %q vs %q err=%v", id1, id3, err)
	}
	// 消费完成后再入队同 key：仍返回首次 ID，不产生新任务
	lease := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if err := q.Ack(ctx, lease); err != nil {
		t.Fatal(err)
	}
	id4, err := q.Enqueue(ctx, Task{TenantID: "t1", IdempotencyKey: "k1", Kind: "scan"})
	if err != nil || id4 != id1 {
		t.Fatalf("完成后同 key 入队应返回首次 ID: %q err=%v", id4, err)
	}
	if st := q.Stats(); st.Done != 1 || st.Pending != 1 { // pending=1 是 t2 的任务
		t.Fatalf("完成后同 key 不应新增任务: %+v", st)
	}
}

// TestDequeueContextAndClose ctx 取消/关闭队列时阻塞消费者被唤醒。
func TestDequeueContextAndClose(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Dequeue(ctx, "w1", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx 取消应立即返回: %v", err)
	}
	// 关闭队列唤醒阻塞消费者
	done := make(chan error, 1)
	go func() {
		_, err := q.Dequeue(context.Background(), "w2", time.Second)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	q.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrQueueClosed) {
			t.Fatalf("关闭队列应返回 ErrQueueClosed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close 未唤醒阻塞消费者")
	}
	if _, err := q.Enqueue(context.Background(), Task{Kind: "scan"}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("关闭后 Enqueue 应失败: %v", err)
	}
}

// TestEnqueueValidation 显式重复 ID / 任务 ID 生成 / MaxAttempts 归一。
func TestEnqueueValidation(t *testing.T) {
	ctx := context.Background()
	q := NewMemoryQueue(QueueOptions{DefaultMaxAttempts: 4, LeaseTTL: time.Second})
	if _, err := q.Enqueue(ctx, Task{ID: "dup", Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, Task{ID: "dup", Kind: "scan"}); err == nil {
		t.Fatal("重复任务 ID 应报错")
	}
	lease := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if lease.Task.MaxAttempts != 4 {
		t.Fatalf("MaxAttempts 应归一为队列默认 4: %d", lease.Task.MaxAttempts)
	}
	if err := q.Ack(ctx, lease); err != nil {
		t.Fatal(err)
	}
	// 任务显式 MaxAttempts 优先
	if _, err := q.Enqueue(ctx, Task{Kind: "scan", MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	lease2 := dequeueWithTimeout(t, q, "w1", 0, time.Second)
	if lease2.Task.MaxAttempts != 1 {
		t.Fatalf("任务显式 MaxAttempts 应优先: %d", lease2.Task.MaxAttempts)
	}
	if err := q.Nack(ctx, lease2, "once"); err != nil {
		t.Fatal(err)
	}
	if st := q.Stats(); st.Dead != 1 {
		t.Fatalf("MaxAttempts=1 失败应直接进死信: %+v", st)
	}
}

// TestWorkerPoolConsumesAndStops WorkerPool 端到端：并发消费 + 优雅停止。
func TestWorkerPoolConsumesAndStops(t *testing.T) {
	const total = 24
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 2 * time.Second})
	var handled atomic.Int64
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 4, LeaseTTL: 2 * time.Second,
		Handler: func(ctx context.Context, task Task) error {
			handled.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := pool.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(ctx); !errors.Is(err, ErrPoolStarted) {
		t.Fatalf("重复启动应报错: %v", err)
	}
	for i := 0; i < total; i++ {
		if _, err := q.Enqueue(ctx, Task{Kind: "scan"}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, "全部任务处理完成", func() bool { return handled.Load() == total })
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if st := pool.Stats(); st.Processed != total || st.Running != 0 || !st.Stopped {
		t.Fatalf("池统计异常: %+v", st)
	}
	if st := q.Stats(); st.Done != total {
		t.Fatalf("队列统计异常: %+v", st)
	}
	// 停止后不再消费新任务
	if _, err := q.Enqueue(ctx, Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if st := q.Stats(); st.Pending != 1 {
		t.Fatalf("停止后不应继续消费: %+v", st)
	}
	// Stop 幂等
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatalf("重复 Stop 应成功: %v", err)
	}
}

// TestGracefulStopWaitsInflight 优雅停止：在跑任务完成前不返回，完成后正常退出。
func TestGracefulStopWaitsInflight(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 2 * time.Second})
	release := make(chan struct{})
	var started atomic.Int64
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 2, LeaseTTL: 2 * time.Second,
		Handler: func(ctx context.Context, task Task) error {
			started.Add(1)
			<-release
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := pool.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := q.Enqueue(ctx, Task{Kind: "scan"}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 3*time.Second, "两个任务开始执行", func() bool { return started.Load() == 2 })
	stopDone := make(chan error, 1)
	go func() { stopDone <- pool.Stop(context.Background()) }()
	select {
	case err := <-stopDone:
		t.Fatalf("在跑任务未完成时 Stop 不应返回: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 未在任务完成后返回")
	}
	if st := pool.Stats(); st.Processed != 2 {
		t.Fatalf("应 Ack 2 个任务: %+v", st)
	}
}

// TestStopTimeout 优雅停止超时：ctx 到期返回错误（任务留待租约回收）。
func TestStopTimeout(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 2 * time.Second})
	release := make(chan struct{})
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 1, LeaseTTL: 2 * time.Second,
		Handler: func(ctx context.Context, task Task) error {
			<-release
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(context.Background(), Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "任务开始执行", func() bool { return pool.Stats().Running == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := pool.Stop(ctx); err == nil {
		t.Fatal("停止超时应返回错误")
	}
	close(release)
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatalf("任务结束后 Stop 应成功: %v", err)
	}
}

// TestConcurrencyCap 并发上限：请求 100 → 实际 16；执行中并发不超过 16。
func TestConcurrencyCap(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 3 * time.Second})
	release := make(chan struct{})
	var inFlight, maxSeen atomic.Int64
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 100, LeaseTTL: 3 * time.Second,
		Handler: func(ctx context.Context, task Task) error {
			cur := inFlight.Add(1)
			for {
				old := maxSeen.Load()
				if cur <= old || maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			<-release
			inFlight.Add(-1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pool.Workers() != MaxWorkers {
		t.Fatalf("并发应截断到 %d，实际 %d", MaxWorkers, pool.Workers())
	}
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxWorkers*2; i++ {
		if _, err := q.Enqueue(context.Background(), Task{Kind: "scan"}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 3*time.Second, "并发拉满 16", func() bool { return inFlight.Load() == MaxWorkers })
	time.Sleep(30 * time.Millisecond)
	if got := maxSeen.Load(); got > MaxWorkers {
		t.Fatalf("并发超过硬上限：%d > %d", got, MaxWorkers)
	}
	close(release)
	waitFor(t, 5*time.Second, "任务全部完成", func() bool { return pool.Stats().Processed == MaxWorkers*2 })
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Workers<=0 时默认 4
	def, err := NewWorkerPool(q, PoolOptions{Handler: func(context.Context, Task) error { return nil }})
	if err != nil || def.Workers() != 4 {
		t.Fatalf("默认并发应为 4: %v %v", def.Workers(), err)
	}
	// Handler 必填
	if _, err := NewWorkerPool(q, PoolOptions{}); !errors.Is(err, ErrNoHandler) {
		t.Fatalf("缺 Handler 应报错: %v", err)
	}
}

// TestPoolRetryDeadLetter WorkerPool 失败 → Nack → 重试耗尽 → 死信。
func TestPoolRetryDeadLetter(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{DefaultMaxAttempts: 2, LeaseTTL: 2 * time.Second})
	var attempts atomic.Int64
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 2, LeaseTTL: 2 * time.Second,
		Handler: func(ctx context.Context, task Task) error {
			attempts.Add(1)
			return errors.New("执行失败")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool.Stop(context.Background()) }()
	if _, err := q.Enqueue(context.Background(), Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "重试耗尽进入死信", func() bool { return q.Stats().Dead == 1 })
	if got := attempts.Load(); got != 2 {
		t.Fatalf("应执行 2 次（上限 2）: %d", got)
	}
	dead := q.DeadLetters()
	if len(dead) != 1 || dead[0].Reason != "执行失败" || dead[0].Attempts != 2 {
		t.Fatalf("死信内容异常: %+v", dead)
	}
	if st := pool.Stats(); st.Failed != 2 || st.Processed != 0 {
		t.Fatalf("池统计异常: %+v", st)
	}
}

// TestHeartbeatCancelsHandler 心跳失败（租约被回收）时取消执行 ctx。
// 心跳间隔故意大于租约 TTL：首次续租时租约已过期 → ErrLeaseExpired → 取消执行。
func TestHeartbeatCancelsHandler(t *testing.T) {
	q := NewMemoryQueue(QueueOptions{LeaseTTL: 30 * time.Millisecond})
	handlerCtxDone := make(chan struct{})
	var once sync.Once
	pool, err := NewWorkerPool(q, PoolOptions{
		Workers: 1, LeaseTTL: 30 * time.Millisecond, Heartbeat: 100 * time.Millisecond,
		Handler: func(ctx context.Context, task Task) error {
			<-ctx.Done() // 等心跳失败触发的取消
			once.Do(func() { close(handlerCtxDone) })
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(context.Background(), Task{Kind: "scan"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerCtxDone:
	case <-time.After(2 * time.Second):
		t.Fatal("租约丢失后执行 ctx 应被取消")
	}
	q.Close() // 停止再投递，避免测试收尾时又跑一轮
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = pool.Stop(stopCtx)
}
