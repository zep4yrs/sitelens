// WorkerPool：并发消费队列任务、心跳续租、优雅停止。
//
// 语义：
//   - 并发上限 MaxWorkers=16（PoolOptions.Workers 超出截断）；
//   - 每个任务执行期间独立心跳续租；租约丢失（心跳返回 ErrLeaseExpired）
//     立即取消执行 ctx，避免旧 worker 继续写副作用；
//   - Handler 成功 → Ack；失败 → Nack（队列按重试上限决定重投或死信）；
//   - 优雅停止：只停止拉取新任务，在跑任务继续到完成（Stop 的 ctx 为等待上限；
//     超时返回错误，未确认任务由租约到期自动回收重投）。
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// PoolStats WorkerPool 运行统计（只读快照）。
type PoolStats struct {
	Workers   int   // 并发 worker 数（已按 MaxWorkers 截断）
	Running   int64 // 当前执行中任务数
	Processed int64 // 成功 Ack 数
	Failed    int64 // 失败 Nack 数（含将重投与进死信）
	Lost      int64 // 租约丢失导致 Ack/Nack 失败的次数
	Started   bool
	Stopped   bool
}

// WorkerPool 任务执行池。
type WorkerPool struct {
	q    Queue
	opts PoolOptions

	mu        sync.Mutex
	started   bool
	stopped   bool
	deqCtx    context.Context
	cancelDeq context.CancelFunc
	stopCh    chan struct{}

	wg        sync.WaitGroup // worker 协程
	running   atomic.Int64
	processed atomic.Int64
	failed    atomic.Int64
	lost      atomic.Int64
}

// NewWorkerPool 创建执行池（不启动；Handler 必填，Workers 默认 4、上限 16）。
func NewWorkerPool(q Queue, opts PoolOptions) (*WorkerPool, error) {
	if q == nil {
		return nil, errors.New("worker: 队列为空")
	}
	if opts.Handler == nil {
		return nil, ErrNoHandler
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Workers > MaxWorkers {
		opts.Workers = MaxWorkers
	}
	if opts.LeaseTTL <= 0 {
		opts.LeaseTTL = defaultLeaseTTL
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = opts.LeaseTTL / 3
	}
	if opts.Heartbeat < 10*time.Millisecond {
		opts.Heartbeat = 10 * time.Millisecond
	}
	if opts.WorkerID == "" {
		opts.WorkerID = "worker"
	}
	return &WorkerPool{q: q, opts: opts, stopCh: make(chan struct{})}, nil
}

// Start 启动 worker 协程（只允许一次；ctx 取消时停止拉取并取消执行 ctx）。
func (p *WorkerPool) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return ErrPoolStarted
	}
	p.started = true
	p.deqCtx, p.cancelDeq = context.WithCancel(ctx)
	for i := 0; i < p.opts.Workers; i++ {
		p.wg.Add(1)
		go p.run(ctx, i)
	}
	return nil
}

// run 单个 worker 主循环：拉取 → 执行 → 再拉取；停止信号/ctx 结束时退出。
func (p *WorkerPool) run(ctx context.Context, idx int) {
	defer p.wg.Done()
	workerID := fmt.Sprintf("%s-%d", p.opts.WorkerID, idx)
	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		lease, err := p.q.Dequeue(p.deqCtx, workerID, p.opts.LeaseTTL)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, ErrQueueClosed) {
				return
			}
			// 队列临时异常：短暂退避，避免忙转（停止/取消时立刻退出）
			select {
			case <-time.After(20 * time.Millisecond):
			case <-p.stopCh:
				return
			case <-ctx.Done():
				return
			}
			continue
		}
		p.handle(ctx, lease)
	}
}

// handle 执行单个任务：心跳续租 + Handler + Ack/Nack。
func (p *WorkerPool) handle(ctx context.Context, lease *Lease) {
	p.running.Add(1)
	defer p.running.Add(-1)

	hctx, hcancel := context.WithCancel(ctx)
	defer hcancel()

	hbStop := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		p.heartbeat(hctx, hcancel, hbStop, lease)
	}()

	err := p.opts.Handler(hctx, lease.Task)
	close(hbStop)
	hbWG.Wait()

	if err == nil {
		if aerr := p.q.Ack(context.Background(), lease); aerr != nil {
			p.lost.Add(1) // 租约已丢：任务会被重投，不计成功
			return
		}
		p.processed.Add(1)
		return
	}
	if nerr := p.q.Nack(context.Background(), lease, err.Error()); nerr != nil {
		p.lost.Add(1)
		return
	}
	p.failed.Add(1)
}

// heartbeat 周期续租；续租失败（租约被回收）立即取消执行 ctx。
func (p *WorkerPool) heartbeat(ctx context.Context, cancel context.CancelFunc,
	stop <-chan struct{}, lease *Lease) {
	t := time.NewTicker(p.opts.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := p.q.Heartbeat(context.Background(), lease, p.opts.LeaseTTL); err != nil {
				cancel()
				return
			}
		}
	}
}

// Stop 优雅停止：停止拉取新任务，等待在跑任务完成。
// ctx 为等待上限；超时返回错误（未确认任务由租约到期自动回收重投）。
func (p *WorkerPool) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return ErrPoolNotStarted
	}
	first := !p.stopped
	if first {
		p.stopped = true
		p.cancelDeq()
	}
	p.mu.Unlock()
	if first {
		close(p.stopCh)
	}
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("worker: 优雅停止超时（在跑任务未完成）：%w", ctx.Err())
	}
}

// Stats 运行统计快照。
func (p *WorkerPool) Stats() PoolStats {
	p.mu.Lock()
	st := PoolStats{Workers: p.opts.Workers, Started: p.started, Stopped: p.stopped}
	p.mu.Unlock()
	st.Running = p.running.Load()
	st.Processed = p.processed.Load()
	st.Failed = p.failed.Load()
	st.Lost = p.lost.Load()
	return st
}

// Workers 并发 worker 数（已按 MaxWorkers 截断）。
func (p *WorkerPool) Workers() int { return p.opts.Workers }
