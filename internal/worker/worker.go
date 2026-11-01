// Package worker 企业版 6.x 分布式任务执行骨架：任务队列（lease/心跳/重投/
// 幂等键）+ WorkerPool（并发消费、优雅停止、重试与死信）。
//
// 设计口径（与扫描器主链路解耦，engine/server 不感知）：
//   - Queue 接口只表达分布式队列语义（Enqueue/Dequeue/Ack/Nack/Heartbeat），
//     内存实现 MemoryQueue 用 mutex 保护状态 + notify channel 唤醒阻塞消费者；
//   - lease（可见性超时）：Dequeue 投递后任务进入 running，租约到期仍未 Ack
//     则回收重投（计一次尝试）；心跳可续租；
//   - 重试上限：任务尝试次数达到 MaxAttempts 后失败进入死信队列（state=dead），
//     不再重投；
//   - 幂等键：同 TenantID + IdempotencyKey 重复 Enqueue 只保留一条任务并返回
//     首次的 ID（同 key 不重复执行）；跨租户互不影响；
//   - WorkerPool 并发上限 16（超出截断），优雅停止只停拉取、等在跑任务完成。
//
// 本包零外部依赖（仅标准库），不读写 engine/server 状态；接线方负责按 Kind
// 分派业务 Handler 与提供分布式 Queue 实现（Redis/DB 等实现同一接口即可）。
package worker

import (
	"context"
	"errors"
	"time"
)

// State 任务状态。
type State string

const (
	StatePending State = "pending" // 已入队待投递
	StateRunning State = "running" // 已投递（持有租约）
	StateDone    State = "done"    // 执行成功并 Ack
	StateFailed  State = "failed"  // 本次尝试失败、等待重投
	StateDead    State = "dead"    // 重试耗尽/不可重试，进入死信队列
)

// 队列/池错误（errors.Is 可用）。
var (
	// ErrQueueClosed 队列已关闭，不再接受新任务。
	ErrQueueClosed = errors.New("worker: 队列已关闭")
	// ErrLeaseExpired 租约已过期/已被回收/不属于该投递（旧 worker 不得再 Ack）。
	ErrLeaseExpired = errors.New("worker: 租约已过期或不属于该投递")
	// ErrInvalidLease 租约参数非法（nil/缺 token/缺 task id）。
	ErrInvalidLease = errors.New("worker: 租约参数非法")
	// ErrPoolNotStarted WorkerPool 未启动即调用 Stop。
	ErrPoolNotStarted = errors.New("worker: 池未启动")
	// ErrPoolStarted WorkerPool 重复启动。
	ErrPoolStarted = errors.New("worker: 池已启动")
	// ErrNoHandler WorkerPool 未配置 Handler。
	ErrNoHandler = errors.New("worker: 未配置 Handler")
)

// Task 一个待执行任务。
type Task struct {
	ID             string    // 任务 ID（空 = Enqueue 自动生成）
	TenantID       string    // 租户（多租户隔离；幂等键按租户隔离）
	Kind           string    // 任务类型（由 Handler 分派业务）
	Payload        []byte    // 任务载荷（调用方自定义编码，本包不解释）
	IdempotencyKey string    // 幂等键（空 = 不去重；同租户同 key 只执行一次）
	MaxAttempts    int       // 重试上限（0 = 用队列默认值）
	CreatedAt      time.Time // 入队时间（空 = Enqueue 填充）
}

// Lease 一次投递的租约（分布式语义：租户/执行者/到期时间）。
type Lease struct {
	Token    string    // 投递令牌（唯一；Ack/Nack/Heartbeat 必须带同一令牌）
	Task     Task      // 被投递的任务快照
	TenantID string    // 任务所属租户（= Task.TenantID）
	WorkerID string    // 领取任务的 worker 标识
	Deadline time.Time // 租约到期时间（到期未 Ack 则回收重投）
	Attempts int       // 本次是第几次投递（从 1 开始）
}

// Queue 分布式任务队列接口。
//
// Dequeue 阻塞直到有可见任务或 ctx 结束（取消/超时）；leaseTTL<=0 用队列默认。
// Ack 标记成功；Nack 标记本次尝试失败（未达重试上限则重投，否则进死信）；
// Heartbeat 续租（租约已被回收时返回 ErrLeaseExpired）。
type Queue interface {
	Enqueue(ctx context.Context, t Task) (string, error)
	Dequeue(ctx context.Context, workerID string, leaseTTL time.Duration) (*Lease, error)
	Ack(ctx context.Context, lease *Lease) error
	Nack(ctx context.Context, lease *Lease, reason string) error
	Heartbeat(ctx context.Context, lease *Lease, extend time.Duration) (*Lease, error)
}

// DeadLetter 死信记录（重试耗尽/不可重试的任务）。
type DeadLetter struct {
	Task     Task      // 任务快照（Attempts 为最终尝试次数）
	Reason   string    // 最后一次失败原因（Nack reason / 租约过期说明）
	Attempts int       // 总投递次数
	FailedAt time.Time // 进入死信的时间
}

// QueueStats 队列状态快照（只读）。
type QueueStats struct {
	Pending   int   // 待投递
	Running   int   // 持有租约执行中
	Done      int   // 已完成
	Failed    int   // 尝试失败、等待重投
	Dead      int   // 死信
	Leases    int   // 当前活跃租约数
	Enqueued  int64 // 累计入队（含去重命中前的新任务）
	Delivered int64 // 累计投递次数
}

// Handler 任务执行器（按 Task.Kind 分派业务；ctx 在租约丢失时被取消）。
type Handler func(ctx context.Context, t Task) error

// PoolOptions WorkerPool 参数。
type PoolOptions struct {
	Workers   int           // 并发 worker 数（默认 4；硬上限 MaxWorkers=16，超出截断）
	LeaseTTL  time.Duration // 租约/可见性超时（默认 30s）
	Heartbeat time.Duration // 心跳续租间隔（默认 LeaseTTL/3，最小 10ms）
	Handler   Handler       // 任务执行器（必填）
	WorkerID  string        // worker 标识前缀（默认 "worker"）
}

// MaxWorkers WorkerPool 并发硬上限（产品红线：单实例并发 ≤16）。
const MaxWorkers = 16

// defaultLeaseTTL 默认租约（可见性超时）。
const defaultLeaseTTL = 30 * time.Second

// defaultMaxAttempts 默认重试上限（含首次投递）。
const defaultMaxAttempts = 3
