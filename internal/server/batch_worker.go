// 企业化 6.x：批量扫描 worker 池路径（config.Batch.UseWorkerPool=true 时启用）。
//
// 与旧并发路径（runBatchLegacy）语义对齐：
//   - 同 host 串行（hostLocks）避免把同一站点并发打爆；
//   - 单条 URL 重试 batchMaxAttempts 次（指数退避），成功落历史并计算 diff；
//   - 进度/行/状态文件/取消/Webhook 收尾与旧路径一致。
//
// 默认关闭（UseWorkerPool=false）→ runBatch 直接走旧路径，行为零变化。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
	"cnb.cool/feng-qiao/sitelens/internal/worker"
)

// runBatch 批量入口：按配置分派 worker 池路径或旧并发路径（默认旧路径）。
func (s *Server) runBatch(jobID string, items []batchItem, st *batchState) {
	if s.cfg.Batch.UseWorkerPool {
		s.runBatchWorkerPool(jobID, items, st)
		return
	}
	s.runBatchLegacy(jobID, items, st)
}

// batchTaskPayload worker 任务载荷（批量条目 + 原始下标，用于回写状态文件）。
type batchTaskPayload struct {
	Index int    `json:"i"`
	URL   string `json:"url"`
	Level string `json:"level"`
}

// runBatchWorkerPool 用 worker 池分派批量扫描。
func (s *Server) runBatchWorkerPool(jobID string, items []batchItem, st *batchState) {
	workers := s.cfg.Batch.Workers
	if workers <= 0 {
		workers = 3
	}
	if workers > worker.MaxWorkers {
		workers = worker.MaxWorkers
	}
	const leaseTTL = 10 * time.Minute // 租约上限；心跳按 LeaseTTL/3 续租
	q := worker.NewMemoryQueue(worker.QueueOptions{LeaseTTL: leaseTTL})

	var mu sync.Mutex
	done := 0
	var lines []string
	rows := make([]map[string]any, 0, len(items))
	// 同 host 串行锁（与旧路径一致）。
	hostLocks := map[string]*sync.Mutex{}
	var hostMu sync.Mutex
	lockFor := func(raw string) *sync.Mutex {
		h := batchHost(raw)
		hostMu.Lock()
		defer hostMu.Unlock()
		l, ok := hostLocks[h]
		if !ok {
			l = &sync.Mutex{}
			hostLocks[h] = l
		}
		return l
	}

	pool, err := worker.NewWorkerPool(q, worker.PoolOptions{
		Workers: workers, LeaseTTL: leaseTTL, WorkerID: "batch",
		Handler: func(ctx context.Context, task worker.Task) (herr error) {
			// 单条扫描 panic 不拖垮整个批量任务：转为错误 → 队列记死信。
			defer func() {
				if r := recover(); r != nil {
					herr = fmt.Errorf("批量扫描 panic: %v", r)
				}
			}()
			var payload batchTaskPayload
			if uerr := json.Unmarshal(task.Payload, &payload); uerr != nil {
				return uerr
			}
			it := batchItem{URL: payload.URL, Level: payload.Level}
			i := payload.Index
			if st != nil {
				mu.Lock()
				st.Items[i].Status = "running"
				_ = s.saveBatchState(st)
				mu.Unlock()
			}
			if s.jobs.CancelRequested(jobID) {
				mu.Lock()
				lines = append(lines, it.URL+" -> 已跳过（任务取消）")
				rows = append(rows, map[string]any{"url": it.URL, "status": "skipped", "level": it.Level})
				if st != nil {
					st.Items[i].Status = "skipped"
					_ = s.saveBatchState(st)
				}
				mu.Unlock()
			} else {
				res, attempts, elapsed := s.scanBatchURL(jobID, it, lockFor)
				if res.Error != "" {
					mu.Lock()
					lines = append(lines, it.URL+" -> 失败（"+res.Error+"，尝试 "+fmt.Sprint(attempts)+" 次）")
					rows = append(rows, map[string]any{"url": it.URL, "status": "failed", "error": res.Error,
						"level": it.Level, "attempts": attempts, "elapsed_ms": elapsed})
					if st != nil {
						st.Items[i].Status = "failed"
						st.Items[i].Attempts = attempts
						st.Items[i].Error = res.Error
						st.Items[i].ElapsedMS = elapsed
						_ = s.saveBatchState(st)
					}
					mu.Unlock()
				} else {
					s.st.Save(res, map[string]any{"batch": true})
					row := map[string]any{"url": it.URL, "status": "done",
						"level": it.Level, "attempts": attempts,
						"findings": len(res.Vulnerabilities) + len(res.Verified), "techs": len(res.Technologies), "elapsed_ms": elapsed}
					if n, fx, ok := s.DiffURL(it.URL); ok {
						row["new_findings"] = n
						row["fixed"] = fx
					}
					mu.Lock()
					lines = append(lines, fmt.Sprintf("%s -> 完成（%d 项技术）", it.URL, len(res.Technologies)))
					rows = append(rows, row)
					if st != nil {
						st.Items[i].Status = "done"
						st.Items[i].Attempts = attempts
						st.Items[i].Findings = len(res.Vulnerabilities) + len(res.Verified)
						st.Items[i].Techs = len(res.Technologies)
						st.Items[i].ElapsedMS = elapsed
						_ = s.saveBatchState(st)
					}
					mu.Unlock()
				}
			}
			mu.Lock()
			done++
			d, ln := done, append([]string{}, lines...)
			rws := make([]map[string]any, len(rows))
			copy(rws, rows)
			mu.Unlock()
			s.jobs.Update(jobID, func(j *store.Job) {
				j.Done = d
				j.Progress = d * 100 / len(items)
				if len(ln) > 0 {
					j.Message = ln[len(ln)-1]
				}
				j.Result = map[string]any{"lines": ln, "rows": rws}
			})
			return nil
		},
	})
	if err != nil {
		// 池创建失败（理论不可达）：回退旧路径，保证批量不丢。
		log.Printf("警告：批量 worker 池创建失败（%v）；回退旧并发路径", err)
		s.runBatchLegacy(jobID, items, st)
		return
	}
	if err := pool.Start(context.Background()); err != nil {
		log.Printf("警告：批量 worker 池启动失败（%v）；回退旧并发路径", err)
		s.runBatchLegacy(jobID, items, st)
		return
	}
	enqueued := 0
	for i, it := range items {
		payload, _ := json.Marshal(batchTaskPayload{Index: i, URL: it.URL, Level: it.Level})
		// 单条重试已在 scanBatchURL 内完成，队列不再重复投递（MaxAttempts=1）。
		if _, err := q.Enqueue(context.Background(), worker.Task{
			Kind: "batch-scan", Payload: payload, MaxAttempts: 1,
		}); err != nil {
			log.Printf("警告：批量任务入队失败（%s）：%v", it.URL, err)
			continue
		}
		enqueued++
	}
	if enqueued < len(items) {
		log.Printf("警告：批量任务入队不完整（%d/%d），未入队项按失败收尾", enqueued, len(items))
	}
	// 等待全部任务确认（Ack/死信）；取消时 handler 会把剩余项快速标记 skipped。
	for {
		stats := q.Stats()
		if stats.Done+stats.Dead >= enqueued {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := pool.Stop(context.Background()); err != nil {
		log.Printf("警告：批量 worker 池停止异常：%v", err)
	}
	q.Close()

	// ---- 收尾（与旧路径语义一致） ----
	wasCancelled := s.jobs.CancelRequested(jobID)
	if st != nil {
		if wasCancelled {
			st.Cancelled = true
			_ = s.saveBatchState(st)
		} else {
			st.Finished = true
			_ = s.saveBatchState(st)
			s.deleteBatchState(jobID)
		}
	}
	s.jobs.Update(jobID, func(j *store.Job) {
		if wasCancelled {
			j.Status = "cancelled"
			j.Message = "批量已取消（未开始的 URL 已跳过，可断点续跑）"
		} else {
			j.Status = "done"
			j.Message = "批量完成"
		}
	})
	mu.Lock()
	finalRows := make([]map[string]any, len(rows))
	copy(finalRows, rows)
	finalDone := done
	mu.Unlock()
	if hook := s.cfg.Batch.WebhookURL; hook != "" {
		event := "batch.done"
		if wasCancelled {
			event = "batch.cancelled"
		}
		payload := map[string]any{
			"event": event, "job_id": jobID, "total": len(items), "done": finalDone,
			"tag": batchTagOf(items), "rows": finalRows,
		}
		go func() {
			if err := NotifyBatch(hook, payload); err != nil {
				log.Printf("批量 webhook 通知失败：%v", err)
			}
		}()
	}
}

// scanBatchURL 执行单条批量扫描（含重试/退避/同 host 串行/信号量），
// 旧路径与 worker 池路径共用，保证两条路径扫描语义一致。
func (s *Server) scanBatchURL(jobID string, it batchItem, lockFor func(string) *sync.Mutex) (*engine.Result, int, int64) {
	start := time.Now()
	opts := engine.DefaultOptions()
	if it.Level != "" {
		opts = scanOptions(map[string]any{"level": it.Level})
	}
	var res *engine.Result
	attempts := 0
	hostLock := lockFor(it.URL)
	for attempt := 1; attempt <= batchMaxAttempts; attempt++ {
		attempts = attempt
		s.sem <- struct{}{}
		hostLock.Lock()
		res = s.eng.Scan(it.URL, opts, nil,
			func() bool { return s.jobs.CancelRequested(jobID) })
		hostLock.Unlock()
		<-s.sem
		if res.Error == "" || s.jobs.CancelRequested(jobID) {
			break
		}
		if attempt < batchMaxAttempts {
			time.Sleep(time.Duration(attempt*300) * time.Millisecond)
		}
	}
	return res, attempts, time.Since(start).Milliseconds()
}
