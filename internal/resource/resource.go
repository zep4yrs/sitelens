// Package resource 资源治理（4.0 Track A）。
//
// 起因（原开发文档立项）：用户实测「任务管理器里资源占用有点高」——引擎空闲
// RSS ≈1GB。定位主因是情报库全量常驻解码 + 无 GC 软上限。本包承载 Track A 的
// 可测试件，避免把调优散落到 main/serve 里。
//
// 当前实现：
//
//	A1 GC 软上限（SetMemoryLimit + SetGCPercent）——零行为变化的 Quick Win
//	A4 归还 RSS（FreeOSMemory，扫描结束后调用）
//
// 设计：全部为**进程级、幂等、可关**的调整，默认参数保守（软限 1GiB），
// 不影响正确性；不改变任何扫描语义。
package resource

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
)

// appliedLimitBytes 缓存 Apply 设置的上限（读指标时用；不靠 SetMemoryLimit 回读，
// 因为「读」的唯一 API 是 SetMemoryLimit(-1) 再设回——那会在读的瞬间临时取消限制）。
var appliedLimitBytes atomic.Int64

// GCConfig GC 调优参数（零值 = 用默认）。
type GCConfig struct {
	// MemoryLimitMiB 软内存上限（MiB）。0 = 用 DefaultMemoryLimitMiB。
	// 负值 = 不设上限（显式关闭）。
	MemoryLimitMiB int
	// GCPercent GOGC 目标百分比。0 = 用 DefaultGCPercent；负值 = 不调整。
	GCPercent int
}

const (
	// DefaultMemoryLimitMiB 默认软内存上限：1 GiB。
	// 依据：4.0 目标「引擎空闲 RSS ≤ 300MB / full 峰值 ≤ 800MB」，
	// 1GiB 软限给足余量又能让 GC 在尖峰前提早介入（Go 默认只按堆增长倍率回收，
	// 1.5GB 峰值实测即由此放大）。
	DefaultMemoryLimitMiB = 1024
	// DefaultGCPercent 默认 GOGC。Go 默认 100（堆翻倍才回收）；
	// 降到 70 让回收更早、堆更紧，代价是少量 CPU——对扫描类工作负载合适。
	DefaultGCPercent = 70
)

// Apply 应用 GC 调优。幂等；返回实际生效的参数（便于日志与测试断言）。
//
// 说明：SetMemoryLimit 是**软限制**——超限时 GC 更积极地回收，而不是拒绝分配
// （不会导致 OOM 或分配失败），故对正确性零影响。
func Apply(cfg GCConfig) (limitBytes int64, gcPercent int) {
	limitMiB := cfg.MemoryLimitMiB
	switch {
	case limitMiB == 0:
		limitMiB = DefaultMemoryLimitMiB
	case limitMiB < 0:
		limitMiB = -1 // 显式关闭
	}
	if limitMiB > 0 {
		limitBytes = int64(limitMiB) << 20
		debug.SetMemoryLimit(limitBytes)
	} else {
		// 恢复「无软限」：Go 用 math.MaxInt64 表示不限制。
		limitBytes = int64(^uint64(0) >> 1)
		debug.SetMemoryLimit(limitBytes)
	}
	appliedLimitBytes.Store(limitBytes)

	gc := cfg.GCPercent
	switch {
	case gc == 0:
		gc = DefaultGCPercent
	case gc < 0:
		gc = -1
	}
	if gc > 0 {
		debug.SetGCPercent(gc)
	}
	return limitBytes, gc
}

// ReleaseToOS 把未使用的堆内存归还操作系统（A4）。
//
// 用于「扫描结束」钩子：扫描期堆会膨胀，不主动归还时任务管理器里的 RSS
// 要等很久才回落（Go 的 scavenger 是渐进式的）。FreeOSMemory 会触发一次
// stop-the-world 的强制回收——**只在扫描边界调用**（不在热路径），
// 代价可接受，换来用户「扫描完内存立刻降下来」的直观感受。
func ReleaseToOS() {
	debug.FreeOSMemory()
}

// DefaultGCConfig 默认 GC 配置（供调用方显式传参时使用）。
func DefaultGCConfig() GCConfig {
	return GCConfig{MemoryLimitMiB: DefaultMemoryLimitMiB, GCPercent: DefaultGCPercent}
}

// Stats 返回当前内存运行指标（资源仪表用；只读）。
type Stats struct {
	HeapAllocMiB   float64 `json:"heap_alloc_mb"`   // 当前堆上对象占用
	HeapSysMiB     float64 `json:"heap_sys_mb"`     // 向 OS 申请的堆
	HeapInuseMiB   float64 `json:"heap_inuse_mb"`   // 在用 span
	RSSMiB         float64 `json:"rss_mb"`          // 进程常驻（近似）
	NumGC          uint32  `json:"num_gc"`          // GC 次数
	Goroutines     int     `json:"goroutines"`      // 协程数
	MemoryLimitMiB float64 `json:"memory_limit_mb"` // 当前软上限（-1 = 不限）
}

// Snapshot 采集一次内存指标。RSS 用 HeapSys 近似——Go 标准库不直接暴露 RSS，
// 但对「资源占用大概多少」这个用途足够（HeapSys 是向 OS 申请的量）。
//
// 软上限取缓存值；若从未 Apply（缓存为 0），临时用 SetMemoryLimit(-1) 读一次
// 运行时真值并**立刻设回**（该窗口极短且只发生在首次采集）。
func Snapshot() Stats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	const mib = 1024 * 1024
	limit := appliedLimitBytes.Load()
	if limit == 0 {
		limit = debug.SetMemoryLimit(-1) // 读运行时真值
		debug.SetMemoryLimit(limit)      // 立刻设回
	}
	return Stats{
		HeapAllocMiB:   bytesToMiB(m.HeapAlloc),
		HeapSysMiB:     bytesToMiB(m.HeapSys),
		HeapInuseMiB:   bytesToMiB(m.HeapInuse),
		RSSMiB:         bytesToMiB(m.HeapSys),
		NumGC:          m.NumGC,
		Goroutines:     runtime.NumGoroutine(),
		MemoryLimitMiB: float64(limit) / mib,
	}
}

func bytesToMiB(b uint64) float64 {
	return float64(int64(b)/1024.0/1024.0*10) / 10
}
