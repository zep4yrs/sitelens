package resource

import (
	"runtime"
	"runtime/debug"
	"testing"
)

// TestApplySetsLimitAndGC：A1 生效——软上限与 GOGC 被设为期望值。
func TestApplySetsLimitAndGC(t *testing.T) {
	// 用完恢复原值（避免影响同进程其它测试）。
	oldLimit := debug.SetMemoryLimit(-1)
	oldGC := debug.SetGCPercent(-1)
	debug.SetMemoryLimit(oldLimit)
	debug.SetGCPercent(oldGC)
	defer func() {
		debug.SetMemoryLimit(oldLimit)
		debug.SetGCPercent(oldGC)
	}()

	limitBytes, gc := Apply(GCConfig{MemoryLimitMiB: 256, GCPercent: 50})
	if want := int64(256) << 20; limitBytes != want {
		t.Errorf("软上限 = %d，期望 %d", limitBytes, want)
	}
	if gc != 50 {
		t.Errorf("GOGC = %d，期望 50", gc)
	}
	// 运行时读回校验（读完立刻设回）。
	got := debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(got)
	if got != limitBytes {
		t.Errorf("运行时软上限 = %d，期望 %d", got, limitBytes)
	}
	if p := debug.SetGCPercent(-1); p != 50 {
		t.Errorf("运行时 GOGC = %d，期望 50", p)
	} else {
		debug.SetGCPercent(p)
	}
}

// TestApplyDefaults：零值 → 默认参数（1GiB / 70）。
func TestApplyDefaults(t *testing.T) {
	oldLimit := debug.SetMemoryLimit(-1)
	oldGC := debug.SetGCPercent(-1)
	defer func() {
		debug.SetMemoryLimit(oldLimit)
		debug.SetGCPercent(oldGC)
	}()
	limitBytes, gc := Apply(GCConfig{})
	if want := int64(DefaultMemoryLimitMiB) << 20; limitBytes != want {
		t.Errorf("默认软上限 = %d，期望 %d", limitBytes, want)
	}
	if gc != DefaultGCPercent {
		t.Errorf("默认 GOGC = %d，期望 %d", gc, DefaultGCPercent)
	}
}

// TestApplyNegativeDisablesLimit：负值 = 显式关闭软限（保留可关能力）。
func TestApplyNegativeDisablesLimit(t *testing.T) {
	oldLimit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(oldLimit)

	limitBytes, _ := Apply(GCConfig{MemoryLimitMiB: -1, GCPercent: -1})
	// Go 的「不限」= math.MaxInt64
	if limitBytes != int64(^uint64(0)>>1) {
		t.Errorf("关闭软限应设 math.MaxInt64，实得 %d", limitBytes)
	}
}

// TestSnapshotNoSideEffect：A1 关键正确性——Snapshot 读取**不得**改动当前软限
// （SetMemoryLimit 的读法是设 -1 再设回，早期实现有副作用）。
func TestSnapshotNoSideEffect(t *testing.T) {
	oldLimit := debug.SetMemoryLimit(-1)
	oldGC := debug.SetGCPercent(-1)
	defer func() {
		debug.SetMemoryLimit(oldLimit)
		debug.SetGCPercent(oldGC)
	}()
	Apply(GCConfig{MemoryLimitMiB: 512, GCPercent: 70})

	_ = Snapshot() // 多次采集
	_ = Snapshot()

	got := debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(got)
	if want := int64(512) << 20; got != want {
		t.Errorf("Snapshot 后软上限被改动：%d，期望 %d", got, want)
	}
	st := Snapshot()
	if st.MemoryLimitMiB < 511 || st.MemoryLimitMiB > 513 {
		t.Errorf("Snapshot.MemoryLimitMiB = %.1f，期望 ≈512", st.MemoryLimitMiB)
	}
}

// TestSnapshotReportsRuntime：指标可采集且非零（资源仪表数据源）。
func TestSnapshotReportsRuntime(t *testing.T) {
	Apply(GCConfig{MemoryLimitMiB: 256})
	// 分配一点内存，确保有可观测的堆占用。
	buf := make([][]byte, 64)
	for i := range buf {
		buf[i] = make([]byte, 64*1024)
	}
	runtime.GC()
	st := Snapshot()
	if st.HeapAllocMiB <= 0 || st.HeapSysMiB <= 0 {
		t.Errorf("堆指标应 > 0：alloc=%.1f sys=%.1f", st.HeapAllocMiB, st.HeapSysMiB)
	}
	if st.Goroutines <= 0 {
		t.Errorf("协程数应 > 0，实得 %d", st.Goroutines)
	}
	runtime.KeepAlive(buf)
}

// TestReleaseToOS：A4 可调用且不 panic（归还后堆仍在合理范围）。
func TestReleaseToOS(t *testing.T) {
	buf := make([]byte, 8<<20)
	buf[0] = 1
	ReleaseToOS()
	st := Snapshot()
	if st.HeapSysMiB < 0 {
		t.Error("指标异常")
	}
	runtime.KeepAlive(buf)
}
