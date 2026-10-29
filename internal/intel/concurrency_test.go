package intel

// 并发一致性回归用例（BUG-004 在 kev_test.go；此文件覆盖 BUG-014）。

import (
	"strings"
	"sync"
	"testing"
)

// TestApplyOverridesConcurrentMatchConsistent BUG-014 回归：OSV 同步
// （ApplyOverrides 合并覆盖）与扫描线程（Match 遍历情报表 / Stats 统计）
// 并发。
//
// 注：本机 CGO_ENABLED=0 且无 C 编译器，-race 无法运行（-race requires
// cgo）；用例按 -race 友好设计，需在带 CGO 的环境用
// `CGO_ENABLED=1 go test -race ./internal/intel` 复核。
//
// 旧实现在 k.vulns 上原地 sort.Slice 并逐条改字段，扫描可能读到
// 「Affected 已补齐、CVSS 还是旧值」这类错配中间态（静默错误结论），
// 排序与遍历并发还会让扫描看到乱序行。修法为副本合并 + 整体替换：
// 任意时刻读侧看到的常驻表，要么是「覆盖前」，要么是「覆盖后」，
// 每行的字段组合必须自洽。
func TestApplyOverridesConcurrentMatchConsistent(t *testing.T) {
	kb := &KB{
		vulns: []Entry{
			{ID: 1, Src: "afrog", Name: "Log4Shell", Product: "Apache Log4j",
				CVE: "CVE-2021-44228", Severity: "high", Affected: ">=2.0,<2.15"},
			{ID: 2, Src: "afrog", Name: "Log4j 拒绝服务", Product: "Apache Log4j",
				CVE: "CVE-2021-45046", Severity: "critical"},
		},
		kev: map[string]bool{},
	}
	techs := []TechHit{{Name: "Apache Log4j", Version: "2.14.0"}}
	// 预热：惰性解码标记/关键词索引只建一次，避免把「首用初始化」的
	// 并发也算进本用例（本用例只验证覆盖合并与扫描读的快照一致性）。
	if got := kb.Match(techs); len(got) != 2 {
		t.Fatalf("预热 Match 应命中 2 条情报行: %+v", got)
	}

	ov := map[string]Override{
		"CVE-2021-44228": {Affected: ">=2.0,<2.16", CVSSScore: 10, CVSSSev: "critical"},
	}
	const iters = 200
	var wg sync.WaitGroup
	// 写：模拟 OSV 同步 goroutine 反复合并覆盖
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			kb.ApplyOverrides(ov)
		}
	}()
	// 读 1：模拟扫描线程并发 Match（-race 下必须干净）
	wg.Add(2)
	for r := 0; r < 2; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				out := kb.Match(techs)
				if len(out) != 2 {
					t.Errorf("扫描命中数不稳定（换代中间态）: %d", len(out))
				}
			}
		}()
	}
	// 读 2：读侧快照一致性——每条情报行的「区间补齐」与「CVSS 补齐」
	// 必须同时到位或同时缺席，且 ID 序始终有序（旧实现原地排序/改字段
	// 会在这里看到半新半旧）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			kb.vulnsMu.RLock()
			prevID := int64(-1 << 62)
			for j := range kb.vulns {
				e := kb.vulns[j]
				if e.ID < prevID {
					t.Errorf("快照 ID 序错乱: %d 在 %d 之后", e.ID, prevID)
				}
				prevID = e.ID
				if e.CVE != "CVE-2021-44228" {
					continue
				}
				mergedRange := strings.Contains(e.Affected, "2.16")
				mergedCVSS := e.CVSSScore == 10
				if mergedRange != mergedCVSS {
					t.Errorf("覆盖合并中间态: affected=%q cvss=%v", e.Affected, e.CVSSScore)
				}
			}
			kb.vulnsMu.RUnlock()
			_ = kb.IsKEV("CVE-2021-44228")
			_ = kb.kevCount()
		}
	}()
	wg.Wait()

	// 合并最终必须全量生效（每次调用都全量合到副本上，不会丢更新）。
	for _, e := range kb.vulns {
		if e.CVE == "CVE-2021-44228" {
			if !strings.Contains(e.Affected, ">=2.0,<2.16") || e.CVSSScore != 10 {
				t.Fatalf("覆盖未生效: %+v", e)
			}
		}
	}
	out := kb.Match(techs)
	if len(out) != 2 {
		t.Fatalf("合并后 Match 命中数 = %d，期望 2", len(out))
	}
}
