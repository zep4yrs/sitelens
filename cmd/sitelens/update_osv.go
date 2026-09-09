// update-osv 子命令：从 OSV.dev 为 vuln_kb 的 CVE 补全受影响区间与
// CVSS 评分，落盘覆盖文件（serve 启动时自动合并）。公开 API 无需凭据。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

func updateOSVCommand(cfg *config.Config, workers int) int {
	kb, err := intel.Load(cfg.Intel.DumpPath, cfg.Intel.RangesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "情报库加载失败：", err)
		return 1
	}
	jobs := kb.CollectCVEs()
	fmt.Fprintf(os.Stderr, "待查询 CVE：%d 个（并发 %d，源 api.osv.dev）\n", len(jobs), workers)
	if len(jobs) == 0 {
		return 0
	}
	if workers <= 0 {
		workers = 8
	}

	var mu sync.Mutex
	var results []struct {
		cve string
		ov  intel.Override
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := intel.NewOsvClient()
			for i := range next {
				cve := jobs[i]
				v, err := client.FetchVuln(cve)
				if err != nil || v == nil {
					continue // 404/网络抖动：跳过，下次同步再补
				}
				aff := intel.OsvAffectedFromVuln(*v)
				score, sev := intel.OsvCVSSFromVuln(*v)
				if aff == "" && score == 0 {
					continue
				}
				mu.Lock()
				results = append(results, struct {
					cve string
					ov  intel.Override
				}{cve, intel.Override{Affected: aff, CVSSScore: score, CVSSSev: sev}})
				mu.Unlock()
			}
		}()
	}
	go func() {
		for i := 0; i < len(jobs); i++ {
			next <- i
		}
		close(next)
	}()
	wg.Wait()

	ov := map[string]intel.Override{}
	for _, r := range results {
		ov[r.cve] = r.ov
	}
	data, err := json.MarshalIndent(ov, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "序列化失败：", err)
		return 1
	}
	if err := os.WriteFile(cfg.Intel.OverridesPath, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写入失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "OSV 同步完成：%d 条覆盖写入 %s\n", len(results), cfg.Intel.OverridesPath)
	fmt.Fprintln(os.Stderr, "下次 serve 启动时自动合并进知识库。")
	return 0
}
