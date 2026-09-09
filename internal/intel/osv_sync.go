package intel

import (
	"sync"
)

// OsvSyncCollect 并发查询 OSV，返回带区间或评分的覆盖集合。
// 网络错误/无记录的 CVE 跳过。workers<=0 时取 8。
func OsvSyncCollect(cves []string, workers int) map[string]Override {
	if workers <= 0 {
		workers = 8
	}
	var mu sync.Mutex
	results := map[string]Override{}
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := NewOsvClient()
			for i := range next {
				cve := cves[i]
				v, err := client.FetchVuln(cve)
				if err != nil || v == nil {
					continue
				}
				aff := OsvAffectedFromVuln(*v)
				score, sev := OsvCVSSFromVuln(*v)
				if aff == "" && score == 0 {
					continue
				}
				mu.Lock()
				results[cve] = Override{Affected: aff, CVSSScore: score, CVSSSev: sev}
				mu.Unlock()
			}
		}()
	}
	go func() {
		for i := 0; i < len(cves); i++ {
			next <- i
		}
		close(next)
	}()
	wg.Wait()
	return results
}
