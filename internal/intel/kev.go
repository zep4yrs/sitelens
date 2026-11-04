// KEV 在野利用清单的获取、合并与本地缓存。
// 对齐 python 分支 scanner/intel_update.py 的守护语义：
// 服务启动即拉取一次，此后按配置间隔（默认 24h）轮询 CISA 公开源。
package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// KEVFeedURL CISA 已知被利用漏洞公开源（固定常量，无用户输入，无 SSRF 面）。
const KEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// FetchKEV 拉取并解析 KEV 源，返回条目。
func FetchKEV(feedURL string, timeout time.Duration) ([]KevEntry, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(feedURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("KEV 源返回 HTTP %d", resp.StatusCode)
	}
	var feed struct {
		Title string `json:"title"`
		CVEs  []struct {
			CVE       string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&feed); err != nil {
		return nil, err
	}
	out := make([]KevEntry, 0, len(feed.CVEs))
	for _, c := range feed.CVEs {
		out = append(out, KevEntry{CVE: c.CVE, DateAdded: c.DateAdded})
	}
	return out, nil
}

// MergeKEV 把条目并入内存 KEV 索引，返回新增条数。
//
// 并发纪律（BUG-004）：KEV 守护 goroutine 会周期性调用本方法，而同进程
// 扫描线程在 Match/ServiceProbe 路径上读 KEV 表；map 无锁并发读写会让
// Go 直接 fatal error（不可 recover，整个 serve 进程退出）。写侧统一持
// kevMu 写锁，读侧持读锁（见 IsKEV / kevCount）。
func (k *KB) MergeKEV(entries []KevEntry) int {
	k.kevMu.Lock()
	defer k.kevMu.Unlock()
	if k.kev == nil {
		k.kev = map[string]bool{}
	}
	added := 0
	for _, e := range entries {
		key := e.CVE
		if key == "" {
			continue
		}
		key = upper(key)
		if !k.kev[key] {
			k.kev[key] = true
			added++
		}
	}
	return added
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

// SaveKEVExtra 本地缓存（data/state/kev_extra.json），重启后无需等待拉取。
func SaveKEVExtra(path string, entries []KevEntry) error {
	data, err := json.Marshal(map[string]any{"updated_at": time.Now().Format(time.RFC3339), "cves": entries})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadKEVExtra 读取本地缓存。
func LoadKEVExtra(path string) ([]KevEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var box struct {
		CVEs []KevEntry `json:"cves"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return nil, err
	}
	return box.CVEs, nil
}

// IsKEV 查询 CVE 是否在 CISA KEV（在野利用）清单内。
// 供 4.0 impact 先验标注（P10）等外部消费方使用；未挂载/未知返回 false。
// 并发安全：与 MergeKEV 的写并发（BUG-004）。
func (k *KB) IsKEV(cve string) bool {
	if k == nil || cve == "" {
		return false
	}
	key := strings.ToUpper(strings.TrimSpace(cve))
	k.kevMu.RLock()
	ok := k.kev[key]
	k.kevMu.RUnlock()
	return ok
}

// kevCount KEV 表条数（并发安全；供 Stats 使用）。
func (k *KB) kevCount() int {
	if k == nil {
		return 0
	}
	k.kevMu.RLock()
	defer k.kevMu.RUnlock()
	return len(k.kev)
}

// CVSSFor 查询 CVE 的 CVSS base score（NVD 投影；未挂载/未知返回 0）。
// 供 4.0 impact 先验标注（P10）使用。
func (k *KB) CVSSFor(cve string) float64 {
	if k == nil || cve == "" {
		return 0
	}
	if s := k.NVD(); s != nil {
		if e, ok := s.ByCVE(cve); ok {
			return e.Score
		}
	}
	return 0
}

// CVSSForLoaded 同 CVSSFor，但**只在 NVD 索引已常驻时**查询（不触发 1.7GB
// 懒加载），第二个返回值报告该条是否携带真实评分（0.0 也算，C2-04/C2-02）。
// 供扫描/图收尾这类"顺带查询"的消费方使用。
func (k *KB) CVSSForLoaded(cve string) (float64, bool) {
	if k == nil || cve == "" {
		return 0, false
	}
	s := k.NVDIfLoaded()
	if s == nil {
		return 0, false
	}
	e, ok := s.ByCVE(cve)
	if !ok {
		return 0, false
	}
	return e.Score, e.HasScore()
}
