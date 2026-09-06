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
func (k *KB) MergeKEV(entries []KevEntry) int {
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
