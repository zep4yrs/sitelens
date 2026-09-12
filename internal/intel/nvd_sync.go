package intel

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// 可注入点（测试用）：API 端点与页间节流。
var (
	nvdAPIURL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdNoKeyWait = 6500 * time.Millisecond // 无 key 官方限速 5 请求/30 秒
	nvdKeyWait   = 1100 * time.Millisecond // 有 key 50 请求/30 秒，留余量
)

// SyncNVD 全量镜像 NVD CVE 字典到 outPath（JSON.gz，tmp+rename 原子写）。
//
// 源 NVD API 2.0（公开，无需凭据；NVD_API_KEY 环境变量非必填，有则放宽限速）。
// apiKey 只从环境变量读取，不落配置、不落日志。
func SyncNVD(outPath, apiKey string, progress func(done, total int, skipped int)) error {
	const (
		pageSize = 2000
	)
	delay := nvdNoKeyWait
	if apiKey != "" {
		delay = nvdKeyWait
	}
	client := &http.Client{Timeout: 120 * time.Second}

	var cves []NVDEntry
	startIndex := 0
	skipped := 0
	total := -1
	for {
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", nvdAPIURL, pageSize, startIndex)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "SiteLens")
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("第 %d 页请求失败: %w", startIndex/pageSize+1, err)
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("第 %d 页读取失败: %w", startIndex/pageSize+1, rerr)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("第 %d 页 HTTP %d: %s", startIndex/pageSize+1, resp.StatusCode,
				strings.TrimSpace(string(body[:min(len(body), 200)])))
		}
		var page struct {
			TotalResults    int `json:"totalResults"`
			ResultsPerPage  int `json:"resultsPerPage"`
			Vulnerabilities []struct {
				Cve struct {
					ID           string `json:"id"`
					Published    string `json:"published"`
					LastModified string `json:"lastModified"`
					VulnStatus   string `json:"vulnStatus"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Metrics map[string][]struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							VectorString string  `json:"vectorString"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"metrics"`
					Configurations []struct {
						Nodes []struct {
							CpeMatch []cpeMatchJSON `json:"cpeMatch"`
						} `json:"nodes"`
					} `json:"configurations"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("第 %d 页解析失败: %w", startIndex/pageSize+1, err)
		}
		if total < 0 {
			total = page.TotalResults
		}
		for _, v := range page.Vulnerabilities {
			c := v.Cve
			if c.VulnStatus == "Rejected" {
				skipped++
				continue
			}
			e := NVDEntry{
				CVE: c.ID, Pub: c.Published, Mod: c.LastModified,
			}
			for _, d := range c.Descriptions {
				if d.Lang == "en" {
					e.Descr = truncateRunes(d.Value, 280)
					break
				}
			}
			// 评分优先 v3.1 → v3.0 → v2（无 key 响应里同为空则留空）
			for _, metricName := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
				if ms, ok := c.Metrics[metricName]; ok && len(ms) > 0 && e.Score == 0 {
					e.Score = ms[0].CvssData.BaseScore
					e.Vector = ms[0].CvssData.VectorString
					e.Sev = strings.ToLower(ms[0].CvssData.BaseSeverity)
				}
			}
			seen := map[string]bool{}
			for _, cfgItem := range c.Configurations {
				for _, node := range cfgItem.Nodes {
					for _, m := range node.CpeMatch {
						if m.Criteria == "" || seen[m.Criteria] {
							continue
						}
						seen[m.Criteria] = true
						vp, ver, ok := cpeVendorProduct(m.Criteria)
						if !ok {
							continue
						}
						e.Prods = append(e.Prods, NVDProd{
							VP: vp, V: ver,
							EE: m.VersionEndExcluding, EI: m.VersionEndIncluding,
							SE: m.VersionStartExcluding, SI: m.VersionStartIncluding,
						})
					}
				}
			}
			cves = append(cves, e)
		}
		if progress != nil {
			progress(len(cves), total, skipped)
		}
		startIndex += pageSize
		if len(page.Vulnerabilities) == 0 || startIndex >= total {
			break
		}
		time.Sleep(delay)
	}
	return writeNVDFile(outPath, cves)
}

// cpeMatchJSON NVD 响应里的单条 CPE 匹配约束。
type cpeMatchJSON struct {
	Criteria              string `json:"criteria"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
}

// cpeVendorProduct 从 cpe23Uri 取 part/vendor/product 与版本段。
func cpeVendorProduct(criteria string) (vp, ver string, ok bool) {
	// cpe:2.3:a:vendor:product:version:...
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 || parts[0] != "cpe" {
		return "", "", false
	}
	if parts[5] != "*" && parts[5] != "" {
		ver = parts[5]
	}
	return parts[3] + "/" + parts[4], ver, true
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func writeNVDFile(outPath string, cves []NVDEntry) error {
	tmp := outPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)
	if err := enc.Encode(map[string]any{
		"version": 1,
		"count":   len(cves),
		"cves":    cves,
	}); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, outPath)
}
