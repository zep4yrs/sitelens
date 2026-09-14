package intel

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
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
		entries, rej, err := parseNVDPage(body)
		if err != nil {
			return fmt.Errorf("第 %d 页解析失败: %w", startIndex/pageSize+1, err)
		}
		if total < 0 {
			total = rej.total
		}
		skipped += rej.skipped
		cves = append(cves, entries...)
		if progress != nil {
			progress(len(cves), total, skipped)
		}
		startIndex += pageSize
		if len(entries) == 0 || startIndex >= total {
			break
		}
		time.Sleep(delay)
	}
	return writeNVDFile(outPath, cves)
}

// nvdPageMeta 页级元信息。
type nvdPageMeta struct {
	total   int
	skipped int
}

// parseNVDPage 解析一页/一文件 NVD CVE 数据（API 2.0 与年度 feed 同格式），
// 返回投影后的条目与元信息。API 与 feed 两条同步路径共用此函数。
func parseNVDPage(body []byte) ([]NVDEntry, nvdPageMeta, error) {
	var page nvdPageJSON
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, nvdPageMeta{}, err
	}
	meta := nvdPageMeta{total: page.TotalResults}
	var out []NVDEntry
	for _, v := range page.Vulnerabilities {
		c := v.Cve
		if c.VulnStatus == "Rejected" {
			meta.skipped++
			continue
		}
		out = append(out, cveToEntry(c))
	}
	return out, meta, nil
}

// cveToEntry 把 NVD 原始 CVE 投影为紧凑 NVDEntry（含 P5 的 CWEs）。
func cveToEntry(c nvdCVEJSON) NVDEntry {
	e := NVDEntry{CVE: c.ID, Pub: c.Published, Mod: c.LastModified}
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
	// CWE 关联（P5）：weaknesses 里的 CWE-NNN，过滤占位值，去重升序。
	e.CWEs = collectCWEs(c.Weaknesses)
	seen := map[string]bool{}
	for _, cfgItem := range c.Configurations {
		for _, node := range cfgItem.Nodes {
			for _, m := range node.CpeMatch {
				if m.Criteria == "" || seen[m.Criteria] {
					continue
				}
				seen[m.Criteria] = true
				vp, _, ok := cpeVendorProduct(m.Criteria)
				if !ok {
					continue
				}
				// A2：只留 vendor/product（版本边界无消费方，见 NVDProd 注释）
				e.Prods = append(e.Prods, NVDProd{VP: vp})
			}
		}
	}
	return e
}

// nvdPageJSON NVD API 2.0 页 / 年度 feed 的顶层结构（两者同形）。
type nvdPageJSON struct {
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		Cve nvdCVEJSON `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdCVEJSON NVD 单条 CVE 的原始结构（API 与 feed 同形）。
type nvdCVEJSON struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Weaknesses []nvdWeaknessJSON `json:"weaknesses"`
	Metrics    map[string][]struct {
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
}

// cpeMatchJSON NVD 响应里的单条 CPE 匹配约束。
type cpeMatchJSON struct {
	Criteria              string `json:"criteria"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
}

// nvdWeaknessJSON NVD 响应里的单条 weakness（P5）。
type nvdWeaknessJSON struct {
	Type        string `json:"type"`
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}

// collectCWEs 从 NVD weaknesses 里抽取 CWE 编号（去重、升序）。
// 只保留形如 CWE-<数字> 的值；NVD-CWE-noinfo / NVD-CWE-Other 等占位值丢弃
// （它们不携带真实弱类型信息，收进来只会污染关联）。
func collectCWEs(ws []nvdWeaknessJSON) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range ws {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if !isCWENumber(v) || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// isCWENumber 判断是否为 CWE-<数字> 形态（区分 CWE 编号与 NVD 占位值）。
func isCWENumber(s string) bool {
	if !strings.HasPrefix(s, "CWE-") {
		return false
	}
	digits := s[len("CWE-"):]
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
		"version": 3, // v3：prods 只留 vp（A2 瘦身；v1/v2 数据仍可读）
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
