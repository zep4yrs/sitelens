package intel

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	nvdRetryWait = 2 * time.Second         // 单页失败重试的基础退避（测试可注入）
)

// SyncNVD 全量镜像 NVD CVE 字典到 outPath（JSON.gz，tmp+rename 原子写）。
//
// 源 NVD API 2.0（公开，无需凭据；NVD_API_KEY 环境变量非必填，有则放宽限速）。
// apiKey 只从环境变量读取，不落配置、不落日志。
//
// C2-09 断点续传：全量同步在无 key 限速下要数小时，旧实现任一页失败即
// return，已抓页面全部作废。现在每页失败先重试（2 次退避），仍失败则把
// 已抓条目 + 下一页 startIndex 落盘到 outPath+".partial.json.gz" 再返回错误；
// 下次运行自动从断点继续，成功后删除断点文件。部分进度也会周期性落盘，
// 进程被杀时最多丢最近 N 页。
func SyncNVD(outPath, apiKey string, progress func(done, total int, skipped int)) error {
	const (
		pageSize      = 2000
		progressEvery = 25 // 每 N 页落一次断点（避免频繁写数百 MB）
		maxRetries    = 3
	)
	delay := nvdNoKeyWait
	if apiKey != "" {
		delay = nvdKeyWait
	}
	client := &http.Client{Timeout: 120 * time.Second}

	progPath := nvdProgressPath(outPath)
	var cves []NVDEntry
	startIndex := 0
	skipped := 0
	total := -1
	if p, err := loadNVDProgress(progPath); err != nil {
		log.Printf("intel: NVD 断点文件损坏，重新开始全量同步（%s）：%v", progPath, err)
	} else if p != nil {
		cves, startIndex, total = p.Entries, p.StartIndex, p.Total
		log.Printf("intel: 从断点继续 NVD 同步：已有 %d 条，startIndex=%d，total=%d",
			len(cves), startIndex, total)
		if len(cves) > 0 && progress != nil {
			progress(len(cves), total, skipped)
		}
	}
	pageNo := startIndex / pageSize
	for {
		if total >= 0 && startIndex >= total && len(cves) > 0 {
			break
		}
		pageNo++
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", nvdAPIURL, pageSize, startIndex)
		var (
			entries []NVDEntry
			rej     nvdPageMeta
			err     error
		)
		for attempt := 1; attempt <= maxRetries; attempt++ {
			entries, rej, err = fetchNVDPage(client, url, apiKey)
			if err == nil {
				break
			}
			log.Printf("intel: NVD 第 %d 页失败（第 %d/%d 次）：%v", pageNo, attempt, maxRetries, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * nvdRetryWait)
			}
		}
		if err != nil {
			if serr := saveNVDProgress(progPath, &nvdSyncProgress{
				Version: 1, StartIndex: startIndex, Total: total,
				UpdatedAt: time.Now().Format(time.RFC3339), Entries: cves,
			}); serr != nil {
				return fmt.Errorf("第 %d 页失败且断点写入失败（已抓 %d 条无法保留）: %v（原错误: %w）",
					pageNo, len(cves), serr, err)
			}
			return fmt.Errorf("第 %d 页失败，已保留断点（%d 条，重跑本命令可从断点继续，断点文件 %s）: %w",
				pageNo, len(cves), progPath, err)
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
		if pageNo%progressEvery == 0 {
			if serr := saveNVDProgress(progPath, &nvdSyncProgress{
				Version: 1, StartIndex: startIndex, Total: total,
				UpdatedAt: time.Now().Format(time.RFC3339), Entries: cves,
			}); serr != nil {
				log.Printf("intel: NVD 断点写入失败（%d 条）：%v", len(cves), serr)
			}
		}
		// 用原始 vulnerabilities 条数判断是否还有下一页：Rejected 条目会被
		// 过滤掉，若整页都是 Rejected 则 len(entries)==0 会误判结束。
		if rej.raw == 0 || (total >= 0 && startIndex >= total) {
			break
		}
		time.Sleep(delay)
	}
	if err := writeNVDFile(outPath, cves); err != nil {
		return err
	}
	// 成功：清掉断点文件（失败不影响已写出的正式文件）。
	if err := os.Remove(progPath); err != nil && !os.IsNotExist(err) {
		log.Printf("intel: 删除 NVD 断点文件失败（%s）：%v", progPath, err)
	}
	return nil
}

// fetchNVDPage 拉取并解析一页 NVD API 数据（含 HTTP 状态校验）。
func fetchNVDPage(client *http.Client, url, apiKey string) ([]NVDEntry, nvdPageMeta, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nvdPageMeta{}, err
	}
	req.Header.Set("User-Agent", "SiteLens")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nvdPageMeta{}, err
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, nvdPageMeta{}, fmt.Errorf("读取响应失败: %w", rerr)
	}
	if resp.StatusCode != 200 {
		return nil, nvdPageMeta{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode,
			strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	return parseNVDPage(body)
}

// nvdProgressPath 断点文件路径（与正式产物同目录，成功后被删除）。
func nvdProgressPath(outPath string) string { return outPath + ".partial.json.gz" }

// nvdSyncProgress NVD 分页同步断点（C2-09）。
type nvdSyncProgress struct {
	Version    int        `json:"version"`
	StartIndex int        `json:"start_index"`
	Total      int        `json:"total"`
	UpdatedAt  string     `json:"updated_at"`
	Entries    []NVDEntry `json:"entries"`
}

// loadNVDProgress 读断点文件；不存在返回 (nil, nil)。
func loadNVDProgress(path string) (*nvdSyncProgress, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var p nvdSyncProgress
	if err := json.NewDecoder(gz).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// saveNVDProgress 原子写断点文件（tmp+rename，gz 压缩）。
func saveNVDProgress(path string, p *nvdSyncProgress) error {
	if path == "" || p == nil {
		return fmt.Errorf("断点参数为空")
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(p); err != nil {
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
	return os.Rename(tmp, path)
}

// nvdPageMeta 页级元信息。
type nvdPageMeta struct {
	total   int
	skipped int
	raw     int // 原始 vulnerabilities 条数（含 Rejected），判断翻页结束用
}

// parseNVDPage 解析一页/一文件 NVD CVE 数据（API 2.0 与年度 feed 同格式），
// 返回投影后的条目与元信息。API 与 feed 两条同步路径共用此函数。
func parseNVDPage(body []byte) ([]NVDEntry, nvdPageMeta, error) {
	var page nvdPageJSON
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, nvdPageMeta{}, err
	}
	entries, meta := projectNVDPage(page)
	return entries, meta, nil
}

// parseNVDPageReader 与 parseNVDPage 同语义，但直接从流解码（年度 feed
// 路径用，避免 io.ReadAll 把解压后的整年 JSON 再复制一份，C2-12）。
func parseNVDPageReader(r io.Reader) ([]NVDEntry, nvdPageMeta, error) {
	var page nvdPageJSON
	if err := json.NewDecoder(r).Decode(&page); err != nil {
		return nil, nvdPageMeta{}, err
	}
	entries, meta := projectNVDPage(page)
	return entries, meta, nil
}

// projectNVDPage 把已解码的页投影为紧凑条目。
func projectNVDPage(page nvdPageJSON) ([]NVDEntry, nvdPageMeta) {
	meta := nvdPageMeta{total: page.TotalResults, raw: len(page.Vulnerabilities)}
	var out []NVDEntry
	for _, v := range page.Vulnerabilities {
		c := v.Cve
		if c.VulnStatus == "Rejected" {
			meta.skipped++
			continue
		}
		out = append(out, cveToEntry(c))
	}
	return out, meta
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
	// 评分优先 v3.1 → v3.0 → v2：按版本优先级取**第一个存在的 metric**。
	//
	// C2-04：旧实现用 `e.Score == 0` 当"尚未取到"的哨兵，于是官方 0.0 分
	// （Impact<=0 的合法结果）会被下一版本的分数覆盖；同时 0 分在写端被
	// omitempty 省略，读端无法与"缺失"区分。现在用独立的 ScoreSet 标记，
	// 0 分也保留为真实评分。
	for _, metricName := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		if e.ScoreSet {
			break
		}
		ms, ok := c.Metrics[metricName]
		if !ok || len(ms) == 0 {
			continue
		}
		e.Score = ms[0].CvssData.BaseScore
		e.Vector = ms[0].CvssData.VectorString
		e.Sev = strings.ToLower(ms[0].CvssData.BaseSeverity)
		e.ScoreSet = true
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
