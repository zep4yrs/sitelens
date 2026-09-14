package intel

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NVD 年度批量 feed 同步（4.0 P5 新增）。
//
// 背景：NVD API 2.0 无 key 限速 5 请求/30 秒，全库（30 万+ CVE）需数小时；
// feed 走 CDN 分发，按年打包（每年 3~10MB），全量同步时间大幅缩短，
// 且**数据与 API 2.0 同格式**（顶层 vulnerabilities[].cve），解析逻辑复用
// parseNVDPage。
//
// 用法：
//
//	sitelens update-nvd feed [起始年] [结束年]
//
// 未给年份默认 2002..当前年（NVD 从 2002 起有数据）。产出文件与 API 模式一致，
// 且**新增 CWEs 字段**（v2 格式）。

// nvdFeedURL 年度 feed 模板（{year} 占位）。测试可注入替换。
var nvdFeedURL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz"

// nvdFeedMetaURL 年度 meta 文件（含 sha256，可选校验）。当前仅记录，未强制校验。
var nvdFeedMetaURL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.meta"

// SyncNVDFeed 从年度 feed 同步 [fromYear, toYear] 的 CVE 到 outPath。
//
// 逐年下载、逐年解析、合并写出；单年失败不中断（记录到错误列表），
// 全部年份都失败才返回错误。progress(done,total,skipped) 按「已处理年份」回调。
func SyncNVDFeed(outPath string, fromYear, toYear int,
	progress func(done, total, skipped int)) error {

	if fromYear < 2002 {
		fromYear = 2002
	}
	if toYear < fromYear {
		toYear = fromYear
	}
	client := &http.Client{Timeout: 10 * time.Minute}

	var all []NVDEntry
	var errs []error
	skipped := 0
	yearCount := toYear - fromYear + 1
	done := 0

	for y := fromYear; y <= toYear; y++ {
		url := fmt.Sprintf(nvdFeedURL, y)
		entries, rej, err := fetchFeedYear(client, url)
		if err != nil {
			errs = append(errs, fmt.Errorf("%d 年: %w", y, err))
			done++
			if progress != nil {
				progress(done, yearCount, skipped)
			}
			continue
		}
		all = append(all, entries...)
		skipped += rej.skipped
		done++
		if progress != nil {
			progress(done, yearCount, skipped)
		}
	}
	if len(all) == 0 {
		if len(errs) > 0 {
			return fmt.Errorf("年度 feed 全部失败：%w", errs[0])
		}
		return fmt.Errorf("年度 feed 未取到任何 CVE（检查年份范围 %d-%d）", fromYear, toYear)
	}
	if err := writeNVDFile(outPath, all); err != nil {
		return err
	}
	if len(errs) > 0 {
		// 部分年份失败：数据已写出，但明确告知缺口（不静默）。
		return fmt.Errorf("部分年份失败（已写出 %d 条）：%v", len(all), errs)
	}
	return nil
}

// fetchFeedYear 下载并解析单一年度的 feed。
func fetchFeedYear(client *http.Client, url string) ([]NVDEntry, nvdPageMeta, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nvdPageMeta{}, err
	}
	req.Header.Set("User-Agent", "SiteLens")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nvdPageMeta{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nvdPageMeta{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// feed 是 .json.gz，直接流式 gunzip。
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nvdPageMeta{}, fmt.Errorf("gunzip: %w", err)
	}
	body, err := io.ReadAll(gz)
	if err != nil {
		return nil, nvdPageMeta{}, fmt.Errorf("读取: %w", err)
	}
	return parseNVDPage(body)
}

// feedYearOf 从 meta 文本提取 lastModifiedDate（辅助信息；当前未强制校验）。
func feedYearOf(metaJSON []byte) string {
	var m struct {
		LastModifiedDate string `json:"lastModifiedDate"`
	}
	_ = json.Unmarshal(metaJSON, &m)
	return m.LastModifiedDate
}
