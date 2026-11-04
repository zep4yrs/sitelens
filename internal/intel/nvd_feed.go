package intel

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"strings"
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
// 且**新增 CWEs 字段**（v2 格式；v3 起 prods 只留 vendor/product）。

// nvdFeedURL 年度 feed 模板（{year} 占位）。测试可注入替换。
var nvdFeedURL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz"

// nvdFeedMetaURL 年度 meta 文件模板。meta 为 JSON，含 sha256 / lastModifiedDate。
var nvdFeedMetaURL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.meta"

// errFeedDigestMismatch 标记"下载内容与 meta 声明摘要不符"（C2-12）。
// 这种失败意味着数据完整性不可信：调用方必须拒绝该年数据，且不得覆盖旧文件。
var errFeedDigestMismatch = errors.New("年度 feed 摘要校验失败")

// nvdFeedMeta 年度 feed 的 meta 声明（NVD JSON feed 的 .meta 是 JSON）。
type nvdFeedMeta struct {
	LastModifiedDate string `json:"lastModifiedDate"`
	Size             int64  `json:"size"`
	GzSize           int64  `json:"gzSize"`
	SHA256           string `json:"sha256"`
}

// parseFeedMeta 解析 meta JSON。
func parseFeedMeta(data []byte) (*nvdFeedMeta, error) {
	var m nvdFeedMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// fetchFeedMeta 下载并解析年度 meta（1MB 上限；404/解析失败/无 sha256 → error）。
func fetchFeedMeta(client *http.Client, url string) (*nvdFeedMeta, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SiteLens")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 meta: %w", err)
	}
	m, err := parseFeedMeta(data)
	if err != nil {
		return nil, fmt.Errorf("解析 meta: %w", err)
	}
	if strings.TrimSpace(m.SHA256) == "" {
		return nil, errors.New("meta 未声明 sha256")
	}
	return m, nil
}

// SyncNVDFeed 从年度 feed 同步 [fromYear, toYear] 的 CVE 到 outPath。
//
// 逐年下载、逐年解析、合并写出；单年网络/解析失败不中断（记录到错误列表），
// 全部年份都失败才返回错误。progress(done,total,skipped) 按「已处理年份」回调。
//
// C2-12 摘要校验：下载前取该年 meta 的 sha256，对下载到的 gz 字节做流式
// 摘要比对。**任一年摘要不匹配 → 整次更新拒绝写出**（保留旧数据不被覆盖），
// 返回明确错误（含期望/实际摘要）。meta 缺失/不可解析/未声明 sha256 →
// 打 warn 并保持旧行为（不校验），不因 meta 本身故障阻断同步。
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
	var integrityErrs []error
	skipped := 0
	yearCount := toYear - fromYear + 1
	done := 0

	for y := fromYear; y <= toYear; y++ {
		feedURL := fmt.Sprintf(nvdFeedURL, y)
		metaURL := fmt.Sprintf(nvdFeedMetaURL, y)
		wantSHA := ""
		if m, merr := fetchFeedMeta(client, metaURL); merr != nil {
			// meta 不可用：保持旧行为（不校验），但必须留痕，避免"校验静默失效"。
			log.Printf("intel: %d 年 feed meta 不可用，跳过摘要校验（%s）：%v", y, metaURL, merr)
		} else {
			wantSHA = strings.TrimSpace(m.SHA256)
			if m.LastModifiedDate != "" {
				log.Printf("intel: %d 年 feed meta：lastModified=%s sha256=%s", y, m.LastModifiedDate, wantSHA)
			}
		}
		entries, rej, err := fetchFeedYear(client, feedURL, wantSHA)
		if err != nil {
			errs = append(errs, fmt.Errorf("%d 年: %w", y, err))
			if errors.Is(err, errFeedDigestMismatch) {
				integrityErrs = append(integrityErrs, err)
			}
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

	// 摘要与数据完整性直接相关：只要有一年不符就整体拒绝写出，
	// 保留磁盘上已有的（可能是完整的）旧镜像——绝不拿可疑数据覆盖。
	if len(integrityErrs) > 0 {
		return fmt.Errorf("%w：已拒绝更新并保留原文件（%s）；%v",
			errFeedDigestMismatch, outPath, errors.Join(integrityErrs...))
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
//
// wantSHA 非空时对下载的**原始 gz 字节**做流式 sha256 校验（C2-12）：
// 解析与摘要共用同一路 Read，不额外缓冲整份文件；不匹配返回
// errFeedDigestMismatch（含期望/实际），调用方须拒绝该年数据。
// wantSHA == "" 表示 meta 不可用，保持旧行为（不校验）。
func fetchFeedYear(client *http.Client, url, wantSHA string) ([]NVDEntry, nvdPageMeta, error) {
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

	// feed 是 .json.gz，直接流式 gunzip + 流式 JSON 解码（C2-12）：
	// 旧实现 io.ReadAll 会把解压后的整年 JSON（数百 MB 量级）完整读入
	// 内存再 Unmarshal，峰值内存约为数据本身的 2~3 倍。
	var body io.Reader = resp.Body
	var hasher hash.Hash
	if wantSHA != "" {
		hasher = sha256.New()
		body = io.TeeReader(resp.Body, hasher)
	}
	gz, err := gzip.NewReader(body)
	if err != nil {
		return nil, nvdPageMeta{}, fmt.Errorf("gunzip: %w", err)
	}
	entries, meta, perr := parseNVDPageReader(gz)
	// 排空 gzip 流（同时触发 gzip CRC 校验），再经 tee 排空原始字节：
	// 只有把整份下载内容都读过，流式摘要才等价于"对完整文件做 sha256"。
	if _, derr := io.Copy(io.Discard, gz); derr != nil && perr == nil {
		return nil, meta, fmt.Errorf("读取 feed: %w", derr)
	}
	if _, derr := io.Copy(io.Discard, body); derr != nil && perr == nil {
		return nil, meta, fmt.Errorf("读取 feed 尾部: %w", derr)
	}
	if perr != nil {
		return nil, meta, fmt.Errorf("解析 feed: %w", perr)
	}
	if hasher != nil {
		got := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(got, wantSHA) {
			log.Printf("intel: 年度 feed 摘要不符（%s）：meta 声明 sha256=%s，实际 sha256=%s；已拒绝该年数据",
				url, wantSHA, got)
			return nil, meta, fmt.Errorf("%w：meta 声明 sha256=%s，实际 sha256=%s（%s）",
				errFeedDigestMismatch, wantSHA, got, url)
		}
		log.Printf("intel: 年度 feed 摘要校验通过（%s）：sha256=%s", url, got)
	}
	return entries, meta, nil
}

// feedYearOf 从 meta 文本提取 lastModifiedDate（辅助信息）。
func feedYearOf(metaJSON []byte) string {
	m, err := parseFeedMeta(metaJSON)
	if err != nil {
		return ""
	}
	return m.LastModifiedDate
}
