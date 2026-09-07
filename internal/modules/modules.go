// Package modules 主动探测模块：目录探测 / 子域名枚举 / WebShell 探测。
// 默认关闭，仅限授权目标；请求总量有硬上限（config.ActiveConfig）。
// 判定语义对齐 python 分支 scanner/modules.py：
// 目录命中 = 200/401/403 且尺寸偏离软404基线；403 可选一次绕过重试；
// 子域名 = DNS 可解析；WebShell = 200 且正文非空。
package modules

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// PageHit 一条路径探测命中（目录 / WebShell 共用行结构）。
type PageHit struct {
	URL    string `json:"url"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Title  string `json:"title"`
}

// loadWords 字典加载：去空行 + 截取上限。
func loadWords(dir, name string, limit int) []string {
	if limit <= 0 {
		limit = 300
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// soft404Sizes 基线：探测随机不存在路径的响应尺寸集合。
func soft404Sizes(client *httpx.Client, baseURL string) map[int]bool {
	sizes := map[int]bool{}
	for _, p := range []string{"sl-nope-9f3a2", "sl-nope-81b7d?q=x"} {
		u := strings.TrimRight(baseURL, "/") + "/" + p
		if r, err := client.GetFollow(u); err == nil && r != nil {
			sizes[len(r.Body)] = true
		}
	}
	return sizes
}

// bypassHeaders 403 绕过重试常用头（Python dir_bypass 同款思路）。
func bypassHeaders() map[string]string {
	return map[string]string{
		"X-Forwarded-For": "127.0.0.1",
		"Referer":         "base",
		"X-Original-URL":  "base",
	}
}

// DirScan 目录探测：命中 = 200/401/403 且尺寸不在软404基线；
// 403 且 bypass 开启时以伪造来源头重试一次。
func DirScan(client *httpx.Client, baseURL string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []PageHit {
	words := loadWords(cfg.WordlistDir, "dir_default.txt", cfg.DirMaxPaths)
	if len(words) == 0 {
		return nil
	}
	base := strings.TrimRight(baseURL, "/")
	baseline := soft404Sizes(client, baseURL)
	hits := []PageHit{}
	for i, w := range words {
		if cancel != nil && cancel() {
			break
		}
		u := base + "/" + strings.TrimLeft(w, "/")
		r, err := client.GetFollow(u)
		if err != nil || r == nil {
			if progress != nil {
				progress(i+1, len(words), w)
			}
			continue
		}
		status := r.Status
		if status == 403 && cfg.DirBypass403 {
			h := bypassHeaders()
			h["Referer"] = baseURL
			h["X-Original-URL"] = "/"
			if r2, e2 := client.GetFollowWith(u, h); e2 == nil && r2 != nil {
				status = r2.Status
				r = r2
			}
		}
		if (status == 200 || status == 401 || status == 403) && !baseline[len(r.Body)] {
			hits = append(hits, PageHit{
				URL: u, Path: "/" + strings.TrimLeft(w, "/"),
				Status: status, Size: len(r.Body),
				Title: htmlx.Parse(r.Body).Title,
			})
		}
		if progress != nil {
			progress(i+1, len(words), w)
		}
	}
	return hits
}

// WebshellProbe WebShell 探测：命中 = 200 且正文非空（后台马常驻路径）。
func WebshellProbe(client *httpx.Client, baseURL string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []PageHit {
	words := loadWords(cfg.WordlistDir, "shell_default.txt", cfg.ShellMaxPaths)
	if len(words) == 0 {
		return nil
	}
	base := strings.TrimRight(baseURL, "/")
	// 软 404 基线：与 DirScan 同源——站点对不存在路径返回 200+内容时，
	// 未过滤会把每个探测路径都误报成 webshell（tools 站实测暴露）
	baseline := soft404Sizes(client, baseURL)
	hits := []PageHit{}
	for i, w := range words {
		if cancel != nil && cancel() {
			break
		}
		u := base + "/" + strings.TrimLeft(w, "/")
		r, err := client.GetFollow(u)
		if err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 && !baseline[len(r.Body)] {
			hits = append(hits, PageHit{
				URL: u, Path: "/" + strings.TrimLeft(w, "/"),
				Status: 200, Size: len(r.Body),
			})
		}
		if progress != nil {
			progress(i+1, len(words), w)
		}
	}
	return hits
}

// Resolver 域名解析函数（可注入替身便于离线测试）。
type Resolver func(host string) ([]string, error)

// systemResolver 系统 DNS。
func systemResolver(host string) ([]string, error) { return net.LookupHost(host) }

// SubdomainEnum 子域名枚举：字典并发解析，可解析即视为存在。
func SubdomainEnum(domain string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool) []string {
	return SubdomainEnumWith(domain, cfg, progress, cancel, systemResolver)
}

// SubdomainEnumWith 可注入解析器的枚举实现。
func SubdomainEnumWith(domain string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool,
	resolve Resolver) []string {
	words := loadWords(cfg.WordlistDir, "subs_default.txt", cfg.SubMaxWords)
	if len(words) == 0 || domain == "" {
		return nil
	}
	workers := cfg.SubWorkers
	if workers <= 0 {
		workers = 20
	}
	var mu sync.Mutex
	found := []string{}
	idx := atomic.Int64{}
	var wg sync.WaitGroup
	total := len(words)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if cancel != nil && cancel() {
					return
				}
				i := int(idx.Add(1)) - 1
				if i >= total {
					return
				}
				sub := words[i] + "." + domain
				if addrs, err := resolve(sub); err == nil && len(addrs) > 0 {
					mu.Lock()
					found = append(found, sub)
					mu.Unlock()
				}
				if progress != nil {
					progress(i+1, total, words[i])
				}
			}
		}()
	}
	wg.Wait()
	return found
}

// FormatHits 汇总行文本（进度消息用）。
func FormatHit(h PageHit) string {
	return fmt.Sprintf("%s -> %d (%dB)", h.Path, h.Status, h.Size)
}

// FPHit FingerDir 主动指纹命中。
type FPHit struct {
	Product string `json:"product"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

// ActiveFP FingerDir 主动路径指纹：对精编 spec 路径逐个探测，
// status/body_contains/body_not_contains/content_type/header_contains
// 声明的条件全命中才算（对齐 Python _spec_match）。maxRequests 为请求上限。
func ActiveFP(client *httpx.Client, baseURL string,
	rows []intel.FingerDirRow, progress func(done, total int, msg string),
	cancel func() bool, maxRequests int) []FPHit {
	if maxRequests <= 0 {
		maxRequests = 30
	}
	base := strings.TrimRight(baseURL, "/")
	total := 0
	for _, r := range rows {
		total += len(r.Spec.Paths)
	}
	if total > maxRequests {
		total = maxRequests
	}
	done := 0
	hits := []FPHit{}
	for _, row := range rows {
		for _, p := range row.Spec.Paths {
			if done >= maxRequests {
				return hits
			}
			if cancel != nil && cancel() {
				return hits
			}
			u := base + p
			r, err := client.GetDirect(u)
			done++
			if err == nil && r != nil && specMatch(r, row.Spec) {
				hits = append(hits, FPHit{Product: row.Product, Path: p, Status: r.Status})
			}
			if progress != nil {
				progress(done, total, row.Product)
			}
		}
	}
	return hits
}

// specMatch 全部声明条件均须满足。
func specMatch(r *httpx.Response, spec intel.FingerDirMatchSpec) bool {
	if len(spec.Status) > 0 {
		okStatus := false
		for _, s := range spec.Status {
			if r.Status == s {
				okStatus = true
				break
			}
		}
		if !okStatus {
			return false
		}
	}
	low := strings.ToLower(r.Body)
	for _, kw := range spec.BodyContains {
		if !strings.Contains(low, strings.ToLower(kw)) {
			return false
		}
	}
	for _, kw := range spec.BodyNotContains {
		if strings.Contains(low, strings.ToLower(kw)) {
			return false
		}
	}
	ct := ""
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
			break
		}
	}
	for _, kw := range spec.ContentType {
		if !strings.Contains(strings.ToLower(ct), strings.ToLower(kw)) {
			return false
		}
	}
	for _, kw := range spec.HeaderContains {
		found := false
		for k, v := range r.Headers {
			if strings.Contains(strings.ToLower(k+"="+v), strings.ToLower(kw)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
