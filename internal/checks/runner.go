// 验证引擎执行器：RunChecks（软 404 基线 / 回显剔除 / 二次确认）。
package checks

import (
	"fmt"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// Hit 一条已验证发现。
type Hit struct {
	Check    string `json:"check"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
}

// Options 执行参数。
type Options struct {
	Level       string
	IncludeIDs  []string
	CancelCheck func() bool
	OnProgress  func(done, total int, msg string)
}

var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func sortHits(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool {
		sa, sb := severityRank[hits[i].Severity], severityRank[hits[j].Severity]
		if sa != sb {
			return sa < sb
		}
		return hits[i].Check < hits[j].Check
	})
}

// RunChecks 执行 check 集（core = 核心集，all = 核心+扩展+联动）。
func RunChecks(client *httpx.Client, targetURL string, level string,
	includeIDs []string, cancelCheck func() bool,
	onProgress func(done, total int, msg string)) []Hit {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	inc := map[string]bool{}
	for _, id := range includeIDs {
		inc[id] = true
	}
	var selected []Check
	for _, c := range allChecks {
		if level == "all" || c.Lv == 0 || inc[c.ID] {
			selected = append(selected, c)
		}
	}

	baseSize, basePrefix := soft404Baseline(client, targetURL)

	hits := []Hit{}
	total := len(selected)
	for i, chk := range selected {
		if cancelCheck != nil && cancelCheck() {
			break
		}
		u := joinURL(targetURL, strings.TrimLeft(chk.Path, "/"))
		resp, gerr := client.GetFollow(u)
		if gerr != nil || resp == nil {
			onProgress(i+1, total, chk.Path)
			continue
		}
		body := stripEcho(resp.Body, u, chk.Path)
		if !matchBody(chk.Match, body) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		// 软 404：与不存在路径响应一致
		if baseSize > 0 && len(resp.Body) == baseSize &&
			strings.HasPrefix(strings.ToLower(body[:min(200, len(body))]),
				strings.ToLower(basePrefix[:min(200, len(basePrefix))])) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		// 二次确认：立即重放，两次都命中才采信
		resp2, gerr2 := client.GetFollow(u)
		if gerr2 != nil {
			onProgress(i+1, total, chk.Path)
			continue
		}
		body2 := stripEcho(resp2.Body, u, chk.Path)
		if !matchBody(chk.Match, body2) {
			onProgress(i+1, total, chk.Path)
			continue
		}
		hits = append(hits, Hit{
			Check: chk.ID, Title: chk.Title, Severity: chk.Sev,
			URL: u, Advice: chk.Advice,
			Evidence: fmt.Sprintf("HTTP %d（二次确认）", resp2.Status),
		})
		onProgress(i+1, total, chk.Path)
	}
	sortHits(hits)
	return hits
}

// matchBody 判定 body 是否满足 check 的包含条件。
func matchBody(m Match, body string) bool {
	if len(m.Contains) == 0 {
		return m.Status != 404 && m.Status != 0
	}
	for _, kw := range m.Contains {
		if !strings.Contains(body, kw) {
			return false
		}
	}
	return true
}

// stripEcho 剔除响应中回显的请求 URL 与路径（防自指误报）。
func stripEcho(body string, reqURL string, path string) string {
	body = strings.ReplaceAll(body, reqURL, "")
	body = strings.ReplaceAll(body, path, "")
	return body
}

func joinURL(base, path string) string {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + strings.TrimLeft(path, "/")
}

// soft404Baseline 取一个不存在路径的响应做软 404 基线。
func soft404Baseline(client *httpx.Client, targetURL string) (int, string) {
	resp, err := client.GetFollow(joinURL(targetURL, "__sitelens_probe_none__"))
	if err != nil || resp == nil {
		return 0, ""
	}
	prefix := strings.ToLower(resp.Body)
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	return len(resp.Body), prefix
}
