// Evidence 抽取：从 httpx 响应提取指纹匹配所需的全部信号。
// HTML 解析统一走 internal/htmlx（标题/脚本/meta 单一实现）。
package sitelens

import (
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// Evidence 一次采集得到的全部信号（对齐 Python extract_signals 的子集）。
type Evidence struct {
	URL         string
	FinalURL    string
	Status      int
	Headers     map[string]string
	Body        string
	Title       string            // <title>
	ScriptSrcs  []string          // <script src> 外链地址
	Metas       map[string]string // meta name/property(小写) → content
	CookieNames []string          // Set-Cookie 的 Cookie 名列表
}

// Header 大小写不敏感取响应头。
func (e *Evidence) Header(name string) string {
	for k, v := range e.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// Extract 从响应抽取证据。
func Extract(resp *httpx.Response) *Evidence {
	doc := htmlx.Parse(resp.Body)
	ev := &Evidence{
		URL:        resp.FinalURL,
		FinalURL:   resp.FinalURL,
		Status:     resp.Status,
		Headers:    resp.Headers,
		Body:       resp.Body,
		Title:      doc.Title,
		ScriptSrcs: doc.ScriptSrcs,
		Metas:      doc.Metas,
	}
	ev.CookieNames = parseCookieNames(resp.Header("Set-Cookie"))
	return ev
}

// parseCookieNames 从 Set-Cookie 值中取 Cookie 名（支持合并头切分）。
func parseCookieNames(setCookie string) []string {
	var names []string
	seen := map[string]bool{}
	for _, seg := range strings.Split(setCookie, ",") {
		head := strings.TrimSpace(strings.SplitN(seg, ";", 2)[0])
		if head == "" {
			continue
		}
		nv := strings.SplitN(head, "=", 2)
		name := strings.ToLower(strings.TrimSpace(nv[0]))
		if name == "" || name == "expires" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}
