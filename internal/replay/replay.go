// Package replay 验证回归（3.0 P3）：把历史已验证发现按原探针重放，
// 判定「仍在/已修复」。重放语义与 dast 探测一致：同 URL + 原 payload
// 单请求，不跟随重定向；时延类/出带类发现不可单请求复现，计 unsupported
// 不进回归分母（诚实口径）。
package replay

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/dast"
)

// NewFetcher 标准重放客户端（不跟随重定向；timeout 毫秒，0=10s）。
func NewFetcher(timeoutMS int) dast.Fetcher {
	t := 10 * time.Second
	if timeoutMS > 0 {
		t = time.Duration(timeoutMS) * time.Millisecond
	}
	return noRedirectClient{client: &http.Client{
		Timeout: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type noRedirectClient struct{ client *http.Client }

func (c noRedirectClient) GetSmall(rawURL string) *dast.Resp {
	resp, err := c.client.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || len(buf) >= 64*1024 {
			break
		}
	}
	return &dast.Resp{Status: resp.StatusCode, Headers: map[string]string{
		"Location": resp.Header.Get("Location"),
	}, Body: string(buf)}
}

func (c noRedirectClient) PostFormSmall(rawURL string, data map[string]string) *dast.Resp {
	return c.GetSmall(rawURL)
}

// Status 单条重放结论。
type Status string

const (
	Present     Status = "present"     // 仍在：原探针再次命中
	Gone        Status = "gone"        // 已修复：原探针不再命中
	Unsupported Status = "unsupported" // 类别不可单请求复现（不计分母）
)

// Stats 批量重放统计。
type Stats struct {
	Total       int `json:"total"`
	Present     int `json:"present"`
	Gone        int `json:"gone"`
	Unsupported int `json:"unsupported"`
}

// RegressionRate 回归率（1.0 = 全部仍在；分母为可重放条数）。
func (s Stats) RegressionRate() float64 {
	denom := s.Present + s.Gone
	if denom == 0 {
		return 0
	}
	return float64(s.Present) / float64(denom)
}

// sqlErrKeywords 报错型 SQLi 的最小复判词表（与 dast 探测同源语义的子集）。
var sqlErrKeywords = []string{
	"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
	"sqlserver", "unclosed quotation", "quoted string not properly terminated",
}

// One 重放单条已验证发现（v = history 里的 verified map）。
func One(f dast.Fetcher, v map[string]any) (Status, string) {
	check, _ := v["check"].(string)
	url, _ := v["url"].(string)
	param, _ := v["param"].(string)
	payload, _ := v["payload"].(string)
	if url == "" || param == "" || payload == "" {
		return Unsupported, "缺少 url/param/payload（旧记录或非注入类发现）"
	}
	probe := dast.SetParam(url, param, payload)
	resp := f.GetSmall(probe)
	if resp == nil {
		return Gone, "请求失败（目标不可达或响应为空）"
	}
	body := strings.ToLower(resp.Body)
	loc := resp.Header("Location")
	switch check {
	case "xss-reflect":
		if strings.Contains(resp.Body, "<script") && strings.Contains(strings.ToLower(resp.Body), strings.ToLower(payload)) {
			return Present, "原 payload 仍以未转义 script 回显"
		}
		return Gone, "标记被转义或未回显"
	case "sqli-error":
		for _, kw := range sqlErrKeywords {
			if strings.Contains(body, kw) {
				return Present, "SQL 报错特征仍在：" + kw
			}
		}
		return Gone, "报错特征消失"
	case "open-redirect":
		if (resp.Status == 301 || resp.Status == 302 || resp.Status == 303 ||
			resp.Status == 307 || resp.Status == 308) && strings.Contains(loc, payload) {
			return Present, "Location 仍精确携带原 payload"
		}
		return Gone, "跳转不再携带注入目标"
	case "lfi-passwd":
		if strings.Contains(body, "root:") {
			return Present, "/etc/passwd 内容仍可读"
		}
		return Gone, "系统文件不可读"
	default:
		return Unsupported, fmt.Sprintf("类别 %s 暂不支持单请求重放", check)
	}
}

// Batch 重放一批 verified 条目（自动跳过非 dast 来源）。
func Batch(f dast.Fetcher, entries []map[string]any) (Stats, []Result) {
	st := Stats{}
	var out []Result
	for i, v := range entries {
		if src, _ := v["src"].(string); src != "dast" {
			continue
		}
		st.Total++
		s, note := One(f, v)
		switch s {
		case Present:
			st.Present++
		case Gone:
			st.Gone++
		default:
			st.Unsupported++
		}
		out = append(out, Result{Idx: i, Check: str(v, "check"), Status: s, Note: note})
	}
	return st, out
}

// Result 单条重放明细。
type Result struct {
	Idx    int    `json:"idx"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Note   string `json:"note"`
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}
