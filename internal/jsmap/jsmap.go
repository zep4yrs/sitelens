// Package jsmap JS 攻击面提取：bundle 内 API 端点枚举 + SourceMap 泄露检测。
// 源码地图（.js.map）公网可访问即暴露原始源码；bundle 里硬编码的接口路径
// 暴露内部 API 攻击面。均为只读检测。移植自 python 分支 scanner/jsmap.py。
package jsmap

import (
	"net/url"
	"regexp"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

var apiRE = regexp.MustCompile(`["'](/(?:api|v[12]|rest|graphql|gateway|service)[/_a-zA-Z0-9\-]{2,50})["']`)
var mapRE = regexp.MustCompile(`sourceMappingURL=(\S+?)["'\s]`)

const maxBundleBytes = 400_000

// Finding 一条已验证发现（对齐 verified 条目形态，src=js）。
type Finding struct {
	Check    string `json:"check"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
	Src      string `json:"src"`
}

// Endpoint 一个攻击面端点。
type Endpoint struct {
	Endpoint string `json:"endpoint"`
	Kind     string `json:"kind"` // api | sourcemap
}

// Fetcher 字节拉取接口（httpx 适配）。
type Fetcher interface {
	FetchBytes(rawURL string) ([]byte, error)
}

// httpxFetch httpx 客户端适配。
type httpxFetch struct{ c *httpx.Client }

// NewFetcher 用 httpx 客户端构造 Fetcher。
func NewFetcher(c *httpx.Client) Fetcher { return httpxFetch{c} }

func (f httpxFetch) FetchBytes(rawURL string) ([]byte, error) {
	r, err := f.c.GetDirect(rawURL)
	if err != nil || r == nil {
		return nil, err
	}
	return []byte(r.Body), nil
}

// Run 扫描页面外链脚本主 bundle：返回 (发现, 端点列表)。
func Run(f Fetcher, pageURL string, doc *htmlx.Doc, maxBundles int) ([]Finding, []Endpoint) {
	if maxBundles <= 0 {
		maxBundles = 4
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, nil
	}
	var findings []Finding
	var endpoints []Endpoint
	seen := map[string]bool{}

	count := 0
	for _, src := range doc.ScriptSrcs {
		if count >= maxBundles {
			break
		}
		u, err := base.Parse(src)
		if err != nil {
			continue
		}
		abs := u.String()
		data, ferr := f.FetchBytes(abs)
		count++
		if ferr != nil || data == nil {
			continue
		}
		text := string(data)
		if len(text) > maxBundleBytes {
			text = text[:maxBundleBytes]
		}

		// SourceMap 泄露
		if m := mapRE.FindStringSubmatch(text + " "); m != nil {
			if mu, e2 := url.Parse(abs); e2 == nil {
				if ru, e3 := mu.Parse(m[1]); e3 == nil {
					mapURL := ru.String()
					mdata, merr := f.FetchBytes(mapURL)
					if merr == nil && len(mdata) > 0 &&
						(mdata[0] == '{' || mdata[0] == '[') {
						findings = append(findings, Finding{
							Check:    "sourcemap-leak",
							Title:    "SourceMap 源码地图泄露",
							Severity: "medium",
							URL:      mapURL,
							Evidence: "map 文件公网可访问（含原始源码引用）",
							Advice:   "生产环境移除 .map 文件或关闭 sourceMap 生成",
							Src:      "js",
						})
						endpoints = append(endpoints,
							Endpoint{Endpoint: mapURL, Kind: "sourcemap"})
					}
				}
			}
		}

		// API 端点枚举
		for _, ep := range apiRE.FindAllStringSubmatch(text, -1) {
			if !seen[ep[1]] {
				seen[ep[1]] = true
				endpoints = append(endpoints, Endpoint{Endpoint: ep[1], Kind: "api"})
			}
		}
	}
	return findings, endpoints
}
