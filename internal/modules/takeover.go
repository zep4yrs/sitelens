// 子域名接管探测（opt-in，只读）：CNAME 指向已知云服务 + 该服务
// 的"未认领/已删除"特征页 = 可接管信号（§12 改进路线 P1）。
//
// 判定链：CNAME 命中签名后缀 → 请求该子域名自身（服务方的 404 页
// 由边缘节点代答）→ 正文命中特征串 → 输出高危发现。探测对象是
// 目标域自己的子域名，每候选仅 1 次请求，总量受 TakeoverMax 封顶。
package modules

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// TakeoverSig 已知可接管云服务的指纹（CNAME 后缀 + 边缘 404 页特征）。
// 特征串取自各服务官方"未找到"页的稳定文案，宁缺毋滥——误报的
// "可接管"会让人白排查一轮 DNS。
type TakeoverSig struct {
	Service  string   // 服务名（GitHub Pages / Heroku / S3 …）
	CNAMEs   []string // CNAME 目标后缀（小写，含前导点或完整后缀）
	Markers  []string // 响应正文特征（任一命中即判定）
	Severity string
	Advice   string
}

// takeoverSigs 精选表：只收录 CNAME 后缀稳定 + 特征页文案可长期
// 复现的服务（来源：can-i-take-over-xyz 公开清单的核验子集）。
var takeoverSigs = []TakeoverSig{
	{
		Service: "GitHub Pages", CNAMEs: []string{".github.io"},
		Markers:  []string{"There isn't a GitHub Pages site here."},
		Severity: "high",
		Advice:   "在 GitHub 仓库设置中绑定该自定义域，或删除失效 DNS 记录",
	},
	{
		Service: "Heroku", CNAMEs: []string{".herokuapp.com"},
		Markers:  []string{"No such app"},
		Severity: "high",
		Advice:   "回收 herokuapp 应用名或删除 DNS 记录",
	},
	{
		Service: "AWS S3", CNAMEs: []string{".s3.amazonaws.com", ".s3-website", ".s3.dualstack"},
		Markers:  []string{"NoSuchBucket"},
		Severity: "high",
		Advice:   "重建同名 S3 桶或删除 DNS 记录",
	},
	{
		Service: "Azure", CNAMEs: []string{".azurewebsites.net", ".cloudapp.azure.com"},
		Markers:  []string{"404 Web Site not found."},
		Severity: "high",
		Advice:   "回收 Azure 应用名或删除 DNS 记录",
	},
	{
		Service: "CloudFront", CNAMEs: []string{".cloudfront.net"},
		Markers:  []string{"ERROR: The request could not be satisfied", "Bad request."},
		Severity: "medium",
		Advice:   "重建同源 CloudFront 分配或删除 DNS 记录",
	},
	{
		Service: "Shopify", CNAMEs: []string{".myshopify.com"},
		Markers:  []string{"Sorry, this shop is currently unavailable"},
		Severity: "high",
		Advice:   "回收 myshopify 店铺名或删除 DNS 记录",
	},
	{
		Service: "Fastly", CNAMEs: []string{".fastly.net"},
		Markers:  []string{"Fastly error: unknown domain:"},
		Severity: "high",
		Advice:   "在 Fastly 重新绑定域或删除 DNS 记录",
	},
	{
		Service: "Netlify", CNAMEs: []string{".netlify.com"},
		Markers:  []string{"Not Found - Request ID"},
		Severity: "medium",
		Advice:   "在 Netlify 绑定自定义域或删除 DNS 记录",
	},
	{
		Service: "Tumblr", CNAMEs: []string{".tumblr.com", "domains.tumblr.com"},
		Markers:  []string{"There's nothing here."},
		Severity: "medium",
		Advice:   "回收 Tumblr 博客名或删除 DNS 记录",
	},
	{
		Service: "Zendesk", CNAMEs: []string{".zendesk.com"},
		Markers:  []string{"Help Center Closed", "this help center no longer exists"},
		Severity: "high",
		Advice:   "回收 Zendesk 子域或删除 DNS 记录",
	},
	{
		Service: "Bitbucket", CNAMEs: []string{".bitbucket.io"},
		Markers:  []string{"Repository not found"},
		Severity: "high",
		Advice:   "重建 Bitbucket Pages 仓库或删除 DNS 记录",
	},
	{
		Service: "Surge.sh", CNAMEs: []string{".surge.sh"},
		Markers:  []string{"project not found"},
		Severity: "medium",
		Advice:   "重新发布同名项目或删除 DNS 记录",
	},
	{
		Service: "Pantheon", CNAMEs: []string{".pantheonsite.io"},
		Markers:  []string{"The gods are wise", "does not exist on Pantheon"},
		Severity: "high",
		Advice:   "回收 Pantheon 站点名或删除 DNS 记录",
	},
	{
		Service: "Readme.io", CNAMEs: []string{".readme.io"},
		Markers:  []string{"Project doesnt exist... yet!"},
		Severity: "medium",
		Advice:   "回收 readme 项目名或删除 DNS 记录",
	},
	{
		Service: "Helpjuice", CNAMEs: []string{".helpjuice.com"},
		Markers:  []string{"We could not find what you're looking for"},
		Severity: "medium",
		Advice:   "回收 Helpjuice 子域或删除 DNS 记录",
	},
	{
		Service: "Intercom", CNAMEs: []string{".custom.intercom.help", ".intercom.help"},
		Markers:  []string{"This page is reserved for artistic dogs"},
		Severity: "medium",
		Advice:   "在 Intercom 绑定自定义域或删除 DNS 记录",
	},
	{
		Service: "Ghost", CNAMEs: []string{".ghost.io"},
		Markers:  []string{"The thing you were looking for is no longer here"},
		Severity: "medium",
		Advice:   "在 Ghost(Pro) 绑定自定义域或删除 DNS 记录",
	},
	{
		Service: "Wix", CNAMEs: []string{".wixdns.net", ".wixsite.com"},
		Markers:  []string{"Error 404 - Wix.com"},
		Severity: "medium",
		Advice:   "在 Wix 绑定域名或删除 DNS 记录",
	},
}

// cnameResolver 可注入的 CNAME 查询（测试替身用）。
type cnameResolver func(host string) (string, error)

func systemCNAME(host string) (string, error) { return net.LookupCNAME(host) }

// bodyFetcher 可注入的正文抓取（生产= httpx 客户端，测试= 桩）。
type bodyFetcher func(url string) (int, string, error)

// TakeoverProbe 生产入口：逐子域 CNAME + 特征页判定，并发受限，
// 探测总量受 cfg.TakeoverMax 封顶（0=默认 50）。
// 注意：progress 回调会在 worker goroutine 内被并发调用——调用方传入
// 的闭包须自行保证并发安全（如原子计数器）。
func TakeoverProbe(client *httpx.Client, subdomains []string,
	cfg config.ActiveConfig, progress func(done, total int, msg string),
	cancel func() bool) []TakeoverHit {
	return TakeoverProbeWith(subdomains, cfg, progress, cancel,
		systemCNAME, func(url string) (int, string, error) {
			resp, err := client.GetFollow(url)
			if err != nil || resp == nil {
				return 0, "", err
			}
			return resp.Status, resp.Body, nil
		})
}

// TakeoverHit 一条接管信号。
type TakeoverHit struct {
	Sub      string `json:"sub"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
}

// TakeoverProbeWith 可注入实现：subdomains 待测子域；resolveCNAME 查
// 规范名；fetch 抓子域自身响应（特征页由云边缘节点代答）。命中判定
// = CNAME 后缀匹配 && 正文特征任一命中。双条件缺一不可：只有 CNAME
// 匹配不请求（可能已重新绑定），只有特征不查 CNAME（特征页撞车）。
func TakeoverProbeWith(subdomains []string, cfg config.ActiveConfig,
	progress func(done, total int, msg string), cancel func() bool,
	resolveCNAME cnameResolver, fetch bodyFetcher) []TakeoverHit {

	max := cfg.TakeoverMax
	if max <= 0 {
		max = 50
	}
	if len(subdomains) > max {
		subdomains = subdomains[:max]
	}
	total := len(subdomains)
	if total == 0 {
		return nil
	}

	workers := 8
	var mu sync.Mutex
	var hits []TakeoverHit
	idx := atomic.Int64{}
	var wg sync.WaitGroup
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
				sub := subdomains[i]
				if progress != nil {
					progress(i+1, total, "接管探测 "+sub)
				}
				cn, err := resolveCNAME(sub)
				if err != nil || cn == "" {
					continue
				}
				cn = strings.ToLower(strings.TrimSuffix(cn, "."))
				sig := matchTakeoverSig(cn)
				if sig == nil {
					continue
				}
				status, body, err := fetch("https://" + sub)
				if err != nil {
					status, body, err = fetch("http://" + sub)
					if err != nil {
						continue
					}
				}
				_ = status
				low := strings.ToLower(body)
				for _, mk := range sig.Markers {
					if strings.Contains(low, strings.ToLower(mk)) {
						mu.Lock()
						hits = append(hits, TakeoverHit{
							Sub: sub, Service: sig.Service,
							Severity: sig.Severity,
							Evidence: fmt.Sprintf("CNAME→%s，页面特征 %q", cn, mk),
							Advice:   sig.Advice,
						})
						mu.Unlock()
						break
					}
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].Sub < hits[j].Sub })
	return hits
}

// matchTakeoverSig 按 CNAME 后缀匹配签名表；无命中返回 nil。
func matchTakeoverSig(cname string) *TakeoverSig {
	for i := range takeoverSigs {
		for _, suffix := range takeoverSigs[i].CNAMEs {
			if strings.HasSuffix(cname, suffix) || strings.HasSuffix(cname, strings.TrimPrefix(suffix, ".")) {
				return &takeoverSigs[i]
			}
		}
	}
	return nil
}
