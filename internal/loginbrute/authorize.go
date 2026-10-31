// 授权白名单（LB-02，additive）。
//
// Options.AllowHosts 为空 = 不限制（既有行为零变化）；非空时目标 host
// （忽略端口，支持 "*.example.com" 后缀匹配）必须在白名单内，否则直接
// 返回错误且**不发出任何请求**。
//
// 白名单不只看 PageURL：JSON 模式的 JSONEndpoint、多步登录每一步的提交
// 地址（页面里解析出的 action 可能是跨域地址）同样受约束——否则页面内容
// 就能把请求带出授权范围。
package loginbrute

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// allowHostList 把白名单归一为小写主机名列表（去端口/空白）。
func allowHostList(allow []string) []string {
	out := make([]string, 0, len(allow))
	for _, a := range allow {
		if h := normalizeAllowHost(a); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// normalizeAllowHost 归一单条白名单：小写、去空白、去端口。
// 支持 "*." 前缀（匹配子域，不含裸域本身）。
func normalizeAllowHost(entry string) string {
	a := strings.ToLower(strings.TrimSpace(entry))
	if a == "" {
		return ""
	}
	if strings.HasPrefix(a, "*.") {
		return "*." + strings.TrimPrefix(a, "*.")
	}
	if host, _, err := net.SplitHostPort(a); err == nil {
		a = host
	}
	return strings.Trim(a, "[]") // IPv6 字面量 [::1]
}

// hostAllowed 判断 host 是否命中白名单（host 为不带端口的小写主机名）。
func hostAllowed(allow []string, host string) bool {
	for _, a := range allow {
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(host, a[1:]) && len(host) > len(a)-1 {
				return true
			}
			continue
		}
		if a == host {
			return true
		}
	}
	return false
}

// urlHost 取 URL 的主机名（小写、不带端口）；解析失败返回空。
func urlHost(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// checkAllowHosts 校验目标地址是否在授权白名单内（零请求前置检查）。
// PageURL 与 JSONEndpoint（非空时）都必须命中；AllowHosts 为空直接放行。
func checkAllowHosts(opts *Options) error {
	allow := allowHostList(opts.AllowHosts)
	if len(allow) == 0 {
		return nil
	}
	for _, raw := range []string{opts.PageURL, opts.JSONEndpoint} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if err := requireAllowedURL(allow, raw); err != nil {
			return err
		}
	}
	return nil
}

// requireAllowedURL 校验单个 URL 的 host 在白名单内（多步登录每步 action 用）。
func requireAllowedURL(allow []string, rawURL string) error {
	if len(allow) == 0 {
		return nil
	}
	host := urlHost(rawURL)
	if host == "" {
		return fmt.Errorf("无法解析目标地址 %q，已拒绝执行（未发出任何请求）", rawURL)
	}
	if !hostAllowed(allow, host) {
		return fmt.Errorf("目标 %s 不在授权白名单（Options.AllowHosts）内：已拒绝执行，未发出任何请求", host)
	}
	return nil
}

// requireStepAllowed 校验多步登录某一步的提交地址（白名单为空时放行）。
func requireStepAllowed(opts *Options, rawURL string) error {
	return requireAllowedURL(allowHostList(opts.AllowHosts), rawURL)
}
