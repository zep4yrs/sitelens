package target

import "strings"

// Allowed 判断 host 是否在 allow_hosts 白名单内（空列表 = 不限制）。
// 规则：
//   - 精确匹配（大小写不敏感）；
//   - "*.example.com" 后缀匹配（匹配子域，不匹配 apex example.com）；
//   - 空白/空项忽略。
//
// 白名单是"授权护栏"而非 SSRF 防护：SSRF/内网/gov.cn 等硬闸门不受此影响。
func Allowed(host string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, raw := range allow {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
			continue
		}
		if h == p {
			return true
		}
	}
	return false
}
