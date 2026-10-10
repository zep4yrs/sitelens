// 黑盒 check id → CWE 映射（P2 引入，P5 归口到 internal/cwe）。
//
// 本文件保留 engine 侧的薄封装：映射表的权威定义在 internal/cwe，
// 这里只做转发 + 黑盒特有的 impact 归类，避免两处表各写一份而漂移。
package engine

import (
	"cnb.cool/feng-qiao/sitelens/internal/cwe"
)

// CWEForCheck 返回 check id 对应的 CWE 列表（权威表见 internal/cwe）。
func CWEForCheck(checkID string) []string { return cwe.ForCheck(checkID) }

// impactKindForCheck 把 check id 归到统一的 impact 类型（P2 粗粒度）。
// 仅用于把 exploit 已验证的影响归类，不作为建链依据。
// check id 以合并后生效的那套为准（PR #29 的深度面命名），历史别名一并保留。
func impactKindForCheck(checkID string) string {
	switch checkID {
	case "xss-reflect", "xss-reflect-cookie", "xss-reflect-header":
		return "execution"
	case "sqli-error", "sqli-blind-time", "bool-blind-sqli",
		"sqli-error-cookie", "sqli-error-header",
		"nosql-inject", "nosql-injection", "xpath-inject", "xpath-injection",
		"ldap-inject", "ssti", "expression-inject":
		return "modification"
	case "lfi-passwd", "sourcemap-leak", "crlf-injection":
		return "disclosure"
	case "open-redirect", "crlf-inject":
		return "redirect"
	case "ssrf-oob":
		return "ssrf"
	case "deser-surface", "cmd-inject", "cmdi-time", "log4j-inject":
		return "execution"
	case "xxe":
		return "disclosure"
	case "upload-surface", "upload-bypass":
		return "execution"
	}
	return "unknown"
}
