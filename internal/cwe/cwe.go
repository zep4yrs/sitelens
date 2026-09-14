// Package cwe 弱类型（CWE）关联的统一入口（4.0 P5）。
//
// 定位：把「某条发现属于哪类弱点」这一映射集中到一处，供三条来源使用——
//
//	黑盒 check id   → CWE（nuclei/内置 check/DAST/passive/jsmap 的 check 名）
//	白盒 rule id    → CWE（audit 正则规则 id）
//	CVE             → CWE（NVD weaknesses 字段，经 NVDLookup 注入）
//
// 并负责把映射落成 internal/model 的 cwe_rel 实体（附证据引用）。
//
// 依赖：只依赖 internal/model（+ 标准库）。CVE→CWE 经 NVDLookup 接口注入，
// 不直接 import internal/intel——保持本包可用于任何 NVD 数据源（含测试桩）。
//
// 纪律：**只映射已核实的真实 id，未收录返回 nil（宁缺不猜）**；
// 自动产出的 cwe_rel 一律 probable，不给 confirmed（CWE 关联是分类提示，
// 不是漏洞判决）。
package cwe

import (
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// NVDLookup CVE → CWE 查询（由 internal/intel 的 NVDStore 实现；
// 测试可注入桩）。返回空切片/nil 表示无数据。
type NVDLookup interface {
	CWEsFor(cve string) []string
}

// checkCWE 黑盒 check id → CWE。来源为各检测包的真实 check 名
// （internal/dast、internal/checks、internal/passive、internal/jsmap）。
var checkCWE = map[string][]string{
	// dast（参数级注入探测）
	"xss-reflect":     {"CWE-79"},
	"sqli-error":      {"CWE-89"},
	"sqli-blind-time": {"CWE-89"},
	"bool-blind-sqli": {"CWE-89"},
	"open-redirect":   {"CWE-601"},
	"lfi-passwd":      {"CWE-22"},
	"ssrf-oob":        {"CWE-918"},
	"deser-surface":   {"CWE-502"},

	// passive（被动检测）
	"cookie-attrs": {"CWE-1004"},
	"csrf-form":    {"CWE-352"},

	// jsmap（JS 攻击面）
	"sourcemap-leak": {"CWE-540"},

	// checks 内置：敏感文件/备份泄露
	"git-leak":     {"CWE-538"},
	"git-index":    {"CWE-538"},
	"svn-leak":     {"CWE-538"},
	"env-leak":     {"CWE-538"},
	"ds-store":     {"CWE-538"},
	"bak-dump":     {"CWE-538"},
	"bak-site":     {"CWE-538"},
	"bak-config":   {"CWE-538"},
	"composer":     {"CWE-538"},
	"package-json": {"CWE-538"},
	"webconfig":    {"CWE-538"},
	"crossdomain":  {"CWE-538"},

	// checks 内置：调试/管理端点未授权暴露
	"phpinfo":        {"CWE-200"},
	"actuator":       {"CWE-200"},
	"actuator-env":   {"CWE-200"},
	"swagger":        {"CWE-200"},
	"api-docs":       {"CWE-200"},
	"druid":          {"CWE-284"},
	"server-status":  {"CWE-200"},
	"debug-page":     {"CWE-200"},
	"metrics":        {"CWE-200"},
	"grafana":        {"CWE-284"},
	"kibana":         {"CWE-284"},
	"eureka":         {"CWE-284"},
	"nacos":          {"CWE-284"},
	"solr":           {"CWE-284"},
	"harbor":         {"CWE-284"},
	"jenkins":        {"CWE-284"},
	"adminer":        {"CWE-284"},
	"tomcat-manager": {"CWE-284"},
	"dir-list":       {"CWE-548"},
	"admin-path":     {"CWE-284"},
	"tp-admin":       {"CWE-284"},
	"login-root":     {"CWE-284"},
	"wp-users":       {"CWE-200"},
	"wp-xmlrpc":      {"CWE-284"},
	"wp-login":       {"CWE-284"},

	// 弱口令
	"weak-basic-auth": {"CWE-521"},
}

// ruleCWE 白盒 audit 规则 id → CWE。
var ruleCWE = map[string]string{
	"PY-EVAL":      "CWE-95",
	"PY-EXEC":      "CWE-95",
	"JS-EVAL":      "CWE-95",
	"PY-OSPOPEN":   "CWE-78",
	"PHP-CMD":      "CWE-78",
	"PY-SQLFMT":    "CWE-89",
	"PY-PICKLE":    "CWE-502",
	"PHP-INCLUDE":  "CWE-98",
	"PY-MD5":       "CWE-916",
	"PY-RAND":      "CWE-916",
	"PY-SECRET":    "CWE-798",
	"JS-SECRET":    "CWE-798",
	"JS-INNERHTML": "CWE-79",
	"PY-TEMPFILE":  "CWE-377",
	// AST sink 规则（audit 实体化时以 AST-<sink> 命名）
	"AST-exec_cmd":    "CWE-78",
	"AST-code_exec":   "CWE-95",
	"AST-sql":         "CWE-89",
	"AST-deserialize": "CWE-502",
	"AST-path":        "CWE-22",
	"AST-weak_hash":   "CWE-916",
	"AST-template":    "CWE-1336",
}

// ForCheck 返回黑盒 check id 的 CWE（未收录返回 nil，返回副本）。
func ForCheck(checkID string) []string {
	return copyList(checkCWE[strings.ToLower(strings.TrimSpace(checkID))])
}

// ForRule 返回白盒规则 id 的 CWE（未收录返回 nil）。大小写不敏感，
// 兼容 audit 的 "AST-exec_cmd" 与 "PY-SQLFMT" 两种命名。
func ForRule(ruleID string) []string {
	v, ok := ruleCWE[strings.ToUpper(strings.TrimSpace(ruleID))]
	if !ok {
		// AST 规则名含小写下划线，需原样再查一次。
		v, ok = ruleCWE[strings.TrimSpace(ruleID)]
	}
	if !ok || v == "" {
		return nil
	}
	return []string{v}
}

// ForVulnNode 按节点来源选择映射：白盒用 rule_id，黑盒用 check_id。
// CVE 通道由 Relate 另行处理（需 NVD）。
func ForVulnNode(v model.VulnNode) []string {
	if v.Origin == model.OriginWhitebox {
		if c := ForRule(v.RuleID); len(c) > 0 {
			return c
		}
	}
	if c := ForCheck(v.CheckID); len(c) > 0 {
		return c
	}
	// 节点自带的 CWEs（P2/P4 实体化时已填）作为兜底。
	return copyList(v.CWEs)
}

// Count 返回已收录的映射条数（供文档/统计与测试断言）。
func Count() (checks, rules int) { return len(checkCWE), len(ruleCWE) }

// Relate 为图中的漏洞节点补齐 cwe_rel 实体（幂等）。返回新增条数。
//
// 关联来源优先级：
//  1. 节点自身的 check_id / rule_id 映射（本地表）
//  2. 节点自带的 CWEs（P2/P4 已填）
//  3. CVE → NVD weaknesses（nvd 非 nil 时）
//
// 每条 cwe_rel 都带上节点已有证据引用（可追溯）；一律 probable。
func Relate(g *model.ScanGraph, nvd NVDLookup) int {
	if g == nil {
		return 0
	}
	added := 0
	for i := range g.VulnNodes {
		v := g.VulnNodes[i]
		cwes := ForVulnNode(v)
		// CVE 通道：补充（不替换）本地映射结果。
		if v.CVE != "" && nvd != nil {
			cwes = mergeUnique(cwes, nvd.CWEsFor(v.CVE))
		}
		for _, cweID := range cwes {
			rel := model.NewCWERel(model.KindVulnNode, v.ID, cweID, "mapping",
				model.ConfProbable, v.EvidenceIDs)
			if _, ok := g.Add(rel); ok {
				added++
			}
		}
	}
	return added
}

// ForCVE 直接查 CVE 的 CWE（便捷入口；nvd 为 nil 返回 nil）。
func ForCVE(nvd NVDLookup, cve string) []string {
	if nvd == nil || cve == "" {
		return nil
	}
	return nvd.CWEsFor(cve)
}

// ---- 内部辅助 ----

func copyList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// mergeUnique 合并两组 CWE（去重、升序）。
func mergeUnique(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
