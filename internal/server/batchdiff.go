package server

// 本文件实现 BT-03「结果 diff」：同一 URL 最近两次扫描的 finding 集合对比，
// 按稳定指纹判定新增（new）/已修复（fixed）。纯读历史，不改任何存储。
//
// 接线说明（Lead 在 server.go runBatch 成功分支里调用，本文件不改 server.go）：
//   s.st.Save(res, ...) 之后（此时本次扫描已是该 URL 的最新历史记录）：
//       if n, fx, ok := s.DiffURL(it.URL); ok {
//           row["new_findings"] = n
//           row["fixed"] = fx
//       }
//   row 是 runBatch 里构造的 map[string]any；DiffURL 内部自行查最近两条记录，
//   不改变 Save 的调用顺序。批量结束后也可把汇总放进 job.Result / webhook payload。

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// DiffURL 对比同一 URL 最近两次扫描的 finding 集合（按稳定指纹）：
//
//	newFindings 本次有、上次没有（新增风险）；
//	fixed       上次有、本次没有（视为已修复）；
//	ok          false = 历史不足（同 URL 少于两次有效结果）或参数非法。
//
// 说明：比较对象取历史上该 URL 最新的两条记录（新→旧），不依赖调用时机；
// 指纹只由 finding 的身份字段构成（见 vulnerabilityFingerprint /
// verifiedFingerprint），描述/评分/证据等易变字段不参与，避免情报库刷新或
// 证据措辞变化被误判成「新增/修复」。
func (s *Server) DiffURL(rawURL string) (newFindings, fixed int, ok bool) {
	key := diffURLKey(rawURL)
	if key == "" || s.st == nil {
		return 0, 0, false
	}
	limit := 1000
	if s.cfg != nil && s.cfg.Web.HistoryCap > 0 {
		limit = s.cfg.Web.HistoryCap
	}
	sums := s.st.List(limit, "")
	ids := make([]int64, 0, 2)
	for _, sm := range sums {
		if diffURLKey(sm.URL) != key {
			continue
		}
		ids = append(ids, sm.ID)
		if len(ids) == 2 {
			break
		}
	}
	if len(ids) < 2 {
		return 0, 0, false
	}
	cur, prev := s.st.Get(ids[0]), s.st.Get(ids[1])
	if cur == nil || prev == nil || cur.Result == nil || prev.Result == nil {
		return 0, 0, false
	}
	newFindings, fixed = diffFingerprints(findingFingerprints(prev.Result), findingFingerprints(cur.Result))
	return newFindings, fixed, true
}

// diffURLKey 归一化 URL 作为「同一目标」的比对键：scheme/host 小写、去默认端口、
// 空 path 视作 "/"、去尾部斜杠，保留 path/query（不同路径/参数是不同页面）。
// 解析失败退化为 trim+小写，保证「不能解析的串」也能按字面比对。
func diffURLKey(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(s)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return strings.ToLower(s)
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if port != "" {
		b.WriteString(":")
		b.WriteString(port)
	}
	b.WriteString(p)
	if q := u.RawQuery; q != "" {
		b.WriteString("?")
		b.WriteString(q)
	}
	return b.String()
}

// findingFingerprints 把一次扫描结果里的全部 finding 映射为「稳定指纹集合」。
// 覆盖漏洞情报命中（vulnerabilities）与验证型发现（verified）两条来源。
// 同一次扫描内的重复条目按集合去重（不影响新增/修复计数语义）。
func findingFingerprints(res *engine.Result) map[string]struct{} {
	out := make(map[string]struct{})
	if res == nil {
		return out
	}
	for _, v := range res.Vulnerabilities {
		if fp := vulnerabilityFingerprint(v); fp != "" {
			out[fp] = struct{}{}
		}
	}
	for _, m := range res.Verified {
		if fp := verifiedFingerprint(m); fp != "" {
			out[fp] = struct{}{}
		}
	}
	return out
}

// diffFingerprints 集合差：cur 有 prev 无 = new；prev 有 cur 无 = fixed。
func diffFingerprints(prev, cur map[string]struct{}) (newN, fixedN int) {
	for fp := range cur {
		if _, ok := prev[fp]; !ok {
			newN++
		}
	}
	for fp := range prev {
		if _, ok := cur[fp]; !ok {
			fixedN++
		}
	}
	return newN, fixedN
}

// vulnerabilityFingerprint 漏洞情报条目的稳定指纹：
//   - 有 CVE → 身份=CVE 编号（版本/评分/描述变化不影响身份）；
//   - 无 CVE → 身份=Product|Name|Tech|Type 四元组（情报库内部 id 会随库刷新
//     变化，不作为身份，避免整批「新增/修复」）。
//
// 空的（全字段缺失）条目返回 ""，不参与 diff（无法作为稳定身份）。
func vulnerabilityFingerprint(f intel.Finding) string {
	cve := strings.ToUpper(strings.TrimSpace(f.CVE))
	if cve != "" {
		return hashFingerprint("vuln", cve)
	}
	parts := []string{
		normField(f.Product), normField(f.Name), normField(f.Tech), normField(f.Type),
	}
	if strings.Trim(strings.Join(parts, ""), "|") == "" {
		return ""
	}
	return hashFingerprint("vuln", strings.Join(parts, "|"))
}

// verifiedFingerprint 验证型发现（map 形态）的稳定指纹：
// 身份 = src|check|url（check 缺失时退回 title）。证据/建议/请求响应等字段
// 易随扫描细节变化，不参与身份；url 只做归一化（host 大小写/默认端口）。
func verifiedFingerprint(m map[string]any) string {
	check := mapField(m, "check")
	if check == "" {
		check = mapField(m, "title")
	}
	src := mapField(m, "src")
	if check == "" && src == "" && mapField(m, "url") == "" {
		return ""
	}
	u := diffURLKey(mapField(m, "url"))
	return hashFingerprint("verified", src+"|"+check+"|"+u)
}

// normField 身份字段归一化：去两端空白 + 小写（情报字段大小写不稳定）。
func normField(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// mapField 读取 map 里的字符串字段（兼容 json.Number/数字等非字符串直接忽略）。
func mapField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// hashFingerprint 生成 128-bit 指纹十六进制（sha256 前 16 字节）。
// 只作为进程内 diff 集合键，不对外当安全指纹；128-bit 足够避免碰撞。
func hashFingerprint(kind, identity string) string {
	sum := sha256.Sum256([]byte(kind + "|" + identity))
	return hex.EncodeToString(sum[:16])
}
