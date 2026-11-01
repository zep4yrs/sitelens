package dast

// G09 越权矩阵（IDOR / 水平 / 垂直）只读检测原语。
//
// 输入 base URL + 多会话（authn.Session，复用 CP-02）+ 资源路径模板；
// 对每个角色用其会话请求资源 ID 集合，比较 **状态码 / 响应长度 / 关键字段
// 指纹**，输出 Finding（type/severity/evidence/replay）。
//
// 安全纪律：
//   - 严格只读：只发 GET，本文件不调用任何 POST 方法；
//   - 限速由调用方控制：本文件不 sleep、不并发，逐请求串行；
//   - 请求数硬上限（IDORMatrix.MaxRequests）：耗尽即停止（Truncated=true），
//     不越界多发一个请求；
//   - 凭据不落证据：replay 里只放**脱敏占位**，绝不写 Cookie/Token 原值；
//   - 宁少报：只有「可读 + 关键字段指纹非空且一致」才判定越权；仅回显
//     请求 ID 的响应（无身份字段）不算证据。

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/authn"
)

const (
	defaultIDORMaxRequests = 200
	defaultIDORMaxID       = 5
	maxIDORIDs             = 50
	maxIDORTemplates       = 20
	maxIDORSessions        = 10
	maxIDORFindings        = 100
	idorBodyLimit          = 256 << 10 // 指纹只读前 256KB，防超大响应拖 CPU
	maxIDORFPPairs         = 32
	maxIDORFPValueLen      = 64
)

// IDORMatrix 越权矩阵输入（纯数据）。
type IDORMatrix struct {
	// BaseURL 站点根地址（http/https），相对模板按它解析。
	BaseURL string
	// Templates 资源路径模板（含 "{id}"，如 /user/{id}、/order/{id}）；
	// 不含 "{id}" 的模板只探测一次。绝对 URL 必须与 BaseURL 同主机。
	Templates []string
	// IDs 资源 ID 集合（字符串）；为空时使用 1..MaxID。
	IDs []string
	// MaxID IDs 为空时的 ID 上限（默认 5，上限 100）。
	MaxID int
	// Sessions 多角色会话（≥1，角色名唯一；凭据只用于发请求，不落证据）。
	Sessions []authn.Session
	// RoleIDs 可选：角色 → 该角色「自己的」资源 ID。提供后按
	// 「B 角色能读 A 角色的资源」直接判定 idor-read（比矩阵重叠更精确）。
	RoleIDs map[string][]string
	// AdminRoles 管理/高权角色名；垂直越权判定需要它（为空则跳过垂直）。
	AdminRoles []string
	// AdminPaths 管理路径模板（可含 "{id}"，如 /admin/users/{id}）。
	AdminPaths []string
	// MaxRequests 本次检测的请求硬上限（默认 200，上限 5000）。
	MaxRequests int
}

// IDORFinding 一条越权发现（证据链字段只含脱敏会话标识）。
type IDORFinding struct {
	Type       string `json:"type"` // idor-read / idor-horizontal / idor-vertical
	Severity   string `json:"severity"`
	Role       string `json:"role"`                  // 发起访问的角色（攻击者视角）
	VictimRole string `json:"victim_role,omitempty"` // 资源归属角色（可读越权/垂直时）
	URL        string `json:"url"`
	Evidence   string `json:"evidence"`
	Replay     string `json:"replay"` // curl（凭据脱敏占位）
}

// IDORResult 检测结果。
type IDORResult struct {
	Findings  []IDORFinding
	Requests  int  // 实际发出的 GET 数
	Truncated bool // 是否因 MaxRequests 提前停止
}

// HeaderFetcher 已由 dast 定义（GetWithHeaders）；IDOR 矩阵必须能按角色注入
// 请求头，因此要求 Fetcher 实现该可选接口。

// idorRole 已注入材料的多角色会话（headers 含凭据，只用于发请求）。
type idorRole struct {
	name    string
	headers map[string]string
}

// idorCell 一个 (模板,ID,角色) 单元的判定材料。
type idorCell struct {
	status   int
	size     int
	fp       string // 关键字段指纹（强指纹：排除请求 ID 回显）
	readable bool
}

// idorRunner 串行只读探针 + 请求预算。
type idorRunner struct {
	hf        HeaderFetcher
	max       int
	reqs      int
	truncated bool
}

// get 单次只读 GET（带角色会话头）；预算耗尽返回 nil 并标记 truncated。
func (r *idorRunner) get(headers map[string]string, rawURL string) *Resp {
	if r.reqs >= r.max {
		r.truncated = true
		return nil
	}
	r.reqs++
	return r.hf.GetWithHeaders(rawURL, headers)
}

// DetectIDOR 执行只读越权矩阵检测。
//
// 判定口径：
//  1. idor-read（提供 RoleIDs 时）：A 角色的资源 ID 被 B 角色读到，且两侧
//     关键字段指纹非空且一致（B 不是管理角色）；
//  2. idor-horizontal（未提供 RoleIDs 时）：同一资源 ID 被 ≥2 个非管理角色
//     以一致指纹读到（资源未按会话主体隔离）；
//  3. idor-vertical：低权角色在管理路径上读到与管理角色一致的内容。
//
// 只发 GET；请求数受 MaxRequests 限制；不 sleep（限速由调用方控制）。
func DetectIDOR(m IDORMatrix, f Fetcher) (*IDORResult, error) {
	if f == nil {
		return nil, fmt.Errorf("dast: IDOR 检测需要非空 Fetcher")
	}
	hf, ok := f.(HeaderFetcher)
	if !ok {
		return nil, fmt.Errorf("dast: IDOR 检测需要支持自定义请求头的 Fetcher（HeaderFetcher）")
	}
	base, err := idorParseBase(m.BaseURL)
	if err != nil {
		return nil, err
	}
	roles, err := idorRoles(m.Sessions, m.AdminRoles)
	if err != nil {
		return nil, err
	}
	templates, err := idorTemplates(m.Templates, "Templates")
	if err != nil {
		return nil, err
	}
	adminPaths, err := idorTemplates(m.AdminPaths, "AdminPaths")
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 && len(adminPaths) == 0 {
		return nil, fmt.Errorf("dast: IDOR 检测至少需要一个 Templates 或 AdminPaths")
	}
	ids, err := idorIDs(m.IDs, m.MaxID, m.RoleIDs)
	if err != nil {
		return nil, err
	}

	maxReq := m.MaxRequests
	if maxReq <= 0 {
		maxReq = defaultIDORMaxRequests
	}
	if maxReq > 5000 {
		maxReq = 5000
	}
	r := &idorRunner{hf: hf, max: maxReq}
	res := &IDORResult{}

	nonAdmin := idorNonAdminSet(roles, m.AdminRoles)
	matrix := idorProbeMatrix(r, base, templates, ids, roles)
	adminMatrix := idorProbeMatrix(r, base, adminPaths, ids, roles)

	switch {
	case len(m.RoleIDs) > 0:
		res.Findings = append(res.Findings, idorReadFindings(matrix, base, templates, ids, roles, m.RoleIDs, nonAdmin)...)
	default:
		res.Findings = append(res.Findings, idorHorizontalFindings(matrix, base, templates, ids, roles, nonAdmin)...)
	}
	if len(m.AdminRoles) > 0 {
		res.Findings = append(res.Findings, idorVerticalFindings(adminMatrix, base, adminPaths, ids, roles, m.AdminRoles)...)
	}

	res.Findings = idorFinalizeFindings(res.Findings)
	res.Requests = r.reqs
	res.Truncated = r.truncated
	return res, nil
}

// ---- 输入校验/规范化 ----

func idorParseBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("dast: IDOR 检测缺少 BaseURL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("dast: BaseURL 非法: %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("dast: BaseURL 仅支持 http/https: %q", raw)
	}
	u.Scheme = scheme
	u.Fragment = ""
	u.RawQuery = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// idorRoles 校验会话并展开为（角色名 → 请求头）。凭据只留在内存。
func idorRoles(sessions []authn.Session, adminRoles []string) ([]idorRole, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("dast: IDOR 检测至少需要一个会话")
	}
	if len(sessions) > maxIDORSessions {
		return nil, fmt.Errorf("dast: 会话数超过上限 %d", maxIDORSessions)
	}
	seen := make(map[string]bool, len(sessions))
	out := make([]idorRole, 0, len(sessions))
	for i, s := range sessions {
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("第 %d 个会话：%w", i+1, err)
		}
		name := strings.TrimSpace(s.Role)
		if seen[name] {
			return nil, fmt.Errorf("dast: 会话角色 %q 重复", name)
		}
		seen[name] = true
		hm, err := s.HeaderMap()
		if err != nil {
			return nil, fmt.Errorf("第 %d 个会话：%w", i+1, err)
		}
		out = append(out, idorRole{name: name, headers: hm})
	}
	for _, ar := range adminRoles {
		if ar = strings.TrimSpace(ar); ar != "" && !seen[ar] {
			return nil, fmt.Errorf("dast: AdminRoles 中的角色 %q 不在 Sessions 里", ar)
		}
	}
	return out, nil
}

func idorTemplates(in []string, field string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) > maxIDORTemplates {
			return nil, fmt.Errorf("dast: %s 超过上限 %d", field, maxIDORTemplates)
		}
	}
	return out, nil
}

// idorIDs 归一化 ID 集合：显式 IDs 优先，否则 1..MaxID；并把 RoleIDs 里
// 出现的 ID 并入探测集（否则「B 读 A 资源」需要的那次探测缺失）。
func idorIDs(ids []string, maxID int, roleIDs map[string][]string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(id string) error {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return nil
		}
		seen[id] = true
		out = append(out, id)
		if len(out) > maxIDORIDs {
			return fmt.Errorf("dast: 资源 ID 数超过上限 %d", maxIDORIDs)
		}
		return nil
	}
	for _, id := range ids {
		if err := add(id); err != nil {
			return nil, err
		}
	}
	for _, list := range roleIDs {
		if len(list) > maxIDORIDs {
			return nil, fmt.Errorf("dast: RoleIDs 单角色 ID 数超过上限 %d", maxIDORIDs)
		}
		for _, id := range list {
			if err := add(id); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		n := maxID
		if n <= 0 {
			n = defaultIDORMaxID
		}
		if n > 100 {
			n = 100
		}
		for i := 1; i <= n; i++ {
			if err := add(strconv.Itoa(i)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// ---- 探测矩阵 ----

// idorTemplateIDs 模板实际要探测的 ID 列表：含 "{id}" 用资源 ID 集合，
// 不含占位符的模板只探测一次（空 ID）。
func idorTemplateIDs(tpl string, ids []string) []string {
	if strings.Contains(tpl, "{id}") {
		return ids
	}
	return []string{""}
}

// idorProbeMatrix 逐模板×ID×角色只读探测，返回 map[模板\x00ID]map[角色]cell。
// 预算耗尽后剩余单元直接留空（后续比对自动跳过，不会多发请求）。
func idorProbeMatrix(r *idorRunner, base *url.URL, templates, ids []string, roles []idorRole) map[string]map[string]idorCell {
	matrix := make(map[string]map[string]idorCell, len(templates)*len(ids))
	for _, tpl := range templates {
		for _, id := range idorTemplateIDs(tpl, ids) {
			u := idorResolveURL(base, tpl, id)
			if u == "" {
				continue
			}
			key := tpl + "\x00" + id
			byRole := make(map[string]idorCell, len(roles))
			matrix[key] = byRole
			for _, role := range roles {
				if r.truncated {
					break
				}
				byRole[role.name] = idorCellOf(r.get(role.headers, u), id)
			}
		}
	}
	return matrix
}

// idorResolveURL 模板 + ID → 完整 URL；相对模板按 BaseURL 拼接，绝对 URL
// 必须与 BaseURL 同主机（避免越权检测打到域外目标）。
func idorResolveURL(base *url.URL, tpl, id string) string {
	if base == nil || tpl == "" {
		return ""
	}
	escaped := url.PathEscape(id)
	raw := strings.ReplaceAll(tpl, "{id}", escaped)
	var u *url.URL
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return ""
		}
		if !strings.EqualFold(parsed.Host, base.Host) {
			return ""
		}
		u = parsed
	} else {
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		u = base.ResolveReference(parsed)
	}
	u.Fragment = ""
	return u.String()
}

// idorCellOf 响应 → 判定单元：2xx/3xx? 这里只把 2xx 且非拒绝页当「可读」。
func idorCellOf(resp *Resp, requestedID string) idorCell {
	if resp == nil {
		return idorCell{}
	}
	c := idorCell{status: resp.Status, size: len(resp.Body)}
	if resp.Status < 200 || resp.Status > 299 || strings.TrimSpace(resp.Body) == "" {
		return c
	}
	if authzRespDenied(resp.Status, resp.Body) {
		return c
	}
	c.readable = true
	c.fp = idorStrongFingerprint(resp.Body, requestedID)
	return c
}

// ---- 关键字段指纹 ----

// idorIdentityKeys 身份/归属类字段白名单（只有这些字段参与越权比对；
// 其余字段（时间戳/随机 token/计数器）会造成抖动，不参与）。
var idorIdentityKeys = map[string]bool{
	"id": true, "ids": true, "uid": true, "user": true, "user_id": true, "userid": true,
	"account": true, "account_id": true, "email": true, "mail": true,
	"name": true, "username": true, "owner": true, "owner_id": true,
	"role": true, "roles": true, "tenant": true, "tenant_id": true,
	"balance": true, "amount": true, "order": true, "order_id": true,
	"phone": true, "mobile": true, "admin": true, "is_admin": true,
	"permissions": true, "level": true, "org": true, "company": true, "department": true,
}

// idorFieldPairRe 文本/HTML 里的 key=value / key: value 身份字段。
var idorFieldPairRe = regexp.MustCompile(`(?i)([a-z_][a-z0-9_]{1,24})\s*[=:]\s*(?:"([^"]{0,64})"|'([^']{0,64})'|([A-Za-z0-9._@+:-]{1,64}))`)

// idorStrongFingerprint 关键字段强指纹：只保留身份类字段，并剔除「就是本次
// 请求 ID 的回显」（如 {"id":"1"} / {"user":"1"}），避免纯回显造成误报。
// 无身份字段返回空串（不可比对）。
func idorStrongFingerprint(body, requestedID string) string {
	if len(body) > idorBodyLimit {
		body = body[:idorBodyLimit]
	}
	pairs := idorFieldPairs(body)
	if len(pairs) == 0 {
		return ""
	}
	wantID := strings.TrimSpace(requestedID)
	set := make([]string, 0, len(pairs))
	seen := map[string]bool{}
	for _, kv := range pairs {
		key, val := strings.ToLower(kv[0]), kv[1]
		if !idorIdentityKeys[key] {
			continue
		}
		if key == "id" || key == "ids" {
			continue // 请求 ID 本身不构成跨角色证据
		}
		if val == "" || len(val) > maxIDORFPValueLen {
			continue
		}
		if wantID != "" && strings.EqualFold(val, wantID) {
			continue // 回显请求 ID，不是资源归属信息
		}
		pair := key + "=" + val
		if seen[pair] {
			continue
		}
		seen[pair] = true
		set = append(set, pair)
		if len(set) >= maxIDORFPPairs {
			break
		}
	}
	if len(set) == 0 {
		return ""
	}
	sort.Strings(set)
	// 指纹归一化后再 sha256 截断：证据里不放大段原文，同时长度固定。
	sum := sha256.Sum256([]byte(strings.Join(set, "&")))
	return "fp:" + fmt.Sprintf("%x", sum[:8]) + "&" + strings.Join(set[:min(len(set), 6)], "&")
}

// idorFieldPairs 抽取身份字段键值对：优先 JSON（含数组/嵌套，深度≤4），
// 否则退回文本正则。
func idorFieldPairs(body string) [][2]string {
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		out := make([][2]string, 0, 8)
		idorWalkJSON(v, 0, &out)
		if len(out) > 0 {
			return out
		}
	}
	return idorRegexPairs(body)
}

func idorWalkJSON(v any, depth int, out *[][2]string) {
	if depth > 4 || v == nil {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := t[k]
			switch x := val.(type) {
			case string:
				*out = append(*out, [2]string{k, x})
			case float64:
				*out = append(*out, [2]string{k, formatIDORNumber(x)})
			case bool:
				*out = append(*out, [2]string{k, strconv.FormatBool(x)})
			case map[string]any, []any:
				idorWalkJSON(x, depth+1, out)
			}
		}
	case []any:
		for _, item := range t {
			idorWalkJSON(item, depth+1, out)
		}
	}
}

// formatIDORNumber 数字字段转文本（去掉无意义小数尾巴）。
func formatIDORNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// idorRegexPairs 非 JSON 文本的字段提取（HTML/表单/JS 片段）。
func idorRegexPairs(body string) [][2]string {
	ms := idorFieldPairRe.FindAllStringSubmatch(body, 128)
	out := make([][2]string, 0, len(ms))
	for _, m := range ms {
		val := ""
		for i := 2; i < len(m); i++ {
			if m[i] != "" {
				val = m[i]
				break
			}
		}
		out = append(out, [2]string{m[1], val})
	}
	return out
}

// ---- 判定 ----

// idorNonAdminSet 非管理角色集合（AdminRoles 为空时所有角色都算非管理）。
func idorNonAdminSet(roles []idorRole, adminRoles []string) map[string]bool {
	admin := map[string]bool{}
	for _, a := range adminRoles {
		admin[strings.TrimSpace(a)] = true
	}
	out := make(map[string]bool, len(roles))
	for _, r := range roles {
		out[r.name] = !admin[r.name]
	}
	return out
}

// idorReadFindings RoleIDs 模式：A 的资源被 B 读到（B 非管理角色）。
func idorReadFindings(matrix map[string]map[string]idorCell, base *url.URL, templates, ids []string, roles []idorRole, roleIDs map[string][]string, nonAdmin map[string]bool) []IDORFinding {
	var out []IDORFinding
	roleOrder := make([]string, 0, len(roles))
	for _, r := range roles {
		roleOrder = append(roleOrder, r.name)
	}
	for _, victim := range roleOrder {
		if !nonAdmin[victim] {
			continue // 管理角色作为资源归属方没有「越权」意义
		}
		for _, id := range roleIDs[victim] {
			if len(out) >= maxIDORFindings {
				return out
			}
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			for _, tpl := range templates {
				if !strings.Contains(tpl, "{id}") {
					continue // 资源 ID 越权只对含 {id} 的模板有意义
				}
				cells := matrix[tpl+"\x00"+id]
				vc, ok := cells[victim]
				if !ok || !vc.readable || vc.fp == "" {
					continue
				}
				u := idorResolveURL(base, tpl, id)
				if u == "" {
					continue
				}
				for _, attacker := range roleOrder {
					if attacker == victim || !nonAdmin[attacker] {
						continue
					}
					ac, ok := cells[attacker]
					if !ok || !ac.readable || ac.fp != vc.fp {
						continue
					}
					out = append(out, IDORFinding{
						Type: "idor-read", Severity: "high",
						Role: attacker, VictimRole: victim, URL: u,
						Evidence: idorEvidence("B 角色读到了 A 角色的资源",
							tpl, id, victim, vc, attacker, ac),
						Replay: idorReplayCurl(u, attacker),
					})
				}
			}
		}
	}
	return out
}

// idorHorizontalFindings 矩阵重叠模式：同一资源被 ≥2 个非管理角色以一致
// 关键字段指纹读到 → 水平越权。
func idorHorizontalFindings(matrix map[string]map[string]idorCell, base *url.URL, templates, ids []string, roles []idorRole, nonAdmin map[string]bool) []IDORFinding {
	var out []IDORFinding
	for _, tpl := range templates {
		for _, id := range idorTemplateIDs(tpl, ids) {
			if len(out) >= maxIDORFindings {
				return out
			}
			cells, ok := matrix[tpl+"\x00"+id]
			if !ok {
				continue
			}
			groups := map[string][]string{} // fp → 角色（保持配置顺序）
			for _, r := range roles {
				if !nonAdmin[r.name] {
					continue
				}
				c := cells[r.name]
				if !c.readable || c.fp == "" {
					continue
				}
				groups[c.fp] = append(groups[c.fp], r.name)
			}
			u := idorResolveURL(base, tpl, id)
			if u == "" {
				continue
			}
			for fp, names := range groups {
				if len(names) < 2 {
					continue
				}
				first := names[0]
				fc := cells[first]
				for _, other := range names[1:] {
					if len(out) >= maxIDORFindings {
						return out
					}
					oc := cells[other]
					// 证据里只放指纹摘要（fp: 前缀段），不重复拼接完整指纹。
					ev := fmt.Sprintf("资源 %s id=%q 被多个非管理角色读到：角色 %q（HTTP %d，%d 字节）"+
						"与角色 %q（HTTP %d，%d 字节），关键字段指纹一致 %s。",
						tpl, id, first, fc.status, fc.size, other, oc.status, oc.size, idorFPBrief(fp))
					out = append(out, IDORFinding{
						Type: "idor-horizontal", Severity: "high",
						Role: other, VictimRole: first, URL: u,
						Evidence: ev, Replay: idorReplayCurl(u, other),
					})
				}
			}
		}
	}
	return out
}

// idorVerticalFindings 垂直越权：低权角色在管理路径上读到与管理角色一致
// 的关键内容。要求「管理角色可读」作为管理路径成立的证据（宁少报）。
func idorVerticalFindings(matrix map[string]map[string]idorCell, base *url.URL, paths, ids []string, roles []idorRole, adminRoles []string) []IDORFinding {
	admin := map[string]bool{}
	for _, a := range adminRoles {
		admin[strings.TrimSpace(a)] = true
	}
	var out []IDORFinding
	for _, tpl := range paths {
		for _, id := range idorTemplateIDs(tpl, ids) {
			if len(out) >= maxIDORFindings {
				return out
			}
			cells, ok := matrix[tpl+"\x00"+id]
			if !ok {
				continue
			}
			var adminRole string
			var adminCell idorCell
			for _, r := range roles {
				if !admin[r.name] {
					continue
				}
				if c := cells[r.name]; c.readable && c.fp != "" {
					adminRole, adminCell = r.name, c
					break
				}
			}
			if adminRole == "" {
				continue // 管理角色都读不到：无法证明这是管理路径
			}
			u := idorResolveURL(base, tpl, id)
			if u == "" {
				continue
			}
			for _, r := range roles {
				if admin[r.name] {
					continue
				}
				lc := cells[r.name]
				if !lc.readable || lc.fp != adminCell.fp {
					continue
				}
				out = append(out, IDORFinding{
					Type: "idor-vertical", Severity: "high",
					Role: r.name, VictimRole: adminRole, URL: u,
					Evidence: idorEvidence("低权角色访问管理路径成功且内容与管理角色一致",
						tpl, id, adminRole, adminCell, r.name, lc),
					Replay: idorReplayCurl(u, r.name),
				})
			}
		}
	}
	return out
}

// idorEvidence 统一证据文案（只含角色名/状态/大小/指纹摘要；无凭据）。
func idorEvidence(headline, tpl, id, victimRole string, victimCell idorCell, attackerRole string, attackerCell idorCell) string {
	return fmt.Sprintf("%s：模板 %s id=%q；角色 %q 响应 HTTP %d（%d 字节），角色 %q 响应 HTTP %d（%d 字节），"+
		"两侧关键字段指纹一致 %s。",
		headline, tpl, id, victimRole, victimCell.status, victimCell.size,
		attackerRole, attackerCell.status, attackerCell.size, idorFPBrief(victimCell.fp))
}

// idorFPBrief 指纹摘要（fp:<16hex> 段；证据不放大段原文）。
func idorFPBrief(fp string) string {
	if i := strings.IndexByte(fp, '&'); i > 0 {
		return fp[:i]
	}
	if fp == "" {
		return "(空)"
	}
	return fp
}

// idorReplayCurl 复现命令：只放脱敏占位头，绝不含真实 Cookie/Token。
func idorReplayCurl(rawURL, role string) string {
	role = strings.TrimSpace(role)
	if role == "" {
		role = "role"
	}
	placeholder := "Cookie: <redacted: session for " + role + ">"
	return "curl -sk --path-as-is -H " + shellQuote(placeholder) + " " + shellQuote(rawURL)
}

// idorFinalizeFindings 去重（type+role+victim+url）并稳定排序、截断上限。
func idorFinalizeFindings(in []IDORFinding) []IDORFinding {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]IDORFinding, 0, len(in))
	for _, f := range in {
		key := f.Type + "\x00" + f.Role + "\x00" + f.VictimRole + "\x00" + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
		if len(out) >= maxIDORFindings {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].VictimRole < out[j].VictimRole
	})
	return out
}
