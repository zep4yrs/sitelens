// CP-02 多角色/多会话（additive）：一次扫描携带多个已认证会话，供
// IDOR/越权检测在两次请求之间切换身份。本文件**不含检测逻辑**，只提供
// 会话材料与注入/切换原语。
//
// 安全口径与 matrix.go 一致：凭据不落日志/不返回；Session/Set 的 String()
// 全部脱敏；请求头名/值按 RFC 7230 与防头注入规则校验；空凭据明确报错。
package authn

import (
	"fmt"
	"sort"
	"strings"
)

// Session 一个已认证会话（角色 + 注入材料）。
type Session struct {
	Role    string            // 角色名（同一批会话内唯一，供 IDOR 对照）
	Headers map[string]string // 会话请求头（如 Authorization / X-API-Key）
	Cookies string            // Cookie 字符串（"k=v; k2=v2"）
}

// Validate 校验会话：Role 非空且唯一性由 ApplyAll 保证；Headers 名/值合法、
// 值非空；Cookies 合法；Headers 与 Cookies 不得同时表达 Cookie（避免歧义）；
// 至少有一种注入材料（空凭据明确报错）。
func (s Session) Validate() error {
	role := strings.TrimSpace(s.Role)
	if role == "" {
		return fmt.Errorf("authn: 会话缺少 Role（多会话需要角色名做 IDOR 对照）")
	}
	cookieHeader := false
	for k, v := range s.Headers {
		if err := validateHeaderName(k); err != nil {
			return fmt.Errorf("authn: 会话 %q：%v", role, err)
		}
		if err := validateHeaderValue(v); err != nil {
			return fmt.Errorf("authn: 会话 %q：%v", role, err)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("authn: 会话 %q 的请求头 %q 值为空（空凭据不注入）", role, k)
		}
		if strings.EqualFold(k, "Cookie") {
			cookieHeader = true
		}
	}
	if c := strings.TrimSpace(s.Cookies); c != "" {
		if cookieHeader {
			return fmt.Errorf("authn: 会话 %q 同时给了 Cookie 头和 Cookies 字段，注入目标不明确", role)
		}
		if err := validateCookie(c); err != nil {
			return fmt.Errorf("authn: 会话 %q：%v", role, err)
		}
	}
	if len(s.Headers) == 0 && strings.TrimSpace(s.Cookies) == "" {
		return fmt.Errorf("authn: 会话 %q 既没有请求头也没有 Cookie（空凭据不注入）", role)
	}
	return nil
}

// Apply 把会话注入 client（先校验后注入；失败不修改 client）。
// 请求头按名称排序注入，保证顺序稳定可复现。
func (s Session) Apply(client Client) error {
	if client == nil {
		return fmt.Errorf("authn: 注入目标客户端为空")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	for _, k := range sortedKeys(s.Headers) {
		client.SetHeader(k, s.Headers[k])
	}
	if c := strings.TrimSpace(s.Cookies); c != "" {
		client.SetCookie(c)
	}
	return nil
}

// HeaderMap 返回会话请求头副本（Cookies 字段合并为 Cookie 头）。
// 返回值含凭据：调用方不得写日志/落证据。
func (s Session) HeaderMap() (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(s.Headers)+1)
	for k, v := range s.Headers {
		out[k] = v
	}
	if c := strings.TrimSpace(s.Cookies); c != "" {
		out["Cookie"] = c
	}
	return out, nil
}

// String 脱敏表示：只输出 Role 与头名，不输出任何值（防日志泄露凭据）。
func (s Session) String() string {
	return fmt.Sprintf("authn.Session{role=%q, headers=%v, cookies=%s}",
		s.Role, sortedKeys(s.Headers), configuredMark(s.Cookies))
}

// Set 多会话集合（ApplyAll 返回）：首个会话立即生效，其余用 Use 切换。
type Set struct {
	client   Client
	sessions []Session
	order    []string // 与 sessions 对齐的角色名（已 trim）
	current  int
}

// ApplyAll 校验并注入多个会话（一次扫描带多个身份）。
//
// 语义：全部会话先整体校验（任一非法/角色重复 → 错误且 client 零副作用），
// 通过后把**第一个会话**应用到 client（后续请求的默认身份），返回 *Set 供
// 在两次请求之间切换角色：
//
//	set, err := authn.ApplyAll(client, []authn.Session{admin, user})
//	set.Use("admin"); /* 请求 A */
//	set.Use("user");  /* 请求 B */
//
// 不含越权检测逻辑：比对/判定由调用方实现。
func ApplyAll(client Client, sessions []Session) (*Set, error) {
	if client == nil {
		return nil, fmt.Errorf("authn: 注入目标客户端为空")
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("authn: 至少需要一个会话（空凭据不注入）")
	}
	seen := make(map[string]bool, len(sessions))
	roles := make([]string, 0, len(sessions))
	for i, s := range sessions {
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("第 %d 个会话：%w", i+1, err)
		}
		role := strings.TrimSpace(s.Role)
		if seen[role] {
			return nil, fmt.Errorf("authn: 会话角色 %q 重复（切换身份会歧义）", role)
		}
		seen[role] = true
		roles = append(roles, role)
	}
	// 全部校验通过后才动 client：失败零副作用。
	if err := sessions[0].Apply(client); err != nil {
		return nil, err
	}
	return &Set{client: client, sessions: sessions, order: roles, current: 0}, nil
}

// Len 会话数。
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.sessions)
}

// Roles 返回角色名列表（副本，保持配置顺序）。
func (s *Set) Roles() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Current 当前生效的角色名（空 Set 返回空串）。
func (s *Set) Current() string {
	if s == nil || s.current < 0 || s.current >= len(s.order) {
		return ""
	}
	return s.order[s.current]
}

// Use 切换角色并把该会话注入 client（未知角色 → 错误且不改动当前身份）。
func (s *Set) Use(role string) error {
	if s == nil {
		return fmt.Errorf("authn: 会话集为空")
	}
	want := strings.TrimSpace(role)
	idx := -1
	for i, r := range s.order {
		if r == want {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("authn: 未知角色 %q（可用角色：%s）", want, strings.Join(s.order, ", "))
	}
	if err := s.sessions[idx].Apply(s.client); err != nil {
		return err
	}
	s.current = idx
	return nil
}

// Session 返回指定角色的会话副本（供按请求注入 HeaderMap 的接线方式）。
func (s *Set) Session(role string) (Session, bool) {
	if s == nil {
		return Session{}, false
	}
	want := strings.TrimSpace(role)
	for i, r := range s.order {
		if r == want {
			return copySession(s.sessions[i]), true
		}
	}
	return Session{}, false
}

// String 脱敏表示：只输出角色列表与当前角色，不输出会话材料。
func (s *Set) String() string {
	if s == nil {
		return "authn.Set<nil>"
	}
	return fmt.Sprintf("authn.Set{roles=%v, current=%q}", s.order, s.Current())
}

// copySession 深拷贝会话（Headers 副本），避免调用方改动影响集合内状态。
func copySession(s Session) Session {
	out := Session{Role: s.Role, Cookies: s.Cookies}
	if len(s.Headers) > 0 {
		out.Headers = make(map[string]string, len(s.Headers))
		for k, v := range s.Headers {
			out.Headers[k] = v
		}
	}
	return out
}

// sortedKeys 排序后的 map 键（稳定注入/展示顺序）。
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
