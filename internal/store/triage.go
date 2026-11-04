// triage.go CP-08 UI triage 后端：误报标记 + 白名单的持久化（store 侧）。
//
// 两份额外状态文件，与 history.json 同目录、各自独立版本号、各自原子写：
//
//	<dataDir>/triage.json     误报/确认/忽略标记（按 scan_id + fingerprint 索引）
//	<dataDir>/whitelist.json  白名单（host 精确 / "*.子域" + rule_id）
//
// 设计边界：
//   - **不改既有 store.go 的读写路径**：状态挂在包内 per-Store 注册表上，首次
//     调用时懒加载；history.json 的 Save/List/Get/Delete 等一行未动（「不破坏
//     既有 store 行为」）。
//   - 原子写：临时文件（同目录）+ fsync + rename；rename 被占用时退回
//     「备份→替换→删备份」，失败回滚内存——内存里查到的 = 已落盘的。
//   - 损坏容错：JSON 解析失败的文件隔离为 <name>.<nano>.corrupt 后按空库继续
//     （与 history.json 的隔离策略一致）；解析失败不阻断结果页/白名单入口。
//   - 并发安全：状态自带 RWMutex，同一 Store 可被多个 HTTP handler 并发调用。
//   - fingerprint 是不透明字符串：由服务端生成（internal/server 的
//     vulnerabilityFingerprint / verifiedFingerprint，口径与 SARIF
//     partialFingerprints 同源），store 只负责存取，不解释其内容。
//
// 已知边界（如实）：一个 dataDir 只应由一个 Store 实例持有（与 history.json
// 相同语义）；本文件不监听历史记录删除/裁剪，标记记录独立保留。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// 复核结论取值（与前端 CP-08 的 verdict 枚举一致）。
const (
	TriageFalsePositive = "false_positive" // 误报
	TriageConfirmed     = "confirmed"      // 确认（需要修）
	TriageIgnored       = "ignored"        // 暂不处理
)

const (
	triageFileName    = "triage.json"
	whitelistFileName = "whitelist.json"
	triageFileVersion = 1

	maxFingerprintLen  = 256
	maxTriageNoteRunes = 2000
	maxHostLen         = 253
	maxRuleIDLen       = 256
	maxReasonRunes     = 512
)

// 参数校验错误（handler 据此区分 400 与 500）。
var (
	ErrInvalidTriage    = errors.New("triage 参数非法")
	ErrInvalidWhitelist = errors.New("whitelist 参数非法")
)

// TriageEntry 一条发现的人工复核记录（scan_id + fingerprint 唯一）。
type TriageEntry struct {
	ScanID      int64  `json:"scan_id"`
	Fingerprint string `json:"fingerprint"`
	Verdict     string `json:"verdict"` // false_positive / confirmed / ignored
	Note        string `json:"note,omitempty"`
	UpdatedAt   string `json:"updated_at"` // RFC3339（UTC）
}

// WhitelistEntry 白名单条目。
//
// Host 允许两种形态：
//   - 精确域名：example.com —— 只匹配 example.com 本身
//   - 子域通配：*.example.com —— 匹配至少一层子域（a.example.com、
//     a.b.example.com），**不匹配**裸 example.com（与常见「通配不含 apex」一致）
//
// RuleID 为规则 id（如 xss-reflect）；"*" 表示该 host 下所有规则。
type WhitelistEntry struct {
	Host      string `json:"host"`
	RuleID    string `json:"rule_id"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at"` // RFC3339（UTC）
}

// triageDoc / whitelistDoc 磁盘结构（带版本号，便于未来迁移）。
type triageDoc struct {
	Version int           `json:"version"`
	Entries []TriageEntry `json:"entries"`
}

type whitelistDoc struct {
	Version int              `json:"version"`
	Entries []WhitelistEntry `json:"entries"`
}

// triageState 一个 dataDir 对应的 triage/whitelist 内存态。
type triageState struct {
	dir           string
	triagePath    string
	whitelistPath string

	mu      sync.RWMutex
	triage  map[int64]map[string]TriageEntry // scan_id → fingerprint → 记录
	entries []WhitelistEntry                 // 白名单（保序，落盘前排序）
}

// atomicRename 落盘替换钩子（生产恒为 os.Rename；测试注入失败以验证回滚）。
var atomicRename = os.Rename

// triageState 取（首次懒加载）当前 Store 的 triage 状态。
//
// C-19：状态挂在 Store 字段（s.triage，见 store.go）上，不再用按 *Store
// 的全局 sync.Map。原实现里 map 键永不删除：进程内每次 New/NewTiered
// 都留下一个无法回收的 triageState（测试、CLI 多命令、未来多租户场景），
// 20000 次 New 即 20000 份状态常驻，属于缓慢内存泄漏。
func (s *Store) triageState() (*triageState, error) {
	if s == nil || s.dataDir == "" {
		return nil, errors.New("triage: 存储未初始化（data_dir 为空）")
	}
	s.triageMu.Lock()
	defer s.triageMu.Unlock()
	if s.triage != nil {
		return s.triage, nil
	}
	st := &triageState{
		dir:           s.dataDir,
		triagePath:    filepath.Join(s.dataDir, triageFileName),
		whitelistPath: filepath.Join(s.dataDir, whitelistFileName),
		triage:        map[int64]map[string]TriageEntry{},
	}
	st.load()
	s.triage = st
	return st, nil
}

// ---- 加载 / 隔离 ----

// load 从磁盘载入两份状态；任一文件缺失/损坏都不阻断（首次使用、断电截断、
// 手滑编辑修复后都能继续用）。
func (st *triageState) load() {
	st.loadTriage()
	st.loadWhitelist()
}

func (st *triageState) loadTriage() {
	data, path, ok := readWithBak(st.triagePath)
	if !ok {
		return
	}
	var doc triageDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		quarantineCorrupt(path, err)
		return
	}
	for _, e := range doc.Entries {
		if !validLoadedTriage(e) {
			continue // 单条脏数据只跳过该条，不整份丢弃
		}
		st.put(e)
	}
}

func (st *triageState) loadWhitelist() {
	data, path, ok := readWithBak(st.whitelistPath)
	if !ok {
		return
	}
	var doc whitelistDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		quarantineCorrupt(path, err)
		return
	}
	for _, e := range doc.Entries {
		host, herr := normalizeHostPattern(e.Host)
		if herr != nil {
			continue
		}
		rule := strings.TrimSpace(e.RuleID)
		if rule == "" || len(rule) > maxRuleIDLen {
			continue
		}
		e.Host, e.RuleID = host, rule
		st.upsertWhitelistLocked(e)
	}
}

// readWithBak 读状态文件；正式文件缺失但 .bak 存在（原子替换中途崩溃残留）时，
// 从备份恢复并转正（与 internal/server 的 schedules.json 同策略）。
func readWithBak(path string) ([]byte, string, bool) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, path, true
	}
	if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "警告：读取 %s 失败（%v），按空库继续\n", path, err)
		return nil, path, false
	}
	bak := path + ".bak"
	bdata, berr := os.ReadFile(bak)
	if berr != nil {
		return nil, path, false // 首次使用：无文件
	}
	if rerr := atomicRename(bak, path); rerr == nil {
		fmt.Fprintf(os.Stderr, "提示：%s 缺失，已从 .bak 恢复\n", path)
	}
	return bdata, path, true
}

// quarantineCorrupt 隔离损坏文件（改名留档，不覆盖原始字节，便于人工抢救）。
func quarantineCorrupt(path string, cause error) {
	dst := fmt.Sprintf("%s.%d.corrupt", path, time.Now().UnixNano())
	if err := os.Rename(path, dst); err != nil {
		fmt.Fprintf(os.Stderr, "警告：%s 解析失败且隔离失败（%v），按空库继续（原始错误 %v）\n",
			path, err, cause)
		return
	}
	fmt.Fprintf(os.Stderr, "警告：%s 解析失败已隔离到 %s，按空库继续：%v\n",
		path, filepath.Base(dst), cause)
}

// ---- 出盘 ----

// atomicWriteJSON 原子写 JSON：同目录唯一临时文件 + fsync + rename。
//
// 覆盖语义与 internal/server 的 schedules.json 一致：先直接 rename（POSIX
// 原子替换），被占用/平台差异导致失败时退回「备份→替换→删备份」，替换失败
// 回滚旧文件——宁可保留旧数据也不留下空文件窗口。
func atomicWriteJSON(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功后 rename 已移走，失败则清理残留
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := atomicRename(tmpName, path); err == nil {
		return nil
	}
	bak := path + ".bak"
	_ = os.Remove(bak)
	if err := atomicRename(path, bak); err != nil {
		return fmt.Errorf("替换状态文件失败（%s）：%w", path, err)
	}
	if err := atomicRename(tmpName, path); err != nil {
		_ = atomicRename(bak, path) // 回滚：宁可保留旧文件
		return err
	}
	_ = os.Remove(bak)
	return nil
}

// ---- 误报标记 ----

// TriageMark 写入/覆盖一条复核记录（scan_id + fingerprint 唯一）。
// verdict 非法、fingerprint 为空等参数问题返回 ErrInvalidTriage（handler 映射 400）；
// 落盘失败返回普通错误（handler 映射 500），并回滚内存。
func (s *Store) TriageMark(scanID int64, fingerprint, verdict, note string) error {
	if scanID <= 0 {
		return fmt.Errorf("%w：scan_id 必须为正整数", ErrInvalidTriage)
	}
	fp := strings.TrimSpace(fingerprint)
	if fp == "" {
		return fmt.Errorf("%w：fingerprint 不能为空", ErrInvalidTriage)
	}
	if len(fp) > maxFingerprintLen {
		return fmt.Errorf("%w：fingerprint 超长（>%d 字节）", ErrInvalidTriage, maxFingerprintLen)
	}
	if !validVerdict(verdict) {
		return fmt.Errorf("%w：未知 verdict %q（可选 %s/%s/%s）", ErrInvalidTriage,
			verdict, TriageFalsePositive, TriageConfirmed, TriageIgnored)
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > maxTriageNoteRunes {
		return fmt.Errorf("%w：note 超长（>%d 字符）", ErrInvalidTriage, maxTriageNoteRunes)
	}
	st, err := s.triageState()
	if err != nil {
		return err
	}
	entry := TriageEntry{
		ScanID: scanID, Fingerprint: fp, Verdict: verdict,
		Note: note, UpdatedAt: nowRFC3339(),
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	old, hadOld := st.triageGetLocked(scanID, fp)
	st.put(entry)
	if perr := st.persistTriageLocked(); perr != nil {
		// 回滚内存：保持「查到的 = 已落盘的」，避免重启后结论凭空消失。
		if hadOld {
			st.put(old)
		} else {
			st.deleteTriageLocked(scanID, fp)
		}
		return fmt.Errorf("triage: 保存失败：%w", perr)
	}
	return nil
}

// TriageList 返回某次扫描的全部复核记录（按 fingerprint 升序，稳定输出）。
func (s *Store) TriageList(scanID int64) []TriageEntry {
	st, err := s.triageState()
	if err != nil {
		return []TriageEntry{}
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	m := st.triage[scanID]
	out := make([]TriageEntry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// TriageSummary 按结论汇总某次扫描的复核数（fp=误报, confirmed=确认, ignored=忽略）。
func (s *Store) TriageSummary(scanID int64) (fp, confirmed, ignored int) {
	st, err := s.triageState()
	if err != nil {
		return 0, 0, 0
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	for _, e := range st.triage[scanID] {
		switch e.Verdict {
		case TriageFalsePositive:
			fp++
		case TriageConfirmed:
			confirmed++
		case TriageIgnored:
			ignored++
		}
	}
	return fp, confirmed, ignored
}

// ---- 白名单 ----

// WhitelistAdd 新增/更新一条白名单（host + rule_id 唯一；重复添加覆盖原因）。
// host 支持精确域名与 "*.example.com"；ruleID 传 "*" 表示该 host 下所有规则。
func (s *Store) WhitelistAdd(host, ruleID, reason string) error {
	pattern, err := normalizeHostPattern(host)
	if err != nil {
		return fmt.Errorf("%w：%v", ErrInvalidWhitelist, err)
	}
	rule := strings.TrimSpace(ruleID)
	if rule == "" {
		return fmt.Errorf("%w：rule_id 不能为空（全部规则请传 \"*\"）", ErrInvalidWhitelist)
	}
	if len(rule) > maxRuleIDLen {
		return fmt.Errorf("%w：rule_id 超长（>%d 字节）", ErrInvalidWhitelist, maxRuleIDLen)
	}
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > maxReasonRunes {
		return fmt.Errorf("%w：reason 超长（>%d 字符）", ErrInvalidWhitelist, maxReasonRunes)
	}
	st, err := s.triageState()
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	idx := st.whitelistIndexLocked(pattern, rule)
	prev := append([]WhitelistEntry(nil), st.entries...)
	if idx >= 0 {
		st.entries[idx].Reason = reason // 保留首次 CreatedAt：白名单是"永久生效"语义
	} else {
		st.entries = append(st.entries, WhitelistEntry{
			Host: pattern, RuleID: rule, Reason: reason, CreatedAt: nowRFC3339(),
		})
	}
	if perr := st.persistWhitelistLocked(); perr != nil {
		st.entries = prev
		return fmt.Errorf("whitelist: 保存失败：%w", perr)
	}
	return nil
}

// WhitelistRemove 删除一条白名单；不存在返回 (false, nil)（幂等，重复删除不报错）。
func (s *Store) WhitelistRemove(host, ruleID string) (bool, error) {
	pattern, err := normalizeHostPattern(host)
	if err != nil {
		return false, fmt.Errorf("%w：%v", ErrInvalidWhitelist, err)
	}
	rule := strings.TrimSpace(ruleID)
	if rule == "" {
		return false, fmt.Errorf("%w：rule_id 不能为空", ErrInvalidWhitelist)
	}
	st, err := s.triageState()
	if err != nil {
		return false, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	idx := st.whitelistIndexLocked(pattern, rule)
	if idx < 0 {
		return false, nil
	}
	prev := append([]WhitelistEntry(nil), st.entries...)
	st.entries = append(st.entries[:idx], st.entries[idx+1:]...)
	if perr := st.persistWhitelistLocked(); perr != nil {
		st.entries = prev
		return false, fmt.Errorf("whitelist: 保存失败：%w", perr)
	}
	return true, nil
}

// WhitelistList 返回全部白名单（按 host、rule_id 排序，稳定输出）。
func (s *Store) WhitelistList() []WhitelistEntry {
	st, err := s.triageState()
	if err != nil {
		return []WhitelistEntry{}
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]WhitelistEntry, 0, len(st.entries))
	out = append(out, st.entries...)
	sortWhitelist(out)
	return out
}

// IsWhitelisted 判断 host+ruleID 是否命中白名单。
// host 会被规范化（小写、去协议/路径/端口/尾点）；ruleID 大小写不敏感，
// 白名单里的 "*" 条目匹配该 host 下任意规则。
func (s *Store) IsWhitelisted(host, ruleID string) bool {
	st, err := s.triageState()
	if err != nil {
		return false
	}
	q := normalizeHost(host)
	if q == "" {
		return false
	}
	rid := strings.TrimSpace(ruleID)
	st.mu.RLock()
	defer st.mu.RUnlock()
	for _, e := range st.entries {
		if e.RuleID != "*" && !strings.EqualFold(e.RuleID, rid) {
			continue
		}
		if hostMatch(e.Host, q) {
			return true
		}
	}
	return false
}

// ---- 内部工具 ----

func validVerdict(v string) bool {
	switch v {
	case TriageFalsePositive, TriageConfirmed, TriageIgnored:
		return true
	}
	return false
}

func validLoadedTriage(e TriageEntry) bool {
	return e.ScanID > 0 && strings.TrimSpace(e.Fingerprint) != "" && validVerdict(e.Verdict)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func (st *triageState) put(e TriageEntry) {
	m := st.triage[e.ScanID]
	if m == nil {
		m = map[string]TriageEntry{}
		st.triage[e.ScanID] = m
	}
	m[e.Fingerprint] = e
}

func (st *triageState) triageGetLocked(scanID int64, fp string) (TriageEntry, bool) {
	m := st.triage[scanID]
	if m == nil {
		return TriageEntry{}, false
	}
	e, ok := m[fp]
	return e, ok
}

func (st *triageState) deleteTriageLocked(scanID int64, fp string) {
	m := st.triage[scanID]
	if m == nil {
		return
	}
	delete(m, fp)
	if len(m) == 0 {
		delete(st.triage, scanID)
	}
}

// persistTriageLocked 全量落盘（调用方持有写锁）。
func (st *triageState) persistTriageLocked() error {
	doc := triageDoc{Version: triageFileVersion, Entries: st.triageEntriesLocked()}
	return atomicWriteJSON(st.triagePath, doc)
}

// triageEntriesLocked 摊平索引并排序（scan_id → fingerprint），保证文件可 diff。
func (st *triageState) triageEntriesLocked() []TriageEntry {
	out := make([]TriageEntry, 0, len(st.triage))
	for _, m := range st.triage {
		for _, e := range m {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScanID != out[j].ScanID {
			return out[i].ScanID < out[j].ScanID
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// persistWhitelistLocked 全量落盘（调用方持有写锁）。
func (st *triageState) persistWhitelistLocked() error {
	entries := make([]WhitelistEntry, 0, len(st.entries))
	entries = append(entries, st.entries...)
	sortWhitelist(entries)
	doc := whitelistDoc{Version: triageFileVersion, Entries: entries}
	return atomicWriteJSON(st.whitelistPath, doc)
}

func (st *triageState) whitelistIndexLocked(pattern, rule string) int {
	for i := range st.entries {
		if st.entries[i].Host == pattern && strings.EqualFold(st.entries[i].RuleID, rule) {
			return i
		}
	}
	return -1
}

func (st *triageState) upsertWhitelistLocked(e WhitelistEntry) {
	if idx := st.whitelistIndexLocked(e.Host, e.RuleID); idx >= 0 {
		st.entries[idx] = e
		return
	}
	st.entries = append(st.entries, e)
}

func sortWhitelist(list []WhitelistEntry) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Host != list[j].Host {
			return list[i].Host < list[j].Host
		}
		return list[i].RuleID < list[j].RuleID
	})
}

// normalizeHost 把 host/URL 规范成小写裸主机名（去协议/路径/查询/端口/尾点）。
// 例：HTTPS://Example.COM:8443/x?y=1 → example.com
func normalizeHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
			h = u.Hostname()
		}
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	// 去端口：仅当恰好一个冒号（IPv6 字面量含多个冒号，原样保留）。
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	return h
}

// normalizeHostPattern 规范化白名单 host 模式（精确域名或 "*.子域"）。
//
// 拒绝：空值、含通配符但不在首段（如 a.*.com）、含路径/查询、超长、纯 "*"。
func normalizeHostPattern(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", errors.New("host 不能为空")
	}
	if p == "*" {
		return "", errors.New("host 不支持纯 *（子域通配请写 \"*.example.com\"）")
	}
	wildcard := false
	if strings.HasPrefix(p, "*.") {
		wildcard = true
		p = p[2:]
	}
	base := normalizeHost(p)
	if base == "" {
		return "", errors.New("host 不能为空")
	}
	if strings.ContainsAny(base, "*?") {
		return "", errors.New("host 只支持首段通配（*.example.com）")
	}
	if strings.Contains(base, ":") || strings.Contains(base, "..") {
		return "", errors.New("host 格式非法")
	}
	if len(base) > maxHostLen {
		return "", fmt.Errorf("host 超长（>%d 字节）", maxHostLen)
	}
	if wildcard {
		if !strings.Contains(base, ".") {
			return "", errors.New("通配需至少两级域名（如 *.example.com）")
		}
		return "*." + base, nil
	}
	return base, nil
}

// hostMatch host 是否匹配白名单模式（pattern 已规范化）。
// 精确：完全相等（大小写不敏感）；通配 "*.example.com"：匹配任意层子域，
// 不匹配裸 example.com。
func hostMatch(pattern, host string) bool {
	if pattern == "" || host == "" {
		return false
	}
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		// suffix 形如 ".example.com"：host 必须比 suffix 更长且以之结尾。
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return strings.EqualFold(pattern, host)
}
