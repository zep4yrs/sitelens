// C-09（Wave-3）：SQL 后端的复核（triage）/白名单（whitelist）持久化。
//
// 语义与 JSON 后端（internal/store/triage.go）保持一致：
//   - scan_triage：scan_id + fingerprint 唯一，重复标记覆盖 verdict/note；
//   - whitelist：host + rule_id 唯一，重复添加保留首次 created_at、只更新 reason；
//   - 参数校验错误统一包 ErrInvalidTriage / ErrInvalidWhitelist（handler 映射 400）。
//
// 表结构见 migrations/004_triage_whitelist.sql（双方言通用）。
package store

import (
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// TriageTable 复核表名（迁移 004）。
	TriageTable = "scan_triage"
	// WhitelistTable 白名单表名（迁移 004）。
	WhitelistTable = "whitelist"
)

// TriageMark 写入/覆盖一条复核记录（scan_id + fingerprint 唯一）。
//
// verdict 非法、fingerprint 为空等参数问题返回 ErrInvalidTriage（handler 400）；
// 落库失败返回普通错误（handler 500）。
func (s *SQLStore) TriageMark(scanID int64, fingerprint, verdict, note string) error {
	if err := s.ready(); err != nil {
		return err
	}
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
	q := "INSERT INTO " + TriageTable +
		" (scan_id,fingerprint,verdict,note,updated_at) VALUES (" +
		s.dialect.placeholders(5) + ")" +
		" ON CONFLICT(scan_id,fingerprint) DO UPDATE SET" +
		" verdict=excluded.verdict, note=excluded.note, updated_at=excluded.updated_at"
	if _, err := s.db.Exec(q, scanID, fp, verdict, note, nowRFC3339()); err != nil {
		return fmt.Errorf("triage: 保存失败：%w", err)
	}
	return nil
}

// TriageList 返回某次扫描的全部复核记录（按 fingerprint 升序，稳定输出）。
func (s *SQLStore) TriageList(scanID int64) []TriageEntry {
	if err := s.ready(); err != nil {
		return []TriageEntry{}
	}
	q := "SELECT fingerprint, verdict, note, updated_at FROM " + TriageTable +
		" WHERE scan_id = " + s.dialect.placeholder(1) + " ORDER BY fingerprint"
	rows, err := s.db.Query(q, scanID)
	if err != nil {
		log.Printf("警告：SQL 复核记录查询失败（scan_id=%d）：%v", scanID, err)
		return []TriageEntry{}
	}
	defer rows.Close()
	out := make([]TriageEntry, 0, 8)
	for rows.Next() {
		var e TriageEntry
		e.ScanID = scanID
		if err := rows.Scan(&e.Fingerprint, &e.Verdict, &e.Note, &e.UpdatedAt); err != nil {
			log.Printf("警告：SQL 复核记录读取失败（scan_id=%d）：%v", scanID, err)
			return []TriageEntry{}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("警告：SQL 复核记录遍历失败（scan_id=%d）：%v", scanID, err)
		return []TriageEntry{}
	}
	return out
}

// TriageSummary 按结论汇总某次扫描的复核数（fp=误报, confirmed=确认, ignored=忽略）。
func (s *SQLStore) TriageSummary(scanID int64) (fp, confirmed, ignored int) {
	if err := s.ready(); err != nil {
		return 0, 0, 0
	}
	q := "SELECT verdict, COUNT(*) FROM " + TriageTable +
		" WHERE scan_id = " + s.dialect.placeholder(1) + " GROUP BY verdict"
	rows, err := s.db.Query(q, scanID)
	if err != nil {
		log.Printf("警告：SQL 复核汇总查询失败（scan_id=%d）：%v", scanID, err)
		return 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var verdict string
		var n int
		if err := rows.Scan(&verdict, &n); err != nil {
			return 0, 0, 0
		}
		switch verdict {
		case TriageFalsePositive:
			fp = n
		case TriageConfirmed:
			confirmed = n
		case TriageIgnored:
			ignored = n
		}
	}
	return fp, confirmed, ignored
}

// WhitelistAdd 新增/更新一条白名单（host + rule_id 唯一；重复添加覆盖原因）。
// host 支持精确域名与 "*.example.com"；ruleID 传 "*" 表示该 host 下所有规则。
func (s *SQLStore) WhitelistAdd(host, ruleID, reason string) error {
	if err := s.ready(); err != nil {
		return err
	}
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
	q := "INSERT INTO " + WhitelistTable +
		" (host,rule_id,reason,created_at) VALUES (" +
		s.dialect.placeholders(4) + ")" +
		" ON CONFLICT(host,rule_id) DO UPDATE SET reason=excluded.reason"
	if _, err := s.db.Exec(q, pattern, rule, reason, nowRFC3339()); err != nil {
		return fmt.Errorf("whitelist: 保存失败：%w", err)
	}
	return nil
}

// WhitelistRemove 删除一条白名单；不存在返回 (false, nil)（幂等，重复删除不报错）。
func (s *SQLStore) WhitelistRemove(host, ruleID string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	pattern, err := normalizeHostPattern(host)
	if err != nil {
		return false, fmt.Errorf("%w：%v", ErrInvalidWhitelist, err)
	}
	rule := strings.TrimSpace(ruleID)
	if rule == "" {
		return false, fmt.Errorf("%w：rule_id 不能为空", ErrInvalidWhitelist)
	}
	q := "DELETE FROM " + WhitelistTable +
		" WHERE host = " + s.dialect.placeholder(1) +
		" AND rule_id = " + s.dialect.placeholder(2)
	r, err := s.db.Exec(q, pattern, rule)
	if err != nil {
		return false, fmt.Errorf("whitelist: 删除失败：%w", err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("whitelist: 读取影响行数失败：%w", err)
	}
	return n > 0, nil
}

// WhitelistList 返回全部白名单（按 host、rule_id 排序，稳定输出）。
func (s *SQLStore) WhitelistList() []WhitelistEntry {
	if err := s.ready(); err != nil {
		return []WhitelistEntry{}
	}
	q := "SELECT host, rule_id, reason, created_at FROM " + WhitelistTable +
		" ORDER BY host, rule_id"
	rows, err := s.db.Query(q)
	if err != nil {
		log.Printf("警告：SQL 白名单查询失败：%v", err)
		return []WhitelistEntry{}
	}
	defer rows.Close()
	out := make([]WhitelistEntry, 0, 16)
	for rows.Next() {
		var e WhitelistEntry
		var reason sql.NullString // 001 的 whitelist.reason 可空（历史表兼容）
		if err := rows.Scan(&e.Host, &e.RuleID, &reason, &e.CreatedAt); err != nil {
			log.Printf("警告：SQL 白名单读取失败：%v", err)
			return []WhitelistEntry{}
		}
		e.Reason = reason.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("警告：SQL 白名单遍历失败：%v", err)
		return []WhitelistEntry{}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// IsWhitelisted 判断 host+ruleID 是否命中白名单（与 JSON 后端同语义：
// host 规范化、ruleID 大小写不敏感、"*" 匹配该 host 下任意规则）。
//
// 白名单量级小（人工维护），直接取全表在 Go 侧做模式匹配；避免把
// hostMatch 的 wildcard 语义塞进 SQL（双方言差异大且易误判）。
func (s *SQLStore) IsWhitelisted(host, ruleID string) bool {
	q := normalizeHost(host)
	if q == "" {
		return false
	}
	rid := strings.TrimSpace(ruleID)
	for _, e := range s.WhitelistList() {
		if e.RuleID != "*" && !strings.EqualFold(e.RuleID, rid) {
			continue
		}
		if hostMatch(e.Host, q) {
			return true
		}
	}
	return false
}
