// triage_test.go CP-08 复核/白名单持久化的 store 侧单测。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTriageStore 建一个临时 dataDir 的 Store。
// C-19 起 triage 状态挂在 Store 字段上（不再是按 *Store 的全局 map），
// 随 Store 一起被 GC 回收，测试无需再手动清理。
func newTriageStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, dir
}

// reopenTriageStore 用同一 dataDir 新建 Store（验证「真落盘」而不是只读内存）。
func reopenTriageStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatalf("New(reopen): %v", err)
	}
	return s
}

func assertNoTempLeftover(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("发现临时文件残留：%s", e.Name())
		}
	}
}

func readTriageDoc(t *testing.T, dir string) triageDoc {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, triageFileName))
	if err != nil {
		t.Fatalf("读 triage.json: %v", err)
	}
	var doc triageDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("triage.json 不是合法 JSON: %v", err)
	}
	return doc
}

func readWhitelistDoc(t *testing.T, dir string) whitelistDoc {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, whitelistFileName))
	if err != nil {
		t.Fatalf("读 whitelist.json: %v", err)
	}
	var doc whitelistDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("whitelist.json 不是合法 JSON: %v", err)
	}
	return doc
}

// TestTriageMarkRoundTrip 标记 → 列表/汇总 → 落盘 → 新 Store 重载，全链路一致。
func TestTriageMarkRoundTrip(t *testing.T) {
	s, dir := newTriageStore(t)
	if err := s.TriageMark(7, "fp-b", TriageConfirmed, "确认可复现"); err != nil {
		t.Fatalf("mark fp-b: %v", err)
	}
	if err := s.TriageMark(7, "fp-a", TriageFalsePositive, "误报：WAF 指纹"); err != nil {
		t.Fatalf("mark fp-a: %v", err)
	}
	if err := s.TriageMark(8, "fp-c", TriageIgnored, ""); err != nil {
		t.Fatalf("mark fp-c: %v", err)
	}

	list := s.TriageList(7)
	if len(list) != 2 || list[0].Fingerprint != "fp-a" || list[1].Fingerprint != "fp-b" {
		t.Fatalf("列表应按 fingerprint 升序且只含 scan 7: %+v", list)
	}
	if list[0].Verdict != TriageFalsePositive || list[0].Note != "误报：WAF 指纹" {
		t.Fatalf("字段丢失: %+v", list[0])
	}
	if _, err := time.Parse(time.RFC3339, list[0].UpdatedAt); err != nil {
		t.Fatalf("updated_at 应为 RFC3339: %q (%v)", list[0].UpdatedAt, err)
	}

	if fp, c, ig := s.TriageSummary(7); fp != 1 || c != 1 || ig != 0 {
		t.Fatalf("summary(7) = %d/%d/%d want 1/1/0", fp, c, ig)
	}
	if fp, c, ig := s.TriageSummary(8); fp != 0 || c != 0 || ig != 1 {
		t.Fatalf("summary(8) = %d/%d/%d want 0/0/1", fp, c, ig)
	}
	if got := s.TriageList(999); len(got) != 0 {
		t.Fatalf("未标记的扫描应返回空列表: %+v", got)
	}

	doc := readTriageDoc(t, dir)
	if doc.Version != triageFileVersion || len(doc.Entries) != 3 {
		t.Fatalf("落盘内容不符: version=%d entries=%d", doc.Version, len(doc.Entries))
	}
	// 文件内按 (scan_id, fingerprint) 排序，保证可 diff。
	if doc.Entries[0].ScanID != 7 || doc.Entries[0].Fingerprint != "fp-a" ||
		doc.Entries[2].ScanID != 8 || doc.Entries[2].Fingerprint != "fp-c" {
		t.Fatalf("落盘顺序不稳定: %+v", doc.Entries)
	}

	// 新 Store 同目录 = 真从磁盘重载（不是读旧内存）。
	s2 := reopenTriageStore(t, dir)
	if got := s2.TriageList(7); len(got) != 2 || got[1].Fingerprint != "fp-b" {
		t.Fatalf("重载后列表不符: %+v", got)
	}
	if fp, c, ig := s2.TriageSummary(7); fp != 1 || c != 1 || ig != 0 {
		t.Fatalf("重载后 summary 不符: %d/%d/%d", fp, c, ig)
	}
	assertNoTempLeftover(t, dir)
}

// TestTriageMarkOverwrite 同一 scan+fingerprint 重复标记覆盖，不产生重复条目。
func TestTriageMarkOverwrite(t *testing.T) {
	s, dir := newTriageStore(t)
	if err := s.TriageMark(1, "fp", TriageFalsePositive, "第一次"); err != nil {
		t.Fatal(err)
	}
	if err := s.TriageMark(1, "fp", TriageIgnored, "改主意了"); err != nil {
		t.Fatal(err)
	}
	list := s.TriageList(1)
	if len(list) != 1 {
		t.Fatalf("覆盖应只有一条: %+v", list)
	}
	if list[0].Verdict != TriageIgnored || list[0].Note != "改主意了" {
		t.Fatalf("覆盖未生效: %+v", list[0])
	}
	if doc := readTriageDoc(t, dir); len(doc.Entries) != 1 {
		t.Fatalf("落盘应只有一条: %d", len(doc.Entries))
	}
	// fp 大小写不同视为不同指纹（指纹是哈希/不透明串，不做大小写折叠）。
	if err := s.TriageMark(1, "FP", TriageConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	if got := s.TriageList(1); len(got) != 2 {
		t.Fatalf("不同指纹应各自一条: %+v", got)
	}
}

// TestTriageValidation 参数非法返回 ErrInvalidTriage（handler 据此 400）。
func TestTriageValidation(t *testing.T) {
	s, _ := newTriageStore(t)
	longFP := strings.Repeat("a", maxFingerprintLen+1)
	longNote := strings.Repeat("注", maxTriageNoteRunes+1)
	cases := []struct {
		name              string
		scanID            int64
		fp, verdict, note string
	}{
		{"scan_id 非正", 0, "fp", TriageConfirmed, ""},
		{"scan_id 负数", -3, "fp", TriageConfirmed, ""},
		{"fingerprint 空", 1, "   ", TriageConfirmed, ""},
		{"fingerprint 超长", 1, longFP, TriageConfirmed, ""},
		{"verdict 未知", 1, "fp", "maybe", ""},
		{"verdict 空", 1, "fp", "", ""},
		{"note 超长", 1, "fp", TriageConfirmed, longNote},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := s.TriageMark(c.scanID, c.fp, c.verdict, c.note)
			if err == nil {
				t.Fatal("应返回错误")
			}
			if !errors.Is(err, ErrInvalidTriage) {
				t.Fatalf("错误应可用 ErrInvalidTriage 判定: %v", err)
			}
		})
	}
	// 合法边界值应通过。
	if err := s.TriageMark(1, strings.Repeat("a", maxFingerprintLen),
		TriageConfirmed, strings.Repeat("注", maxTriageNoteRunes)); err != nil {
		t.Fatalf("边界值应通过: %v", err)
	}
}

// TestTriageAtomicWriteRollback 落盘失败：返回错误、旧文件不变、内存回滚、
// 无临时文件残留。
func TestTriageAtomicWriteRollback(t *testing.T) {
	s, dir := newTriageStore(t)
	if err := s.TriageMark(1, "fp-old", TriageFalsePositive, "旧"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, triageFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	orig := atomicRename
	atomicRename = func(string, string) error { return errors.New("注入的 rename 失败") }
	func() {
		defer func() { atomicRename = orig }()
		err := s.TriageMark(1, "fp-new", TriageConfirmed, "新")
		if err == nil {
			t.Fatal("rename 失败时应返回错误")
		}
		if errors.Is(err, ErrInvalidTriage) {
			t.Fatalf("落盘失败不应归类为参数错误: %v", err)
		}
	}()

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("失败后旧文件应保持不变:\nbefore=%s\nafter=%s", before, after)
	}
	if got := s.TriageList(1); len(got) != 1 || got[0].Fingerprint != "fp-old" {
		t.Fatalf("失败后内存应回滚: %+v", got)
	}
	assertNoTempLeftover(t, dir)

	// 钩子恢复后正常写入。
	if err := s.TriageMark(1, "fp-new", TriageConfirmed, "新"); err != nil {
		t.Fatalf("恢复后应可写入: %v", err)
	}
	if got := s.TriageList(1); len(got) != 2 {
		t.Fatalf("恢复后应有两条: %+v", got)
	}
}

// TestTriageCorruptFileTolerance 损坏文件隔离并从空库继续，随后的写入正常。
func TestTriageCorruptFileTolerance(t *testing.T) {
	s, dir := newTriageStore(t)
	path := filepath.Join(dir, triageFileName)
	if err := os.WriteFile(path, []byte("{not a json doc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.TriageList(1); len(got) != 0 {
		t.Fatalf("损坏文件应按空库继续，实得 %+v", got)
	}
	corrupts, _ := filepath.Glob(path + ".*.corrupt")
	if len(corrupts) != 1 {
		t.Fatalf("损坏文件应被隔离留档，实得 %v", corrupts)
	}
	if err := s.TriageMark(1, "fp", TriageConfirmed, ""); err != nil {
		t.Fatalf("损坏容错后应可写入: %v", err)
	}
	if doc := readTriageDoc(t, dir); len(doc.Entries) != 1 {
		t.Fatalf("恢复后落盘不符: %+v", doc)
	}
}

// TestTriageBakRecovery 正式文件缺失但 .bak 在（原子替换中途崩溃残留）→ 从备份恢复。
func TestTriageBakRecovery(t *testing.T) {
	s, dir := newTriageStore(t)
	path := filepath.Join(dir, triageFileName)
	doc := triageDoc{Version: triageFileVersion, Entries: []TriageEntry{
		{ScanID: 5, Fingerprint: "fp-bak", Verdict: TriageFalsePositive, UpdatedAt: nowRFC3339()},
	}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.TriageList(5); len(got) != 1 || got[0].Fingerprint != "fp-bak" {
		t.Fatalf("应从 .bak 恢复: %+v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf(".bak 应转正为正式文件: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Fatal("恢复后不应残留 .bak")
	}
}

// TestTriageConcurrent 并发标记/查询/汇总：不 panic、不丢条目、落盘可回读。
func TestTriageConcurrent(t *testing.T) {
	s, dir := newTriageStore(t)
	const workers, perWorker = 16, 10
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				scan := int64(w%4) + 1
				fp := fmt.Sprintf("fp-%02d-%02d", w, i)
				verdict := TriageConfirmed
				if i%3 == 0 {
					verdict = TriageFalsePositive
				}
				if err := s.TriageMark(scan, fp, verdict, "并发"); err != nil {
					t.Errorf("并发标记失败: %v", err)
					return
				}
				_ = s.TriageList(scan)
				_, _, _ = s.TriageSummary(scan)
			}
		}(w)
	}
	wg.Wait()

	total := 0
	for scan := int64(1); scan <= 4; scan++ {
		list := s.TriageList(scan)
		fp, c, ig := s.TriageSummary(scan)
		if fp+c+ig != len(list) {
			t.Fatalf("scan %d: summary(%d+%d+%d) != list(%d)", scan, fp, c, ig, len(list))
		}
		total += len(list)
	}
	if total != workers*perWorker {
		t.Fatalf("并发标记丢失：总共 %d 条，期望 %d", total, workers*perWorker)
	}
	doc := readTriageDoc(t, dir)
	if len(doc.Entries) != total {
		t.Fatalf("落盘条数不符：%d != %d", len(doc.Entries), total)
	}
	assertNoTempLeftover(t, dir)
}

// TestTriageDoesNotBreakHistory 复核写入不影响既有 history.json 行为。
func TestTriageDoesNotBreakHistory(t *testing.T) {
	s, dir := newTriageStore(t)
	id := s.Save(sampleResult("a.com", "A", 2), map[string]any{"deep": true})
	if err := s.TriageMark(id, "fp-1", TriageFalsePositive, ""); err != nil {
		t.Fatal(err)
	}
	if rec := s.Get(id); rec == nil || rec.Host != "a.com" {
		t.Fatalf("历史读取被破坏: %+v", rec)
	}
	if got := s.List(10, ""); len(got) != 1 || got[0].ID != id {
		t.Fatalf("历史列表被破坏: %+v", got)
	}
	data, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h history
	if err := json.Unmarshal(data, &h); err != nil || len(h.Scans) != 1 {
		t.Fatalf("history.json 被破坏: %v %+v", err, h)
	}
}

// ---- 白名单 ----

// TestWhitelistMatch 精确/子域通配/规则匹配/规范化。
func TestWhitelistMatch(t *testing.T) {
	s, _ := newTriageStore(t)
	if err := s.WhitelistAdd("example.com", "xss-reflect", "已知误报"); err != nil {
		t.Fatal(err)
	}
	if err := s.WhitelistAdd("*.example.org", "*", "整站忽略"); err != nil {
		t.Fatal(err)
	}
	if err := s.WhitelistAdd("Example.NET", "SQLi", ""); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, rule string
		want       bool
		why        string
	}{
		{"example.com", "xss-reflect", true, "精确命中"},
		{"Example.COM", "XSS-REFLECT", true, "大小写不敏感"},
		{"https://example.com:8443/path?q=1", "xss-reflect", true, "查询 host 规范化"},
		{"example.com.", "xss-reflect", true, "尾点规范化"},
		{"example.com", "sqli", false, "规则不匹配"},
		{"a.example.com", "xss-reflect", false, "精确条目不匹配子域"},
		{"a.example.org", "anything", true, "子域通配 + 规则 *"},
		{"a.b.example.org", "other", true, "多层子域通配"},
		{"example.org", "anything", false, "通配不匹配裸域"},
		{"notexample.org", "anything", false, "后缀必须带点边界"},
		{"example.net", "sqli", true, "Add 时 host 已规范化"},
		{"", "xss-reflect", false, "空 host"},
		{"example.com", "", false, "空规则不匹配具体条目"},
	}
	for _, c := range cases {
		if got := s.IsWhitelisted(c.host, c.rule); got != c.want {
			t.Errorf("IsWhitelisted(%q,%q) = %v want %v（%s）", c.host, c.rule, got, c.want, c.why)
		}
	}
}

// TestWhitelistCRUDAndPersistence 增删改查 + 重复添加覆盖原因 + 重载持久化。
func TestWhitelistCRUDAndPersistence(t *testing.T) {
	s, dir := newTriageStore(t)
	if err := s.WhitelistAdd("a.com", "rule-1", "原因一"); err != nil {
		t.Fatal(err)
	}
	if err := s.WhitelistAdd("*.b.com", "*", ""); err != nil {
		t.Fatal(err)
	}
	list := s.WhitelistList()
	if len(list) != 2 || list[0].Host != "*.b.com" || list[1].Host != "a.com" {
		t.Fatalf("列表应按 host 排序: %+v", list)
	}
	created := list[1].CreatedAt
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Fatalf("created_at 应为 RFC3339: %q", created)
	}

	time.Sleep(2 * time.Millisecond) // 让 Updated/Created 时间戳可区分
	if err := s.WhitelistAdd("a.com", "rule-1", "原因二"); err != nil {
		t.Fatal(err)
	}
	list = s.WhitelistList()
	if len(list) != 2 {
		t.Fatalf("重复添加不应产生新条目: %+v", list)
	}
	if list[1].Reason != "原因二" || list[1].CreatedAt != created {
		t.Fatalf("重复添加应只更新原因、保留创建时间: %+v", list[1])
	}

	// 删除：不存在幂等返回 false；存在返回 true 并落盘。
	if ok, err := s.WhitelistRemove("nope.com", "rule-1"); err != nil || ok {
		t.Fatalf("删除不存在条目应 (false,nil)，实得 ok=%v err=%v", ok, err)
	}
	if ok, err := s.WhitelistRemove("a.com", "rule-1"); err != nil || !ok {
		t.Fatalf("删除已有条目应 (true,nil)，实得 ok=%v err=%v", ok, err)
	}
	if list = s.WhitelistList(); len(list) != 1 || list[0].Host != "*.b.com" {
		t.Fatalf("删除后列表不符: %+v", list)
	}
	assertNoTempLeftover(t, dir)

	doc := readWhitelistDoc(t, dir)
	if doc.Version != triageFileVersion || len(doc.Entries) != 1 {
		t.Fatalf("落盘内容不符: %+v", doc)
	}

	// 新 Store 同目录重载：白名单仍能命中。
	s2 := reopenTriageStore(t, dir)
	if !s2.IsWhitelisted("host.b.com", "whatever") {
		t.Fatal("重载后子域白名单应仍命中")
	}
	if s2.IsWhitelisted("a.com", "rule-1") {
		t.Fatal("已删除的条目不应命中")
	}
}

// TestWhitelistValidation 非法 host/rule/reason 返回 ErrInvalidWhitelist。
func TestWhitelistValidation(t *testing.T) {
	s, _ := newTriageStore(t)
	cases := []struct{ name, host, rule, reason string }{
		{"host 空", "   ", "r", ""},
		{"纯 *", "*", "r", ""},
		{"中间段通配", "a.*.com", "r", ""},
		{"单级通配", "*.com", "r", ""},
		{"rule 空", "a.com", "  ", ""},
		{"rule 超长", "a.com", strings.Repeat("r", maxRuleIDLen+1), ""},
		{"reason 超长", "a.com", "r", strings.Repeat("由", maxReasonRunes+1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := s.WhitelistAdd(c.host, c.rule, c.reason); err == nil ||
				!errors.Is(err, ErrInvalidWhitelist) {
				t.Fatalf("应返回 ErrInvalidWhitelist，实得 %v", err)
			}
		})
	}
	// URL 形态的 host 应被接受并规范化。
	if err := s.WhitelistAdd("https://Example.com:8443/x", "r", ""); err != nil {
		t.Fatalf("URL 形态 host 应被接受: %v", err)
	}
	if !s.IsWhitelisted("example.com", "r") {
		t.Fatal("URL 形态 host 应规范化后命中")
	}
	if ok, err := s.WhitelistRemove("", "r"); ok || !errors.Is(err, ErrInvalidWhitelist) {
		t.Fatalf("删除空 host 应报参数错误，实得 ok=%v err=%v", ok, err)
	}
}

// TestWhitelistAtomicWriteRollback 落盘失败：旧文件不变、内存回滚、无残留。
func TestWhitelistAtomicWriteRollback(t *testing.T) {
	s, dir := newTriageStore(t)
	if err := s.WhitelistAdd("a.com", "r1", "旧"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, whitelistFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := atomicRename
	atomicRename = func(string, string) error { return errors.New("注入的 rename 失败") }
	func() {
		defer func() { atomicRename = orig }()
		if err := s.WhitelistAdd("b.com", "r2", "新"); err == nil {
			t.Fatal("rename 失败时应返回错误")
		}
	}()
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("失败后旧文件应保持不变:\nbefore=%s\nafter=%s", before, after)
	}
	if list := s.WhitelistList(); len(list) != 1 || list[0].Host != "a.com" {
		t.Fatalf("失败后内存应回滚: %+v", list)
	}
	assertNoTempLeftover(t, dir)
}

// TestWhitelistCorruptTolerance 损坏文件隔离并继续（白名单失效方向安全：发现重新出现）。
func TestWhitelistCorruptTolerance(t *testing.T) {
	s, dir := newTriageStore(t)
	path := filepath.Join(dir, whitelistFileName)
	if err := os.WriteFile(path, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if list := s.WhitelistList(); len(list) != 0 {
		t.Fatalf("损坏文件应按空库继续: %+v", list)
	}
	corrupts, _ := filepath.Glob(path + ".*.corrupt")
	if len(corrupts) != 1 {
		t.Fatalf("损坏文件应被隔离留档，实得 %v", corrupts)
	}
	if err := s.WhitelistAdd("a.com", "r", ""); err != nil {
		t.Fatalf("容错后应可写入: %v", err)
	}
	if !s.IsWhitelisted("a.com", "r") {
		t.Fatal("容错后白名单应生效")
	}
}

// TestWhitelistConcurrent 并发增删查：不 panic、条目数正确、落盘可回读。
func TestWhitelistConcurrent(t *testing.T) {
	s, dir := newTriageStore(t)
	const workers = 12
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			host := fmt.Sprintf("h%d.example.com", w)
			if err := s.WhitelistAdd(host, "r", "并发"); err != nil {
				t.Errorf("并发添加失败: %v", err)
				return
			}
			_ = s.IsWhitelisted(host, "r")
			_ = s.WhitelistList()
		}(w)
	}
	wg.Wait()
	if list := s.WhitelistList(); len(list) != workers {
		t.Fatalf("并发添加条目数不符: %d != %d", len(list), workers)
	}
	if doc := readWhitelistDoc(t, dir); len(doc.Entries) != workers {
		t.Fatalf("落盘条数不符: %d != %d", len(doc.Entries), workers)
	}
	assertNoTempLeftover(t, dir)
}

// TestTriageUninitializedStore 零值 Store 的入口返回明确错误/空结果，不 panic。
func TestTriageUninitializedStore(t *testing.T) {
	var s Store
	if err := s.TriageMark(1, "fp", TriageConfirmed, ""); err == nil {
		t.Fatal("未初始化 Store 的 TriageMark 应报错")
	}
	if got := s.TriageList(1); len(got) != 0 {
		t.Fatalf("未初始化 Store 的 TriageList 应返回空: %+v", got)
	}
	if fp, c, ig := s.TriageSummary(1); fp+c+ig != 0 {
		t.Fatalf("未初始化 Store 的 summary 应为零: %d/%d/%d", fp, c, ig)
	}
	if s.IsWhitelisted("a.com", "r") {
		t.Fatal("未初始化 Store 的 IsWhitelisted 应返回 false")
	}
	if list := s.WhitelistList(); len(list) != 0 {
		t.Fatalf("未初始化 Store 的 WhitelistList 应返回空: %+v", list)
	}
	if err := s.WhitelistAdd("a.com", "r", ""); err == nil {
		t.Fatal("未初始化 Store 的 WhitelistAdd 应报错")
	}
}
