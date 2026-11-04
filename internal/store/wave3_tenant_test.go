// wave3_tenant_test.go BL-5（多租户数据面隔离）+ C-09（triage/whitelist 落 SQL）。
//
// 覆盖：
//   - JSON Store / Tiered：SaveForTenant 写入归属、ListForTenant/GetForTenant/
//     DeleteForTenant 过滤、legacy（tenant=""）只对全局可见、归档分片同样带租户；
//   - SQL（真实 sqlite）：迁移 003/004、租户过滤列表/Get/Delete/Stats、
//     复核与白名单持久化（重开 store 仍在）。
package store

import (
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

// tenantResult 造一条最小扫描结果（租户隔离测试不关心内容细节）。
func tenantResult(host string) *engine.Result {
	return &engine.Result{
		URL: "https://" + host, Host: host, Title: "标题 " + host,
		Status: 200, ScannedAt: "2026-01-01 00:00:00",
	}
}

// TestTenantClearAll 租户清空只删本租户（含归档墓碑），legacy 与其它租户保留。
func TestTenantClearAll(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	idA1 := tv.SaveForTenant(tenantResult("a1.example"), nil, "tenant-a")
	tv.SaveForTenant(tenantResult("b1.example"), nil, "tenant-b")
	tv.SaveForTenant(tenantResult("a2.example"), nil, "tenant-a") // 归档 a1/b1
	idLegacy := tv.Save(tenantResult("legacy.example"), nil)
	if idA1 <= 0 || idLegacy <= 0 {
		t.Fatal("seed 失败")
	}
	if n := tv.ClearAllForTenant("tenant-a"); n != 2 {
		t.Fatalf("清空 tenant-a 应删 2 条，实际 %d", n)
	}
	if got := tv.ListForTenant(10, "", "tenant-a"); len(got) != 0 {
		t.Fatalf("tenant-a 应已清空: %+v", got)
	}
	if got := tv.ListForTenant(10, "", "tenant-b"); len(got) != 1 {
		t.Fatalf("tenant-b 记录不应被清: %+v", got)
	}
	if tv.GetForTenant(idLegacy, "") == nil {
		t.Fatal("legacy 记录不应被租户清空删除")
	}
	// 归档分片里的 tenant-a 记录已墓碑：重建索引后仍不可见
	if err := os.Remove(filepath.Join(dir, "archive", "index.json")); err == nil {
		tv2, err := NewTiered(dir, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got := tv2.ListForTenant(10, "", "tenant-a"); len(got) != 0 {
			t.Fatalf("索引重建后被清租户记录不应复活: %+v", got)
		}
	}
}

// TestStoreTenantIsolation JSON Store 层：租户读写过滤 + legacy 可见性。
func TestStoreTenantIsolation(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	idA := s.SaveForTenant(tenantResult("a.example"), nil, "tenant-a")
	idB := s.SaveForTenant(tenantResult("b.example"), nil, "tenant-b")
	idLegacy := s.Save(tenantResult("legacy.example"), nil) // tenant=""
	if idA <= 0 || idB <= 0 || idLegacy <= 0 {
		t.Fatalf("SaveForTenant 返回非法 id: %d/%d/%d", idA, idB, idLegacy)
	}

	// 列表：tenant-a 只见自己；legacy 记录不对具体租户可见
	listA := s.ListForTenant(10, "", "tenant-a")
	if len(listA) != 1 || listA[0].ID != idA || listA[0].Tenant != "tenant-a" {
		t.Fatalf("tenant-a 列表异常: %+v", listA)
	}
	if got := s.ListForTenant(10, "", "tenant-b"); len(got) != 1 || got[0].ID != idB {
		t.Fatalf("tenant-b 列表异常: %+v", got)
	}
	if got := s.ListForTenant(10, "", ""); len(got) != 3 {
		t.Fatalf("空租户（auth 关闭）应见全部 3 条: %+v", got)
	}
	// Get：跨租户按「不存在」处理
	if s.GetForTenant(idA, "tenant-a") == nil {
		t.Fatal("同租户 Get 应命中")
	}
	if s.GetForTenant(idA, "tenant-b") != nil {
		t.Fatal("跨租户 Get 必须返回 nil（404 不泄露存在性）")
	}
	if s.GetForTenant(idLegacy, "tenant-a") != nil {
		t.Fatal("legacy 空租户记录不得对具体租户可见")
	}
	if s.GetForTenant(idLegacy, "") == nil {
		t.Fatal("auth 关闭（空租户）应能读 legacy 记录")
	}
	// Delete：跨租户 false 且原记录仍在
	if s.DeleteForTenant(idA, "tenant-b") {
		t.Fatal("跨租户 Delete 必须返回 false")
	}
	if s.GetForTenant(idA, "tenant-a") == nil {
		t.Fatal("跨租户 Delete 不得真删")
	}
	if !s.DeleteForTenant(idA, "tenant-a") {
		t.Fatal("同租户 Delete 应成功")
	}
	if s.GetForTenant(idA, "tenant-a") != nil {
		t.Fatal("删除后不应再读到")
	}
}

// TestTieredTenantIsolationAcrossArchive Tiered 层：主库 + 归档分片都按租户过滤。
func TestTieredTenantIsolationAcrossArchive(t *testing.T) {
	dir := t.TempDir()
	tv, err := NewTiered(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	// keep=1：交替保存两个租户，强制把记录推进归档分片
	idA1 := tv.SaveForTenant(tenantResult("a1.example"), nil, "tenant-a")
	idB1 := tv.SaveForTenant(tenantResult("b1.example"), nil, "tenant-b") // 归档 a1
	idA2 := tv.SaveForTenant(tenantResult("a2.example"), nil, "tenant-a") // 归档 b1
	idB2 := tv.SaveForTenant(tenantResult("b2.example"), nil, "tenant-b") // 归档 a2
	// 归档文件里应带 tenant 字段
	stats := tv.ArchiveStats()
	if stats["archived"] != 3 {
		t.Fatalf("应归档 3 条，实际 %v", stats)
	}

	listA := tv.ListForTenant(10, "", "tenant-a")
	if len(listA) != 2 || listA[0].ID != idA2 || listA[1].ID != idA1 {
		t.Fatalf("tenant-a 跨档列表异常: %+v", listA)
	}
	listB := tv.ListForTenant(10, "", "tenant-b")
	if len(listB) != 2 || listB[0].ID != idB2 || listB[1].ID != idB1 {
		t.Fatalf("tenant-b 跨档列表异常: %+v", listB)
	}
	if got := tv.ListForTenant(10, "", ""); len(got) != 4 {
		t.Fatalf("空租户应见全部 4 条: %+v", got)
	}
	// 归档记录（idA1）跨租户不可读、同租户可读
	if tv.GetForTenant(idA1, "tenant-b") != nil {
		t.Fatal("归档记录跨租户 Get 必须 nil")
	}
	if rec := tv.GetForTenant(idA1, "tenant-a"); rec == nil || rec.Host != "a1.example" {
		t.Fatalf("归档记录同租户 Get 异常: %+v", rec)
	}
	// 跨租户删归档记录：false 且仍在；同租户删：成功
	if tv.DeleteForTenant(idA1, "tenant-b") {
		t.Fatal("跨租户删归档记录必须 false")
	}
	if tv.GetForTenant(idA1, "tenant-a") == nil {
		t.Fatal("跨租户删除不得真删归档记录")
	}
	if !tv.DeleteForTenant(idA1, "tenant-a") {
		t.Fatal("同租户删归档记录应成功")
	}
	if got := tv.ListForTenant(10, "", "tenant-a"); len(got) != 1 || got[0].ID != idA2 {
		t.Fatalf("删归档后 tenant-a 列表异常: %+v", got)
	}
	// 统计按租户口径
	stA := tv.HistoryStatsForTenant("tenant-a")
	if stA["scans"] != 1 {
		t.Fatalf("tenant-a 统计应 1 条: %+v", stA)
	}
	stB := tv.HistoryStatsForTenant("tenant-b")
	if stB["scans"] != 2 {
		t.Fatalf("tenant-b 统计应 2 条: %+v", stB)
	}
}

// TestSQLTenantIsolation SQL（真实 sqlite）租户隔离 E2E。
func TestSQLTenantIsolation(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	st := NewSQLStore(db)
	idA, err := st.SaveScanForTenant(tenantResult("a.example"), nil, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	idB, err := st.SaveScanForTenant(tenantResult("b.example"), nil, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	idLegacy, err := st.SaveScan(tenantResult("legacy.example"), nil)
	if err != nil {
		t.Fatal(err)
	}

	listA, err := st.ListScansPageForTenant(0, 10, "", "tenant-a")
	if err != nil || len(listA) != 1 || listA[0].ID != idA || listA[0].Tenant != "tenant-a" {
		t.Fatalf("SQL tenant-a 列表异常: %+v err=%v", listA, err)
	}
	if got, _ := st.ListScansPageForTenant(0, 10, "", "tenant-b"); len(got) != 1 || got[0].ID != idB {
		t.Fatalf("SQL tenant-b 列表异常: %+v", got)
	}
	if got, _ := st.ListScansPageForTenant(0, 10, "", ""); len(got) != 3 {
		t.Fatalf("SQL 空租户应见全部 3 条: %+v", got)
	}
	if rec, _ := st.GetScanForTenant(idA, "tenant-a"); rec == nil || rec.Host != "a.example" {
		t.Fatalf("SQL 同租户 Get 异常: %+v", rec)
	}
	if rec, _ := st.GetScanForTenant(idA, "tenant-b"); rec != nil {
		t.Fatal("SQL 跨租户 Get 必须返回 nil")
	}
	if rec, _ := st.GetScanForTenant(idLegacy, "tenant-a"); rec != nil {
		t.Fatal("SQL legacy 记录不得对具体租户可见")
	}
	// 跨租户删除：false 且仍在
	if ok, err := st.DeleteScanForTenant(idA, "tenant-b"); err != nil || ok {
		t.Fatalf("SQL 跨租户 Delete 应 (false,nil): %v err=%v", ok, err)
	}
	if rec, _ := st.GetScanForTenant(idA, "tenant-a"); rec == nil {
		t.Fatal("SQL 跨租户 Delete 不得真删")
	}
	// 统计
	statsA, err := st.StatsForTenant("tenant-a")
	if err != nil || statsA.Scans != 1 || statsA.Hosts != 1 {
		t.Fatalf("SQL tenant-a 统计异常: %+v err=%v", statsA, err)
	}
	if all, _ := st.Stats(); all.Scans != 3 {
		t.Fatalf("SQL 全局统计应 3 条: %+v", all)
	}
	// 租户清空：只删本租户，其它租户与 legacy 保留
	if n, err := st.DeleteScansForTenant("tenant-a"); err != nil || n != 1 {
		t.Fatalf("DeleteScansForTenant = %d err=%v want 1", n, err)
	}
	if rec, _ := st.GetScanForTenant(idB, "tenant-b"); rec == nil {
		t.Fatal("租户清空不得影响其它租户")
	}
	if rec, _ := st.GetScan(idLegacy); rec == nil {
		t.Fatal("租户清空不得影响 legacy 记录")
	}
}

// TestSQLMigration003Idempotent 迁移 003/004 可重复应用（ALTER 已存在列容忍）。
func TestSQLMigration003Idempotent(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("首次 ApplyMigrations: %v", err)
	}
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("重复 ApplyMigrations 应成功（003 ALTER 幂等）: %v", err)
	}
	st := NewSQLStore(db)
	id, err := st.SaveScanForTenant(tenantResult("x.example"), nil, "tenant-x")
	if err != nil || id != 1 {
		t.Fatalf("迁移后 SaveScanForTenant: id=%d err=%v", id, err)
	}
	if rec, _ := st.GetScanForTenant(id, "tenant-x"); rec == nil {
		t.Fatal("迁移后租户读取异常")
	}
}

// TestSQLTriageWhitelistPersist C-09：SQL 复核/白名单持久化（重开 store 仍在）。
func TestSQLTriageWhitelistPersist(t *testing.T) {
	db := openSQLiteTestDB(t)
	if err := ApplyMigrations(db); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	st := NewSQLStore(db)
	scanID, err := st.SaveScanForTenant(tenantResult("triage.example"), nil, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	// 复核：写入/覆盖/汇总
	if err := st.TriageMark(scanID, "fp-1", TriageConfirmed, "确认"); err != nil {
		t.Fatalf("TriageMark: %v", err)
	}
	if err := st.TriageMark(scanID, "fp-1", TriageFalsePositive, "改判误报"); err != nil {
		t.Fatalf("TriageMark 覆盖: %v", err)
	}
	if err := st.TriageMark(scanID, "fp-2", TriageIgnored, ""); err != nil {
		t.Fatalf("TriageMark fp-2: %v", err)
	}
	if err := st.TriageMark(scanID, "fp-3", "bogus", ""); err == nil {
		t.Fatal("非法 verdict 应报 ErrInvalidTriage")
	}
	list := st.TriageList(scanID)
	if len(list) != 2 || list[0].Fingerprint != "fp-1" || list[0].Verdict != TriageFalsePositive {
		t.Fatalf("TriageList 异常: %+v", list)
	}
	fp, confirmed, ignored := st.TriageSummary(scanID)
	if fp != 1 || confirmed != 0 || ignored != 1 {
		t.Fatalf("TriageSummary 异常: fp=%d confirmed=%d ignored=%d", fp, confirmed, ignored)
	}
	// 白名单：通配 + "*" 规则 + 删除
	if err := st.WhitelistAdd("*.example.com", "rule-1", "测试"); err != nil {
		t.Fatalf("WhitelistAdd: %v", err)
	}
	if !st.IsWhitelisted("sub.example.com", "rule-1") {
		t.Fatal("通配白名单应命中子域")
	}
	if st.IsWhitelisted("example.com", "rule-1") {
		t.Fatal("*.example.com 不应命中裸域")
	}
	if err := st.WhitelistAdd("example.com", "*", "全部规则"); err != nil {
		t.Fatalf("WhitelistAdd *: %v", err)
	}
	if !st.IsWhitelisted("example.com", "anything") {
		t.Fatal("\"*\" 规则应命中任意 rule")
	}
	if removed, err := st.WhitelistRemove("*.example.com", "rule-1"); err != nil || !removed {
		t.Fatalf("WhitelistRemove: %v err=%v", removed, err)
	}
	if removed, err := st.WhitelistRemove("*.example.com", "rule-1"); err != nil || removed {
		t.Fatalf("重复删除应 (false,nil): %v err=%v", removed, err)
	}
	if got := st.WhitelistList(); len(got) != 1 || got[0].RuleID != "*" {
		t.Fatalf("WhitelistList 异常: %+v", got)
	}
	// 删除扫描记录 → 复核记录同步清理
	if ok, err := st.DeleteScanForTenant(scanID, "tenant-a"); err != nil || !ok {
		t.Fatalf("DeleteScanForTenant: %v err=%v", ok, err)
	}
	if got := st.TriageList(scanID); len(got) != 0 {
		t.Fatalf("删除扫描后复核记录应清理: %+v", got)
	}
	// 持久化：同一 DB 上新建 SQLStore（等价进程重启后重连）仍可读到白名单
	st2 := NewSQLStore(db)
	if got := st2.WhitelistList(); len(got) != 1 || got[0].Host != "example.com" {
		t.Fatalf("重连后白名单丢失: %+v", got)
	}
	if err := st2.TriageMark(scanID, "fp-after", TriageConfirmed, "重启后写入"); err != nil {
		t.Fatalf("重启后 TriageMark: %v", err)
	}
	if got := st2.TriageList(scanID); len(got) != 1 || got[0].Fingerprint != "fp-after" {
		t.Fatalf("重启后复核写入异常: %+v", got)
	}
}
