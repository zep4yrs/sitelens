// wave3_tenant_test.go BL-5（A-04）多租户数据面隔离的 HTTP 级回归。
//
// 断言口径：
//   - token 模式：跨租户按 {id} 读取/删除/导出/重放/图/diff/复核/job 一律 404
//     （不泄露存在性），同租户正常 200；
//   - 列表/统计只含本租户记录；
//   - legacy（tenant=""）记录只对「auth 关闭（空租户）」可见；
//   - auth 关闭保持既有行为（全局可读）。
package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/authz"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// authDoBody 同 authDo，但带 JSON 请求体（POST/PUT 用）。
func authDoBody(t *testing.T, method, url, token, tenant, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// wave3TenantResult 造一条最小扫描结果。
func wave3TenantResult(host string) *engine.Result {
	return &engine.Result{
		URL: "https://" + host, Host: host, Title: "标题 " + host,
		Status: 200, ScannedAt: "2026-01-01 00:00:00",
	}
}

// TestTenantDataPlaneIsolation token 模式跨租户 IDOR 全链路 404。
func TestTenantDataPlaneIsolation(t *testing.T) {
	const secret = "wave3-secret-0123456789"
	s, api := newAuthTestServer(t, "token", secret)
	idA := s.st.SaveForTenant(wave3TenantResult("a.example"), nil, "tenant-a")
	idB := s.st.SaveForTenant(wave3TenantResult("b.example"), nil, "tenant-b")
	idLegacy := s.st.Save(wave3TenantResult("legacy.example"), nil)
	if idA <= 0 || idB <= 0 || idLegacy <= 0 {
		t.Fatalf("seed 记录 id 异常: %d/%d/%d", idA, idB, idLegacy)
	}
	tokA := issueAuthToken(t, secret, authz.RoleAdmin, "tenant-a")
	tokB := issueAuthToken(t, secret, authz.RoleAdmin, "tenant-b")

	// 1) history detail：跨租户 404、同租户 200
	if code, body := authDo(t, http.MethodGet, api.URL+"/api/history/"+itoa64(idA), tokB, ""); code != 404 {
		t.Fatalf("跨租户读 history 应 404，实际 %d %v", code, body)
	}
	if code, body := authDo(t, http.MethodGet, api.URL+"/api/history/"+itoa64(idA), tokA, ""); code != 200 {
		t.Fatalf("同租户读 history 应 200，实际 %d %v", code, body)
	}
	// legacy 记录对具体租户不可见
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/history/"+itoa64(idLegacy), tokA, ""); code != 404 {
		t.Fatalf("legacy 记录不应被租户读到，实际 %d", code)
	}

	// 2) 列表：只含本租户
	code, body := authDo(t, http.MethodGet, api.URL+"/api/history?limit=50", tokA, "")
	if code != 200 {
		t.Fatalf("history 列表: %d", code)
	}
	scans, _ := body["scans"].([]any)
	if len(scans) != 1 {
		t.Fatalf("tenant-a 列表应只有 1 条，实际 %v", body)
	}
	first, _ := scans[0].(map[string]any)
	if int64(first["id"].(float64)) != idA {
		t.Fatalf("tenant-a 列表混入他人记录: %v", first)
	}

	// 3) 跨租户删除 404 且不真删；同租户删除 200
	if code, _ := authDo(t, http.MethodDelete, api.URL+"/api/history/"+itoa64(idA), tokB, ""); code != 404 {
		t.Fatalf("跨租户删除应 404，实际 %d", code)
	}
	if s.st.GetForTenant(idA, "tenant-a") == nil {
		t.Fatal("跨租户删除不得真删")
	}
	if code, body := authDo(t, http.MethodDelete, api.URL+"/api/history/"+itoa64(idB), tokB, ""); code != 200 || body["deleted"] != true {
		t.Fatalf("同租户删除应 200 deleted=true，实际 %d %v", code, body)
	}

	// 4) 导出：跨租户 404、同租户 200
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/export/"+itoa64(idA)+"?fmt=json", tokB, ""); code != 404 {
		t.Fatalf("跨租户导出应 404，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/export/"+itoa64(idA)+"?fmt=json", tokA, ""); code != 200 {
		t.Fatalf("同租户导出应 200，实际 %d", code)
	}

	// 5) 重放：跨租户 404
	if code, _ := authDo(t, http.MethodPost, api.URL+"/api/replay/"+itoa64(idA), tokB, ""); code != 404 {
		t.Fatalf("跨租户重放应 404，实际 %d", code)
	}

	// 6) 图：跨租户 404（记录不存在）；同租户 404（未收集图，语义不同）
	code, cross := authDo(t, http.MethodGet, api.URL+"/api/graph/"+itoa64(idA), tokB, "")
	if code != 404 || cross["error"] != "记录不存在" {
		t.Fatalf("跨租户读图应 404 记录不存在，实际 %d %v", code, cross)
	}
	code, own := authDo(t, http.MethodGet, api.URL+"/api/graph/"+itoa64(idA), tokA, "")
	if code != 404 || own["error"] == "记录不存在" {
		t.Fatalf("同租户读图应走「未收集」分支，实际 %d %v", code, own)
	}

	// 7) diff：任一侧跨租户 404
	if code, _ := authDo(t, http.MethodGet,
		api.URL+"/api/diff?a="+itoa64(idA)+"&b="+itoa64(idB), tokA, ""); code != 404 {
		t.Fatalf("跨租户 diff 应 404，实际 %d", code)
	}

	// 8) 复核：跨租户标记 404、同租户 200
	code, cross = authDoBody(t, http.MethodPost, api.URL+"/api/triage/"+itoa64(idA), tokB, "", `{}`)
	if code != 404 {
		t.Fatalf("跨租户 triage 应 404，实际 %d %v", code, cross)
	}
	code, own = authDoBody(t, http.MethodPost, api.URL+"/api/triage/"+itoa64(idA), tokA, "",
		`{"fingerprint":"fp-1","verdict":"confirmed","note":"ok"}`)
	if code != 200 {
		t.Fatalf("同租户 triage 应 200，实际 %d %v", code, own)
	}

	// 9) job：跨租户 404、同租户 200
	s.jobs.Create("job-tenant-a", "scan", map[string]any{"url": "https://a.example"}, 100)
	s.jobs.Update("job-tenant-a", func(j *store.Job) { j.Tenant = "tenant-a" })
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/job/job-tenant-a", tokB, ""); code != 404 {
		t.Fatalf("跨租户读 job 应 404，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/job/job-tenant-a", tokA, ""); code != 200 {
		t.Fatalf("同租户读 job 应 200，实际 %d", code)
	}

	// 10) 统计：只统计本租户（idB 已在步骤 3 同租户删除）
	code, body = authDo(t, http.MethodGet, api.URL+"/api/stats", tokA, "")
	if code != 200 {
		t.Fatalf("stats: %d", code)
	}
	hist, _ := body["history"].(map[string]any)
	if hist == nil || hist["scans"].(float64) != 1 {
		t.Fatalf("tenant-a 统计应为 1 条，实际 %v", body["history"])
	}

	// 11) 清空：租户管理员只清空本租户，不影响其它租户/legacy
	code, body = authDo(t, http.MethodPost, api.URL+"/api/history/clear", tokA, "")
	if code != 200 || body["cleared"].(float64) != 1 {
		t.Fatalf("tenant-a 清空应只删 1 条，实际 %d %v", code, body)
	}
	if s.st.GetForTenant(idA, "tenant-a") != nil {
		t.Fatal("tenant-a 记录应已清空")
	}
	if s.st.GetForTenant(idLegacy, "") == nil {
		t.Fatal("legacy 记录不应被租户清空删除")
	}
}

// TestSQLScanStoreTriageTenantPersist server 的 SQL 适配器（C-09 + BL-5）：
// 复核/白名单经接口落 SQL，重开适配器后仍在；租户隔离在适配器层同样生效。
func TestSQLScanStoreTriageTenantPersist(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "wave3.db")
	st, err := openSQLScanStoreWithFallback("sqlite", dsn, "")
	if err != nil {
		t.Fatalf("openSQLScanStoreWithFallback: %v", err)
	}
	closeStore := func(s scanStore) {
		if a, ok := s.(*sqlScanStore); ok {
			if raw, ok := a.db.DB().(*sql.DB); ok {
				_ = raw.Close()
			}
		}
	}
	t.Cleanup(func() { closeStore(st) })
	idA := st.SaveForTenant(wave3TenantResult("a.example"), nil, "tenant-a")
	if idA <= 0 {
		t.Fatalf("SQL SaveForTenant: id=%d", idA)
	}
	idB := st.SaveForTenant(wave3TenantResult("b.example"), nil, "tenant-b")
	if idB <= 0 {
		t.Fatalf("SQL SaveForTenant tenant-b: id=%d", idB)
	}
	if st.GetForTenant(idB, "tenant-a") != nil {
		t.Fatal("SQL 适配器跨租户 Get 应 nil")
	}
	if got := st.ListForTenant(10, "", "tenant-a"); len(got) != 1 || got[0].ID != idA {
		t.Fatalf("SQL 适配器租户列表异常: %+v", got)
	}
	// C-09：复核/白名单（SQL 后端不再 503）
	if err := st.TriageMark(idA, "fp-1", "confirmed", "ok"); err != nil {
		t.Fatalf("SQL 适配器 TriageMark: %v", err)
	}
	if err := st.WhitelistAdd("*.example.com", "rule-1", "原因"); err != nil {
		t.Fatalf("SQL 适配器 WhitelistAdd: %v", err)
	}
	if !st.IsWhitelisted("sub.example.com", "rule-1") {
		t.Fatal("SQL 适配器白名单应命中")
	}
	// 重开适配器（同一 dsn，等价进程重启）→ 复核/白名单仍在
	st2, err := openSQLScanStoreWithFallback("sqlite", dsn, "")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { closeStore(st2) })
	if got := st2.TriageList(idA); len(got) != 1 || got[0].Fingerprint != "fp-1" {
		t.Fatalf("重开复核记录丢失: %+v", got)
	}
	if got := st2.WhitelistList(); len(got) != 1 || got[0].RuleID != "rule-1" {
		t.Fatalf("重开白名单丢失: %+v", got)
	}
	// 租户清空只删本租户
	if n := st2.ClearAllForTenant("tenant-a"); n != 1 {
		t.Fatalf("SQL 适配器租户清空应 1 条，实际 %d", n)
	}
	if st2.GetForTenant(idB, "tenant-b") == nil {
		t.Fatal("SQL 适配器租户清空不得影响其它租户")
	}
}

// TestLegacyVisibleOnlyWhenAuthOff auth 关闭（none 模式）保持全局可见。
func TestLegacyVisibleOnlyWhenAuthOff(t *testing.T) {
	s, api := newAuthTestServer(t, "none", "")
	idA := s.st.SaveForTenant(wave3TenantResult("a.example"), nil, "tenant-a")
	idLegacy := s.st.Save(wave3TenantResult("legacy.example"), nil)
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/history/"+itoa64(idLegacy), "", ""); code != 200 {
		t.Fatalf("auth 关闭时 legacy 记录应可读，实际 %d", code)
	}
	if code, _ := authDo(t, http.MethodGet, api.URL+"/api/history/"+itoa64(idA), "", ""); code != 200 {
		t.Fatalf("auth 关闭时应全局可读（既有行为），实际 %d", code)
	}
	if got := len(s.st.ListForTenant(10, "", "")); got != 2 {
		t.Fatalf("auth 关闭列表应含 2 条，实际 %d", got)
	}
}
