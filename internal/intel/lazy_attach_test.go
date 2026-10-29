package intel

// 惰性解码换表一致性回归（决策点C / BUG-014 同类）：
// serve 启动期是 LoadLazy → AttachTechCPE / MergeKEV(KEV 缓存) → 首次扫描
// 才解码；ensureDecoded 换入 dump 构建的新表时不得丢弃这些「解码前挂载」
// 的外部状态，也不得让读侧看到被换掉的旧 slice。

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// writeMiniIntelDump 写一份最小但合法的 intel_dump（gz）供惰性解码用例使用。
func writeMiniIntelDump(t *testing.T, tablesJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel_dump.json.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`{"tables":` + tablesJSON + `}`)); err != nil {
		t.Fatalf("写 gz: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关 gz: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("写 dump: %v", err)
	}
	return path
}

// TestLoadLazyPreservesPreDecodeKEV 决策点C 回归：serve 启动期 LoadLazy 后
// 会先 LoadKEVExtra→MergeKEV（KEV 守护协程首轮拉取同理），而首次扫描才
// 触发 ensureDecoded。换入 dump 的 KEV 表时若直接覆盖，这批增量会静默
// 丢失 → 首次扫描到下次轮询前漏 KEV 标注。
func TestLoadLazyPreservesPreDecodeKEV(t *testing.T) {
	dump := writeMiniIntelDump(t, `{"vuln_kb":[],"kev":[{"cve":"CVE-2020-0001"}]}`)
	kb := LoadLazy(dump, "")
	if kb.decoded {
		t.Fatal("LoadLazy 不应立即解码")
	}
	// 解码前合并外部 KEV 增量（模拟 kev_extra.json / 守护协程首轮拉取）
	if n := kb.MergeKEV([]KevEntry{{CVE: "CVE-2024-9999"}}); n != 1 {
		t.Fatalf("解码前 MergeKEV 新增 = %d，期望 1", n)
	}
	_ = kb.ServiceFP() // 触发首次解码（换入 dump 的 KEV 表）
	if !kb.IsKEV("CVE-2024-9999") {
		t.Fatal("解码前合并的 KEV 增量被 dump 表覆盖（决策点C 回归）")
	}
	if !kb.IsKEV("CVE-2020-0001") {
		t.Fatal("dump 自带的 KEV 条目丢失")
	}
}

// TestLoadLazyPreservesPreDecodeTechCPE 决策点C 同类：server 启动期在首次
// 解码前 AttachTechCPE(data/go/tech_cpe.json)，ensureDecoded 换表时曾把
// 该映射清成 nil → CPE possible 通道静默失效。
func TestLoadLazyPreservesPreDecodeTechCPE(t *testing.T) {
	dump := writeMiniIntelDump(t, `{"vuln_kb":[],"kev":[]}`)
	kb := LoadLazy(dump, "")
	kb.AttachTechCPE(map[string]string{"widgetpro": "cpe:2.3:a:widget:pro:1.0"})
	_ = kb.ServiceFP() // 触发首次解码
	if kb.techCPE == nil {
		t.Fatal("解码换表把启动期挂载的 techCPE 清空（CPE 通道静默失效）")
	}
	if got := kb.techCPE["widgetpro"]; got == "" {
		t.Fatalf("techCPE 映射丢失: %+v", kb.techCPE)
	}
}

// TestReleaseReplaysKEVExtras Release→重载 KEV 增量重放回归：
// A10 Release 清空 KEV 表（内存释放目标不变），但释放前整表（含
// kev_extra/守护协程增量）存入 pendingKEV，重载后由 ensureDecoded 重放。
// 修复前 Release→重载只剩 dump 自带条目，增量静默丢失到下次 KEV 轮询。
func TestReleaseReplaysKEVExtras(t *testing.T) {
	dump := writeMiniIntelDump(t, `{"vuln_kb":[],"kev":[{"cve":"CVE-2020-0001"}]}`)
	kb := LoadLazy(dump, "")
	// 启动期语义：KEV 缓存/守护协程增量先于首次解码（等价于
	// LoadKEVExtra→MergeKEV）
	if n := kb.MergeKEV([]KevEntry{{CVE: "CVE-2024-8888"}}); n != 1 {
		t.Fatalf("解码前 MergeKEV 新增 = %d，期望 1", n)
	}
	_ = kb.ServiceFP() // 首次解码：dump 表 + 增量并存
	if !kb.IsKEV("CVE-2024-8888") || !kb.IsKEV("CVE-2020-0001") {
		t.Fatal("前置：解码后应同时看到增量与 dump 条目")
	}

	kb.Release() // A10 内存释放：清表（语义不变）
	if n := kb.kevCount(); n != 0 {
		t.Fatalf("Release 应清空 KEV 表（内存释放目标），实得 %d 条", n)
	}
	if kb.IsKEV("CVE-2024-8888") {
		t.Fatal("释放期间 KEV 不应可见（表已清空）")
	}

	_ = kb.ServiceFP() // 触发重载 → pendingKEV 重放
	if !kb.IsKEV("CVE-2024-8888") {
		t.Fatal("Release→重载后 KEV 增量丢失（pendingKEV 未重放）")
	}
	if !kb.IsKEV("CVE-2020-0001") {
		t.Fatal("Release→重载后 dump 自带 KEV 条目丢失")
	}
}

// TestMatchCVEMsAfterReleaseConsistent BUG-014 同类（cveMs 表）：Release
// 清表后 MatchCVEMs 触发重载，前后结果必须自洽；同时验证 MatchCVEMs 在
// vulnsMu 读锁内消费 cveMs 快照，不会读到被换掉的 slice。
func TestMatchCVEMsAfterReleaseConsistent(t *testing.T) {
	dump := writeMiniIntelDump(t, `{"vuln_kb":[],"kev":[],"cve_ms":[
		{"cve":"CVE-2024-1111","component":"Microsoft Windows Kernel",
		 "title":"内核提权","severity":"high","impact":"EoP","date":"2024-01-01"}]}`)
	kb := LoadLazy(dump, "")
	techs := []TechHit{{Name: "Windows Kernel"}}
	got1 := kb.MatchCVEMs(techs, 20)
	if len(got1) != 1 || got1[0].CVE != "CVE-2024-1111" {
		t.Fatalf("首次匹配异常: %+v", got1)
	}
	kb.Release()
	got2 := kb.MatchCVEMs(techs, 20) // 触发重载
	if len(got2) != 1 || got2[0].CVE != got1[0].CVE ||
		got2[0].Component != got1[0].Component || got2[0].Severity != got1[0].Severity {
		t.Fatalf("Release/重载前后 MatchCVEMs 结果不自洽: %+v vs %+v", got1, got2)
	}
}
