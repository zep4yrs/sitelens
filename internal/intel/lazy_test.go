package intel

import (
	"path/filepath"
	"strings"
	"testing"
)

// lazyPaths 项目真实主数据（相对 intel 包目录）。
func lazyPaths() (string, string) {
	return filepath.Join("..", "..", "data", "intel_dump.json.gz"),
		filepath.Join("..", "..", "data", "affected_ranges.json")
}

// TestLoadLazyDeferredDecode：LoadLazy 只记路径不解码，首次访问才解码。
func TestLoadLazyDeferredDecode(t *testing.T) {
	dump, ranges := lazyPaths()
	kb := LoadLazy(dump, ranges)
	if kb.decoded {
		t.Fatal("LoadLazy 不应立即解码")
	}
	if kb.LoadError() != "" {
		t.Fatalf("未使用不应有错误: %s", kb.LoadError())
	}
	_ = kb.ServiceFP() // 首次访问触发解码
	if !kb.decoded {
		t.Fatal("访问后应完成解码")
	}
	if kb.LoadError() != "" {
		t.Fatalf("真实数据解码不应失败: %s", kb.LoadError())
	}
	if len(kb.vulns) == 0 {
		t.Fatal("解码后 vuln 表为空")
	}
}

// TestLoadLazyPendingTplApplied：解码前 AttachTplIntel 挂起，解码后按序并入并参与匹配。
func TestLoadLazyPendingTplApplied(t *testing.T) {
	dump, ranges := lazyPaths()
	kb := LoadLazy(dump, ranges)
	kb.AttachTplIntel([]Entry{{Src: "tpl", Name: "挂起行", Product: "WidgetPro"}})
	if len(kb.pendingTpl) != 1 {
		t.Fatalf("未解码时应挂起，实得 %d", len(kb.pendingTpl))
	}
	_ = kb.FingerDir() // 触发解码
	if len(kb.pendingTpl) != 0 {
		t.Fatal("解码后挂起队列应清空")
	}
	out := kb.Match([]TechHit{{Name: "WidgetPro"}})
	if len(out) != 1 {
		t.Fatalf("挂起模板行应参与匹配: %+v", out)
	}
}

// TestLoadLazyMissingDumpLoadError：源缺失时错误延迟到使用点，表保持空态可用。
func TestLoadLazyMissingDumpLoadError(t *testing.T) {
	kb := LoadLazy(filepath.Join(t.TempDir(), "nope.json.gz"), "")
	_ = kb.ServiceFP()
	if kb.LoadError() == "" {
		t.Fatal("缺失文件应产生 LoadError")
	}
	out := kb.Match([]TechHit{{Name: "nginx"}}) // 空态不 panic
	if len(out) != 0 {
		t.Fatalf("空库不应命中: %+v", out)
	}
}

// TestReleaseReplaysTplAndOverrides：Release 后重载须恢复模板行与覆盖（A10 真实 bug 回归锁）。
func TestReleaseReplaysTplAndOverrides(t *testing.T) {
	dump, ranges := lazyPaths()
	kb, err := Load(dump, ranges)
	if err != nil {
		t.Fatal(err)
	}
	// 挑一条带 CVE 的主数据行打覆盖标记
	var cve string
	for _, v := range kb.vulns {
		if v.CVE != "" {
			cve = v.CVE
			break
		}
	}
	if cve == "" {
		t.Fatal("主数据无 CVE 行，无法验证覆盖")
	}
	kb.AttachTplIntel([]Entry{{Src: "tpl", Name: "重放行", Product: "WidgetPro"}})
	if n := kb.ApplyOverrides(map[string]Override{cve: {Affected: "REPLAY-MARK"}}); n == 0 {
		t.Fatalf("覆盖未生效: %s", cve)
	}
	total := len(kb.vulns)
	kb.Release()
	_ = kb.ServiceFP() // 触发重载
	if len(kb.vulns) != total {
		t.Fatalf("重载后应恢复 主数据+模板行: %d != %d", len(kb.vulns), total)
	}
	found := false
	for _, v := range kb.vulns {
		if v.CVE == cve && strings.Contains(v.Affected, "REPLAY-MARK") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("覆盖未重放: %s", cve)
	}
	out := kb.Match([]TechHit{{Name: "WidgetPro"}})
	if len(out) != 1 {
		t.Fatalf("模板行重载后应参与匹配: %+v", out)
	}
}

// TestReleaseRearmsLazy：Release 清表复位后，下次访问自动重载回同量数据。
func TestReleaseRearmsLazy(t *testing.T) {
	dump, ranges := lazyPaths()
	kb, err := Load(dump, ranges)
	if err != nil {
		t.Fatal(err)
	}
	n := len(kb.vulns)
	if n == 0 {
		t.Fatal("主数据 vuln 表为空")
	}
	kb.Release()
	if kb.decoded || kb.vulns != nil {
		t.Fatal("Release 后应复位解码标记并清表")
	}
	_ = kb.ServiceFP()
	if len(kb.vulns) != n {
		t.Fatalf("重载后条数不符: %d != %d", len(kb.vulns), n)
	}
}
