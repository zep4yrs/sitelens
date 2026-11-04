package server

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// TestCSVCellSafeFormulaInjection V-14：CSV 公式注入转义。
// 被扫页面的 <meta generator>/响应头/JS 变量可让技术名/版本/证据以 = + - @
// 或制表/回车开头；Excel/WPS 会当公式求值（数据外带/DDE）。
func TestCSVCellSafeFormulaInjection(t *testing.T) {
	for _, in := range []string{"=1+1", "+1", "-1", "@SUM(A1)", "\t=cmd|' /C calc'!A0", "\r=1"} {
		got := csvCellSafe(in)
		if !strings.HasPrefix(got, `"'`) {
			t.Errorf("csvCellSafe(%q)=%q，应以 \"' 前缀转义", in, got)
		}
		if !strings.HasSuffix(got, `"`) {
			t.Errorf("csvCellSafe(%q)=%q，应整体加引号", in, got)
		}
	}
	// 正常值原样（不改变既有导出内容）
	for _, in := range []string{"", "WordPress", "6.4", "http://example.com"} {
		if got := csvCellSafe(in); got != in {
			t.Errorf("csvCellSafe(%q)=%q，普通值不应改写", in, got)
		}
	}
	// 内嵌双引号需成对转义
	if got := csvCellSafe(`=HYPERLINK("http://evil")`); !strings.Contains(got, `""`) {
		t.Errorf("内嵌双引号未转义: %q", got)
	}
}

// TestExportCSVFormulaInjectionEndToEnd 明细/宽表 CSV 里危险单元格都被转义。
func TestExportCSVFormulaInjectionEndToEnd(t *testing.T) {
	rec := &store.ScanRecord{
		ScanSummary: store.ScanSummary{ID: 1, URL: "http://t.example/", Host: "t.example"},
		Result: &engine.Result{Technologies: []engine.Tech{{
			Name:       "=cmd|' /C calc'!A0",
			Categories: []string{"cms"},
			Confidence: 90,
			Version:    `=HYPERLINK("http://evil.example")`,
			Website:    "@SUM(1+1)",
			Evidence:   []string{"=1+1"},
		}}},
	}
	detail := detailCSV(rec, []string{"cms"})
	wide := wideCSV([]*store.ScanRecord{rec}, []string{"cms"})
	for name, out := range map[string]string{"detail": detail, "wide": wide} {
		if out == "" {
			t.Fatalf("%s CSV 为空", name)
		}
		// 不允许出现"行首/逗号后直接是公式"的单元格
		for _, bad := range []string{"\n=", "\n+", "\n@", ",=", ",@"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s CSV 存在未转义公式单元格（%q）：\n%s", name, bad, out)
			}
		}
		if !strings.Contains(out, `"'`) {
			t.Errorf("%s CSV 未对危险值做 \"' 前缀：\n%s", name, out)
		}
	}
}
