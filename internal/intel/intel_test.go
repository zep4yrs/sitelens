package intel

import "testing"

func TestKeywordsAntiFlood(t *testing.T) {
	// 多词产品 lookup 侧只按完整短语，防 "api" 泛词误报
	kw := Keywords("Google Analytics", false)
	if !kw["google analytics"] || !kw["googleanalytics"] {
		t.Errorf("短语关键词缺失: %v", kw)
	}
	if kw["google"] {
		t.Errorf("多词产品不应收录单词 google: %v", kw)
	}
	// index 侧收录显著单词（>=4 字符非停用词）
	iw := Keywords("Oracle WebLogic", true)
	if !iw["oracle"] {
		t.Errorf("index 侧应收录 oracle: %v", iw)
	}
	if iw["api"] || iw["app"] {
		t.Errorf("停用词不应收录: %v", iw)
	}
	// 单词产品收录词本身
	sw := Keywords("nginx", false)
	if !sw["nginx"] {
		t.Errorf("单词产品应收录自身: %v", sw)
	}
}

func TestThreeLevelVerdict(t *testing.T) {
	kb := &KB{vulns: []Entry{
		{ID: 1, Src: "afrog", Name: "WP 注入", Product: "WordPress", CVE: "CVE-1",
			Severity: "high", Affected: "<5.5"},
		{ID: 2, Src: "xray", Name: "WP 泄露", Product: "WordPress", CVE: "CVE-2",
			Severity: "medium", Affected: ""},
	}, kev: map[string]bool{}}

	techs := []TechHit{{Name: "WordPress", Version: "4.9.9"}}
	out := kb.Match(techs)
	// 4.9.9 < 5.5 → confirmed
	if len(out) != 2 || out[0].Verdict != "confirmed" {
		t.Fatalf("confirmed 判定失败: %+v", out)
	}
	// 6.0 不在 ID 1 区间（excluded 丢弃）；ID 2 空区间保持 possible 输出
	techs[0].Version = "6.0"
	out = kb.Match(techs)
	if len(out) != 1 || out[0].Verdict != "possible" {
		t.Fatalf("excluded/possible 判定失败: %+v", out)
	}
	// 无版本 → possible；Affected 为空的行也保持 possible 输出
	techs[0].Version = ""
	out = kb.Match(techs)
	if len(out) != 2 || out[0].Verdict != "possible" || out[1].Verdict != "possible" {
		t.Fatalf("possible 判定失败: %+v", out)
	}
}

func TestKEVFlag(t *testing.T) {
	kb := &KB{
		vulns: []Entry{{ID: 1, Src: "afrog", Name: "Log4Shell", Product: "Apache Log4j2",
			CVE: "CVE-2021-44228", Severity: "critical"}},
		kev: map[string]bool{"CVE-2021-44228": true},
	}
	out := kb.Match([]TechHit{{Name: "Apache Log4j2"}})
	if len(out) != 1 || !out[0].KEV {
		t.Errorf("KEV 红标缺失: %+v", out)
	}
}
func TestThreeLevelExcludedDropped(t *testing.T) {
	// 版本不在区间 → excluded 不输出（只输出 possible 的那一条）
	kb := &KB{vulns: []Entry{
		{ID: 1, Src: "afrog", Name: "旧版注入", Product: "WordPress", CVE: "CVE-A",
			Severity: "high", Affected: "<5.5"},
		{ID: 2, Src: "xray", Name: "新版修复", Product: "WordPress", CVE: "CVE-B",
			Severity: "medium", Affected: ">=6.0"},
	}, kev: map[string]bool{}}
	kb.buildIndex()
	out := kb.Match([]TechHit{{Name: "WordPress", Version: "6.1"}})
	if len(out) != 1 || out[0].Verdict != "confirmed" || out[0].CVE != "CVE-B" {
		t.Fatalf("excluded 过滤失败: %+v", out)
	}
}
