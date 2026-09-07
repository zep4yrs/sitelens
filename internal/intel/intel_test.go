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

func TestLookupAliases(t *testing.T) {
	// 指纹名 "Microsoft IIS" 应经别名命中情报产品 "iis"
	kb := &KB{vulns: []Entry{
		{ID: 1, Src: "xray", Name: "HTTP.sys RCE", Product: "iis", CVE: "CVE-1",
			Severity: "high", Affected: ""},
	}, kev: map[string]bool{}}
	kb.buildIndex()
	out := kb.Match([]TechHit{{Name: "Microsoft IIS"}})
	if len(out) != 1 || out[0].Product != "iis" {
		t.Fatalf("IIS 别名未生效: %+v", out)
	}
	// 大小写/首尾空白不敏感
	out = kb.Match([]TechHit{{Name: "  microsoft IIS "}})
	if len(out) != 1 {
		t.Fatalf("别名规范化失败: %+v", out)
	}
	// 同理 Yoast SEO -> wordpress yoast
	kb2 := &KB{vulns: []Entry{
		{ID: 2, Src: "xray", Name: "Yoast 泄露", Product: "wordpress yoast", CVE: "CVE-2",
			Severity: "medium", Affected: ""},
	}, kev: map[string]bool{}}
	kb2.buildIndex()
	if out := kb2.Match([]TechHit{{Name: "Yoast SEO"}}); len(out) != 1 {
		t.Fatalf("Yoast 别名未生效: %+v", out)
	}
	// 无别名的技术不受影响（防误桥接）
	if out := kb2.Match([]TechHit{{Name: "Google Analytics"}}); len(out) != 0 {
		t.Fatalf("无别名技术被误匹配: %+v", out)
	}
}

// TestMatchCVEMsEmptyComponent 空组件名公告不得经反向包含匹配任意技术
// （真实库 34931 条中 1545 条 component 为空，修复前每次扫描 20 条
// 配额全被无关公告占满）。
func TestMatchCVEMsEmptyComponent(t *testing.T) {
	kb := &KB{cveMs: []CVEMsRow{
		{CVE: "CVE-X", Component: "", Title: "空组件公告", Severity: "Important"},
		{CVE: "CVE-Y", Component: "  ", Title: "空白组件公告", Severity: "Important"},
		{CVE: "CVE-Z", Component: "Windows Kernel", Title: "正常公告", Severity: "Important"},
		{CVE: "CVE-W", Component: ".NET", Title: "组件含点号", Severity: "Important"},
	}}
	out := kb.MatchCVEMs([]TechHit{{Name: "Nginx"}}, 20)
	if len(out) != 0 {
		t.Fatalf("Nginx 不应匹配任何 MS 公告: %+v", out)
	}
	// 正向包含（组件名包含技术名）不受影响
	out = kb.MatchCVEMs([]TechHit{{Name: "Windows Kernel"}}, 20)
	if len(out) != 1 {
		t.Fatalf("正向包含被误伤: %+v", out)
	}
	// 反向包含保留 ≥4 字符组件（如 ASP.NET ↔ .NET）
	out = kb.MatchCVEMs([]TechHit{{Name: "ASP.NET"}}, 20)
	if len(out) != 1 || out[0].Component != ".NET" {
		t.Fatalf("反向包含守卫误伤 .NET: %+v", out)
	}
}
