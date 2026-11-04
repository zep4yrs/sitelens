package intel

// Wave-1 修复回归（C-10 / C2-01 / C2-03 / C2-04 / C2-05）。
//
// 这些用例直接使用仓库自带数据（data/intel_dump.json.gz /
// data/intel_overrides.json），属于数据级回归：不只验函数形态，而是验
// "仓库里的真实覆盖数据不会再毒化判定"。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/versioncmp"
)

// ---- C2-01：OSV 区间提取语义 ----

// TestOsvAffectedFromVulnSemantics 覆盖多段 OR、GIT 跳过、last_affected、
// 开区间五种形态（C2-01 的核心行为契约）。
func TestOsvAffectedFromVulnSemantics(t *testing.T) {
	const raw = `{"id":"X","affected":[{"ranges":[
	  {"type":"ECOSYSTEM","events":[
	    {"introduced":"1.0"},{"fixed":"1.5"},
	    {"introduced":"2.0"},{"fixed":"2.5"}]},
	  {"type":"ECOSYSTEM","events":[{"introduced":"3.0"},{"last_affected":"3.4"}]},
	  {"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeefcafe"}]},
	  {"type":"SEMVER","events":[{"introduced":"9.0"},{"fixed":"9.9"}]}
	]}]}`
	var v OsvVuln
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("样例 JSON 解析失败: %v", err)
	}
	aff := OsvAffectedFromVuln(v)
	if aff == "" {
		t.Fatal("应提取到 ECOSYSTEM 区间")
	}
	if strings.Contains(aff, "deadbeef") {
		t.Fatalf("GIT commit hash 不得进入版本区间：%q", aff)
	}
	// 多段区间必须是 OR（"|"），不是拍平的 AND 逗号串。
	if !strings.Contains(aff, "|") {
		t.Fatalf("多段区间应使用 \"|\" 连接（OR），实得 %q", aff)
	}
	alts := strings.Split(aff, "|")
	hits := func(ver string) bool {
		for _, alt := range alts {
			if versioncmp.VersionIn(ver, alt) {
				return true
			}
		}
		return false
	}
	for _, ver := range []string{"1.0", "1.4", "2.0", "2.4", "3.0", "3.4"} {
		if !hits(ver) {
			t.Errorf("版本 %s 应命中（所在区间）: %q", ver, aff)
		}
	}
	for _, ver := range []string{"1.5", "2.5", "3.5", "9.0"} {
		if hits(ver) {
			t.Errorf("版本 %s 不应命中（区间外/SEMVER 不消费）: %q", ver, aff)
		}
	}
	// last_affected 必须被消费
	if !strings.Contains(aff, "<=3.4") {
		t.Errorf("last_affected 未消费: %q", aff)
	}
	// 开区间（无 fixed）：OSV 表示至今未修复，应保留 >=x 且可命中
	open := `{"id":"Y","affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.0"}]}]}]}`
	var ov OsvVuln
	if err := json.Unmarshal([]byte(open), &ov); err != nil {
		t.Fatal(err)
	}
	oa := OsvAffectedFromVuln(ov)
	if oa != ">=4.0" || !versioncmp.VersionIn("4.5", oa) {
		t.Errorf("开区间提取异常: %q", oa)
	}
	// 纯 GIT：无可比区间 → 空串（宁少报，不伪造 ≥0）
	gitOnly := `{"id":"Z","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeef"}]}]}]}`
	var gv OsvVuln
	if err := json.Unmarshal([]byte(gitOnly), &gv); err != nil {
		t.Fatal(err)
	}
	if got := OsvAffectedFromVuln(gv); got != "" {
		t.Fatalf("纯 GIT 区间不应产出版本串: %q", got)
	}
}

// TestSanitizeAffected 历史数据的消费侧兜底（C2-01）。
func TestSanitizeAffected(t *testing.T) {
	cases := []struct{ in, want string }{
		// 历史 update-osv 产物：ECOSYSTEM 数值区间与 GIT hash 被拍平成一个
		// 逗号串（整组不可信 → 丢弃，避免把 hash 交给版本比较器）。
		{">=0,<5f88da2a5ee8ba78917fafd572c7b9fa37e76460", ""},
		{">=1.0,<1.5,>=2.0,<2.5,>=0,<deadbeef", ""},
		// 本来就是干净的 OR 串：原样保留。
		{">=1.0,<1.5|>=2.0,<2.5", ">=1.0,<1.5|>=2.0,<2.5"},
		// 单段干净区间保留。
		{">=8.3,<8.3.7", ">=8.3,<8.3.7"},
		// ">=0" 属空信息（全部版本），丢弃。
		{">=0", ""},
		// 前导 v 归一化。
		{">=v1.2,<v1.5", ">=1.2,<1.5"},
		// 混合分支：坏分支丢弃、好分支保留。
		{">=deadbeef,<cafe|>=3.1,<3.2", ">=3.1,<3.2"},
	}
	for _, c := range cases {
		if got := SanitizeAffected(c.in); got != c.want {
			t.Errorf("SanitizeAffected(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestShippedOverridesDoNotPoisonPossibleRows 数据级回归：仓库自带的
// data/intel_overrides.json 里 128 条 affected 全部来自 GIT 区间（commit
// hash，无版本信息）。旧实现把它们写进 vuln_kb 行后，Match 会把原本
// possible 的行判成 excluded（静默漏报）。
//
// 本用例必须**确定性**：不依赖 data/intel_dump 的具体产品/精选区间，也不
// 依赖 map 迭代顺序——端到端判定用自建的独立小 KB（行 ID 全 0，与真实
// dump 形态一致）；真实 dump 只用于「覆盖后不毒化」的数据级断言。
func TestShippedOverridesDoNotPoisonPossibleRows(t *testing.T) {
	ovPath := filepath.Join("..", "..", "data", "intel_overrides.json")
	raw, err := os.ReadFile(ovPath)
	if err != nil {
		t.Skipf("覆盖数据不在本地（%v），跳过数据级回归", err)
	}
	ov, err := ParseOverrides(raw)
	if err != nil {
		t.Fatalf("解析覆盖数据失败: %v", err)
	}

	// 1) 规范化后不得残留不可比较条件（commit hash 等）。
	withAff := 0
	for cve, o := range ov {
		if o.Affected == "" {
			continue
		}
		withAff++
		for _, alt := range strings.Split(o.Affected, "|") {
			for _, cond := range strings.Split(alt, ",") {
				_, val, ok := splitCondOp(cond)
				if !ok || !osvVersionUsable(val) {
					t.Errorf("%s 规范化后仍含不可比较条件 %q（完整: %q）", cve, cond, o.Affected)
				}
			}
		}
	}
	t.Logf("仓库覆盖数据：规范化后仍带可用版本区间的条目 %d 条（历史形态均为 GIT 区间，已被安全剥离，不再毒化判定）", withAff)

	// 2) 真实主数据：覆盖合并不得把原本空 Affected 的情报行写成非空
	//    （否则 Match 会判 excluded）。只做行级断言，不进 Match（避免受
	//    真实库的精选区间 / 排序 / 截断影响）。
	dump, ranges := lazyPaths()
	kb, err := Load(dump, ranges)
	if err != nil {
		t.Skipf("主数据不在本地（%v），跳过数据级断言", err)
	}
	emptyBefore := map[string]bool{}
	for _, v := range kb.vulns {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		if c != "" && v.Affected == "" {
			emptyBefore[c] = true
		}
	}
	if len(emptyBefore) == 0 {
		t.Skip("主数据里没有 Affected 为空的情报行，无法验证 possible 保持")
	}
	kb.ApplyOverrides(ov)
	for _, v := range kb.vulns {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		if emptyBefore[c] && strings.TrimSpace(v.Affected) != "" {
			t.Errorf("覆盖把原本 Affected 为空的行写成了 %q（%s）——Match 会判 excluded 造成漏报", v.Affected, c)
		}
	}

	// 3) 端到端（独立 KB，确定性）：取一条覆盖里带 affected 的 CVE 作探针。
	//    候选 CVE 必须排序后取第一条——遍历 map 会让"探针是谁"每次不同
	//    （此前 flaky 的直接诱因）。
	var rawOv map[string]Override
	if err := json.Unmarshal(raw, &rawOv); err != nil {
		t.Fatalf("原始覆盖解析失败: %v", err)
	}
	cves := make([]string, 0, len(rawOv))
	for cve, o := range rawOv {
		if strings.TrimSpace(o.Affected) != "" {
			cves = append(cves, cve)
		}
	}
	sort.Strings(cves)
	if len(cves) == 0 {
		t.Skip("覆盖数据里没有带 affected 的条目，无法构造端到端探针")
	}
	probeCVE := cves[0]

	// 独立 KB：同一产品两行、Entry.ID 全为 0（真实 dump 形态）。按 ID 去重
	// 的旧实现会把两行当同一行，只留 map 顺序随机的其中一条——这里同时锁住
	// 「探针必须出现」与「两行都出现」两个契约。
	const probeProduct = "WidgetPro"
	newKB := func() *KB {
		return &KB{vulns: []Entry{
			{Src: "test", Name: "probe", Product: probeProduct, CVE: probeCVE, Severity: "high"},
			{Src: "test", Name: "decoy", Product: probeProduct, CVE: "CVE-2099-9999", Severity: "high"},
		}, kev: map[string]bool{}}
	}
	kbNew := newKB()
	kbNew.ApplyOverrides(ov)
	got := kbNew.Match([]TechHit{{Name: probeProduct, Version: "1.0.0"}})
	var probe *Finding
	for i := range got {
		if strings.EqualFold(got[i].CVE, probeCVE) {
			probe = &got[i]
		}
	}
	if probe == nil {
		t.Fatalf("%s（产品 %q）合并覆盖后从 Match 结果中消失（确定性探针）", probeCVE, probeProduct)
	}
	if probe.Verdict != "possible" {
		t.Fatalf("%s 期望 possible，实得 %q", probeCVE, probe.Verdict)
	}
	if len(got) != 2 {
		t.Fatalf("同一产品（行 ID 全 0）的两行都应输出，实得 %d 条: %+v", len(got), got)
	}
	// 确定性：重复调用结果（集合与顺序）完全一致。
	for i := 0; i < 20; i++ {
		again := kbNew.Match([]TechHit{{Name: probeProduct, Version: "1.0.0"}})
		if len(again) != len(got) {
			t.Fatalf("Match 结果不稳定：第 %d 次 %d 条，首次 %d 条", i, len(again), len(got))
		}
		for j := range again {
			if again[j].CVE != got[j].CVE || again[j].Verdict != got[j].Verdict {
				t.Fatalf("Match 输出不稳定：第 %d 次 %+v，首次 %+v", i, again, got)
			}
		}
	}

	// 4) 旧行为对照（同一独立 KB）：跳过规范化、把原始 hash 区间直接合并，
	//    该行会被判 excluded 并从结果中消失——证明修复前的漏报真实存在。
	kbOld := newKB()
	kbOld.ApplyOverrides(rawOv)
	for _, f := range kbOld.Match([]TechHit{{Name: probeProduct, Version: "1.0.0"}}) {
		if strings.EqualFold(f.CVE, probeCVE) {
			t.Fatalf("旧行为对照应把 %s 判 excluded 而消失，实得 verdict=%q", probeCVE, f.Verdict)
		}
	}
}

// TestMatchRowsWithoutIDsAllEmitted 回归（flaky 的根因）：dump 导出的
// vuln_kb 行没有 id 字段，Entry.ID 全为 0。Match 去重必须按行身份而不是
// ID，否则同一技术的候选行会被当成同一条——每技术只剩 1 条，且留哪条由
// map 迭代顺序决定（非确定性 + 漏报，maxPerTech=20 形同虚设）。
func TestMatchRowsWithoutIDsAllEmitted(t *testing.T) {
	kb := &KB{vulns: []Entry{
		{Src: "x", Name: "a", Product: "WidgetPro", CVE: "CVE-2000-0001", Severity: "high"},
		{Src: "x", Name: "b", Product: "WidgetPro", CVE: "CVE-2000-0002", Severity: "high"},
		{Src: "x", Name: "c", Product: "WidgetPro", CVE: "CVE-2000-0003", Severity: "high"},
	}, kev: map[string]bool{}}
	for i := 0; i < 20; i++ {
		out := kb.Match([]TechHit{{Name: "WidgetPro"}})
		if len(out) != 3 {
			t.Fatalf("第 %d 次：3 行同产品（ID 全 0）都应输出，实得 %d 条: %+v", i, len(out), out)
		}
		for j := range out {
			if out[j].Verdict != "possible" {
				t.Fatalf("第 %d 次：verdict 异常 %+v", i, out)
			}
		}
	}
}

// TestMatchCapDeterministic 截断确定性：候选行超过 maxPerTech 时，留下哪
// 20 条必须是确定集合（同严重度按 CVE 排序），不能随 map 迭代顺序变化。
func TestMatchCapDeterministic(t *testing.T) {
	var vulns []Entry
	for i := 0; i < maxPerTech+5; i++ {
		vulns = append(vulns, Entry{
			Src: "x", Name: "n", Product: "WidgetPro",
			CVE:      "CVE-2000-" + leftPad4(i),
			Severity: "high",
		})
	}
	kb := &KB{vulns: vulns, kev: map[string]bool{}}
	var first []string
	for round := 0; round < 20; round++ {
		out := kb.Match([]TechHit{{Name: "WidgetPro"}})
		if len(out) != maxPerTech {
			t.Fatalf("截断条数应为 %d，实得 %d", maxPerTech, len(out))
		}
		names := make([]string, len(out))
		for i := range out {
			names[i] = out[i].CVE
			if i > 0 && names[i-1] > names[i] {
				t.Fatalf("同严重度输出应按 CVE 升序（确定性），实得 %v", names)
			}
		}
		if first == nil {
			first = names
			continue
		}
		for i := range names {
			if names[i] != first[i] {
				t.Fatalf("第 %d 轮截断集合与首轮不同：%v != %v", round, names, first)
			}
		}
	}
}

// leftPad4 把 0..9999 补成 4 位数字（构造可排序的 CVE 序号）。
func leftPad4(n int) string {
	s := "000" + itoa(n)
	return s[len(s)-4:]
}

// ---- C2-03：Search 不应在本地命中满额时拉起 NVD ----

func writeTinyNVD(t *testing.T, entries []NVDEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nvd.json.gz")
	if err := writeNVDFile(path, entries); err != nil {
		t.Fatalf("写临时 NVD 失败: %v", err)
	}
	return path
}

func TestSearchDoesNotLoadNVDWhenLocalHitsFillLimit(t *testing.T) {
	nvdPath := writeTinyNVD(t, []NVDEntry{{CVE: "CVE-2099-9001", Descr: "x", Prods: []NVDProd{{VP: "acme/widget"}}}})
	kb := &KB{vulns: []Entry{
		{ID: 1, Product: "Widget", CVE: "CVE-2099-0001", Name: "widget bug"},
		{ID: 2, Product: "Gadget", CVE: "CVE-2099-0002", Name: "gadget bug"},
	}, kev: map[string]bool{}}
	kb.AttachNVDPath(nvdPath)
	// limit=1 且本地命中满额：不得触发 NVD 全量解码（C2-03）。
	out := kb.Search("widget", 1)
	if len(out) != 1 {
		t.Fatalf("本地命中数异常: %+v", out)
	}
	if kb.NVDLoaded() {
		t.Fatal("本地命中已满 limit，Search 不应拉起 NVD 索引")
	}
}

// ---- C2-04：CVSS 0.0 与"缺失"区分 ----

func TestNVDZeroScoreRoundtrip(t *testing.T) {
	// 0.0 分是合法 CVSS 结果（Impact<=0）；必须能与"缺失"区分。
	dir := t.TempDir()
	path := filepath.Join(dir, "nvd.json.gz")
	if err := writeNVDFile(path, []NVDEntry{
		{CVE: "CVE-2099-0100", Score: 0, ScoreSet: true, Sev: "none"},
		{CVE: "CVE-2099-0101"}, // 无评分
	}); err != nil {
		t.Fatalf("writeNVDFile: %v", err)
	}
	s, err := LoadNVD(path)
	if err != nil || s == nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	e, ok := s.ByCVE("CVE-2099-0100")
	if !ok {
		t.Fatal("CVE-2099-0100 缺失")
	}
	if !e.HasScore() || e.Score != 0 {
		t.Errorf("0.0 分应保留为真实评分: %+v", e)
	}
	if e, _ := s.ByCVE("CVE-2099-0101"); e.HasScore() {
		t.Errorf("无评分条不应被 HasScore 判为有分: %+v", e)
	}
}

// ---- C2-05：CPE/产品检索确定化 + 严重度优先 ----

func TestByProductDeterministicAndSeverityFirst(t *testing.T) {
	entries := []NVDEntry{
		{CVE: "CVE-2099-0002", Score: 5.0, ScoreSet: true, Prods: []NVDProd{{VP: "acme/widget"}}},
		{CVE: "CVE-2099-0001", Score: 9.8, ScoreSet: true, Prods: []NVDProd{{VP: "acme/widget_pro"}}},
		{CVE: "CVE-2099-0003", Prods: []NVDProd{{VP: "acme/widget_ce"}}},
		{CVE: "CVE-2099-0004", Score: 5.0, ScoreSet: true, Prods: []NVDProd{{VP: "acme/widget_x"}}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nvd.json.gz")
	if err := writeNVDFile(path, entries); err != nil {
		t.Fatal(err)
	}
	s, err := LoadNVD(path)
	if err != nil || s == nil {
		t.Fatalf("LoadNVD: %v", err)
	}
	first := s.ByProduct("widget", 2)
	if len(first) != 2 {
		t.Fatalf("limit=2 应返回 2 条，实得 %d", len(first))
	}
	// 严重度优先：最高分在前；0.0/无评分排最后。
	if first[0].CVE != "CVE-2099-0001" {
		t.Errorf("应先返回最高分条目，实得 %+v", first)
	}
	// 确定性：重复查询 / 新建索引后结果一致（旧实现 map 迭代随机）。
	for i := 0; i < 20; i++ {
		again := s.ByProduct("widget", 2)
		for j := range first {
			if again[j].CVE != first[j].CVE {
				t.Fatalf("ByProduct 结果不确定：第 %d 次 %v != %v", i, again, first)
			}
		}
	}
	all := s.ByProduct("widget", 10)
	if all[len(all)-1].CVE != "CVE-2099-0003" {
		t.Errorf("无评分条目应排末尾: %+v", all)
	}
}

// ---- C-10：Release 不得先触发全量解码 ----

func TestReleaseDoesNotDecode(t *testing.T) {
	dump, ranges := lazyPaths()
	kb := LoadLazy(dump, ranges)
	if kb.decoded {
		t.Fatal("LoadLazy 不应解码")
	}
	kb.AttachTplIntel([]Entry{{Src: "tpl", Name: "挂起行", Product: "WidgetPro"}})
	kb.Release() // 旧实现会 ensureDecoded() → 白付一次 67MB 解码
	if kb.decoded {
		t.Fatal("Release 不应触发惰性解码（C-10）")
	}
	if len(kb.pendingTpl) != 1 {
		t.Fatalf("Release 不应丢弃挂起队列，实得 %d", len(kb.pendingTpl))
	}
	// 重载后挂起行仍生效
	_ = kb.ServiceFP()
	if len(kb.pendingTpl) != 0 {
		t.Fatal("重载后挂起队列应清空")
	}
	out := kb.Match([]TechHit{{Name: "WidgetPro"}})
	if len(out) != 1 {
		t.Fatalf("重载后挂起模板行应参与匹配: %+v", out)
	}
}
