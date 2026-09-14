package cwe

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// stubNVD 测试用 CVE→CWE 桩。
type stubNVD map[string][]string

func (s stubNVD) CWEsFor(cve string) []string { return s[cve] }

// TestForCheck：黑盒 check → CWE（含四源真实 id 与未收录返回 nil）。
func TestForCheck(t *testing.T) {
	cases := map[string]string{
		"xss-reflect":     "CWE-79",
		"sqli-error":      "CWE-89",
		"sqli-blind-time": "CWE-89",
		"lfi-passwd":      "CWE-22",
		"ssrf-oob":        "CWE-918",
		"open-redirect":   "CWE-601",
		"git-leak":        "CWE-538",
		"phpinfo":         "CWE-200",
		"actuator":        "CWE-200",
		"cookie-attrs":    "CWE-1004",
		"csrf-form":       "CWE-352",
		"sourcemap-leak":  "CWE-540",
		"weak-basic-auth": "CWE-521",
	}
	for id, want := range cases {
		got := ForCheck(id)
		if len(got) != 1 || got[0] != want {
			t.Errorf("ForCheck(%q) = %v，期望 [%s]", id, got, want)
		}
	}
	// 大小写不敏感。
	if got := ForCheck("XSS-Reflect"); len(got) != 1 || got[0] != "CWE-79" {
		t.Errorf("大小写应不敏感，实得 %v", got)
	}
	// 未收录 → nil（宁缺不猜）。
	if got := ForCheck("brand-new-check"); got != nil {
		t.Errorf("未收录 check 应返回 nil，实得 %v", got)
	}
}

// TestForRule：白盒规则 → CWE（含 AST-* 命名）。
func TestForRule(t *testing.T) {
	cases := map[string]string{
		"PY-SQLFMT":       "CWE-89",
		"PY-OSPOPEN":      "CWE-78",
		"PHP-CMD":         "CWE-78",
		"PY-EVAL":         "CWE-95",
		"PY-PICKLE":       "CWE-502",
		"JS-INNERHTML":    "CWE-79",
		"AST-exec_cmd":    "CWE-78",
		"AST-sql":         "CWE-89",
		"AST-deserialize": "CWE-502",
		"AST-path":        "CWE-22",
	}
	for id, want := range cases {
		got := ForRule(id)
		if len(got) != 1 || got[0] != want {
			t.Errorf("ForRule(%q) = %v，期望 [%s]", id, got, want)
		}
	}
	if got := ForRule("NOPE-RULE"); got != nil {
		t.Errorf("未收录规则应返回 nil，实得 %v", got)
	}
}

// TestForVulnNode：按 origin 选映射（白盒走 rule_id，黑盒走 check_id）。
func TestForVulnNode(t *testing.T) {
	white := model.VulnNode{Origin: model.OriginWhitebox, RuleID: "PY-SQLFMT"}
	if got := ForVulnNode(white); len(got) != 1 || got[0] != "CWE-89" {
		t.Errorf("白盒节点应走 rule_id，实得 %v", got)
	}
	black := model.VulnNode{Origin: model.OriginBlackbox, CheckID: "ssrf-oob"}
	if got := ForVulnNode(black); len(got) != 1 || got[0] != "CWE-918" {
		t.Errorf("黑盒节点应走 check_id，实得 %v", got)
	}
	// 都未收录时回落到节点自带 CWEs。
	fallback := model.VulnNode{Origin: model.OriginBlackbox, CheckID: "x", CWEs: []string{"CWE-1"}}
	if got := ForVulnNode(fallback); len(got) != 1 || got[0] != "CWE-1" {
		t.Errorf("应回落到节点自带 CWEs，实得 %v", got)
	}
}

// TestRelateAddsCWERels：为图内节点补 cwe_rel，带证据、probable、幂等。
func TestRelateAddsCWERels(t *testing.T) {
	g := model.NewGraph("s")
	ev := model.NewEvidence("response", model.OriginBlackbox, "dast", "s", "http://t/?id=1", "", 0, "sql error")
	g.Add(ev)
	vn := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "", "http://t/?id=1", "id", "", 0,
		model.ObsPositive, "proven", model.ConfConfirmed, []string{ev.ID})
	g.Add(vn)

	n := Relate(g, nil)
	if n == 0 {
		t.Fatal("应补齐 cwe_rel")
	}
	var rel *model.CWERel
	for i := range g.CWERels {
		if g.CWERels[i].SubjectID == vn.ID {
			rel = &g.CWERels[i]
		}
	}
	if rel == nil {
		t.Fatal("未找到该节点的 cwe_rel")
	}
	if rel.CWEID != "CWE-89" {
		t.Errorf("CWE 编号 = %q，期望 CWE-89", rel.CWEID)
	}
	if rel.Confidence != model.ConfProbable {
		t.Errorf("自动关联应为 probable，实得 %q", rel.Confidence)
	}
	if len(rel.EvidenceIDs) == 0 {
		t.Error("cwe_rel 应带证据引用")
	}
	// 幂等。
	if again := Relate(g, nil); again != 0 {
		t.Errorf("二次 Relate 应零新增，实得 %d", again)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("补齐后图应通过校验：%v", err)
	}
}

// TestRelateCVEPath：CVE → NVD weaknesses 通道（桩）。
func TestRelateCVEPath(t *testing.T) {
	g := model.NewGraph("s")
	ev := model.NewEvidence("response", model.OriginBlackbox, "nvd", "s", "", "", 0, "desc")
	g.Add(ev)
	// 该节点 checkID 未收录，只有 CVE 通道能给出 CWE。
	vn := model.NewVulnNode(model.OriginBlackbox, "intel:nvd:CVE-2021-44228", "",
		"", "", "", 0, model.ObsUnknown, "possible", model.ConfPossible, []string{ev.ID})
	vn.CVE = "CVE-2021-44228"
	g.Add(vn)

	nvd := stubNVD{"CVE-2021-44228": {"CWE-20", "CWE-400", "CWE-502", "CWE-917"}}
	if n := Relate(g, nvd); n != 4 {
		t.Fatalf("应补 4 条 CVE→CWE 关联，实得 %d", n)
	}
	got := map[string]bool{}
	for _, r := range g.CWERels {
		got[r.CWEID] = true
	}
	for _, want := range []string{"CWE-20", "CWE-400", "CWE-502", "CWE-917"} {
		if !got[want] {
			t.Errorf("缺少 %s", want)
		}
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("校验失败：%v", err)
	}
}

// TestForCVENilSafe：nvd 为 nil / 空 CVE 时安全返回 nil。
func TestForCVENilSafe(t *testing.T) {
	if got := ForCVE(nil, "CVE-2021-44228"); got != nil {
		t.Errorf("nil 查询器应返回 nil，实得 %v", got)
	}
	if got := ForCVE(stubNVD{}, ""); got != nil {
		t.Errorf("空 CVE 应返回 nil，实得 %v", got)
	}
}

// TestForCheckReturnsCopy：返回值是副本，调用方改动不污染映射表。
func TestForCheckReturnsCopy(t *testing.T) {
	a := ForCheck("xss-reflect")
	if len(a) == 0 {
		t.Fatal("应命中")
	}
	a[0] = "MUTATED"
	if b := ForCheck("xss-reflect"); b[0] != "CWE-79" {
		t.Errorf("映射表被污染：%v", b)
	}
}

// TestCount：收录条数（供文档断言）。
func TestCount(t *testing.T) {
	checks, rules := Count()
	if checks < 40 {
		t.Errorf("check 映射条数偏少：%d", checks)
	}
	if rules < 15 {
		t.Errorf("rule 映射条数偏少：%d", rules)
	}
}
