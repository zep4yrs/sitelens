package engine

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/model"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
)

// TestAddWeakCredential：弱口令命中 → priv_change（mechanism=credential，带证据）。
func TestAddWeakCredential(t *testing.T) {
	c := newCollector("2026-01-01 00:00:00")
	c.addWeakCredential(loginbrute.Hit{
		Type: "basic-auth", User: "tom", Password: "123456",
		URL: "http://t/admin",
	})
	if len(c.g.PrivChanges) != 1 {
		t.Fatalf("应产出 1 条 priv_change，实得 %d", len(c.g.PrivChanges))
	}
	pc := c.g.PrivChanges[0]
	if pc.Mechanism != "credential" {
		t.Errorf("机制 = %q，期望 credential", pc.Mechanism)
	}
	if pc.From != "anonymous" || pc.To != "authenticated" {
		t.Errorf("from/to = %s→%s，期望 anonymous→authenticated", pc.From, pc.To)
	}
	if len(pc.EvidenceIDs) == 0 {
		t.Error("priv_change 必须带证据")
	}
	if err := c.g.Validate(); err != nil {
		t.Fatalf("图应通过校验：%v", err)
	}
}

// TestAddWeakCredentialHighPrivUser：高权用户名只标 suspected-admin（不臆断提权）。
func TestAddWeakCredentialHighPrivUser(t *testing.T) {
	c := newCollector("t")
	c.addWeakCredential(loginbrute.Hit{Type: "basic-auth", User: "root",
		Password: "toor", URL: "http://t/admin"})
	if c.g.PrivChanges[0].To != "suspected-admin" {
		t.Errorf("root 用户应标 suspected-admin，实得 %q", c.g.PrivChanges[0].To)
	}
	// 普通用户不应被标为高权。
	c2 := newCollector("t")
	c2.addWeakCredential(loginbrute.Hit{Type: "basic-auth", User: "alice",
		Password: "pw", URL: "http://t/a"})
	if c2.g.PrivChanges[0].To != "authenticated" {
		t.Errorf("普通用户应为 authenticated，实得 %q", c2.g.PrivChanges[0].To)
	}
}

// TestAddDirBypassSemantics：403 绕过 → restricted-resource（不臆造 admin）。
func TestAddDirBypassSemantics(t *testing.T) {
	c := newCollector("t")
	c.addDirBypass(modules.PageHit{URL: "http://t/secret", Path: "/secret",
		Status: 200, Size: 100, Bypass: "X-Forwarded-For"})
	if len(c.g.PrivChanges) != 1 {
		t.Fatal("应产出 priv_change")
	}
	pc := c.g.PrivChanges[0]
	if pc.Mechanism != "bypass-403" || pc.To != "restricted-resource" {
		t.Errorf("语义不符：%+v", pc)
	}
	if pc.From != "anonymous" {
		t.Errorf("from 应为 anonymous，实得 %q", pc.From)
	}
}

// TestAddDirBypassNoBypass：未绕过的命中不产 priv_change。
func TestAddDirBypassNoBypass(t *testing.T) {
	c := newCollector("t")
	c.addDirBypass(modules.PageHit{URL: "http://t/x", Path: "/x", Status: 403})
	if len(c.g.PrivChanges) != 0 {
		t.Error("无绕过不应产 priv_change")
	}
}

// TestPrivTargetForImpact：exploit 影响判定 → 权限变化终点标签（proven/observed 区分）。
func TestPrivTargetForImpact(t *testing.T) {
	cases := map[string]string{
		"proven":   "impact-reached",
		"observed": "impact-suspected",
	}
	for v, want := range cases {
		if got := privTargetForImpact(v); got != want {
			t.Errorf("privTargetForImpact(%q) = %q，期望 %q", v, got, want)
		}
	}
}

// TestAnnotateImpactPriors：impact 先验标注（KEV/CVSS），仅标注不建链。
func TestAnnotateImpactPriors(t *testing.T) {
	c := newCollector("t")
	ev := c.ev("response", "dast", "http://t/?id=1", "", 0, "sql error")
	vn := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "", "http://t/?id=1", "id", "", 0,
		model.ObsPositive, "proven", model.ConfConfirmed, []string{ev})
	vn.CVE = "CVE-2021-44228"
	c.g.Add(vn)
	c.g.Add(model.NewImpact("modification", "proven", vn.ID, "", nil, model.ConfProbable, []string{ev}))

	c.annotateImpactPriors(
		map[string]string{vn.ID: "CVE-2021-44228"},
		map[string]bool{"CVE-2021-44228": true},
		map[string]float64{"CVE-2021-44228": 10.0},
	)
	im := c.g.Impacts[0]
	if len(im.Priors) != 2 {
		t.Fatalf("应有 kev + cvss 两个先验，实得 %v", im.Priors)
	}
	if im.Priors[0] != "kev" || im.Priors[1] != "cvss:10.0" {
		t.Errorf("先验标注不符：%v", im.Priors)
	}
	// 无 CVE 时不动（不臆造）。
	c2 := newCollector("t")
	ev2 := c2.ev("response", "dast", "http://t/", "", 0, "x")
	vn2 := model.NewVulnNode(model.OriginBlackbox, "c", "", "http://t/", "", "", 0,
		model.ObsPositive, "proven", model.ConfProbable, []string{ev2})
	c2.g.Add(vn2)
	c2.g.Add(model.NewImpact("disclosure", "proven", vn2.ID, "", nil, model.ConfProbable, []string{ev2}))
	c2.annotateImpactPriors(map[string]string{}, nil, nil)
	if len(c2.g.Impacts[0].Priors) != 0 {
		t.Error("无 CVE 不应有先验")
	}
}

// TestIsHighPrivUser：高权用户名识别。
func TestIsHighPrivUser(t *testing.T) {
	for _, u := range []string{"root", "Admin", "administrator", "sa", "SYSTEM"} {
		if !isHighPrivUser(u) {
			t.Errorf("%q 应判为高权", u)
		}
	}
	for _, u := range []string{"alice", "user1", "tom", ""} {
		if isHighPrivUser(u) {
			t.Errorf("%q 不应判为高权", u)
		}
	}
}
