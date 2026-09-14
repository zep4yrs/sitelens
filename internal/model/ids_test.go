package model

import (
	"strings"
	"testing"
)

// TestIDStability 锁死核心性质：同事实多次调用 → ID 完全相同。
// 这是与 3.0 自增 ID 的本质区别，也是 5.0 跨扫描聚合的前提。
func TestIDStability(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{"EntryPointID", EntryPointID("blackbox", "param", "http://x/", "GET", "id", "", ""),
			EntryPointID("blackbox", "param", "http://x/", "GET", "id", "", "")},
		{"EvidenceID", EvidenceID("blackbox", "response", "dast", "http://x/", "", 0, "body"),
			EvidenceID("blackbox", "response", "dast", "http://x/", "", 0, "body")},
		{"VulnNodeID", VulnNodeID("blackbox", "sqli-error", "", "http://x/", "id", "", 0),
			VulnNodeID("blackbox", "sqli-error", "", "http://x/", "id", "", 0)},
		{"DataflowID", DataflowID("a.php", "f", "id", 12), DataflowID("a.php", "f", "id", 12)},
		{"ChainEdgeID", ChainEdgeID("cn_a", "cn_b", "sequence"), ChainEdgeID("cn_a", "cn_b", "sequence")},
		{"CWERelID", CWERelID("vuln_node", "vn_x", "CWE-89", "mapping"), CWERelID("vuln_node", "vn_x", "CWE-89", "mapping")},
		{"PrivChangeID", PrivChangeID("anonymous", "admin", "bypass-403", "vn_x"), PrivChangeID("anonymous", "admin", "bypass-403", "vn_x")},
		{"ImpactID", ImpactID("disclosure", "vn_x"), ImpactID("disclosure", "vn_x")},
		{"EvidenceLinkID", EvidenceLinkID("vn_a", "df_b", "url"), EvidenceLinkID("vn_a", "df_b", "url")},
		{"ChainNodeID", ChainNodeID("entry", "ep_a"), ChainNodeID("entry", "ep_a")},
	}
	for _, c := range cases {
		if c.a != c.b {
			t.Errorf("%s 不稳定：%q != %q", c.name, c.a, c.b)
		}
	}
}

// TestIDDiffersForDifferentFacts：不同事实 → 不同 ID。
func TestIDDiffersForDifferentFacts(t *testing.T) {
	if EntryPointID("blackbox", "param", "http://x/", "GET", "id", "", "") ==
		EntryPointID("blackbox", "param", "http://x/", "GET", "uid", "", "") {
		t.Error("不同参数名不应产生相同 ID")
	}
	// origin 参与哈希：黑盒与白盒同名 check 必须区分。
	if VulnNodeID("blackbox", "sqli", "", "http://x/", "id", "", 0) ==
		VulnNodeID("whitebox", "sqli", "", "http://x/", "id", "", 0) {
		t.Error("黑盒/白盒节点 ID 不应相同")
	}
	// 正文参与证据 ID：不同响应体必须区分。
	if EvidenceID("blackbox", "response", "dast", "u", "", 0, "abc") ==
		EvidenceID("blackbox", "response", "dast", "u", "", 0, "abd") {
		t.Error("不同响应体不应产生相同证据 ID")
	}
}

// TestIDLengthPrefixNoCollision：长度前缀编码必须杜绝分段边界碰撞。
// ["ab","c"] 与 ["a","bc"] 拼接字节相同，但长度前缀使其 ID 不同。
func TestIDLengthPrefixNoCollision(t *testing.T) {
	x := makeID("t", "ab", "c")
	y := makeID("t", "a", "bc")
	if x == y {
		t.Error("长度前缀编码失败：分段边界不同的输入产生了相同 ID")
	}
}

// TestIDNormalization：大小写/空白归一化——"GET"/" get " 视为同一事实。
func TestIDNormalization(t *testing.T) {
	a := EntryPointID("BlackBox", "param", "http://X/", "GET", "id", "", "")
	b := EntryPointID("blackbox", "param", "http://x/", "get", "id", "", "")
	if a != b {
		t.Errorf("归一化失败：%q != %q", a, b)
	}
}

// TestIDShape：ID 形态为 <prefix>_<12hex>。
func TestIDShape(t *testing.T) {
	id := VulnNodeID("blackbox", "x", "", "u", "", "", 0)
	p, digest, ok := IDFields(id)
	if !ok {
		t.Fatalf("IDFields 判定 %q 非法", id)
	}
	if p != "vn" {
		t.Errorf("前缀 = %q，期望 vn", p)
	}
	if len(digest) != idHexLen {
		t.Errorf("摘要长度 = %d，期望 %d", len(digest), idHexLen)
	}
	if err := ValidateID(id, "vn"); err != nil {
		t.Errorf("ValidateID 误报：%v", err)
	}
	if err := ValidateID(id, "ep"); err == nil {
		t.Error("ValidateID 未校验前缀")
	}
	for _, bad := range []string{"", "vn", "vn_", "_abc", "vn_zz", "vn_123"} {
		if err := ValidateID(bad, ""); err == nil {
			t.Errorf("ValidateID 未拒绝非法 ID %q", bad)
		}
	}
	if got := PrefixOf(id); got != "vn" {
		t.Errorf("PrefixOf = %q", got)
	}
}

// TestEvidenceIDContentAddressed：同一响应被多次构造，ID 恒等（引用去重前提）。
func TestEvidenceIDContentAddressed(t *testing.T) {
	e1 := NewEvidence("response", OriginBlackbox, "dast", "scan-1", "http://x/?id=1", "", 0, "<html>err</html>")
	e2 := NewEvidence("response", OriginBlackbox, "dast", "scan-1", "http://x/?id=1", "", 0, "<html>err</html>")
	if e1.ID != e2.ID {
		t.Errorf("同内容证据 ID 不稳定：%q != %q", e1.ID, e2.ID)
	}
	if e1.Digest == "" || e1.Digest != e2.Digest {
		t.Error("证据摘要应基于内容且稳定")
	}
}

// TestVerdictMapping：3.0 历史 verdict 词表 → 统一观测态，语义不合并。
func TestVerdictMapping(t *testing.T) {
	want := map[string]Observation{
		"proven": ObsPositive, "observed": ObsPositive, "confirmed": ObsPositive,
		"present": ObsPositive, "gone": ObsNegative, "unsupported": ObsNotExecuted,
		"skipped": ObsNotExecuted, "none": ObsUnknown, "possible": ObsUnknown,
	}
	for verdict, exp := range want {
		got, ok := ObservationForVerdict(verdict)
		if !ok {
			t.Errorf("verdict %q 未映射", verdict)
			continue
		}
		if got != exp {
			t.Errorf("verdict %q → %q，期望 %q", verdict, got, exp)
		}
	}
	// 未识别词表：不猜测，返回 ok=false 且落 unknown。
	if got, ok := ObservationForVerdict("brand-new-verdict"); ok || got != ObsUnknown {
		t.Errorf("未识别 verdict 应 (unknown,false)，实得 (%q,%v)", got, ok)
	}
}

// TestObservationValidAndSemantics：四态合法性与证据要求。
func TestObservationSemantics(t *testing.T) {
	for _, o := range []Observation{ObsUnknown, ObsNotExecuted, ObsNegative, ObsPositive} {
		if !o.Valid() {
			t.Errorf("%q 应为合法观测态", o)
		}
	}
	if Observation("ok").Valid() {
		t.Error("非法观测态未被拒绝")
	}
	if !ObsPositive.IsEvidenceBacked() {
		t.Error("positive 必须要求证据")
	}
	if ObsNegative.IsEvidenceBacked() {
		t.Error("negative（跑了没发现）不应要求证据")
	}
	if ObsNotExecuted == ObsNegative {
		t.Error("not_executed 与 negative 必须区分")
	}
}

// TestGuardConfidence：无证据时 confirmed 被降级（需求 9）。
func TestGuardConfidence(t *testing.T) {
	if c, down := GuardConfidence(ConfConfirmed, nil); c != ConfProbable || !down {
		t.Errorf("无证据 confirmed 应降为 probable，实得 (%q,%v)", c, down)
	}
	if c, down := GuardConfidence(ConfConfirmed, []string{"ev_1"}); c != ConfConfirmed || down {
		t.Errorf("有证据 confirmed 不应降级，实得 (%q,%v)", c, down)
	}
	// 非 confirmed 不受影响。
	if c, _ := GuardConfidence(ConfPossible, nil); c != ConfPossible {
		t.Errorf("possible 不应被改动，实得 %q", c)
	}
	if !ConfProbable.Valid() || Confidence("sure").Valid() {
		t.Error("置信级合法性判定有误")
	}
}

// TestRefsDedup：引用列表去重去空、保序。
func TestRefsDedup(t *testing.T) {
	got := refs([]string{"a", "", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("refs = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("refs = %v，期望 %v", got, want)
		}
	}
	if refs(nil) != nil || refs([]string{"", ""}) != nil {
		t.Error("空引用应归一为 nil")
	}
}

// TestBodyDigest：空正文摘要为空；非空正文摘要稳定且参与 ID。
func TestBodyDigest(t *testing.T) {
	if bodyDigest("") != "" {
		t.Error("空正文摘要应为空")
	}
	if bodyDigest("x") != bodyDigest("x") || bodyDigest("x") == bodyDigest("y") {
		t.Error("正文摘要应稳定且区分内容")
	}
	if !strings.HasPrefix(EvidenceID("blackbox", "response", "s", "u", "", 0, "x"), "ev_") {
		t.Error("证据 ID 前缀应为 ev_")
	}
}
