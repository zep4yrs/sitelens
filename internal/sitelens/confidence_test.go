// CP-11 指纹置信度校准回归：版本一致/不一致、无证据、同页冲突降权、
// 通道/多页加权、证据文本归类与引擎接线辅助函数。
package sitelens

import (
	"reflect"
	"strings"
	"testing"
)

// ---- 版本交叉校验 ----

func TestCrossCheckVersionConsistent(t *testing.T) {
	vc := CrossCheckVersion([]VersionClaim{
		{Name: "WordPress", Source: ChannelHeader, Version: "6.4.2"},
		{Name: "WordPress", Source: ChannelMeta, Version: "6.4.2"},
		{Name: "WordPress", Source: ChannelBody, Version: "V6.4.2"},
	})
	if !vc.Consistent {
		t.Errorf("同版本不同来源应一致：%+v", vc)
	}
	if vc.Version != "6.4.2" {
		t.Errorf("采信版本 = %q，期望 6.4.2", vc.Version)
	}
	if len(vc.Versions) != 1 || vc.Versions[0] != "6.4.2" {
		t.Errorf("版本列表 = %v", vc.Versions)
	}
	if vc.LowConfidence {
		t.Error("一致时不应标记 low confidence")
	}
}

func TestCrossCheckVersionConflict(t *testing.T) {
	vc := CrossCheckVersion([]VersionClaim{
		{Name: "jQuery", Source: ChannelHeader, Version: "1.12.4"},
		{Name: "jQuery", Source: ChannelBody, Version: "3.5.1"},
	})
	if vc.Consistent {
		t.Fatalf("版本不一致应标记冲突：%+v", vc)
	}
	if !vc.LowConfidence {
		t.Error("版本不一致应标记 low confidence")
	}
	want := []string{"1.12.4", "3.5.1"}
	if !reflect.DeepEqual(vc.Versions, want) {
		t.Errorf("版本列表 = %v，期望 %v", vc.Versions, want)
	}
	if vc.Version != "1.12.4" { // 次数并列取字典序最小，保证确定性
		t.Errorf("采信版本 = %q，期望 1.12.4", vc.Version)
	}
}

func TestCrossCheckVersionEmpty(t *testing.T) {
	for _, claims := range [][]VersionClaim{
		nil,
		{{Name: "Nginx", Source: ChannelHeader, Version: ""}},
	} {
		vc := CrossCheckVersion(claims)
		if !vc.Consistent || vc.LowConfidence {
			t.Errorf("无版本证据应一致且不降级：%+v", vc)
		}
		if vc.Version != "" || len(vc.Versions) != 0 {
			t.Errorf("无版本证据应无采信版本：%+v", vc)
		}
	}
}

func TestCrossCheckVersionMajority(t *testing.T) {
	vc := CrossCheckVersion([]VersionClaim{
		{Source: ChannelHeader, Version: "2.0.0"},
		{Source: ChannelMeta, Version: "2.0.0"},
		{Source: ChannelBody, Version: "1.0.0"},
	})
	if vc.Consistent {
		t.Fatalf("两版本仍算不一致：%+v", vc)
	}
	if vc.Version != "2.0.0" { // 出现次数最多的版本
		t.Errorf("采信版本 = %q，期望 2.0.0", vc.Version)
	}
}

// ---- 证据通道归类 / 引擎接线辅助 ----

func TestChannelOfEvidence(t *testing.T) {
	cases := map[string]string{
		"Server=nginx/1.24.0":          ChannelHeader,
		"cookie PHPSESSID":             ChannelCookie,
		"meta generator=WordPress 6.4": ChannelMeta,
		"icon_hash=123456":             ChannelIcon,
		"src https://x/wp-includes/":   ChannelSrc,
		"内联JS window.__NUXT__":         ChannelInline,
		"关键词 DVWA":                     ChannelBody,
		"正则 /wp-content/":              ChannelBody,
		"":                             ChannelOther,
		"未知形态":                         ChannelOther,
	}
	for evidence, want := range cases {
		if got := ChannelOfEvidence(evidence); got != want {
			t.Errorf("ChannelOfEvidence(%q)=%q，期望 %q", evidence, got, want)
		}
	}
	for _, ch := range []string{ChannelHeader, ChannelCookie, ChannelMeta, ChannelIcon} {
		if !IsStrongChannel(ch) {
			t.Errorf("%q 应为强通道", ch)
		}
	}
	for _, ch := range []string{ChannelBody, ChannelInline, ChannelSrc, ChannelOther} {
		if IsStrongChannel(ch) {
			t.Errorf("%q 不应为强通道", ch)
		}
	}
}

func TestSignalsFromHitsAndMatchHits(t *testing.T) {
	hits := []Hit{
		{Name: "WordPress", Conf: 90, Evidence: "meta generator=WordPress 6.4", Version: "6.4"},
		{Name: "Nginx", Conf: 100, Evidence: "Server=nginx"},
	}
	sigs := SignalsFromHits("https://x/", hits)
	if len(sigs) != 2 {
		t.Fatalf("信号数 = %d", len(sigs))
	}
	if sigs[0].Name != "WordPress" || sigs[0].Channel != ChannelMeta ||
		sigs[0].Version != "6.4" || sigs[0].BaseConf != 90 || sigs[0].Page != "https://x/" {
		t.Errorf("Hit → 信号映射异常：%+v", sigs[0])
	}
	claims := VersionClaimsFromSignals(sigs)
	if len(claims) != 1 || claims[0].Source != ChannelMeta || claims[0].Version != "6.4" {
		t.Errorf("版本声明提取异常：%+v", claims)
	}

	mhs := []MatchHit{
		{Name: "jQuery", Conf: 80, Evidence: "src https://x/jquery-3.5.1.min.js", Version: "3.5.1"},
		{Name: "PHP", Conf: 90, Evidence: "cookie PHPSESSID"},
	}
	msigs := SignalsFromMatchHits("https://x/a", mhs)
	if len(msigs) != 2 || msigs[0].Channel != ChannelSrc || msigs[1].Channel != ChannelCookie {
		t.Errorf("MatchHit → 信号映射异常：%+v", msigs)
	}
	if msigs[0].Page != "https://x/a" {
		t.Errorf("页面未透传：%q", msigs[0].Page)
	}
}

// ---- 置信度打分 ----

func TestScoreTechNoEvidence(t *testing.T) {
	res := ScoreTech(TechConfidenceInput{Name: "Ghost"})
	if res.Confidence != 0 {
		t.Errorf("无证据置信度应为 0，实际 %v", res.Confidence)
	}
	if !res.LowConfidence || ConfidenceBand(res.Confidence) != "low" {
		t.Errorf("无证据应标记 low confidence：%+v", res)
	}
	if res.EvidenceCount != 0 || res.Conflict || res.VersionCheck.Consistent == false {
		t.Errorf("无证据字段异常：%+v", res)
	}
	if len(res.Reasons) == 0 || !strings.Contains(strings.Join(res.Reasons, ";"), "无证据") {
		t.Errorf("无证据 reasons 异常：%v", res.Reasons)
	}
}

func TestScoreTechStrongConsistent(t *testing.T) {
	res := ScoreTech(TechConfidenceInput{
		Name: "WordPress",
		Signals: []ConfidenceSignal{
			{Name: "WordPress", Page: "https://x/", Channel: ChannelHeader, Evidence: "X-Powered-By=WordPress", BaseConf: 90},
			{Name: "WordPress", Page: "https://x/", Channel: ChannelMeta, Evidence: "meta generator=WordPress 6.4", Version: "6.4"},
			{Name: "WordPress", Page: "https://x/", Channel: ChannelCookie, Evidence: "cookie wordpress_logged_in"},
		},
		VersionClaims: []VersionClaim{
			{Name: "WordPress", Source: ChannelMeta, Version: "6.4"},
			{Name: "WordPress", Source: ChannelBody, Version: "6.4"},
		},
	})
	if res.Confidence < 0.9 {
		t.Errorf("强通道一致证据置信度应 >=0.9，实际 %v（%v）", res.Confidence, res.Reasons)
	}
	if res.LowConfidence || ConfidenceBand(res.Confidence) != "high" {
		t.Errorf("一致强证据不应 low：%+v", res)
	}
	if res.ChannelCount != 3 || res.PageCount != 1 || len(res.StrongChannels) != 3 {
		t.Errorf("计数异常：%+v", res)
	}
	if res.Version != "6.4" {
		t.Errorf("版本 = %q", res.Version)
	}
	joined := strings.Join(res.Reasons, ";")
	if !strings.Contains(joined, "强通道") || !strings.Contains(joined, "版本一致") {
		t.Errorf("reasons 应说明强通道与版本一致：%v", res.Reasons)
	}
}

func TestScoreTechVersionConflict(t *testing.T) {
	res := ScoreTech(TechConfidenceInput{
		Name: "jQuery",
		Signals: []ConfidenceSignal{
			{Name: "jQuery", Page: "https://x/", Channel: ChannelHeader, Evidence: "X-JQ=1.12.4", Version: "1.12.4"},
			{Name: "jQuery", Page: "https://x/", Channel: ChannelBody, Evidence: "关键词 jquery-3.5.1", Version: "3.5.1"},
		},
	})
	if !res.LowConfidence {
		t.Errorf("版本不一致应 low confidence：%+v", res)
	}
	if res.VersionCheck.Consistent {
		t.Error("版本校验应为不一致")
	}
	joined := strings.Join(res.Reasons, ";")
	if !strings.Contains(joined, "版本不一致") || !strings.Contains(joined, "low confidence") {
		t.Errorf("reasons 应说明版本不一致：%v", res.Reasons)
	}
	// 同证据下把版本改成一致，置信度应更高（版本冲突确实降权）
	consistent := ScoreTech(TechConfidenceInput{
		Name: "jQuery",
		Signals: []ConfidenceSignal{
			{Name: "jQuery", Page: "https://x/", Channel: ChannelHeader, Evidence: "X-JQ=3.5.1", Version: "3.5.1"},
			{Name: "jQuery", Page: "https://x/", Channel: ChannelBody, Evidence: "关键词 jquery-3.5.1", Version: "3.5.1"},
		},
	})
	if consistent.Confidence <= res.Confidence {
		t.Errorf("版本一致(%v) 应高于冲突(%v)", consistent.Confidence, res.Confidence)
	}
	if consistent.LowConfidence {
		t.Errorf("版本一致不应 low：%+v", consistent)
	}
}

func TestCalibrateTechsSamePageConflictDownweight(t *testing.T) {
	strong := TechConfidenceInput{
		Name:    "Nginx",
		Signals: []ConfidenceSignal{{Name: "Nginx", Page: "https://x/p", Channel: ChannelHeader, Evidence: "Server=nginx", BaseConf: 90}},
	}
	weak := TechConfidenceInput{
		Name:    "VMware",
		Signals: []ConfidenceSignal{{Name: "VMware", Page: "https://x/p", Channel: ChannelBody, Evidence: "关键词 VMware", BaseConf: 60}},
	}
	results := CalibrateTechs([]TechConfidenceInput{strong, weak})
	if len(results) != 2 {
		t.Fatalf("结果数 = %d", len(results))
	}
	isolatedStrong := ScoreTech(strong)
	isolatedWeak := ScoreTech(weak)
	if results[0].Confidence >= isolatedStrong.Confidence {
		t.Errorf("冲突页强证据应被降权：%v vs 独立 %v",
			results[0].Confidence, isolatedStrong.Confidence)
	}
	if results[1].Confidence >= isolatedWeak.Confidence {
		t.Errorf("冲突页弱证据应被降权：%v vs 独立 %v",
			results[1].Confidence, isolatedWeak.Confidence)
	}
	// 弱证据（正文关键词）降权幅度应大于强证据（响应头）
	strongDrop := isolatedStrong.Confidence - results[0].Confidence
	weakDrop := isolatedWeak.Confidence - results[1].Confidence
	if weakDrop <= strongDrop {
		t.Errorf("弱证据降权(%v) 应大于强证据(%v)", weakDrop, strongDrop)
	}
	if !results[0].Conflict || !results[1].Conflict {
		t.Errorf("冲突标记缺失：%+v / %+v", results[0], results[1])
	}
	if !reflect.DeepEqual(results[0].ConflictPages, []string{"https://x/p"}) {
		t.Errorf("冲突页面 = %v", results[0].ConflictPages)
	}
	if !strings.Contains(strings.Join(results[0].Reasons, ";"), "同页冲突") {
		t.Errorf("reasons 应说明同页冲突：%v", results[0].Reasons)
	}
	if ConfidenceBand(results[1].Confidence) != "low" {
		t.Errorf("冲突降权后弱证据应为 low：%v", results[1].Confidence)
	}
}

func TestCalibrateTechsMultiPageBoost(t *testing.T) {
	sig := func(page string) []ConfidenceSignal {
		return []ConfidenceSignal{{Name: "Joomla", Page: page, Channel: ChannelMeta,
			Evidence: "meta generator=Joomla", BaseConf: 70}}
	}
	one := ScoreTech(TechConfidenceInput{Name: "Joomla", Signals: sig("https://x/")})
	three := ScoreTech(TechConfidenceInput{Name: "Joomla", Signals: append(
		append(sig("https://x/"), sig("https://x/a")...), sig("https://x/b")...)})
	if three.PageCount != 3 {
		t.Fatalf("页面数 = %d", three.PageCount)
	}
	if three.Confidence <= one.Confidence {
		t.Errorf("多页一致证据应提升置信度：%v vs %v", three.Confidence, one.Confidence)
	}
}

func TestCalibrateTechsDeterministicAndClamped(t *testing.T) {
	inputs := []TechConfidenceInput{
		{Name: "A", Signals: []ConfidenceSignal{
			{Name: "A", Page: "p1", Channel: ChannelHeader, BaseConf: 100},
			{Name: "A", Page: "p1", Channel: ChannelCookie, BaseConf: 100},
			{Name: "A", Page: "p1", Channel: ChannelMeta, BaseConf: 100},
		}},
		{Name: "B", Signals: []ConfidenceSignal{
			{Name: "B", Page: "p1", Channel: ChannelBody, BaseConf: 50},
		}},
	}
	first := CalibrateTechs(inputs)
	second := CalibrateTechs(inputs)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("同输入应确定性输出：%v vs %v", first, second)
	}
	for _, r := range first {
		if r.Confidence < 0 || r.Confidence > 1 {
			t.Errorf("%s 置信度越界：%v", r.Name, r.Confidence)
		}
		if r.Name == "A" && r.Confidence != 1 {
			t.Errorf("满证据应 clamp 到 1.0，实际 %v", r.Confidence)
		}
	}
	if CalibrateTechs(nil) == nil {
		t.Error("空输入应返回空切片而非 nil")
	}
}

func TestConfidenceHelpers(t *testing.T) {
	bands := map[float64]string{0.95: "high", 0.8: "high", 0.79: "medium", 0.5: "medium", 0.49: "low", 0: "low"}
	for c, want := range bands {
		if got := ConfidenceBand(c); got != want {
			t.Errorf("ConfidenceBand(%v)=%q，期望 %q", c, got, want)
		}
	}
	convs := map[float64]int{0: 0, 0.01: 1, 0.5: 50, 0.92: 92, 1: 100, 1.5: 100}
	for c, want := range convs {
		if got := ConfidenceToConf(c); got != want {
			t.Errorf("ConfidenceToConf(%v)=%d，期望 %d", c, got, want)
		}
	}
}
