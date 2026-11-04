package sitelens

import "testing"

// ---- B2-10 版本归一：精度不同不判冲突 ----

// TestCrossCheckVersionPrecision B2-10 回归：`5` 与 `5.0`、`1.24` 与 `1.24.0`
// 是同一版本的不同精度写法，不得判成"版本冲突"（旧实现按字符串比较 → 降权 +
// 误标 low confidence + 报告给出误导性的"版本不一致"）。
func TestCrossCheckVersionPrecision(t *testing.T) {
	cases := []struct {
		name   string
		claims []VersionClaim
	}{
		{"5 vs 5.0", []VersionClaim{
			{Name: "nginx", Source: ChannelHeader, Version: "5"},
			{Name: "nginx", Source: ChannelBody, Version: "5.0"},
		}},
		{"1.24 vs 1.24.0", []VersionClaim{
			{Name: "nginx", Source: ChannelHeader, Version: "1.24"},
			{Name: "nginx", Source: ChannelMeta, Version: "1.24.0"},
		}},
		{"v1.2.0 vs 1.2", []VersionClaim{
			{Name: "jq", Source: ChannelSrc, Version: "v1.2.0"},
			{Name: "jq", Source: ChannelBody, Version: "1.2"},
		}},
		{"01.2 vs 1.2", []VersionClaim{
			{Name: "x", Source: ChannelHeader, Version: "01.2"},
			{Name: "x", Source: ChannelBody, Version: "1.2"},
		}},
	}
	for _, c := range cases {
		vc := CrossCheckVersion(c.claims)
		if !vc.Consistent {
			t.Errorf("%s: 应判为一致，got Versions=%v", c.name, vc.Versions)
		}
		if vc.LowConfidence {
			t.Errorf("%s: 不应标 low confidence", c.name)
		}
		if len(vc.Versions) != 1 {
			t.Errorf("%s: 版本列表应折叠为 1 项，got %v", c.name, vc.Versions)
		}
	}
}

// TestCrossCheckVersionRealConflict B2-10 反向：真正不同的版本仍须判冲突。
func TestCrossCheckVersionRealConflict(t *testing.T) {
	vc := CrossCheckVersion([]VersionClaim{
		{Name: "nginx", Source: ChannelHeader, Version: "1.24"},
		{Name: "nginx", Source: ChannelBody, Version: "1.25"},
	})
	if vc.Consistent {
		t.Fatal("1.24 vs 1.25 应判为版本冲突")
	}
	if !vc.LowConfidence {
		t.Fatal("版本冲突应标 low confidence")
	}
	if len(vc.Versions) != 2 {
		t.Fatalf("冲突时版本列表应保留 2 项，got %v", vc.Versions)
	}
	// 3.5 vs 3.5.1 是真差异，不是精度问题
	vc2 := CrossCheckVersion([]VersionClaim{
		{Name: "x", Source: ChannelHeader, Version: "3.5"},
		{Name: "x", Source: ChannelBody, Version: "3.5.1"},
	})
	if vc2.Consistent {
		t.Fatal("3.5 vs 3.5.1 应判为冲突")
	}
}

// TestVersionCanonicalKey 归一键的边界：预发布段保留、非数字不折叠。
func TestVersionCanonicalKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"5", "5"},
		{"5.0", "5"},
		{"5.0.0", "5"},
		{"1.24", "1.24"},
		{"1.24.0", "1.24"},
		{"V1.2.3", "1.2.3"},
		{"1.2.3-beta", "1.2.3-beta"},
		{"1.0.0-beta", "1.0.0-beta"}, // 尾部非 0 段，保留
		{"abc", "abc"},               // 非数字：不折叠
		{"", ""},
	}
	for _, c := range cases {
		if got := versionCanonicalKey(c.in); got != c.want {
			t.Errorf("versionCanonicalKey(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}
