package versioncmp

import "testing"

func TestCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.4.2", "6.4.2", 0},
		{"6.4.2", "6.4.3", -1},
		{"6.4.3", "6.4.2", 1},
		{"8.3", "8.3.7", -1}, // 短版本补零：8.3.0 < 8.3.7
		{"14.2.25", "14.1.1", 1},
		{"10", "9.5", 1},
		{"7-jre", "7", 0}, // 后缀忽略
	}
	for _, c := range cases {
		if got := Cmp(c.a, c.b); got != c.want {
			t.Errorf("Cmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionIn(t *testing.T) {
	cases := []struct {
		version, affected string
		want              bool
	}{
		{"6.4.2", "<14.2.25", true},
		{"15.1", "<14.2.25", false},
		{"8.3.6", ">=8.3,<8.3.7", true},
		{"8.3.8", ">=8.3,<8.3.7", false},
		{"6.4.2", "*", true},
		{"6.4.2", "", false},
		{"2.4.1", "<=2.4.1", true},
		{"1.9.2", "!=1.9", true}, // 不等于 1.9 即在范围内
	}
	for _, c := range cases {
		if got := VersionIn(c.version, c.affected); got != c.want {
			t.Errorf("VersionIn(%q, %q) = %v, want %v", c.version, c.affected, got, c.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		text, keyword, want string
	}{
		{"WordPress 6.4.2 Version 6.4.2", "version", "6.4.2"},
		{"generator content=Hexo 4.2.0", "hexo", "4.2.0"},
		{"Powered by xxCMS 管理后台", "xxcms", ""},
		{"release 2026.04 notes", "release", "2026.04"}, // 带点是合法版本
		{"build 20260401", "build", ""},                 // 无点长数字 = 工单号跳过
		{"", "version", ""},
	}
	for _, c := range cases {
		if got := ExtractVersion(c.text, c.keyword); got != c.want {
			t.Errorf("ExtractVersion(%q, %q) = %q, want %q", c.text, c.keyword, got, c.want)
		}
	}
}
