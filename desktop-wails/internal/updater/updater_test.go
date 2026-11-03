package updater

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// testSHA512 一个合法的 64 字节摘要的 base64（内容不重要，格式必须合法）。
func testSHA512() string {
	return base64.StdEncoding.EncodeToString(make([]byte, sha512DigestLen))
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.2.0", "5.1.0", 1},
		{"5.1.0", "5.2.0", -1},
		{"5.1.0", "5.1.0", 0},
		{"v5.1.0", "5.1.0", 0},
		{"5.10.0", "5.9.0", 1},  // 数值比较，非字典序
		{"5.2.0.1", "5.2.0", 1}, // 多一段
		{"5.2.0", "5.2.0.1", -1},
		{"5.2.0", "5.2.0-beta.1", 1}, // 正式版 > 预发布
		{"5.2.0-beta.1", "5.2.0", -1},
		{"6.0.0", "5.99.99", 1},
		{"", "5.0.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestResolveAvailable(t *testing.T) {
	base := "https://github.com/o/r/releases/download/desktop-stable/"
	m := Manifest{Version: "5.2.0", Path: "SiteLens-Setup-5.2.0.exe", SHA512: testSHA512()}
	d := Resolve(base, m, "5.1.0")
	if d.State != "available" {
		t.Fatalf("state=%q，期望 available（err=%v）", d.State, d.Err)
	}
	want := "https://github.com/o/r/releases/download/desktop-stable/SiteLens-Setup-5.2.0.exe"
	if d.URL != want {
		t.Errorf("URL=%q，期望 %q", d.URL, want)
	}
}

func TestResolveLatest(t *testing.T) {
	d := Resolve("https://x/", Manifest{Version: "5.1.0", Path: "a.exe", SHA512: testSHA512()}, "5.1.0")
	if d.State != "latest" {
		t.Errorf("state=%q，期望 latest（err=%v）", d.State, d.Err)
	}
}

// TestResolveNoDowngrade D-05：清单版本低于/等于当前版本时不得报「有更新」，
// 即禁止通过 feed 投递旧版本（降级攻击）。
func TestResolveNoDowngrade(t *testing.T) {
	m := Manifest{Version: "5.1.0", Path: "SiteLens-Setup-5.1.0.exe", SHA512: testSHA512()}
	for _, cur := range []string{"5.1.0", "5.2.0", "6.0.0"} {
		if d := Resolve("https://x/", m, cur); d.State != "latest" {
			t.Errorf("当前 %s、清单 %s 时 state=%q，期望 latest（禁降级）", cur, m.Version, d.State)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	good := testSHA512()
	cases := []struct {
		name string
		base string
		m    Manifest
	}{
		{"缺 version", "https://x/", Manifest{Path: "a.exe", SHA512: good}},
		{"缺 path", "https://x/", Manifest{Version: "9.9.9", SHA512: good}},
		// D-01：缺 sha512 必须直接拒绝，不能「跳过校验继续装」
		{"缺 sha512", "https://x/", Manifest{Version: "9.9.9", Path: "a.exe"}},
		{"sha512 非 base64", "https://x/", Manifest{Version: "9.9.9", Path: "a.exe", SHA512: "abc=="}},
		{"sha512 长度不对", "https://x/",
			Manifest{Version: "9.9.9", Path: "a.exe", SHA512: base64.StdEncoding.EncodeToString([]byte("short"))}},
		// D-05：明文源直接拒绝
		{"http 源", "http://x/", Manifest{Version: "9.9.9", Path: "a.exe", SHA512: good}},
		{"无 scheme 源", "x/", Manifest{Version: "9.9.9", Path: "a.exe", SHA512: good}},
		// path 必须是纯文件名（防路径穿越）
		{"path 带目录", "https://x/", Manifest{Version: "9.9.9", Path: "../a.exe", SHA512: good}},
		{"path 反斜杠", "https://x/", Manifest{Version: "9.9.9", Path: `..\a.exe`, SHA512: good}},
	}
	for _, c := range cases {
		if d := Resolve(c.base, c.m, "5.1.0"); d.State != "error" || d.Err == nil {
			t.Errorf("%s：state=%q err=%v，期望 error", c.name, d.State, d.Err)
		}
	}
}

// TestValidateFeedURL 只允许 https。
func TestValidateFeedURL(t *testing.T) {
	ok := []string{
		"https://github.com/o/r/releases/download/desktop-stable/",
		"https://example.com/dl",
	}
	for _, u := range ok {
		if err := ValidateFeedURL(u); err != nil {
			t.Errorf("ValidateFeedURL(%q) 应通过：%v", u, err)
		}
	}
	bad := []string{"", "http://example.com/dl", "ftp://example.com", "example.com/dl", "//example.com/dl"}
	for _, u := range bad {
		if err := ValidateFeedURL(u); err == nil {
			t.Errorf("ValidateFeedURL(%q) 应拒绝", u)
		}
	}
}

// TestValidateManifestSHA512Strict 摘要必须是合法 base64 且为 64 字节。
func TestValidateManifestSHA512Strict(t *testing.T) {
	base := Manifest{Version: "5.2.0", Path: "a.exe"}
	if err := ValidateManifest(Manifest{Version: "5.2.0", Path: "a.exe", SHA512: testSHA512()}); err != nil {
		t.Fatalf("合法清单应通过：%v", err)
	}
	for _, bad := range []string{
		"",
		"   ",
		"abc==",
		base64.StdEncoding.EncodeToString([]byte("not-64-bytes")),
		strings.Repeat("A", 63), // 合法 base64 但解码长度不对
	} {
		m := base
		m.SHA512 = bad
		if err := ValidateManifest(m); err == nil {
			t.Errorf("sha512=%q 应被拒绝", bad)
		}
	}
}

func TestJoinURL(t *testing.T) {
	cases := [][3]string{
		{"https://a/b/", "x.exe", "https://a/b/x.exe"},
		{"https://a/b", "/x.exe", "https://a/b/x.exe"},
		{"https://a/b/", "/x.exe", "https://a/b/x.exe"},
	}
	for _, c := range cases {
		if got := joinURL(c[0], c[1]); got != c[2] {
			t.Errorf("joinURL(%q,%q)=%q，期望 %q", c[0], c[1], got, c[2])
		}
	}
}

func TestManifestParsesAndDecisionUsesIt(t *testing.T) {
	digest := testSHA512()
	raw := []byte("version: 5.2.0\npath: SiteLens-Setup-5.2.0.exe\nsha512: " + digest +
		"\nreleaseDate: '2026-10-12T00:00:00.000Z'\n")
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "5.2.0" || m.Path != "SiteLens-Setup-5.2.0.exe" || m.SHA512 != digest {
		t.Fatalf("清单解析结果不符：%+v", m)
	}
	if d := Resolve("https://example.com/dl/", m, "5.1.0"); d.State != "available" ||
		filepath_Base(d.URL) != "SiteLens-Setup-5.2.0.exe" {
		t.Errorf("有新版时应给出可用下载地址，实际 %+v", d)
	}
	// 同版本 / 用户已装更高版本（回滚场景）：都不得报「有更新」
	for _, cur := range []string{"5.2.0", "5.3.0"} {
		if d := Resolve("https://example.com/dl/", m, cur); d.State != "latest" {
			t.Errorf("当前 %s 时 state=%q，期望 latest", cur, d.State)
		}
	}
}

// filepath_Base 避免为一行断言引入 filepath（测试语义等同 filepath.Base）。
func filepath_Base(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
