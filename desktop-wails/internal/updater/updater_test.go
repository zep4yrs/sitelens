package updater

import (
	"testing"

	"gopkg.in/yaml.v3"
)

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
	m := Manifest{Version: "5.2.0", Path: "SiteLens-Setup-5.2.0.exe"}
	d := Resolve(base, m, "5.1.0")
	if d.State != "available" {
		t.Fatalf("state=%q，期望 available", d.State)
	}
	want := "https://github.com/o/r/releases/download/desktop-stable/SiteLens-Setup-5.2.0.exe"
	if d.URL != want {
		t.Errorf("URL=%q，期望 %q", d.URL, want)
	}
}

func TestResolveLatest(t *testing.T) {
	d := Resolve("https://x/", Manifest{Version: "5.1.0", Path: "a.exe"}, "5.1.0")
	if d.State != "latest" {
		t.Errorf("state=%q，期望 latest", d.State)
	}
}

func TestResolveErrors(t *testing.T) {
	if d := Resolve("https://x/", Manifest{}, "5.1.0"); d.State != "error" || d.Err == nil {
		t.Error("缺 version 应报 error")
	}
	if d := Resolve("https://x/", Manifest{Version: "9.9.9"}, "5.1.0"); d.State != "error" {
		t.Error("缺 path 应报 error（无法定位安装包）")
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
	raw := []byte("version: 5.2.0\npath: SiteLens-Setup-5.2.0.exe\nsha512: abc==\nreleaseDate: '2026-10-12T00:00:00.000Z'\n")
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "5.2.0" || m.Path != "SiteLens-Setup-5.2.0.exe" || m.SHA512 != "abc==" {
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
