package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestRequireHTTPS BUG-023 回归：更新通道此前接受任意 URL，update-ehole
// 更显式允许 http://。现强制 https：明文下载物直接进扫描链路，中间人
// 可替换模板/指纹。
func TestRequireHTTPS(t *testing.T) {
	ok := []string{
		"https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/master",
		"HTTPS://example.com/pkg.tar.gz",
	}
	for _, u := range ok {
		if err := requireHTTPS(u); err != nil {
			t.Errorf("合法 https 源应通过 %q: %v", u, err)
		}
	}
	bad := []string{
		"http://codeload.github.com/x/tar.gz",
		"HTTP://example.com/x.zip",
		"ftp://example.com/x.zip",
		"file:///etc/passwd",
		"",
		"://bad-url",
		"https:///no-host",
	}
	for _, u := range bad {
		if err := requireHTTPS(u); err == nil {
			t.Errorf("非 https 源应拒绝 %q", u)
		}
	}
}

// TestDownloadUpdateRejectsHTTP 下载入口本身也拦截（不只靠调用方自觉）。
func TestDownloadUpdateRejectsHTTP(t *testing.T) {
	if _, _, _, err := downloadUpdate("http://example.com/x.tar.gz", time.Second, 0); err == nil {
		t.Fatal("downloadUpdate 应拒绝 http://")
	}
}

// TestVerifyUpdateDigest 完整性留痕/硬校验语义：
//   - 未钉期望值：只输出实测 sha256 供人工核对（上游无官方校验和，不伪造通过）；
//   - 钉了期望值：匹配通过、不匹配中止（且中止发生在解包落库之前）。
func TestVerifyUpdateDigest(t *testing.T) {
	t.Setenv(updateSHA256Env, "")
	var buf bytes.Buffer
	if err := verifyUpdateDigest("abc123", &buf); err != nil {
		t.Fatalf("未钉期望值时不应失败: %v", err)
	}
	if !strings.Contains(buf.String(), "abc123") || !strings.Contains(buf.String(), "sha256") {
		t.Fatalf("应输出实测 sha256: %q", buf.String())
	}

	t.Setenv(updateSHA256Env, "ABC123") // 大小写不敏感
	buf.Reset()
	if err := verifyUpdateDigest("abc123", &buf); err != nil {
		t.Fatalf("钉住且匹配应通过: %v", err)
	}
	if !strings.Contains(buf.String(), "校验通过") {
		t.Fatalf("匹配时应报告通过: %q", buf.String())
	}

	t.Setenv(updateSHA256Env, strings.Repeat("0", 64))
	buf.Reset()
	err := verifyUpdateDigest("abc123", &buf)
	if err == nil {
		t.Fatal("钉住且不匹配必须失败（内容可能被篡改）")
	}
	if !strings.Contains(err.Error(), "校验失败") || !strings.Contains(err.Error(), "abc123") {
		t.Fatalf("失败信息应含期望/实测摘要: %v", err)
	}
}

// TestUpdateCommandsRejectHTTP BUG-023 端到端回归：四个更新子命令在
// http:// 源上必须以退出码 1 终止，且不得发起下载/改写本地数据。
func TestUpdateCommandsRejectHTTP(t *testing.T) {
	dir := t.TempDir()
	techPath := filepath.Join(dir, "technologies.json")
	if err := os.WriteFile(techPath, []byte(`{"technologies":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	mkCfg := func() *config.Config {
		cfg := config.Default()
		cfg.Intel.TechnologiesPath = techPath
		cfg.Checks.NucleiDir = filepath.Join(dir, "nuclei")
		return cfg
	}
	before, err := os.ReadFile(techPath)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]int{
		"nuclei": updateNucleiCommand(mkCfg(), "http://example.com/templates.tar.gz"),
		"afrog":  updateAfrogCommand(mkCfg(), "http://example.com/afrog.zip"),
		"fp":     updateFPCommand(mkCfg(), "http://example.com/fingerprints.tar.gz"),
		"ehole":  updateEHoleCommand(mkCfg(), "http://example.com/finger.json"),
	}
	for name, code := range cases {
		if code != 1 {
			t.Errorf("update-%s 对 http:// 源应退出码 1，实际 %d", name, code)
		}
	}
	after, err := os.ReadFile(techPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("拒绝 http 源后不得改写指纹库")
	}
	// 本地文件路径仍可用（update-ehole 的离线通道不能被 https 闸误伤）
	if code := updateEHoleCommand(mkCfg(), techPath); code != 0 {
		t.Fatalf("本地 finger.json 路径应可用，实际退出码 %d", code)
	}
}
