// 更新通道公共闸：强制 https + 实测 sha256 留痕/硬校验（BUG-023）。
//
// 背景：update-nuclei / update-afrog / update-fp / update-ehole 下载的内容
// 直接进入扫描链路（模板库能发请求、指纹库决定识别结论），此前既无完整性
// 校验也无来源约束，update-ehole 还显式接受 http://——明文通道下中间人
// 可替换模板/指纹，属红线级风险（凭证与"可复核"同理：不可放松）。
//
// 上游现状必须诚实说明：本项目取的是 codeload 的「分支最新打包」
// （nuclei-templates master / afrog-pocs main / webappanalyzer main），
// 上游**不发布该打包的官方校验和**。因此这里不伪造"校验通过"：
//  1. 强制 https（禁用明文 http）；
//  2. 下载后把实测 sha256 打到 stderr，供人工与上游发布页对照；
//  3. 允许用 SLENS_UPDATE_SHA256 预置期望摘要（自建镜像/钉版本场景），
//     设置后做硬校验：不匹配即中止，且**在解包落库之前**中止。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// updateSHA256Env 预置期望摘要的环境变量名（十六进制 sha256，大小写不敏感）。
const updateSHA256Env = "SLENS_UPDATE_SHA256"

// requireHTTPS 更新源必须为 https。
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("更新源 URL 不合法：%w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("更新源必须使用 https（当前 %q）；明文 http 可被中间人替换模板/指纹，已拒绝", rawURL)
	}
	if u.Host == "" {
		return fmt.Errorf("更新源 URL 缺少主机名：%q", rawURL)
	}
	return nil
}

// downloadUpdate 下载更新包到临时文件并做完整性校验，返回文件路径、实测
// sha256 与清理函数（调用方 defer 之）。
//
// 先落临时文件再校验、校验通过后调用方才解包落库：边下边解包无法在写入
// 后回滚，一旦期望摘要不匹配就会把被篡改内容写进模板池/指纹库。
// limitBytes<=0 表示不限大小（与旧行为一致）。
func downloadUpdate(rawURL string, timeout time.Duration, limitBytes int64) (string, string, func(), error) {
	if err := requireHTTPS(rawURL); err != nil {
		return "", "", nil, err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", "", nil, fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("下载失败：HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp("", "sitelens-update-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("创建临时文件失败：%w", err)
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	fail := func(err error) (string, string, func(), error) {
		_ = f.Close()
		cleanup()
		return "", "", nil, err
	}
	var body io.Reader = resp.Body
	if limitBytes > 0 {
		body = io.LimitReader(resp.Body, limitBytes+1)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), body)
	if err != nil {
		return fail(fmt.Errorf("下载中断：%w", err))
	}
	if limitBytes > 0 && n > limitBytes {
		return fail(fmt.Errorf("下载内容超过上限（%d 字节）", limitBytes))
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("临时文件写盘失败：%w", err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if err := verifyUpdateDigest(digest, os.Stderr); err != nil {
		cleanup()
		return "", "", nil, err
	}
	return path, digest, cleanup, nil
}

// verifyUpdateDigest 输出实测 sha256；SLENS_UPDATE_SHA256 有值时做硬校验。
//
// 未设置期望值时只留痕不拦截（上游无官方校验和，拦截等于对所有正常更新
// 报错）；设置期望值则视为用户已钉版本，不匹配直接失败。
func verifyUpdateDigest(digest string, w io.Writer) error {
	want := strings.ToLower(strings.TrimSpace(os.Getenv(updateSHA256Env)))
	if want == "" {
		fmt.Fprintf(w, "内容 sha256：%s（上游未提供该打包的官方校验和，请人工核对）\n", digest)
		return nil
	}
	if want != digest {
		return fmt.Errorf("sha256 校验失败：期望 %s，实测 %s（内容可能被篡改，已中止且未落盘）", want, digest)
	}
	fmt.Fprintf(w, "sha256 校验通过：%s\n", digest)
	return nil
}
