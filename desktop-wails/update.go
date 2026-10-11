package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"sitelens-wails/internal/updater"
)

// 更新源：唯一来源是 GitHub 的 desktop-stable release 附件区（与 Electron 壳
// 一致，发版脚本产出的三件套直接可用）。留成变量便于开发态注入本地 feed
// 做端到端验证（SITLENS_UPDATE_URL）。
var updateBaseURL = "https://github.com/zep4rs/sitelens/releases/download/desktop-stable/"

const updateManifestName = "latest.yml"

// checkUpdate 拉清单并判定是否有新版本。任何网络/解析失败都返回 error
// （上层据此在设置页/日志给出可读结论），不静默吞掉。
func checkUpdate(currentVersion string) (updater.Decision, updater.Manifest, error) {
	var empty updater.Manifest
	base := updateBaseURL
	if v := os.Getenv("SITLENS_UPDATE_URL"); v != "" {
		base = v
	}
	url := base
	if url != "" && url[len(url)-1] != '/' {
		url += "/"
	}
	url += updateManifestName

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return updater.Decision{}, empty, fmt.Errorf("取更新清单失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return updater.Decision{}, empty, fmt.Errorf("更新清单不可达（HTTP %d）：%s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return updater.Decision{}, empty, fmt.Errorf("读更新清单失败：%w", err)
	}
	var m updater.Manifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return updater.Decision{}, empty, fmt.Errorf("解析更新清单失败：%w", err)
	}
	return updater.Resolve(base, m, currentVersion), m, nil
}

// downloadAndInstall 下载新版本安装包并**静默就地覆盖安装**，然后退出本进程。
//
// 语义（这就是「覆盖更新」）：
//  1. 下载到用户数据区 updates/ 下（安装目录只读，不能当下载落点）；
//  2. sha512 校验（清单里带摘要，下载被截断/篡改能当场发现）；
//  3. 以 `/S` 拉起 NSIS 安装器：静默分支不起向导页，按注册表 InstallDir
//     就地覆盖原安装目录（installer.nsi 的 InstallDirRegKey 保证「升级不挪窝」）；
//  4. 退出本进程，让安装器替换文件（安装器会拉起新版——`/S` 后由 NSIS 的
//     完成页 runAfterFinish 接管；这里显式 quit 避免占用被替换的文件）。
//
// 失败一律返回 error 且不改动任何已安装文件——下载/校验在替换之前完成。
func downloadAndInstall(d updater.Decision, m updater.Manifest, userData string) error {
	if d.State != "available" {
		return fmt.Errorf("无可用更新（state=%s）", d.State)
	}
	dir := filepath.Join(userData, "updates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("建下载目录失败：%w", err)
	}
	dest := filepath.Join(dir, filepath.Base(m.Path))
	log.Printf("更新下载：%s → %s", d.URL, dest)

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(d.URL)
	if err != nil {
		return fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败（HTTP %d）", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("创建下载文件失败：%w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(dest)
		return fmt.Errorf("写入下载文件失败：%w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(dest)
		return fmt.Errorf("关闭下载文件失败：%w", err)
	}

	if err := verifySHA512(dest, m.SHA512); err != nil {
		os.Remove(dest)
		return err
	}
	log.Printf("更新校验通过，静默覆盖安装：%s", dest)

	// /S = 静默（不起向导页）；安装器按 InstallDirRegKey 就地覆盖。
	cmd := exec.Command(dest, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起安装器失败：%w", err)
	}
	log.Printf("安装器已启动（pid=%d），本进程退出以释放待替换文件", cmd.Process.Pid)
	return nil
}

// verifySHA512 校验文件摘要；清单未提供摘要时跳过（不阻断——但记日志）。
func verifySHA512(path, want string) error {
	if want == "" {
		log.Printf("更新清单未提供 sha512，跳过完整性校验")
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("安装包校验失败（sha512 不匹配，文件可能损坏）")
	}
	return nil
}

// runUpdateCheck 手动检查（托盘入口）：真实检查并把结论反馈给用户，
// 有新版则下载并静默覆盖安装（装完自动重开新版）。
func runUpdateCheck(userData string, app quitApp) {
	d, m, err := checkUpdate(Version)
	if err != nil {
		log.Printf("检查更新失败：%v", err)
		return
	}
	switch d.State {
	case "latest":
		log.Printf("已是最新版本 v%s", d.Current)
	case "available":
		log.Printf("发现新版本 v%s，后台下载并静默覆盖安装", d.Latest)
		go func() {
			if err := downloadAndInstall(d, m, userData); err != nil {
				log.Printf("更新安装失败：%v", err)
				return
			}
			app.Quit()
		}()
	default:
		log.Printf("检查更新异常：state=%s err=%v", d.State, d.Err)
	}
}

// runUpdateCheckQuiet 启动期静默检查：只在「有新版并成功拉起安装器」时留痕，
// 其余情况完全安静（离线/源不可达不该在启动时弹窗打扰）。
func runUpdateCheckQuiet(userData string, app quitApp) {
	d, m, err := checkUpdate(Version)
	if err != nil {
		log.Printf("启动检查更新跳过：%v", err)
		return
	}
	if d.State != "available" {
		log.Printf("启动检查更新：%s（当前 v%s）", d.State, d.Current)
		return
	}
	log.Printf("发现新版本 v%s，后台下载并静默覆盖安装", d.Latest)
	if err := downloadAndInstall(d, m, userData); err != nil {
		log.Printf("后台更新失败：%v", err)
		return
	}
	log.Println("安装器已启动，退出以完成覆盖更新")
	app.Quit()
}

// quitApp 抽象「退出壳」（仅此一项需要，便于将来注入测试替身）。
type quitApp interface{ Quit() }
