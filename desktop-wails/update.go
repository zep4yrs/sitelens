package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"sitelens-wails/internal/updater"
)

// 更新源：唯一来源是 GitHub 的 desktop-stable release 附件区（与 Electron 壳
// 一致，发版脚本产出的三件套直接可用）。
var updateBaseURL = "https://github.com/zep4yrs/sitelens/releases/download/desktop-stable/"

const updateManifestName = "latest.yml"

// updateFeedEnv 开发态注入本地 feed 的环境变量（仍强制 https，见 resolveFeedBase）。
const updateFeedEnv = "SITLENS_UPDATE_URL"

// errUpdateDeclined 用户在确认对话框里选择了「否」。
var errUpdateDeclined = errors.New("用户取消了本次更新")

// resolveFeedBase 决定本次检查使用的更新源目录地址。
//
// D-01/D-05：环境变量覆盖只用于开发态端到端验证，但**不允许**绕过 https
// 强制——明文源下清单与安装包可被一起替换，而 sha512 也来自同一份清单，
// 完整性校验在明文信道下没有任何独立可信度。
func resolveFeedBase() (string, error) {
	base := updateBaseURL
	if v := strings.TrimSpace(os.Getenv(updateFeedEnv)); v != "" {
		base = v
	}
	if err := updater.ValidateFeedURL(base); err != nil {
		return "", err
	}
	return base, nil
}

// checkUpdate 拉清单并判定是否有新版本。任何网络/解析/校验失败都返回 error
// （上层据此在设置页/日志给出可读结论），不静默吞掉。
func checkUpdate(currentVersion string) (updater.Decision, updater.Manifest, error) {
	var empty updater.Manifest
	base, err := resolveFeedBase()
	if err != nil {
		return updater.Decision{}, empty, err
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
	d := updater.Resolve(base, m, currentVersion)
	if d.State == "error" && d.Err != nil {
		return d, m, d.Err
	}
	return d, m, nil
}

// confirmFunc 在**下载之前**询问用户是否安装新版本；返回 false = 用户拒绝。
type confirmFunc func(latest, current string) bool

// downloadAndInstall 下载新版本安装包、校验摘要，然后静默就地覆盖安装。
//
// 安全约束（D-01/D-05，全部 fail-closed）：
//  1. 更新源与下载地址都必须是 https（清单 path 只允许纯文件名，见 updater.ValidateManifest）；
//  2. 清单必须带合法 sha512（缺失/格式非法时 updater.Resolve 已判 error，走不到这里）；
//  3. 摘要不匹配 → 删除文件、返回错误，**绝不执行**；
//  4. 执行安装包之前必须用户显式确认（confirm 回调弹原生对话框，默认按钮是「否」）；
//  5. 任何失败都不改动已安装文件（下载/校验都在替换之前完成）。
func downloadAndInstall(d updater.Decision, m updater.Manifest, userData string, confirm confirmFunc) error {
	if d.State != "available" {
		return fmt.Errorf("无可用更新（state=%s）", d.State)
	}
	// 自动更新当前只有 Windows NSIS 安装器路径（/S 静默覆盖）；Linux/macOS
	// 用各自打包格式（AppImage/dmg），不执行 .exe，明确拒绝而不是静默失败。
	if runtime.GOOS != "windows" {
		return fmt.Errorf("当前平台暂不支持自动更新（仅 Windows 安装器）；请手动下载 %s 安装包", runtime.GOOS)
	}
	// 二次校验（不依赖 Resolve 的实现细节）：清单 + 下载地址都必须在 https 上。
	if err := updater.ValidateManifest(m); err != nil {
		return err
	}
	if u, err := url.Parse(d.URL); err != nil || u.Scheme != updater.FeedScheme {
		return fmt.Errorf("下载地址必须使用 https：%q", d.URL)
	}
	// 确认放在下载之前：用户拒绝时连流量都不该产生。
	if confirm == nil || !confirm(d.Latest, d.Current) {
		return errUpdateDeclined
	}

	dir := filepath.Join(userData, "updates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("建下载目录失败：%w", err)
	}
	dest := filepath.Join(dir, filepath.Base(m.Path))
	log.Printf("更新下载：%s → %s", d.URL, dest)

	client := &http.Client{
		Timeout: 30 * time.Minute,
		// 重定向链同样只允许 https：https 源跳转到 http 等于降级。
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != updater.FeedScheme {
				return fmt.Errorf("下载被重定向到非 https 地址：%s", req.URL.Redacted())
			}
			if len(via) >= 5 {
				return fmt.Errorf("下载重定向次数过多")
			}
			return nil
		},
	}
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
		os.Remove(dest) // 校验失败：删除下载物，绝不执行
		return err
	}
	log.Printf("更新校验通过，静默覆盖安装：%s", dest)

	// /S = 静默（不起向导页）；安装器按 InstallDirRegKey 就地覆盖。
	// 走到这里的唯一前提：https 下载 + 摘要匹配 + 用户已点「是」。
	cmd := exec.Command(dest, "/S")
	hideChildWindow(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起安装器失败：%w", err)
	}
	log.Printf("安装器已启动（pid=%d），本进程退出以释放待替换文件", cmd.Process.Pid)
	return nil
}

// verifySHA512 校验文件摘要。
//
// fail-closed（D-01）：want 为空或格式非法一律返回错误——旧实现在缺摘要时
// 直接 return nil（跳过校验继续安装），等于把完整性校验变成可选。
func verifySHA512(path, want string) error {
	want = strings.TrimSpace(want)
	if want == "" {
		return fmt.Errorf("缺少 sha512 摘要，拒绝安装（无法校验安装包完整性）")
	}
	exp, err := base64.StdEncoding.DecodeString(want)
	if err != nil {
		return fmt.Errorf("sha512 摘要不是合法 base64：%w", err)
	}
	if len(exp) != sha512.Size {
		return fmt.Errorf("sha512 摘要长度非法（期望 %d 字节，实际 %d 字节）", sha512.Size, len(exp))
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
	if !bytes.Equal(h.Sum(nil), exp) {
		return fmt.Errorf("安装包校验失败（sha512 不匹配，文件可能损坏或被篡改）")
	}
	return nil
}

// runUpdateCheck 手动检查（托盘入口）：真实检查 → 用户确认 → 下载 → 校验 → 安装。
//
// D-01：这里（而不是启动路径）才是「下载并执行」的唯一入口，且执行前必须
// 经过 confirmInstallDialog 的原生确认对话框。
func runUpdateCheck(userData string, app quitApp, notify func(kind, title, body string)) {
	d, m, err := checkUpdate(Version)
	if err != nil {
		log.Printf("检查更新失败：%v", err)
		if notify != nil {
			notify(toastErr, "检查更新失败", err.Error())
		}
		return
	}
	switch d.State {
	case "latest":
		log.Printf("已是最新版本 v%s", d.Current)
		if notify != nil {
			notify(toastOK, "已是最新版本", "当前 v"+d.Current)
		}
	case "available":
		log.Printf("发现新版本 v%s（当前 v%s），等待用户确认", d.Latest, d.Current)
		go func() {
			if err := downloadAndInstall(d, m, userData, confirmInstallDialog); err != nil {
				log.Printf("更新未完成：%v", err)
				// 用户主动点「否」是正常操作，不弹错误提示（只留日志）。
				if notify != nil && !errors.Is(err, errUpdateDeclined) {
					notify(toastErr, "更新未完成", err.Error())
				}
				return
			}
			app.Quit()
		}()
	default:
		log.Printf("检查更新异常：state=%s err=%v", d.State, d.Err)
	}
}

// runUpdateCheckStartup 启动期静默检查：**只提示、不下载、不执行**。
//
// D-01：旧实现「发现新版即后台下载并以 /S 静默安装」把更新源变成了远程代码
// 执行通道（源被劫持＝静默装马）。现在启动期只做一次只读检查并提示用户，
// 真正的下载/安装必须走托盘「检查更新」入口——那里会弹原生确认对话框。
func runUpdateCheckStartup(notify func(kind, title, body string)) {
	d, _, err := checkUpdate(Version)
	if err != nil {
		log.Printf("启动检查更新跳过：%v", err)
		return
	}
	if d.State != "available" {
		log.Printf("启动检查更新：%s（当前 v%s）", d.State, d.Current)
		return
	}
	log.Printf("启动检查更新：发现新版本 v%s（当前 v%s），仅提示、不自动安装", d.Latest, d.Current)
	if notify != nil {
		notify(toastInfo, "发现新版本 v"+d.Latest, "点托盘「检查更新」确认下载并安装")
	}
}

// quitApp 抽象「退出壳」（仅此一项需要，便于将来注入测试替身）。
type quitApp interface{ Quit() }
