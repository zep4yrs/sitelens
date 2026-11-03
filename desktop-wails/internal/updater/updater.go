// Package updater 实现桌面壳的「检查更新」核心逻辑（纯函数 + 可注入 IO）。
//
// 为什么自建而不是引第三方 updater：Wails v3 没有官方签名式自动更新
// （desktop/README 的已知边界写过「updater 方案尚未实现」）。本壳的更新
// 语义很简单——**用户确认后下载整包 → 校验 SHA512 → 静默就地覆盖安装 → 重开**，
// 正好是 NSIS 安装器已经支持的能力（`/S` 静默 + 注册表 InstallDir 就地覆盖），
// 不需要增量差分。
//
// 安全边界（D-01/D-05）：源必须 https、清单必须带合法 sha512、清单版本必须
// 严格高于当前版本、摘要不匹配绝不执行、执行前必须用户显式确认。
//
// 本包只放**可测的纯逻辑**：清单解析/校验、版本比较、升级判定。网络下载与
// 进程拉起留在壳里（需要 Windows 环境）。
package updater

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// FeedScheme 更新源唯一允许的协议。
//
// 为什么强制 https（D-01/D-05）：清单与安装包同源，sha512 摘要也来自清单。
// 明文信道下两者可被一起替换，完整性校验没有任何独立可信度——所以「只支持
// https」不是体验取舍，而是校验成立的前提。
const FeedScheme = "https"

// sha512DigestLen SHA512 摘要字节长度（清单里的 sha512 是它的 base64）。
const sha512DigestLen = 64

// ValidateFeedURL 校验更新源目录地址：必须 https 且带主机名。
func ValidateFeedURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("更新源地址非法：%w", err)
	}
	if u.Scheme != FeedScheme {
		return fmt.Errorf("更新源必须使用 https（当前 %q）", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("更新源缺少主机名：%q", raw)
	}
	return nil
}

// ValidateManifest 校验清单必填项与格式：version / path / sha512。
//
// fail-closed（D-01）：旧实现在清单缺 sha512 时「跳过校验继续装」，等于把
// 完整性校验变成可选字段；现在缺摘要或摘要格式非法一律拒绝，绝不进入下载
// 与执行阶段。
//
// path 必须是纯文件名：清单来自网络，不允许通过 ".." 或子目录影响落盘路径
// （落盘另有 filepath.Base 兜底，这里是第二道闸）。
func ValidateManifest(m Manifest) error {
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("更新清单缺 version 字段")
	}
	if strings.TrimSpace(m.Path) == "" {
		return fmt.Errorf("更新清单缺 path 字段（无法定位安装包）")
	}
	p := strings.TrimSpace(m.Path)
	if p != path.Base(p) || strings.ContainsAny(p, `/\`) || p == "." || p == ".." {
		return fmt.Errorf("更新清单 path 非法（必须是纯文件名）：%q", m.Path)
	}
	if strings.TrimSpace(m.SHA512) == "" {
		return fmt.Errorf("更新清单缺 sha512（拒绝更新：无法校验安装包完整性）")
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m.SHA512))
	if err != nil {
		return fmt.Errorf("更新清单 sha512 不是合法 base64：%w", err)
	}
	if len(digest) != sha512DigestLen {
		return fmt.Errorf("更新清单 sha512 长度非法（期望 %d 字节，实际 %d 字节）",
			sha512DigestLen, len(digest))
	}
	return nil
}

// Manifest 更新清单（与 electron-builder 的 latest.yml 兼容子集）。
//
// 复用它的原因：Electron 壳（仍在维护历史线）与发版脚本已经按这个格式产出
// 三件套（exe / .blockmap / latest.yml），自建壳直接读同一份清单，两条壳
// 能共用同一个更新源，发版侧零改动。
type Manifest struct {
	Version     string `yaml:"version"`
	Path        string `yaml:"path"`   // 安装包文件名
	SHA512      string `yaml:"sha512"` // 安装包摘要（校验下载完整性）
	ReleaseDate string `yaml:"releaseDate"`
}

// Compare 比较两个点分版本号（可带 v 前缀）：a>b 返回 1，a<b 返回 -1，相等 0。
//
// 只比较数值段（各段按整数解析），足够覆盖本项目的 x.y.z 版本线；
// 预发布后缀（-beta.1）按「数值段后的字符串」处理：数值相同则字符串更长的
// 视为更新（`5.2.0` > `5.2.0-beta.1`——正式版优先于预发布）。
func Compare(a, b string) int {
	as := splitVer(a)
	bs := splitVer(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		c := compareSeg(av, bv)
		if c != 0 {
			return c
		}
	}
	return 0
}

// splitVer 去掉 v 前缀并切成 . 分隔段。
func splitVer(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
}

// compareSeg 单段比较：纯数值按数值比；含后缀时数值相同则「有后缀」视为更旧。
func compareSeg(a, b string) int {
	an, aok := parseIntPrefix(a)
	bn, bok := parseIntPrefix(b)
	switch {
	case aok && bok:
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
		// 数值相同：带后缀的（预发布）视为更旧
		asuf := strings.TrimPrefix(a, strconv.Itoa(an))
		bsuf := strings.TrimPrefix(b, strconv.Itoa(bn))
		switch {
		case asuf == "" && bsuf == "":
			return 0
		case asuf == "":
			return 1 // a 是正式，b 带后缀
		case bsuf == "":
			return -1
		default:
			return strings.Compare(asuf, bsuf)
		}
	case aok:
		return 1 // 有数值段 > 空段
	case bok:
		return -1
	default:
		return strings.Compare(a, b)
	}
}

// parseIntPrefix 取字符串开头的连续数字并转整数。
func parseIntPrefix(s string) (int, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// Decision 检查更新的结论。
type Decision struct {
	State   string // "latest" | "available" | "error"
	Current string
	Latest  string
	URL     string // 新版本安装包的绝对下载地址（State=available 时有效）
	Err     error
}

// Resolve 由清单、当前版本与下载基址算出结论。
//
// baseURL 是 update 源的目录地址（形如
// https://github.com/<owner>/<repo>/releases/download/desktop-stable/），
// 清单里的 path 相对它拼出绝对下载地址。
//
// 全部校验 fail-closed（D-01/D-05）：源不是 https、清单缺 version/path/sha512、
// 摘要格式非法 → 一律 state=error，调用方据此拒绝更新（绝不进入下载与执行）。
// 「禁降级」由 Compare 保证：清单版本必须**严格高于**当前版本，否则 state=latest。
func Resolve(baseURL string, m Manifest, currentVersion string) Decision {
	d := Decision{Current: currentVersion}
	if err := ValidateFeedURL(baseURL); err != nil {
		d.State = "error"
		d.Err = err
		return d
	}
	if err := ValidateManifest(m); err != nil {
		d.State = "error"
		d.Err = err
		return d
	}
	d.Latest = m.Version
	if Compare(m.Version, currentVersion) <= 0 {
		d.State = "latest"
		return d
	}
	d.State = "available"
	d.URL = joinURL(baseURL, m.Path)
	return d
}

// joinURL 拼下载地址（base 末尾斜杠可选，path 前导斜杠忽略）。
func joinURL(base, path string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	p := strings.TrimLeft(strings.TrimSpace(path), "/")
	if b == "" {
		return p
	}
	if p == "" {
		return b
	}
	return b + "/" + p
}
