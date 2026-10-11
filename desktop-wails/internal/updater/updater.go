// Package updater 实现桌面壳的「检查更新」核心逻辑（纯函数 + 可注入 IO）。
//
// 为什么自建而不是引第三方 updater：Wails v3 没有官方签名式自动更新
// （desktop/README 的已知边界写过「updater 方案尚未实现」）。本壳的更新
// 语义很简单——**下载整包 → 静默就地覆盖安装 → 重开**，正好是 NSIS 安装器
// 已经支持的能力（`/S` 静默 + 注册表 InstallDir 就地覆盖），不需要增量差分。
//
// 本包只放**可测的纯逻辑**：清单解析、版本比较、升级判定。网络下载与
// 进程拉起留在壳里（需要 Windows 环境）。
package updater

import (
	"fmt"
	"strconv"
	"strings"
)

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
func Resolve(baseURL string, m Manifest, currentVersion string) Decision {
	d := Decision{Current: currentVersion}
	if strings.TrimSpace(m.Version) == "" {
		d.State = "error"
		d.Err = fmt.Errorf("更新清单缺 version 字段")
		return d
	}
	d.Latest = m.Version
	if Compare(m.Version, currentVersion) <= 0 {
		d.State = "latest"
		return d
	}
	if strings.TrimSpace(m.Path) == "" {
		d.State = "error"
		d.Err = fmt.Errorf("更新清单缺 path 字段（无法定位安装包）")
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
