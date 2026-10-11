// Package portpolicy 实现桌面壳的端口决策（纯函数，无平台依赖，可跨平台单测）。
//
// 与 Electron 壳 desktop/lib/port-policy.js 契约一致——两种壳不能对同一产品
// 行为给出不同答案：控制台默认 http://127.0.0.1:5087，被占用才换随机空闲端口，
// 协商结果回写偏好文件、下次启动优先认领（否则用户书签/排障 URL 全失效）。
package portpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultFallback 兜底默认端口（与 Electron 壳一致）。
const DefaultFallback = 5087

// Valid 判定是否为可用端口数值（1-65535 整数）。
func Valid(p int) bool { return p > 0 && p <= 65535 }

// Resolve 决定「优先尝试」的端口与来源标签。
// source ∈ "shell"（壳偏好）/ "config"（配置原文）/ "default"（兜底）。
func Resolve(prefPort, confPort int) (int, string) {
	if Valid(prefPort) {
		return prefPort, "shell"
	}
	if Valid(confPort) {
		return confPort, "config"
	}
	return DefaultFallback, "default"
}

// Describe 来源标签 → 中文排障文案。
func Describe(source string) string {
	switch source {
	case "shell":
		return "壳偏好"
	case "config":
		return "配置原文"
	default:
		return "默认"
	}
}

// Listen 拼装监听地址（127.0.0.1:port）。
func Listen(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// ParseConfListenPort 从配置文本里读 web: 段下 listen 的端口；
// 解析不出来返回 0（回退默认——比误读更安全）。
// 逐行扫描：进入 web: 段后找 listen:，遇下一个顶层键即离开该段。
func ParseConfListenPort(text string) int {
	inWeb := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indented := line != trimmed // 有缩进 = 段内键
		if !indented {
			inWeb = trimmed == "web:"
			continue
		}
		if !inWeb || !strings.HasPrefix(trimmed, "listen:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(trimmed, "listen:"))
		val = strings.Trim(val, `"'`)
		if i := strings.LastIndex(val, ":"); i >= 0 { // host:port → port
			val = val[i+1:]
		}
		if p, err := strconv.Atoi(val); err == nil && Valid(p) {
			return p
		}
		return 0
	}
	return 0
}
