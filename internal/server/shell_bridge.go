package server

// 桌面壳 ↔ 引擎的自证与运行环境契约（D-07 / C-17）。
//
// D-07：壳拉起引擎时通过环境变量注入一次性随机串 SITLENS_SHELL_NONCE；
// 壳在 waitReady 阶段读取 /api/version 返回的 nonce，确认当前监听端口的
// 进程确实是「自己拉起的那个引擎」，而不是抢先占住端口的本地进程
// （端口探测与引擎绑定之间存在 TOCTOU 窗口，端口可被本地任意进程抢占）。
//
// 只在环境变量存在时回显：CLI / 裸服务形态不暴露、不改变既有响应契约。
// 非敏感（随机串由壳生成、仅本机进程环境可见，且每次启动重新生成）。

import (
	"os"
	"strings"
)

var shellNonce = strings.TrimSpace(os.Getenv("SITLENS_SHELL_NONCE"))

// versionBody /api/version 响应体；壳的 nonce 校验依赖它（D-07）。
func versionBody() map[string]any {
	m := map[string]any{"name": "SiteLens", "version": Version, "engine": "go"}
	if shellNonce != "" {
		m["nonce"] = shellNonce
	}
	return m
}

// ShellNonce 返回本次进程的壳 nonce（空 = 非壳启动）——供测试与诊断使用。
func ShellNonce() string { return shellNonce }
