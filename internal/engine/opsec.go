package engine

// OPSEC 噪声档位（5.3 P2，设计稿 §4.5）。
//
// 档位只调整「请求节奏」与「检测面」，不改变判定口径：
//
//	stealth   1.2s/主机起步、≤2 req/s、固定间隔；只跑核心 check（Lv=0），
//	          关闭社区模板池/利用级验证——适合生产环境旁路观察；
//	evasive   800ms/主机起步、≤4 req/s、固定间隔；
//	balanced  默认：沿用 rate_mode（balanced 自适应 / polite 固定），行为与 5.2 一致；
//	noisy     200ms/主机、≤8 req/s、固定间隔——仅授权压测环境使用，仍受 5 req/s 代码红线约束（上限 10）。
//
// 所有档位都不突破 5 req/s 代码级红线（httpx 硬下限 200ms）。

import "time"

// Opsec 档位常量（config 已归一，未知值按 balanced）。
const (
	OpsecStealth  = "stealth"
	OpsecEvasive  = "evasive"
	OpsecBalanced = "balanced"
	OpsecNoisy    = "noisy"
)

// NormalizeOpsec 归一 OPSEC 档位：空/未知 → balanced（fail-safe，不放大噪声）。
func NormalizeOpsec(v string) string {
	switch v {
	case OpsecStealth, OpsecEvasive, OpsecBalanced, OpsecNoisy:
		return v
	default:
		return OpsecBalanced
	}
}

// opsecRate 计算档位对应的（最小间隔, 每主机硬上限, 是否自适应）。
func opsecRate(opsec string, interval time.Duration, maxRPS int, adaptive bool) (time.Duration, int, bool) {
	switch NormalizeOpsec(opsec) {
	case OpsecStealth:
		if interval < 1200*time.Millisecond {
			interval = 1200 * time.Millisecond
		}
		return interval, 2, false
	case OpsecEvasive:
		if interval < 800*time.Millisecond {
			interval = 800 * time.Millisecond
		}
		return interval, 4, false
	case OpsecNoisy:
		if interval <= 0 || interval > 200*time.Millisecond {
			interval = 200 * time.Millisecond
		}
		if maxRPS <= 0 || maxRPS > 8 {
			maxRPS = 8
		}
		return interval, maxRPS, false
	default: // balanced
		return interval, maxRPS, adaptive
	}
}

// applyOpsecChecks 按档位收窄检测面（stealth 只跑核心 check + 关利用级验证）。
// 返回收窄后的 Options；不修改调用方原始值（值拷贝）。
func applyOpsecChecks(opts Options, opsec string) Options {
	if NormalizeOpsec(opsec) != OpsecStealth {
		return opts
	}
	if opts.Checks != "none" {
		opts.Checks = "core"
	}
	opts.NucleiSubset = false
	opts.Exploit = false
	opts.DAST = false
	return opts
}
