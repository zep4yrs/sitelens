// SSRF 出带回调探测：把指向本服务 beacon 的 URL 塞进候选参数，
// 目标侧若回连（内部 /beacon 记录命中），即确认参数可触达 SSRF。
// 有界：单扫描最多 MaxProbes 个参数、每参数 1 个请求；beacon 默认关。
package dast

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/beacon"
)

// randToken 生成 128 位随机令牌（beacon 路径随机段，不可预测）。
func randToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ssrfToken 一个出带探测的参数与令牌。
type ssrfToken struct {
	tgt   Target
	token string
}

// ssrfProbe 出带回调探测主流程：塞入 → 轮询 beacon（上限 4s）→ 出 Finding。
func (r *Runner) ssrfProbe(targets []Target) []Finding {
	if r.opts.BeaconBase == "" {
		return nil
	}
	cap := r.opts.MaxProbes
	if cap <= 0 || cap > len(targets) {
		cap = len(targets)
	}
	var tokens []ssrfToken
	for i := 0; i < cap && !r.stopped(); i++ {
		tgt := targets[i]
		token := randToken()
		u := setParam(tgt.URL, tgt.Param, r.opts.BeaconBase+"/b/"+token)
		if len(u) > r.opts.MaxURLLen {
			continue
		}
		r.fetch.GetSmall(u)
		tokens = append(tokens, ssrfToken{tgt: tgt, token: token})
	}
	if len(tokens) == 0 {
		return nil
	}

	// 轮询 beacon 注册表（目标回连是异步的，给 4s 窗口）
	var hits map[string]bool
	for i := 0; i < 20; i++ {
		if r.stopped() {
			break
		}
		time.Sleep(200 * time.Millisecond)
		hits = indexBeaconHits()
		if len(hits) > 0 {
			break
		}
	}

	var out []Finding
	for _, tk := range tokens {
		if hits[tk.token] {
			out = append(out, Finding{
				Check:    "ssrf-oob",
				Title:    "SSRF（出带回调确认）",
				Severity: "high",
				URL:      tk.tgt.URL,
				Param:    tk.tgt.Param,
				Evidence: fmt.Sprintf("参数被注入 beacon 地址后目标侧回连 token=%s（出带确认）", tk.token),
				Advice:   "禁止服务端请求用户可控地址；按需白名单出口域名并禁用内网段",
			})
		}
	}
	return out
}

// indexBeaconHits 进程内 beacon 注册表快照（serve 与引擎同二进制）。
func indexBeaconHits() map[string]bool {
	out := map[string]bool{}
	for _, t := range beacon.Hits() {
		out[t] = true
	}
	return out
}
