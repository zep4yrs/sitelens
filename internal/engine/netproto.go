// 协议模板扫描编排（3.0 非 HTTP 检测）：tcp/dns/ssl 模板 × 探测到的
// 服务端口。门禁与主动模块同闸（仅在授权目标 + 主动开启时执行）。
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/netx"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
)

// NetHit 一条协议模板命中（落 Extras["netproto"]）。
type NetHit struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Proto    string `json:"proto"`
	Port     int    `json:"port,omitempty"`
	Evidence string `json:"evidence"`
}

// netprotoScan 对探测到的服务端口执行协议模板。services 为空时仅跑
// dns 类模板（查询目标域名自身）。返回命中列表（可能为空）。
func (e *Engine) netprotoScan(host string, services []modules.ServiceHit,
	emit func(kind, text string), cancelled func() bool) []NetHit {

	if e.cfg.Checks.NucleiDir == "" {
		return nil
	}
	entries, err := nuclei.Index(e.cfg.Checks.NucleiDir,
		filepath.Join(e.cfg.Store.DataDir, "nuclei_index.json"))
	if err != nil {
		return nil
	}
	var protos []nuclei.Entry
	for _, en := range entries {
		if en.Proto != "" {
			protos = append(protos, en)
		}
	}
	if len(protos) == 0 {
		return nil
	}
	// 严重度优先；协议模板量级 ~百，直接全量调度（无需 LRU 轮转）
	sort.Slice(protos, func(i, j int) bool { return protos[i].Sev < protos[j].Sev })
	cap := e.cfg.Checks.NucleiCap
	if cap <= 0 || cap > len(protos) {
		cap = len(protos)
	}
	protos = protos[:cap]

	cfg := netx.Config{TimeoutMS: e.cfg.Active.ProbeTimeoutMS, MaxRounds: 4}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = 3000
	}
	var out []NetHit
	for _, en := range protos {
		if cancelled() {
			break
		}
		data, err := os.ReadFile(filepath.Join(e.cfg.Checks.NucleiDir,
			filepath.FromSlash(en.Path)))
		if err != nil {
			continue
		}
		nc := nuclei.ConvertNetwork(data)
		if nc == nil {
			continue
		}
		for _, svc := range services {
			if cancelled() {
				break
			}
			// 端口路由：模板声明端口与探测端口一致才跑；无声明端口的全端口跑
			if nc.Proto == "tcp" && nc.Port != 0 && nc.Port != svc.Port {
				continue
			}
			tgt := netx.Target{Scheme: nc.Proto, Host: host, Port: svc.Port}
			if nc.Proto == "dns" {
				tgt = netx.Target{Scheme: "dns", Host: host}
			}
			hit, sig, err := nuclei.RunNetCheck(nc, tgt, cfg, false)
			if err != nil || !hit {
				continue
			}
			out = append(out, NetHit{
				ID: nc.ID, Name: nc.Name, Severity: nc.Severity(),
				Proto: nc.Proto, Port: svc.Port, Evidence: sig,
			})
			emit("hit", fmt.Sprintf("协议命中 %s（%s :%d）%s",
				nc.ID, nc.Proto, svc.Port, sig))
		}
	}
	return out
}
