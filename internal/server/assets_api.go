package server

// 资产提醒后端（CP-09）：证书到期与端口暴露查询。
//
// 安全口径与 hNetsec 完全一致：先 target.Validate（含 SSRF 解析校验），
// 再过 target.Allowed（scan.allow_hosts 授权白名单）；任一失败 400 且
// 不发起任何网络探测。只读查询：CertExpiry 只握手读证书、CheckPorts 只做
// TCP connect（不发送 payload）。
//
// 契约：
//   GET /api/assets/cert-expiry?host=example.com[:443]
//       → {host, not_after, days_left, ok}
//   GET /api/assets/ports?host=example.com
//       → {host, ports:[{check,title,severity,url,evidence,advice}...], count}

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/netsec"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// assetHostQuery 校验 ?host= 参数：SSRF 校验 + allow_hosts 授权。
// 返回（原始 host、校验后主机名、TLS 探测端口）。语义与 hNetsec 一致：
// URL 里显式端口优先；未指定或 http 默认 80 时按 443 探 TLS。
func (s *Server) assetHostQuery(r *http.Request) (rawHost, vhost string, tlsPort int, err error) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	rawHost = strings.TrimSpace(r.URL.Query().Get("host"))
	if rawHost == "" {
		return "", "", 0, fmt.Errorf("缺少 host 参数")
	}
	_, vhost, port, verr := target.Validate(rawHost, cfg.Scan.Resolve)
	if verr != nil {
		return "", "", 0, verr
	}
	if !target.Allowed(vhost, cfg.Scan.AllowHosts) {
		return "", "", 0, fmt.Errorf("目标不在 allow_hosts 授权白名单：%s", vhost)
	}
	tlsPort = port
	if tlsPort == 0 || tlsPort == 80 {
		tlsPort = 443
	}
	return rawHost, vhost, tlsPort, nil
}

// hCertExpiry GET /api/assets/cert-expiry?host= —— 证书到期提醒数据。
// 探测失败（无 TLS/连接失败/无证书）返回 ok=false + 空 not_after/days_left，
// HTTP 状态仍 200（这是查询结果而非请求错误；host 参数非法才是 400）。
func (s *Server) hCertExpiry(w http.ResponseWriter, r *http.Request) {
	_, vhost, tlsPort, err := s.assetHostQuery(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	notAfter, days, ok := netsec.CertExpiry(vhost, tlsPort)
	resp := map[string]any{"host": vhost, "ok": ok}
	if ok {
		resp["not_after"] = notAfter.UTC().Format(time.RFC3339)
		resp["days_left"] = days
	}
	writeJSON(w, 200, resp)
}

// hAssetPorts GET /api/assets/ports?host= —— 默认端口集暴露探测。
// 与 hNetsec 的 ?ports=1 同口径：DefaultPorts、单端口 1.5s 超时；
// 只做 TCP connect + 可选 banner，不发送 payload。
func (s *Server) hAssetPorts(w http.ResponseWriter, r *http.Request) {
	_, vhost, _, err := s.assetHostQuery(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	ports := netsec.CheckPorts(vhost, netsec.DefaultPorts, 1500*time.Millisecond)
	if ports == nil {
		ports = []netsec.Finding{}
	}
	writeJSON(w, 200, map[string]any{"host": vhost, "ports": ports, "count": len(ports)})
}
