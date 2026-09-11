// 协议模板执行器：NetCheck × netx 目标 → (命中, 证据)。
package nuclei

import (
	"fmt"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/netx"
)

// RunNetCheck 对单目标执行协议模板。
//   - tcp：逐 payload Send+Recv（无 payload 则只读 banner），拼接响应匹配；
//   - dns：按 name/type 查询（{{FQDN}}/{{Hostname}} 替换为 t.Host），记录串拼接匹配；
//   - ssl：TLS 握手取证书摘要串匹配。
//
// resolve 语义与 netx 一致：调用方已在扫描入口做过逐 IP 校验时传 false，
// 避免每模板重复 DNS（字面 IP 与保留主机名仍会被闸拦截）。
func RunNetCheck(nc *NetCheck, t netx.Target, cfg netx.Config, resolve bool) (bool, string, error) {
	switch nc.Proto {
	case "tcp":
		return runTCP(nc, t, cfg, resolve)
	case "dns":
		return runDNS(nc, t, cfg)
	case "ssl":
		return runSSL(nc, t, cfg, resolve)
	}
	return false, "", fmt.Errorf("netrun: 未知协议 %q", nc.Proto)
}

func runTCP(nc *NetCheck, t netx.Target, cfg netx.Config, resolve bool) (bool, string, error) {
	if t.Port == 0 {
		t.Port = nc.Port
	}
	if t.Port == 0 {
		return false, "", fmt.Errorf("netrun: tcp 模板 %s 无端口可用", nc.ID)
	}
	conn, err := netx.Dial(t, cfg, resolve)
	if err != nil {
		return false, "", err // 连接失败 ≠ 未命中：目标端口没开是常态
	}
	defer conn.Close()
	var resp strings.Builder
	if len(nc.Payloads) == 0 {
		if data, rerr := conn.Recv(); rerr == nil {
			resp.Write(data)
		}
	} else {
		for _, p := range nc.Payloads {
			if err := conn.Send(p); err != nil {
				break
			}
			if data, rerr := conn.Recv(); rerr == nil {
				resp.Write(data)
			}
		}
	}
	s := sanitizeNetResponse(resp.String())
	hit, sig := nc.MatchNetResponse(s)
	return hit, sig, nil
}

func runDNS(nc *NetCheck, t netx.Target, cfg netx.Config) (bool, string, error) {
	if t.Port != 0 && t.Port != 53 {
		return false, "", fmt.Errorf("netrun: dns 目标端口异常 %d", t.Port)
	}
	name := renderNetName(nc.DNSName, t.Host)
	if name == "" {
		return false, "", fmt.Errorf("netrun: dns 模板 %s 缺查询名", nc.ID)
	}
	records, err := netx.DNSQuery(cfg, name, nc.DNSType)
	if err != nil {
		return false, "", err
	}
	s := sanitizeNetResponse(strings.Join(records, "\n"))
	hit, sig := nc.MatchNetResponse(s)
	return hit, sig, nil
}

func runSSL(nc *NetCheck, t netx.Target, cfg netx.Config, resolve bool) (bool, string, error) {
	if t.Port == 0 {
		t.Port = 443
	}
	conn, err := netx.Dial(t, cfg, resolve)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	summary, ok := conn.TLSSummary()
	if !ok {
		return false, "", fmt.Errorf("netrun: 非 TLS 连接")
	}
	hit, sig := nc.MatchNetResponse(summary)
	return hit, sig, nil
}

// renderNetName dns 模板查询名占位替换（{{FQDN}}/{{Hostname}} → 目标主机）。
func renderNetName(tpl, host string) string {
	name := strings.ReplaceAll(tpl, "{{FQDN}}", host)
	name = strings.ReplaceAll(name, "{{Hostname}}", host)
	name = strings.TrimSuffix(name, ".")
	if strings.Contains(name, "{{") {
		return "" // 其余占位符 v1 不支持
	}
	return name
}

// sanitizeNetResponse 响应串规整：截断超长（匹配面 64KB 足够），控制字节转义。
func sanitizeNetResponse(s string) string {
	if len(s) > 64*1024 {
		s = s[:64*1024]
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r != 127) {
			b.WriteRune(r)
			continue
		}
		b.WriteString(fmt.Sprintf("\\x%02x", r))
	}
	return b.String()
}
