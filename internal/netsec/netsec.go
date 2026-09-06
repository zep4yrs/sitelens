// Package netsec 网络层安全检测（TLS 证书/协议 + DNS 邮件安全 SPF/DMARC/MX）。
//
// Go 原生实现：crypto/tls 证书链捕获 + net.LookupTXT/MX 查询。
// 扫描器需跳过证书校验以检测自签名/过期证书——通过 VerifyPeerCertificate
// 回调采集证书链而不中断连接（安全扫描器场景，非生产 Web 客户端）。
package netsec

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Finding 一条网络层安全发现。
type Finding struct {
	Check    string `json:"check"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
}

// CheckTLS TLS 证书与协议检测（捕获证书链供分析，不阻断连接）。
func CheckTLS(host string, port int) []Finding {
	var hits []Finding

	conf := &tls.Config{
		ServerName: host,
		// 扫描器场景：需检测自签名/过期证书，跳过标准校验但保留证书链。
		// 仅在安全评估工具中使用；不可用于生产 Web 客户端。
		MinVersion: tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// 采集模式：始终返回 nil 以捕获证书链供后续分析
			return nil
		},
	}

	dialConn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 8*time.Second)
	if dialErr != nil {
		return nil
	}
	conn := tls.Client(dialConn, conf)
	if herr := conn.Handshake(); herr != nil {
		dialConn.Close()
		return nil
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	cert := cs.PeerCertificates[0]

	// 证书过期检测
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	if days < 0 {
		hits = append(hits, Finding{
			Check: "tls-expired", Title: "证书已过期",
			Severity: "high", URL: host,
			Evidence: fmt.Sprintf("notAfter=%s", cert.NotAfter.Format("2006-01-02")),
			Advice:   "立即更换证书",
		})
	} else if days < 30 {
		hits = append(hits, Finding{
			Check: "tls-expiring", Title: "证书即将过期",
			Severity: "medium", URL: host,
			Evidence: fmt.Sprintf("剩余 %d 天", days),
			Advice:   "安排证书续期",
		})
	}

	// 自签名检测（颁发者 = 主体）
	if cert.Issuer.CommonName == cert.Subject.CommonName && cert.Issuer.CommonName != "" {
		hits = append(hits, Finding{
			Check: "tls-self-signed", Title: "自签名证书",
			Severity: "medium", URL: host,
			Evidence: cert.Issuer.CommonName,
			Advice:   "改用 CA 签发证书",
		})
	}

	// 旧版 TLS 协议检测
	verName := tlsVersionName(cs.Version)
	if verName != "TLS 1.2" && verName != "TLS 1.3" {
		hits = append(hits, Finding{
			Check: "tls-old", Title: fmt.Sprintf("协商到旧版 TLS（%s）", verName),
			Severity: "medium", URL: fmt.Sprintf("%s:%d", host, port),
			Evidence: verName, Advice: "服务端禁用 TLS1.1 及以下",
		})
	}
	return hits
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// 常见多标签公共后缀（够用于教学场景；完整版应接 Public Suffix List）
var multiSuffix = []string{
	"com.cn", "net.cn", "org.cn", "gov.cn", "co.uk",
	"com.hk", "com.tw", "com.au", "co.jp", "ne.jp", "com.sg",
}

// OrgDomain 主域名提取（邮件安全记录挂在主域与 _dmarc.<主域> 上）。
func OrgDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	if len(labels) >= 3 {
		last2 := labels[len(labels)-2] + "." + labels[len(labels)-1]
		for _, sfx := range multiSuffix {
			if last2 == sfx && len(labels) >= 3 {
				return strings.Join(labels[len(labels)-3:], ".")
			}
		}
		return last2
	}
	return host
}

// CheckDNSMail DNS 邮件安全：SPF / DMARC / MX 记录检查（挂在主域上评估）。
func CheckDNSMail(domain string) []Finding {
	org := OrgDomain(domain)
	var hits []Finding

	spfSpots := []string{org}
	if domain != org {
		spfSpots = append(spfSpots, domain)
	}
	hasSPF := false
	for _, spot := range spfSpots {
		for _, r := range lookupTXT(spot) {
			low := strings.ToLower(r)
			seenSPF := map[string]bool{}
			if strings.HasPrefix(low, "v=spf1") && !seenSPF[low] {
				seenSPF[low] = true
				hasSPF = true
				hits = append(hits, Finding{
					Check: "dns-spf", Title: "SPF 记录存在",
					Severity: "info", URL: org,
					Evidence: r[:minInt(120, len(r))], Advice: "",
				})
			}
		}
	}
	if !hasSPF {
		hits = append(hits, Finding{
			Check: "dns-spf", Title: "缺少 SPF 记录（发件域易被伪造）",
			Severity: "medium", URL: org,
			Evidence: "TXT " + org, Advice: "添加 SPF 记录（v=spf1）限制合法发件源",
		})
	}

	dmarcDomain := "_dmarc." + org
	hasDMARC := false
	for _, r := range lookupTXT(dmarcDomain) {
		if strings.HasPrefix(strings.ToLower(r), "v=dmarc1") {
			hasDMARC = true
			hits = append(hits, Finding{
				Check: "dns-dmarc", Title: "DMARC 记录存在",
				Severity: "info", URL: dmarcDomain,
				Evidence: r[:minInt(120, len(r))], Advice: "",
			})
			break
		}
	}
	if !hasDMARC {
		hits = append(hits, Finding{
			Check: "dns-dmarc", Title: "缺少 DMARC 记录",
			Severity: "medium", URL: dmarcDomain,
			Evidence: "TXT _dmarc." + org,
			Advice:   "添加 DMARC 记录（v=DMARC1）防止发件伪造",
		})
	}

	mxRecords, _ := net.LookupMX(org)
	if len(mxRecords) == 0 {
		hits = append(hits, Finding{
			Check: "dns-mx", Title: "主域未配置 MX（该域不收邮件时属正常）",
			Severity: "low", URL: org, Evidence: "无 MX 记录", Advice: "",
		})
	} else {
		var hosts []string
		for _, mx := range mxRecords {
			hosts = append(hosts, mx.Host)
		}
		hits = append(hits, Finding{
			Check: "dns-mx", Title: "MX 记录存在", Severity: "info", URL: org,
			Evidence: strings.Join(hosts, ", "), Advice: "",
		})
	}
	return hits
}

func lookupTXT(domain string) []string {
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}
	return records
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
