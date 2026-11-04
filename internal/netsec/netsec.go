// Package netsec 网络层安全检测（TLS 证书深度/协议评级 + DNS 邮件安全
// SPF/DMARC/MX + HTTP 传输层安全 HSTS/跳转 + 端口/服务探测 + 批量入口）。
//
// Go 原生实现：crypto/tls 证书链捕获 + net.LookupTXT/MX 查询 + 一次只读
// HTTP GET（响应头分析）+ TCP connect 端口探测。扫描器需跳过证书校验以
// 检测自签名/过期/SAN 不匹配/弱签名等证书，通过 InsecureSkipVerify +
// 证书链采集完成——这是安全扫描器场景，不可用于生产 Web 客户端。
//
// NS-02 新增：证书资产线索（SAN/颁发者/到期，CheckCertAssets/CertExpiry）、
// cipher 套件强度分级与 ALPN h2、端口/服务探测（CheckPorts，只 TCP connect
// + 被动读 banner，不发 payload）、组合与批量入口（CheckHost/CheckHosts）。
//
// 限制：CAA（RFC 8659）查询需要 DNS 库支持，net 标准库没有 LookupCAA；
// 5.2.0/5.2.x 按《网络层与爆破护栏-5.2.0.md》允许的限制跳过，不引入新
// 依赖（引入 DNS 库后再补）。HTTP/3（QUIC/UDP）同理超出 net/http 能力，
// ALPN 只能观测 TLS/TCP 上协商到的 h2/http1.1。
package netsec

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// Finding 一条网络层安全发现。
type Finding struct {
	Check    string `json:"check"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
	// SANs 证书 SAN 线索（仅 tls-protocol/tls-hostname-mismatch 等证书类
	// finding 上带出，避免新增独立 finding 的噪音；资产清单请用
	// CheckCertAssets）。additive 字段，旧调用方忽略即可。
	SANs []string `json:"sans,omitempty"`
}

// tlsProbeTimeout TLS 探测连接/握手总超时。
const tlsProbeTimeout = 8 * time.Second

// tlsHandshake 建 TCP 连接并完成 TLS 握手，返回握手状态。
// 扫描器语义：跳过标准证书校验（InsecureSkipVerify + 采集回调），以便对
// 自签名/过期/域名不符证书做检测；失败返回 ok=false。
func tlsHandshake(host string, port int) (tls.ConnectionState, bool) {
	host = normalizeHost(host)
	if host == "" || port <= 0 || port > 65535 {
		return tls.ConnectionState{}, false
	}
	conf := &tls.Config{
		ServerName: host,
		// 扫描器场景：跳过标准校验但保留证书链（理由见包注释）。
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		// ALPN：观测服务端是否支持 HTTP/2（h2）。服务端不协商时为空。
		NextProtos: []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// 采集模式：始终返回 nil 以捕获证书链供后续分析
			return nil
		},
	}
	dialConn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), tlsProbeTimeout)
	if dialErr != nil {
		return tls.ConnectionState{}, false
	}
	conn := tls.Client(dialConn, conf)
	if herr := conn.Handshake(); herr != nil {
		dialConn.Close()
		return tls.ConnectionState{}, false
	}
	cs := conn.ConnectionState()
	_ = conn.Close()
	return cs, true
}

// CheckTLS TLS 证书与协议检测（捕获证书链供分析，不阻断连接）。
func CheckTLS(host string, port int) []Finding {
	host = normalizeHost(host)
	cs, ok := tlsHandshake(host, port)
	if !ok || len(cs.PeerCertificates) == 0 {
		return nil
	}
	var hits []Finding
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

	// NS-01 证书深度检测（hostname/SAN、链完整性、弱签名、弱密钥）
	certFindings := analyzeCert(host, cs.PeerCertificates)
	sans := certSANs(cert)
	for i := range certFindings {
		if certFindings[i].Check == "tls-hostname-mismatch" {
			certFindings[i].SANs = sans
		}
	}
	hits = append(hits, certFindings...)

	// NS-02 协议评级：cipher 套件强度 + ALPN/HTTP2 能力（info 级）
	hits = append(hits, analyzeProtocol(host, cs, sans)...)
	return hits
}

// CheckCertAssets 证书资产线索（供上层做资产发现/台账）：返回证书 SAN
// 域名列表（DNS+IP，去重保序）、颁发者（优先 CN，空则完整 DN）与到期时间。
// 不做任何 finding（避免噪音）；连接失败/无证书时返回零值。
func CheckCertAssets(host string, port int) (sans []string, issuer string, notAfter time.Time) {
	cs, ok := tlsHandshake(host, port)
	if !ok || len(cs.PeerCertificates) == 0 {
		return nil, "", time.Time{}
	}
	leaf := cs.PeerCertificates[0]
	issuer = leaf.Issuer.CommonName
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}
	return certSANs(leaf), issuer, leaf.NotAfter
}

// CertExpiry 证书到期提醒数据（供上层落盘提醒；本包不实现存储）。
// days 与 CheckTLS 同口径：剩余整天数（向下取整，可负）。
func CertExpiry(host string, port int) (notAfter time.Time, days int, ok bool) {
	cs, ok := tlsHandshake(host, port)
	if !ok || len(cs.PeerCertificates) == 0 {
		return time.Time{}, 0, false
	}
	notAfter = cs.PeerCertificates[0].NotAfter
	return notAfter, int(time.Until(notAfter).Hours() / 24), true
}

// certSANs 证书 SAN 列表（DNS + IP，去重保序；DNS 在前）。
func certSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, d := range cert.DNSNames {
		add(d)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	return out
}

// cipherGrade TLS 协商套件的强度分级（越高越差）。
type cipherGrade int

const (
	cipherStrong cipherGrade = iota // AEAD + 前向保密（或无前向保密但 AEAD），无 finding
	cipherNoFS                      // AEAD 但静态 RSA 密钥交换（无前向保密）
	cipherCBC                       // CBC 模式（无 AEAD）
	cipherWeak                      // RC4/3DES/NULL/EXPORT 等明确弱套件
)

// cipherGradeOf 按套件名分级（纯函数，便于单测覆盖现代栈不再协商的弱套件）。
// 未知套件（CipherSuiteName 返回 0x 十六进制）按 strong 处理，避免误报。
func cipherGradeOf(id uint16) (cipherGrade, string) {
	name := tls.CipherSuiteName(id)
	if strings.HasPrefix(name, "0x") {
		return cipherStrong, name
	}
	up := strings.ToUpper(name)
	switch {
	case strings.Contains(up, "RC4"), strings.Contains(up, "3DES"),
		strings.Contains(up, "NULL"), strings.Contains(up, "DES_CBC"),
		strings.Contains(up, "EXPORT"), strings.Contains(up, "ANON"):
		return cipherWeak, name
	case strings.Contains(up, "CBC"):
		return cipherCBC, name
	case strings.HasPrefix(up, "TLS_RSA_"):
		// 静态 RSA 密钥交换：无前向保密
		return cipherNoFS, name
	}
	return cipherStrong, name
}

// analyzeProtocol NS-02 协议评级：协商 cipher 套件强度分级 + ALPN/HTTP2
// 能力。返回（可能为空）的 tls-weak-cipher 与一条 tls-protocol info。
func analyzeProtocol(host string, cs tls.ConnectionState, sans []string) []Finding {
	verName := tlsVersionName(cs.Version)
	grade, cipherName := cipherGradeOf(cs.CipherSuite)
	if grade != cipherStrong {
		f := Finding{
			Check: "tls-weak-cipher", Severity: "low", URL: host,
			Evidence: fmt.Sprintf("%s %s", verName, cipherName),
		}
		switch grade {
		case cipherWeak:
			f.Title = "协商到弱加密套件（RC4/3DES/NULL）"
			f.Severity = "medium"
			f.Advice = "禁用 RC4/3DES/NULL 套件，仅保留 AEAD（GCM/CHACHA20-POLY1305）"
		case cipherCBC:
			f.Title = "协商到 CBC 模式套件（无 AEAD，易受填充攻击）"
			f.Advice = "优先启用 AEAD 套件（GCM/CHACHA20-POLY1305），禁用 CBC"
		case cipherNoFS:
			f.Title = "协商到静态 RSA 密钥交换套件（无前向保密）"
			f.Advice = "启用 ECDHE/DHE 前向保密套件，禁用静态 RSA 密钥交换"
		}
		return []Finding{f, protocolFinding(host, cs, sans)}
	}
	return []Finding{protocolFinding(host, cs, sans)}
}

// protocolFinding info 级协议能力（TLS 版本 / cipher / ALPN 是否 h2）。
func protocolFinding(host string, cs tls.ConnectionState, sans []string) Finding {
	alpn := cs.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}
	h2 := "no"
	if cs.NegotiatedProtocol == "h2" {
		h2 = "yes"
	}
	return Finding{
		Check: "tls-protocol", Title: "TLS 协议能力",
		Severity: "info", URL: host,
		Evidence: fmt.Sprintf("%s; cipher=%s; alpn=%s; http2=%s",
			tlsVersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite), alpn, h2),
		SANs: sans,
	}
}

// analyzeCert 证书深度分析（纯函数，不发起网络，便于单测用合成夹具）：
// hostname/SAN 不匹配、链完整性、SHA-1/MD5 签名、RSA <2048。
// 过期/自签名/旧协议仍由 CheckTLS 既有逻辑产出，这里不重复。
func analyzeCert(host string, chain []*x509.Certificate) []Finding {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	var hits []Finding

	// 1) hostname/SAN 不匹配（Go 1.15+ 只认 SAN，不认 CN）
	if err := leaf.VerifyHostname(host); err != nil {
		hits = append(hits, Finding{
			Check: "tls-hostname-mismatch", Title: "证书与域名不匹配（hostname/SAN）",
			Severity: "high", URL: host,
			Evidence: fmt.Sprintf("host=%s; SAN=[%s]", host, sanList(leaf)),
			Advice:   "重新签发包含该域名的证书（SAN 扩展）",
		})
	}

	// 2) 签名算法过弱（SHA-1/MD5）
	if alg, weak := weakSignature(leaf.SignatureAlgorithm); weak {
		hits = append(hits, Finding{
			Check: "tls-weak-signature", Title: "证书签名算法过弱（SHA-1/MD5）",
			Severity: "medium", URL: host,
			Evidence: "signatureAlgorithm=" + alg,
			Advice:   "改用 SHA-256 及以上签名算法重签证书",
		})
	}

	// 3) RSA 密钥 < 2048
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pub.N != nil && pub.N.BitLen() < 2048 {
		hits = append(hits, Finding{
			Check: "tls-weak-key", Title: "RSA 密钥长度不足（<2048）",
			Severity: "medium", URL: host,
			Evidence: fmt.Sprintf("RSA %d bits", pub.N.BitLen()),
			Advice:   "更换为 RSA ≥2048 或 ECDSA P-256 及以上密钥",
		})
	}

	// 4) 链完整性：逐级签发关系 + 用系统根构建完整链
	if bad, evidence := chainIncomplete(chain); bad {
		hits = append(hits, Finding{
			Check: "tls-chain", Title: "证书链不完整/无法验证",
			Severity: "medium", URL: host,
			Evidence: evidence,
			Advice:   "部署完整的中间证书链（服务器应下发 leaf + 全部中间证书）",
		})
	}
	return hits
}

// sanList 证书 SAN 列表摘要（DNS + IP）。
func sanList(cert *x509.Certificate) string {
	parts := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	parts = append(parts, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

// weakSignature 弱签名算法判定（SHA-1/MD5 系）。
func weakSignature(alg x509.SignatureAlgorithm) (string, bool) {
	switch alg {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return alg.String(), true
	}
	return alg.String(), false
}

var (
	systemRootsOnce sync.Once
	systemRootsPool *x509.CertPool
)

// systemRoots 系统信任根（一次性加载；不可用时返回 nil，调用方跳过
// 「无法构建可信链」判定以免误报）。
func systemRoots() *x509.CertPool {
	systemRootsOnce.Do(func() {
		systemRootsPool, _ = x509.SystemCertPool()
	})
	return systemRootsPool
}

// chainIncomplete 判定证书链不完整/无法验证：
//   - 链内相邻证书 Issuer/Subject 与签名关系不符（链被拼错）；
//   - 叶子无法经链内中间证书构建到系统信任根（缺中间证书/自签名根不受信）。
//
// 过期/用途不符等其他 Verify 错误不在此报（既有过期检查覆盖）。
func chainIncomplete(chain []*x509.Certificate) (bool, string) {
	if len(chain) == 0 {
		return false, ""
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return true, fmt.Sprintf("证书链第 %d 级签发关系无法验证: %v", i+1, err)
		}
	}
	roots := systemRoots()
	if roots == nil {
		return false, ""
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, verr := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	if verr == nil {
		return false, ""
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(verr, &unknown) {
		return true, "未能构建到系统信任根（缺少中间证书或根不受信）"
	}
	return false, ""
}

// normalizeHost 去掉可能的 scheme/端口/括号，只留主机名。
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
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
	// NS-01：按查询域分组收集 SPF 记录原文（多记录/查找数/语法检查必须
	// 逐域判定——主域与子域各自有 SPF 是合法配置，不能合并成"重复记录"）。
	spfByDomain := map[string][]string{}
	var spfDomains []string
	for _, spot := range spfSpots {
		for _, r := range lookupTXT(spot) {
			low := strings.ToLower(r)
			seenSPF := map[string]bool{}
			if strings.HasPrefix(low, "v=spf1") && !seenSPF[low] {
				seenSPF[low] = true
				hasSPF = true
				if _, ok := spfByDomain[spot]; !ok {
					spfDomains = append(spfDomains, spot)
				}
				spfByDomain[spot] = append(spfByDomain[spot], strings.TrimSpace(r))
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
	} else {
		// NS-01：SPF 语法/查找数深度检查（逐域）
		for _, spot := range spfDomains {
			hits = append(hits, analyzeSPF(spot, spfByDomain[spot])...)
		}
	}

	dmarcDomain := "_dmarc." + org
	hasDMARC := false
	var dmarcRecord string // NS-01：DMARC 记录原文（供策略/rua 解析）
	for _, r := range lookupTXT(dmarcDomain) {
		if strings.HasPrefix(strings.ToLower(r), "v=dmarc1") {
			hasDMARC = true
			dmarcRecord = r
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
	} else {
		// NS-01：DMARC 策略强度与 rua 报告地址
		hits = append(hits, analyzeDMARC(dmarcDomain, dmarcRecord)...)
	}

	// CAA（RFC 8659）：net 标准库没有 LookupCAA，5.2.0 按文档允许的限制跳过。

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

// analyzeSPF SPF 记录深度检查（纯函数）：多份 v=spf1、DNS 查询机制 >10、
// 明显语法异常。对照 RFC 7208：include/a/mx/ptr/exists/redirect 每次触发
// DNS 查询，查找次数上限 10。
func analyzeSPF(domain string, records []string) []Finding {
	if len(records) == 0 {
		return nil
	}
	var hits []Finding
	if len(records) > 1 {
		ev := make([]string, 0, len(records))
		for _, r := range records {
			ev = append(ev, r[:minInt(80, len(r))])
		}
		hits = append(hits, Finding{
			Check: "dns-spf-syntax", Title: "SPF 记录重复（多份 v=spf1，接收方行为未定义）",
			Severity: "low", URL: domain,
			Evidence: strings.Join(ev, " | "),
			Advice:   "只保留一份 SPF 记录（多份会导致 permerror）",
		})
	}
	if n := spfLookupCount(records[0]); n > 10 {
		hits = append(hits, Finding{
			Check: "dns-spf-lookups", Title: "SPF DNS 查询次数超过上限（>10）",
			Severity: "low", URL: domain,
			Evidence: fmt.Sprintf("DNS 查询机制 %d 个（RFC 7208 上限 10）", n),
			Advice:   "精简 include/redirect 链路或改为专用发件子域",
		})
	}
	if issues := spfSyntaxIssues(records[0]); len(issues) > 0 {
		hits = append(hits, Finding{
			Check: "dns-spf-syntax", Title: "SPF 记录语法异常",
			Severity: "low", URL: domain,
			Evidence: strings.Join(issues, "; "),
			Advice:   "检查机制拼写（include:/a/mx/ptr/ip4:/ip6:/exists:/redirect=/all）",
		})
	}
	return hits
}

// spfQualifierStrip 去掉机制前缀限定符（+ - ~ ?）。
func spfQualifierStrip(tok string) string {
	if len(tok) > 0 && strings.ContainsRune("+-~?", rune(tok[0])) {
		return tok[1:]
	}
	return tok
}

// spfLookupCount 统计触发 DNS 查询的机制个数。
func spfLookupCount(record string) int {
	n := 0
	for _, tok := range strings.Fields(record) {
		low := strings.ToLower(spfQualifierStrip(tok))
		switch {
		case strings.HasPrefix(low, "include:"),
			strings.HasPrefix(low, "exists:"),
			strings.HasPrefix(low, "redirect="):
			n++
		case low == "a", strings.HasPrefix(low, "a:"), strings.HasPrefix(low, "a/"):
			n++
		case low == "mx", strings.HasPrefix(low, "mx:"), strings.HasPrefix(low, "mx/"):
			n++
		case low == "ptr", strings.HasPrefix(low, "ptr:"), strings.HasPrefix(low, "ptr/"):
			n++
		}
	}
	return n
}

// spfSyntaxIssues 轻量语法检查：只报明确异常的机制，避免误报。
func spfSyntaxIssues(record string) []string {
	var issues []string
	for _, tok := range strings.Fields(record) {
		if strings.EqualFold(tok, "v=spf1") {
			continue
		}
		base := spfQualifierStrip(tok)
		if base == "" {
			issues = append(issues, "空机制")
			continue
		}
		low := strings.ToLower(base)
		// 明确合法的机制/修饰符
		if low == "all" {
			continue
		}
		if strings.HasPrefix(low, "ip4:") || strings.HasPrefix(low, "ip6:") ||
			strings.HasPrefix(low, "include:") || strings.HasPrefix(low, "exists:") ||
			strings.HasPrefix(low, "redirect=") || strings.HasPrefix(low, "exp=") {
			if strings.HasSuffix(low, ":") || strings.HasSuffix(low, "=") {
				issues = append(issues, "机制缺少参数: "+tok)
			}
			continue
		}
		if low == "a" || strings.HasPrefix(low, "a:") || strings.HasPrefix(low, "a/") ||
			low == "mx" || strings.HasPrefix(low, "mx:") || strings.HasPrefix(low, "mx/") ||
			low == "ptr" || strings.HasPrefix(low, "ptr:") || strings.HasPrefix(low, "ptr/") {
			continue
		}
		issues = append(issues, "未知机制: "+tok)
	}
	return issues
}

// parseDMARCTags 解析 DMARC 记录的 tag=value 列表（键小写，值去空白/引号）。
func parseDMARCTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		tags[key] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return tags
}

// analyzeDMARC DMARC 深度检查（纯函数）：策略强度 p=none/quarantine/reject
// 与聚合报告地址 rua 是否配置。
func analyzeDMARC(domain, record string) []Finding {
	tags := parseDMARCTags(record)
	var hits []Finding
	policy := strings.ToLower(tags["p"])
	switch policy {
	case "none":
		hits = append(hits, Finding{
			Check: "dns-dmarc-policy", Title: "DMARC 策略为 none（仅监控，不拦截伪造邮件）",
			Severity: "medium", URL: domain,
			Evidence: "p=none",
			Advice:   "观察聚合报告后把 p= 调整为 quarantine 或 reject",
		})
	case "quarantine":
		hits = append(hits, Finding{
			Check: "dns-dmarc-policy", Title: "DMARC 策略为 quarantine（可疑邮件隔离）",
			Severity: "info", URL: domain,
			Evidence: "p=quarantine",
			Advice:   "观察报告后升级为 p=reject",
		})
	case "reject":
		hits = append(hits, Finding{
			Check: "dns-dmarc-policy", Title: "DMARC 策略为 reject（强防护）",
			Severity: "info", URL: domain,
			Evidence: "p=reject", Advice: "",
		})
	case "":
		hits = append(hits, Finding{
			Check: "dns-dmarc-policy", Title: "DMARC 记录缺少策略（p=）",
			Severity: "medium", URL: domain,
			Evidence: record[:minInt(120, len(record))],
			Advice:   "补充 p=none|quarantine|reject 策略",
		})
	default:
		hits = append(hits, Finding{
			Check: "dns-dmarc-policy", Title: "DMARC 策略值异常",
			Severity: "low", URL: domain,
			Evidence: "p=" + policy,
			Advice:   "p= 只接受 none/quarantine/reject",
		})
	}
	if strings.TrimSpace(tags["rua"]) == "" {
		hits = append(hits, Finding{
			Check: "dns-dmarc-rua", Title: "DMARC 未配置聚合报告地址（rua=）",
			Severity: "low", URL: domain,
			Evidence: "缺少 rua=",
			Advice:   "添加 rua=mailto:dmarc@<主域> 接收伪造/失败报告",
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

// checkHTTPMaxHops HSTS/跳转探测的最大跟随跳数（旧实现交给 net/http 自动
// 跟随、上限 10 跳；这里收紧到 5 跳，正常 HTTPS 升级只需 1~2 跳）。
const checkHTTPMaxHops = 5

// CheckHTTP HSTS / HTTP→HTTPS 跳转检查。
//
// V-07 安全约束（此前是裸 http.Client 自动跟随：被扫站点一个 302 就能把请求
// 打到内网/云元数据端点，绕过 target.Validate）：
//   - 禁止自动重定向，逐跳手动发起；
//   - 每一跳先过 target.Validate（协议白名单 / 主机黑名单 / metadata 字面 IP /
//     gov.cn / 端口），不合规立即停止，绝不发出该跳请求；
//   - 只跟随**同主机**跳转（允许 http→https、端口变化）。跨主机 302 是常见
//     SSRF 跳板，而 HSTS/升级检查本身不需要跨站跟随。
func CheckHTTP(rawURL string) []Finding {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil
	}
	originHost := strings.ToLower(u.Hostname())
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 扫描器：需观测自签/配置错误站点
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		// 禁自动跟随：每一跳由本函数校验后再手动发起。
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	curURL := u.String()
	var resp *http.Response
	for hop := 0; hop < checkHTTPMaxHops; hop++ {
		// 逐跳静态 SSRF 校验；跨主机跳转不跟随。
		_, host, _, verr := target.Validate(curURL, false)
		if verr != nil || !strings.EqualFold(host, originHost) {
			break
		}
		req, rerr := http.NewRequest(http.MethodGet, curURL, nil)
		if rerr != nil {
			break
		}
		next, derr := client.Do(req)
		if derr != nil {
			// 旧行为：连接失败 → 无发现；中间跳响应体先排空关闭再返回。
			if resp != nil {
				drainAndCloseHTTP(resp)
			}
			return nil
		}
		if resp != nil {
			drainAndCloseHTTP(resp)
		}
		resp = next
		if !isHTTPRedirect(next.StatusCode) {
			break
		}
		loc := strings.TrimSpace(next.Header.Get("Location"))
		if loc == "" {
			break
		}
		resolved, perr := resolveHTTPRedirect(curURL, loc)
		if perr != nil {
			break
		}
		curURL = resolved
	}
	if resp == nil {
		return nil
	}
	defer client.CloseIdleConnections() // 单次请求后释放连接，避免每次扫描残留空闲 socket
	defer resp.Body.Close()
	// 丢弃响应体（上限 4KB，避免下载大页面）；只分析响应头/最终 URL。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	// 手动跟随后的最终 URL 即 curURL（禁用了自动重定向，resp.Request.URL
	// 只代表最后一跳请求，二者一致；直接用 curURL 更明确）。
	finalScheme := ""
	finalURL := curURL
	if fu, ferr := url.Parse(curURL); ferr == nil {
		finalScheme = strings.ToLower(fu.Scheme)
		finalURL = fu.String()
	}
	var hits []Finding

	// HTTP→HTTPS 未跳转
	if scheme == "http" && finalScheme == "http" {
		hits = append(hits, Finding{
			Check: "http-https-redirect", Title: "HTTP 未跳转到 HTTPS",
			Severity: "medium", URL: rawURL,
			Evidence: "最终 URL: " + finalURL,
			Advice:   "配置 301 全站跳转到 HTTPS，并配合 HSTS",
		})
	}

	// HSTS：只在最终响应为 HTTPS 时校验（HTTP 响应上的 HSTS 头无效）
	if finalScheme == "https" {
		hits = append(hits, checkHSTS(finalURL, resp.Header.Get("Strict-Transport-Security"))...)
	}
	return hits
}

// isHTTPRedirect 3xx 跳转状态码（与 net/http 语义一致）。
func isHTTPRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// resolveHTTPRedirect 相对 Location 解析为绝对 URL。
func resolveHTTPRedirect(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

// drainAndCloseHTTP 排空并关闭中间跳响应体（让 keep-alive 连接可复用；
// 只 Close 不读会让 transport 丢弃连接）。
func drainAndCloseHTTP(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}

// hstsMinMaxAge HSTS 建议最小 max-age（6 个月；OWASP 建议 1 年）。
const hstsMinMaxAge int64 = 15552000

// checkHSTS 校验 Strict-Transport-Security 响应头：缺失 / 无 max-age /
// max-age 过短。
func checkHSTS(u, header string) []Finding {
	header = strings.TrimSpace(header)
	if header == "" {
		return []Finding{{
			Check: "http-hsts", Title: "缺少 HSTS 响应头（易受降级/SSL 剥离攻击）",
			Severity: "low", URL: u,
			Evidence: "Strict-Transport-Security 未设置",
			Advice:   "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains",
		}}
	}
	maxAge, ok := hstsMaxAge(header)
	if !ok {
		return []Finding{{
			Check: "http-hsts", Title: "HSTS 响应头缺少 max-age",
			Severity: "low", URL: u,
			Evidence: "Strict-Transport-Security: " + header[:minInt(160, len(header))],
			Advice:   "设置 max-age=31536000（≥6 个月）",
		}}
	}
	if maxAge < hstsMinMaxAge {
		return []Finding{{
			Check: "http-hsts", Title: "HSTS max-age 过短",
			Severity: "low", URL: u,
			Evidence: fmt.Sprintf("max-age=%d（建议 ≥%d 秒）", maxAge, hstsMinMaxAge),
			Advice:   "把 max-age 提升到 31536000（1 年）",
		}}
	}
	return nil
}

// hstsMaxAge 解析 HSTS 头的 max-age 指令（秒）。
func hstsMaxAge(header string) (int64, bool) {
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "max-age") {
			continue
		}
		n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(v), `"`), 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
