package netsec

// NS-01 网络层 P0 单测：证书深度（SAN/弱签名/弱密钥/链）、DMARC/SPF 解析、
// HSTS/HTTP→HTTPS。
//
// 证书类用两类夹具：
//   - 合成 x509.Certificate（纯函数 analyzeCert，确定性覆盖 SHA-1/RSA-1024 等
//     现代 CA 已不会签发的形态）；
//   - httptest 自签 TLS 服务器（验证真实握手 + 证书链采集路径）。

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- 夹具 ----

type synthOpt struct {
	subject    string
	issuer     string
	dnsNames   []string
	ipAddrs    []net.IP
	sigAlg     x509.SignatureAlgorithm
	publicKey  any
	ca         bool
	rawSubject []byte
	rawIssuer  []byte
}

func synthCert(o synthOpt) *x509.Certificate {
	c := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: o.subject},
		Issuer:                pkix.Name{CommonName: o.issuer},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              o.dnsNames,
		IPAddresses:           o.ipAddrs,
		SignatureAlgorithm:    o.sigAlg,
		PublicKey:             o.publicKey,
		BasicConstraintsValid: o.ca,
		IsCA:                  o.ca,
		RawSubject:            o.rawSubject,
		RawIssuer:             o.rawIssuer,
	}
	if o.ca {
		c.KeyUsage = x509.KeyUsageCertSign
	} else {
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return c
}

func rsaPubBits(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return &rsa.PublicKey{N: n, E: 65537}
}

// rsaKeyBits 生成真实 RSA 私钥（TLS 夹具用；1024 位仅用于测试弱密钥检测）。
func rsaKeyBits(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("生成 RSA-%d 私钥失败: %v", bits, err)
	}
	return key
}

func findByCheck(hits []Finding, check string) []Finding {
	var out []Finding
	for _, f := range hits {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func mustFind(t *testing.T, hits []Finding, check, wantSeverity string) Finding {
	t.Helper()
	got := findByCheck(hits, check)
	if len(got) == 0 {
		t.Fatalf("缺少 %s 发现: %+v", check, hits)
	}
	if got[0].Severity != wantSeverity {
		t.Fatalf("%s severity=%q, want %q（%+v）", check, got[0].Severity, wantSeverity, got[0])
	}
	if got[0].Title == "" {
		t.Fatalf("%s 缺少 title", check)
	}
	return got[0]
}

func mustNotFind(t *testing.T, hits []Finding, check string) {
	t.Helper()
	if got := findByCheck(hits, check); len(got) > 0 {
		t.Fatalf("不应出现 %s 发现: %+v", check, got)
	}
}

// ---- CheckTLS / analyzeCert ----

// TestAnalyzeCertHostnameMismatch 证书 SAN 与访问域名不匹配 → high。
func TestAnalyzeCertHostnameMismatch(t *testing.T) {
	cert := synthCert(synthOpt{
		subject:   "example.com",
		issuer:    "Test CA",
		dnsNames:  []string{"example.com", "www.example.com"},
		sigAlg:    x509.SHA256WithRSA,
		publicKey: rsaPubBits(2048),
	})
	hits := analyzeCert("evil.example", []*x509.Certificate{cert})
	f := mustFind(t, hits, "tls-hostname-mismatch", "high")
	if !strings.Contains(f.Evidence, "example.com") {
		t.Fatalf("evidence 应列出证书 SAN: %q", f.Evidence)
	}

	// 匹配时不报（含 SAN 子域精确匹配）
	if hits := analyzeCert("www.example.com", []*x509.Certificate{cert}); len(findByCheck(hits, "tls-hostname-mismatch")) > 0 {
		t.Fatalf("SAN 匹配却报了 hostname mismatch: %+v", hits)
	}
}

// TestAnalyzeCertWeakSignature SHA-1/MD5 签名 → medium；SHA-256 不报。
func TestAnalyzeCertWeakSignature(t *testing.T) {
	base := func(alg x509.SignatureAlgorithm) *x509.Certificate {
		return synthCert(synthOpt{
			subject: "weak-sig.example", issuer: "Test CA",
			dnsNames: []string{"weak-sig.example"}, sigAlg: alg, publicKey: rsaPubBits(2048),
		})
	}
	for _, tc := range []struct {
		alg     x509.SignatureAlgorithm
		wantSub string // x509 的 String() 形态：SHA1-RSA / MD5-RSA / ECDSA-SHA1
	}{
		{x509.SHA1WithRSA, "SHA1"},
		{x509.MD5WithRSA, "MD5"},
		{x509.ECDSAWithSHA1, "ECDSA"},
	} {
		hits := analyzeCert("weak-sig.example", []*x509.Certificate{base(tc.alg)})
		f := mustFind(t, hits, "tls-weak-signature", "medium")
		if !strings.Contains(f.Evidence, tc.wantSub) {
			t.Fatalf("%v evidence=%q, want 含 %q", tc.alg, f.Evidence, tc.wantSub)
		}
	}
	if hits := analyzeCert("weak-sig.example", []*x509.Certificate{base(x509.SHA256WithRSA)}); len(findByCheck(hits, "tls-weak-signature")) > 0 {
		t.Fatalf("SHA-256 不应报弱签名: %+v", hits)
	}
}

// TestAnalyzeCertWeakRSAKey RSA-1024 → medium；RSA-2048 不报；ECDSA 不报。
func TestAnalyzeCertWeakRSAKey(t *testing.T) {
	cert := synthCert(synthOpt{
		subject: "rsa1024.example", issuer: "Test CA",
		dnsNames: []string{"rsa1024.example"}, sigAlg: x509.SHA256WithRSA,
		publicKey: rsaPubBits(1024),
	})
	f := mustFind(t, analyzeCert("rsa1024.example", []*x509.Certificate{cert}), "tls-weak-key", "medium")
	if !strings.Contains(f.Evidence, "1024") {
		t.Fatalf("evidence 应含密钥位数: %q", f.Evidence)
	}
	strong := synthCert(synthOpt{
		subject: "rsa2048.example", issuer: "Test CA",
		dnsNames: []string{"rsa2048.example"}, sigAlg: x509.SHA256WithRSA,
		publicKey: rsaPubBits(2048),
	})
	if hits := analyzeCert("rsa2048.example", []*x509.Certificate{strong}); len(findByCheck(hits, "tls-weak-key")) > 0 {
		t.Fatalf("RSA-2048 不应报弱密钥: %+v", hits)
	}
}

// TestAnalyzeCertChainBrokenLink 链内签发关系不符 → tls-chain medium。
func TestAnalyzeCertChainBrokenLink(t *testing.T) {
	leaf := synthCert(synthOpt{
		subject: "leaf.example", issuer: "Intermediate CA",
		dnsNames: []string{"leaf.example"}, sigAlg: x509.SHA256WithRSA,
		publicKey:  rsaPubBits(2048),
		rawSubject: []byte("leaf"),
		rawIssuer:  []byte("intermediate"),
	})
	leaf.Signature = []byte{1, 2, 3} // 故意不是合法签名
	inter := synthCert(synthOpt{
		subject: "Intermediate CA", issuer: "Root CA", ca: true,
		sigAlg: x509.SHA256WithRSA, publicKey: rsaPubBits(2048),
		rawSubject: []byte("intermediate"), rawIssuer: []byte("root"),
	})
	hits := analyzeCert("leaf.example", []*x509.Certificate{leaf, inter})
	f := mustFind(t, hits, "tls-chain", "medium")
	if !strings.Contains(f.Evidence, "第 1 级") {
		t.Fatalf("evidence 应指出断链层级: %q", f.Evidence)
	}
}

// ---- 真实 TLS 握手夹具（自签证书，覆盖采集路径 + 既有发现语义）----

// tlsFixtureOpt 夹具 TLS 配置（NS-02：ALPN/cipher 评级测试需要定制）。
type tlsFixtureOpt struct {
	NextProtos   []string
	CipherSuites []uint16
}

// newTLSCertFixture 启一个使用指定自签证书的本地 TLS 服务器，返回
// 主机名/端口；CheckTLS 走真实 TCP + TLS 握手 + PeerCertificates 采集。
func newTLSCertFixture(t *testing.T, tpl *x509.Certificate, key any) (string, int) {
	t.Helper()
	return newTLSFixture(t, tpl, key, tlsFixtureOpt{})
}

// newTLSFixture 带 TLS 配置选项的夹具（ALPN/cipher 组合）。
func newTLSFixture(t *testing.T, tpl *x509.Certificate, key any, opt tlsFixtureOpt) (string, int) {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("私钥需实现 crypto.Signer: %T", key)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("生成自签证书失败: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12, // 弱密钥/弱签名/弱套件夹具固定在 TLS1.2，避免 TLS1.3 套件限制
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  signer,
		}},
		NextProtos:   opt.NextProtos,
		CipherSuites: opt.CipherSuites,
	})
	srv := &http.Server{
		Handler:  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("非 TCP 监听: %T", ln.Addr())
	}
	return "127.0.0.1", addr.Port
}

// selfSignedTpl 自签模板（Issuer=Subject，供既有 tls-self-signed 语义校验）。
func selfSignedTpl(cn string, dnsNames []string, ips []net.IP, alg x509.SignatureAlgorithm) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       big.NewInt(42),
		Subject:            pkix.Name{CommonName: cn},
		Issuer:             pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		SignatureAlgorithm: alg,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// TestCheckTLSCapturesSelfSigned 自签证书：CheckTLS 必须能拿到证书并产出
// 既有 tls-self-signed 发现（此前默认校验会让握手失败、所有证书发现空转）。
func TestCheckTLSCapturesSelfSigned(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-self", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	hits := CheckTLS(host, port)
	if len(hits) == 0 {
		t.Fatal("自签证书站点应至少产出 1 条发现（此前因标准校验失败而 0 条）")
	}
	mustFind(t, hits, "tls-self-signed", "medium")
	// 证书 IP SAN 含 127.0.0.1，不应报 hostname mismatch
	mustNotFind(t, hits, "tls-hostname-mismatch")
}

// TestCheckTLSSANMismatchOverWire SAN 只有 example.com，访问 127.0.0.1 →
// hostname/SAN 不匹配（high）。
func TestCheckTLSSANMismatchOverWire(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-mismatch", []string{"example.com"}, nil, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	hits := CheckTLS(host, port)
	f := mustFind(t, hits, "tls-hostname-mismatch", "high")
	if !strings.Contains(f.Evidence, "example.com") {
		t.Fatalf("evidence 应列出 SAN: %q", f.Evidence)
	}
}

// TestCheckTLSSHA1OverWire 真实 TLS 握手中的 SHA-1 签名证书 → medium。
func TestCheckTLSSHA1OverWire(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-sha1", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA1WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	f := mustFind(t, CheckTLS(host, port), "tls-weak-signature", "medium")
	if !strings.Contains(f.Evidence, "SHA1") {
		t.Fatalf("evidence 应含 SHA1: %q", f.Evidence)
	}
}

// TestCheckTLSRSA1024OverWire 真实 TLS 握手中的 RSA-1024 证书 → medium。
func TestCheckTLSRSA1024OverWire(t *testing.T) {
	key := rsaKeyBits(t, 1024)
	tpl := selfSignedTpl("acme-rsa1024", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	f := mustFind(t, CheckTLS(host, port), "tls-weak-key", "medium")
	if !strings.Contains(f.Evidence, "1024") {
		t.Fatalf("evidence 应含密钥位数: %q", f.Evidence)
	}
}

// ---- NS-02 协议评级 / 证书资产 / 到期数据 ----

// TestCipherGradeOf 套件强度分级（含现代栈默认已不协商的 RC4/3DES）。
func TestCipherGradeOf(t *testing.T) {
	cases := []struct {
		id   uint16
		want cipherGrade
	}{
		{tls.TLS_RSA_WITH_RC4_128_SHA, cipherWeak},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, cipherWeak},
		{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, cipherWeak},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, cipherCBC},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, cipherCBC},
		{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, cipherNoFS},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, cipherStrong},
		{tls.TLS_AES_128_GCM_SHA256, cipherStrong},
		{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, cipherStrong},
	}
	for _, tc := range cases {
		got, name := cipherGradeOf(tc.id)
		if got != tc.want {
			t.Fatalf("cipherGradeOf(%s)=%v, want %v", name, got, tc.want)
		}
		if name == "" || strings.HasPrefix(name, "0x") {
			t.Fatalf("已知套件缺少可读名: id=%d name=%q", tc.id, name)
		}
	}
}

// TestCheckTLSWeakCipherOverWire 服务端仅支持 CBC 套件（ECDHE+AES-CBC-SHA1）
// → 协商结果被评级为弱（low）；同时必有 tls-protocol info。
func TestCheckTLSWeakCipherOverWire(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-cbc", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSFixture(t, tpl, key, tlsFixtureOpt{
		// 用客户端默认集里仍存在的 CBC_SHA1 套件（RSA 密钥交换套件的
		// 握手在 Go1.22+ 默认被禁用，夹具改用 ECDHE_RSA+CBC）。
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	})
	hits := CheckTLS(host, port)
	f := mustFind(t, hits, "tls-weak-cipher", "low")
	if !strings.Contains(f.Evidence, "CBC") {
		t.Fatalf("evidence 应含套件名: %q", f.Evidence)
	}
	mustFind(t, hits, "tls-protocol", "info")
}

// TestCheckTLSProtocolAndALPN ALPN 协商到 h2 时 info finding 带 http2=yes，
// 且证书 SAN 通过 additive 字段带出（资产线索）。
func TestCheckTLSProtocolAndALPN(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-alpn", []string{"h2.example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSFixture(t, tpl, key, tlsFixtureOpt{
		NextProtos: []string{"h2", "http/1.1"},
	})
	hits := CheckTLS(host, port)
	f := mustFind(t, hits, "tls-protocol", "info")
	if !strings.Contains(f.Evidence, "alpn=h2") || !strings.Contains(f.Evidence, "http2=yes") {
		t.Fatalf("protocol evidence 应含 ALPN/HTTP2: %q", f.Evidence)
	}
	if len(f.SANs) == 0 || f.SANs[0] != "h2.example.com" {
		t.Fatalf("tls-protocol.SANs 应带出证书 SAN: %+v", f.SANs)
	}

	// 服务端不支持 ALPN → alpn=none / http2=no
	host2, port2 := newTLSCertFixture(t, tpl, key)
	f2 := mustFind(t, CheckTLS(host2, port2), "tls-protocol", "info")
	if !strings.Contains(f2.Evidence, "http2=no") {
		t.Fatalf("无 ALPN 服务端应报 http2=no: %q", f2.Evidence)
	}
}

// TestCheckCertAssets 证书资产线索：SAN 列表 / 颁发者 / 到期时间。
func TestCheckCertAssets(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-assets",
		[]string{"a.example.com", "b.example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	sans, issuer, notAfter := CheckCertAssets(host, port)
	wantDNS := map[string]bool{"a.example.com": true, "b.example.com": true}
	got := map[string]bool{}
	for _, s := range sans {
		got[s] = true
	}
	for d := range wantDNS {
		if !got[d] {
			t.Fatalf("SAN 缺少 %q: %+v", d, sans)
		}
	}
	if !got["127.0.0.1"] {
		t.Fatalf("SAN 应包含 IP 线索: %+v", sans)
	}
	if issuer != "acme-assets" {
		t.Fatalf("issuer=%q, want acme-assets", issuer)
	}
	if notAfter.Unix() != tpl.NotAfter.Unix() {
		t.Fatalf("notAfter=%v, want %v", notAfter, tpl.NotAfter)
	}

	// 连接失败 → 零值
	if sans, issuer, notAfter := CheckCertAssets(host, closedPort(t)); len(sans) != 0 || issuer != "" || !notAfter.IsZero() {
		t.Fatalf("关闭端口应返回零值: %v %q %v", sans, issuer, notAfter)
	}
}

// TestCertExpiry 到期提醒数据 + 失败时 ok=false。
func TestCertExpiry(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-expiry", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	notAfter, days, ok := CertExpiry(host, port)
	if !ok {
		t.Fatal("CertExpiry 应成功")
	}
	if notAfter.Unix() != tpl.NotAfter.Unix() {
		t.Fatalf("notAfter=%v, want %v", notAfter, tpl.NotAfter)
	}
	if days < 0 || days > 1 {
		t.Fatalf("24h 证书 days=%d, want 0..1", days)
	}
	if _, _, ok := CertExpiry(host, closedPort(t)); ok {
		t.Fatal("关闭端口应 ok=false")
	}
}

// TestCheckHostCompose CheckHost 组合 TLS + HTTP（mailCheck=false 时不查 DNS）。
func TestCheckHostCompose(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-host", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)
	hits := CheckHost(host, port, false)
	mustFind(t, hits, "tls-self-signed", "medium")
	mustFind(t, hits, "http-hsts", "low") // 夹具未设 HSTS
	for _, f := range hits {
		if strings.HasPrefix(f.Check, "dns-") {
			t.Fatalf("mailCheck=false 不应有 DNS 发现: %+v", f)
		}
	}
}

// closedPort 返回一个当前无人监听的本地端口（listen 后立即关闭）。
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	return addr.Port
}

// ---- CheckDNSMail 纯解析部分 ----

// TestAnalyzeDMARCPolicy p=none/quarantine/reject/缺失/异常。
func TestAnalyzeDMARCPolicy(t *testing.T) {
	domain := "_dmarc.example.com"
	// none → medium（仅监控）
	hits := analyzeDMARC(domain, "v=DMARC1; p=none; rua=mailto:dmarc@example.com")
	f := mustFind(t, hits, "dns-dmarc-policy", "medium")
	if !strings.Contains(f.Title, "none") {
		t.Fatalf("p=none 标题应标明策略: %q", f.Title)
	}
	mustNotFind(t, hits, "dns-dmarc-rua") // 已配 rua

	// quarantine → info
	hits = analyzeDMARC(domain, "v=DMARC1; p=quarantine; rua=mailto:d@example.com")
	f = mustFind(t, hits, "dns-dmarc-policy", "info")
	if !strings.Contains(f.Title, "quarantine") {
		t.Fatalf("p=quarantine 标题应标明策略: %q", f.Title)
	}

	// reject → info
	hits = analyzeDMARC(domain, "v=DMARC1; p=reject")
	f = mustFind(t, hits, "dns-dmarc-policy", "info")
	if !strings.Contains(f.Title, "reject") {
		t.Fatalf("p=reject 标题应标明策略: %q", f.Title)
	}

	// 缺 p= → medium
	mustFind(t, analyzeDMARC(domain, "v=DMARC1; rua=mailto:d@example.com"), "dns-dmarc-policy", "medium")
	// 非法 p= → low
	mustFind(t, analyzeDMARC(domain, "v=DMARC1; p=allow"), "dns-dmarc-policy", "low")
}

// TestAnalyzeDMARCRua 缺 rua → low；有 rua 不报。
func TestAnalyzeDMARCRua(t *testing.T) {
	domain := "_dmarc.example.com"
	f := mustFind(t, analyzeDMARC(domain, "v=DMARC1; p=reject"), "dns-dmarc-rua", "low")
	if !strings.Contains(f.Evidence, "rua") {
		t.Fatalf("rua 缺失 evidence 应指明: %q", f.Evidence)
	}
	mustNotFind(t, analyzeDMARC(domain, "v=DMARC1; p=reject; rua=mailto:x@example.com"), "dns-dmarc-rua")
	// 带引号/空格的 rua 也应识别
	mustNotFind(t, analyzeDMARC(domain, `v=DMARC1; p=reject; rua="mailto:x@example.com"`), "dns-dmarc-rua")
}

// TestAnalyzeSPFLookups DNS 查询机制 >10 → low；合法少量不报。
func TestAnalyzeSPFLookups(t *testing.T) {
	many := "v=spf1"
	for i := 0; i < 11; i++ {
		many += " include:spf" + strconv.Itoa(i) + ".example.com"
	}
	many += " -all"
	f := mustFind(t, analyzeSPF("example.com", []string{many}), "dns-spf-lookups", "low")
	if !strings.Contains(f.Evidence, "11") {
		t.Fatalf("evidence 应含查找次数: %q", f.Evidence)
	}

	ok := "v=spf1 a mx include:_spf.example.com ip4:192.0.2.0/24 -all"
	if hits := analyzeSPF("example.com", []string{ok}); len(findByCheck(hits, "dns-spf-lookups")) > 0 {
		t.Fatalf("4 个查询机制不应报超限: %+v", hits)
	}
	// redirect= 计入查询数
	redir := "v=spf1 redirect=_spf.example.com"
	if n := spfLookupCount(redir); n != 1 {
		t.Fatalf("redirect= 应计 1 次查询, got %d", n)
	}
}

// TestAnalyzeSPFSyntax 多记录/未知机制/缺参数 → low。
func TestAnalyzeSPFSyntax(t *testing.T) {
	// 多份 v=spf1
	hits := analyzeSPF("example.com", []string{
		"v=spf1 include:a.example.com -all",
		"v=spf1 include:b.example.com -all",
	})
	f := mustFind(t, hits, "dns-spf-syntax", "low")
	if !strings.Contains(f.Title, "重复") {
		t.Fatalf("多记录标题应含重复: %q", f.Title)
	}

	// 未知机制
	hits = analyzeSPF("example.com", []string{"v=spf1 include:ok.example.com b0gus -all"})
	f = mustFind(t, hits, "dns-spf-syntax", "low")
	if !strings.Contains(f.Evidence, "b0gus") {
		t.Fatalf("evidence 应含非法机制: %q", f.Evidence)
	}

	// 机制缺参数
	hits = analyzeSPF("example.com", []string{"v=spf1 include: -all"})
	f = mustFind(t, hits, "dns-spf-syntax", "low")
	if !strings.Contains(f.Evidence, "缺少参数") {
		t.Fatalf("evidence 应含缺参数: %q", f.Evidence)
	}

	// 合法记录不报
	if hits := analyzeSPF("example.com", []string{"v=spf1 include:_spf.example.com ~all"}); len(hits) > 0 {
		t.Fatalf("合法 SPF 不应有发现: %+v", hits)
	}
}

// ---- CheckHTTP ----

// TestCheckHTTPHSTS HSTS 缺失 / max-age 过短 / 缺 max-age / 合规。
func TestCheckHTTPHSTS(t *testing.T) {
	mk := func(hsts string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hsts != "" {
				w.Header().Set("Strict-Transport-Security", hsts)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
	}
	cases := []struct {
		name       string
		hsts       string
		wantSubstr string // 期望 http-hsts 标题含该子串；空 = 不应出现
	}{
		{name: "缺失", hsts: "", wantSubstr: "缺少 HSTS"},
		{name: "过短", hsts: "max-age=600; includeSubDomains", wantSubstr: "过短"},
		{name: "缺max-age", hsts: "includeSubDomains", wantSubstr: "缺少 max-age"},
		{name: "合规", hsts: "max-age=31536000; includeSubDomains", wantSubstr: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := mk(tc.hsts)
			defer srv.Close()
			hits := CheckHTTP(srv.URL)
			got := findByCheck(hits, "http-hsts")
			if tc.wantSubstr == "" {
				if len(got) > 0 {
					t.Fatalf("合规 HSTS 不应报: %+v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("应报 http-hsts（%s）: %+v", tc.wantSubstr, hits)
			}
			if !strings.Contains(got[0].Title, tc.wantSubstr) {
				t.Fatalf("标题=%q, want 含 %q", got[0].Title, tc.wantSubstr)
			}
			if got[0].Severity != "low" {
				t.Fatalf("HSTS 发现 severity=%q, want low", got[0].Severity)
			}
		})
	}
}

// TestCheckHTTPNoHTTPSRedirect 纯 HTTP 站点未跳转 → medium；最终响应为
// HTTP 时不校验 HSTS。
func TestCheckHTTPNoHTTPSRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000") // HTTP 响应上的 HSTS 无效
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	hits := CheckHTTP(srv.URL)
	f := mustFind(t, hits, "http-https-redirect", "medium")
	if !strings.Contains(f.Evidence, "http://") {
		t.Fatalf("evidence 应记录最终 URL: %q", f.Evidence)
	}
	mustNotFind(t, hits, "http-hsts")
}

// TestCheckHTTPRedirectsToHTTPS HTTP → HTTPS 跳转后不报未跳转；对最终
// HTTPS 响应继续校验 HSTS（配好则零发现）。
func TestCheckHTTPRedirectsToHTTPS(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsSrv.URL+"/", http.StatusMovedPermanently)
	}))
	defer plainSrv.Close()
	hits := CheckHTTP(plainSrv.URL)
	if len(hits) != 0 {
		t.Fatalf("HTTP→HTTPS 且 HSTS 合规时不应有发现: %+v", hits)
	}
}

// TestCheckHTTPInvalidInput 非法/非 http(s) 输入直接返回 nil。
func TestCheckHTTPInvalidInput(t *testing.T) {
	for _, in := range []string{"", "not a url", "ftp://example.com/x", "example.com"} {
		if hits := CheckHTTP(in); hits != nil {
			t.Fatalf("CheckHTTP(%q) 应返回 nil, got %+v", in, hits)
		}
	}
}

// TestHSTSParse max-age 解析（含引号/顺序/无 max-age）。
func TestHSTSParse(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   int64
		ok     bool
	}{
		{"max-age=31536000", 31536000, true},
		{"includeSubDomains; max-age=600", 600, true},
		{`max-age="15552000"`, 15552000, true},
		{"max-age=0", 0, true},
		{"includeSubDomains", 0, false},
		{"max-age=abc", 0, false},
		{"max-age=-1", 0, false},
	} {
		got, ok := hstsMaxAge(tc.header)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("hstsMaxAge(%q)=(%d,%v), want (%d,%v)", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

// TestOrgDomain 主域提取回归（既有行为，不因 NS-01 改动）。
func TestOrgDomain(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a.b.example.com", "example.com"},
		{"www.example.com.cn", "example.com.cn"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
	} {
		if got := OrgDomain(tc.in); got != tc.want {
			t.Fatalf("OrgDomain(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
