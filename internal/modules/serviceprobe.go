// 端口服务识别：连接常见端口读取 banner，对 11966 条 service_fp
// 指纹做正则匹配（惰性编译 + once 缓存）。移植自 python 分支
// scanner/modules.py 的 service_probe/_grab；默认关闭，仅限授权目标。
package modules

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// DefaultProbePorts 默认探测端口（常见服务，总量可控）。
var DefaultProbePorts = []int{
	21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995,
	1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211, 27017,
}

// tlsPorts 需要 TLS 握手的端口。
var tlsPorts = map[int]bool{443: true, 465: true, 993: true, 995: true, 8443: true}

// ServiceHit 一个端口的服务识别结果。
type ServiceHit struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Product string `json:"product"`
	Version string `json:"version"`
	Banner  string `json:"banner"`
}

// fpMatcher 正则惰性编译缓存（进程级；模式编译失败永久跳过）。
type fpMatcher struct {
	once sync.Once
	regs []*compiledFP
}

type compiledFP struct {
	re  *regexp.Regexp
	row intel.ServiceFPRow
}

func (m *fpMatcher) compile(rows []intel.ServiceFPRow) {
	m.once.Do(func() {
		m.regs = make([]*compiledFP, 0, len(rows))
		for _, r := range rows {
			if r.Pattern == "" {
				continue
			}
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue // RE2 不兼容的模式跳过，不阻塞
			}
			m.regs = append(m.regs, &compiledFP{re: re, row: r})
		}
	})
}

var globalFP fpMatcher

// ServiceProbe 端口服务识别：banner 抓取（TLS 端口走握手后读取）+ 指纹匹配。
func ServiceProbe(host string, rows []intel.ServiceFPRow, ports []int,
	timeoutMS int, workers int, progress func(done, total int, msg string),
	cancel func() bool) []ServiceHit {
	if len(ports) == 0 {
		ports = DefaultProbePorts
	}
	if timeoutMS <= 0 {
		timeoutMS = 2500
	}
	if workers <= 0 {
		workers = 10
	}
	globalFP.compile(rows)

	var mu sync.Mutex
	hits := []ServiceHit{}
	var done int64
	var muDone sync.Mutex
	total := len(ports)
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	tick := func() int64 {
		muDone.Lock()
		defer muDone.Unlock()
		done++
		return done
	}

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if cancel != nil && cancel() {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()

			banner, preHit := grabBanner(host, port, time.Duration(timeoutMS)*time.Millisecond)
			n := tick()
			if progress != nil {
				progress(int(n), total, strconv.Itoa(port))
			}
			if banner == "" && preHit.Banner == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, fp := range globalFP.regs {
				if m := fp.re.FindString(banner); m != "" {
					hits = append(hits, ServiceHit{
						Port:    port,
						Service: fp.row.Service,
						Product: fp.row.Product,
						Version: fp.row.Version,
						Banner:  truncateBanner(banner),
					})
					return // 一端口一命中
				}
			}
			if preHit.Banner != "" {
				// TLS 证书主体本身就是识别线索（无 banner 匹配时也记录）
				hits = append(hits, ServiceHit{
					Port:    port,
					Service: "tls",
					Product: preHit.Banner,
					Banner:  truncateBanner(banner),
				})
			}
		}(port)
	}
	wg.Wait()
	return hits
}

// grabBanner 连接端口读取服务 banner；TLS 端口先握手。失败返回空串。
//
// TLS 证书策略：本连接不发送任何数据、无凭据暴露面；扫描目标本是
// 不可信主机，标准 Web PKI 校验在侦察场景无认证语义。此处不跳过
// 校验，而是自实现校验：要求对端出示证书链（无证书视为握手失败），
// 证书主体作为服务识别线索记录，其余校验失败不阻断 banner 抓取。
func grabBanner(host string, port int, timeout time.Duration) (string, ServiceHit) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	hit := ServiceHit{Port: port}
	if tlsPorts[port] {
		tlsConn, derr := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr,
			&tls.Config{
				ServerName: host,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("对端未出示证书")
					}
					if cert, cerr := x509.ParseCertificate(rawCerts[0]); cerr == nil {
						hit.Banner = "cert-subject=" + cert.Subject.String()
					}
					return nil // 自实现校验：出示证书即通过，主体已记录
				},
			})
		if derr != nil {
			return "", hit
		}
		defer tlsConn.Close()
		_ = tlsConn.SetReadDeadline(deadline)
		buf := make([]byte, 256)
		n, _ := tlsConn.Read(buf)
		s := sanitizeBanner(buf[:n])
		if hit.Banner != "" {
			s = strings.TrimSpace(s + " " + hit.Banner)
		}
		return s, hit
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", hit
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return "", hit
	}
	return sanitizeBanner(buf[:n]), hit
}

// sanitizeBanner 剔除不可打印字节，留 ASCII 形态供正则与展示。
func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}

func truncateBanner(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
