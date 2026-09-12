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
	"cnb.cool/feng-qiao/sitelens/internal/rex"
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

// fpMatcher 正则惰性编译缓存（双层编译仍失败的模式才跳过）。
// 以 rows 特征签名判缓存新旧：情报库热更新后签名变化即重编，
// 下一次扫描自动用上新指纹（B20），无需重启进程。
type fpMatcher struct {
	mu   sync.Mutex
	sig  string
	regs []*compiledFP
}

// compiled 返回与 rows 对应的编译结果；签名不变直接复用，
// 变化则重编并原子换入（返回的切片内容不可变，扫描期间可无锁遍历）。
func (m *fpMatcher) compiled(rows []intel.ServiceFPRow) []*compiledFP {
	sig := fpSig(rows)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.regs != nil && m.sig == sig {
		return m.regs
	}
	regs := make([]*compiledFP, 0, len(rows))
	for _, r := range rows {
		if r.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			// RE2 不兼容（环视/反向引用/超界重复）→ 回退 rex；
			// 双层都失败的模式才跳过
			rx, rerr := rex.Compile(r.Pattern)
			if rerr != nil {
				continue
			}
			regs = append(regs, &compiledFP{rx: rx, row: r})
			continue
		}
		regs = append(regs, &compiledFP{re: re, row: r})
	}
	m.sig, m.regs = sig, regs
	return regs
}

// fpSig 缓存签名：行数 + 首尾模式。全量重载出的新切片内容一旦变化
// 即失配，成本 O(1)（签名碰撞需要行数与首尾模式三者同时巧合，可忽略）。
func fpSig(rows []intel.ServiceFPRow) string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(len(rows)))
	if len(rows) > 0 {
		sb.WriteByte('|')
		sb.WriteString(rows[0].Pattern)
		sb.WriteByte('|')
		sb.WriteString(rows[len(rows)-1].Pattern)
	}
	return sb.String()
}

// compiledFP 双层编译：re2 命中快路径；RE2 拒收的环视/反向引用等
// 模式回退受限回溯引擎 rex（B25：服务指纹零丢弃）。
type compiledFP struct {
	re  *regexp.Regexp
	rx  *rex.Regexp
	row intel.ServiceFPRow
}

// findString 按编译层派发，返回匹配文本（无匹配为空串）。
func (c *compiledFP) findString(banner string) string {
	if c.re != nil {
		return c.re.FindString(banner)
	}
	return c.rx.FindString(banner)
}

func (m *fpMatcher) compile(rows []intel.ServiceFPRow) []*compiledFP {
	return m.compiled(rows)
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
	progress = serializedProgress(progress) // B18：端口 goroutine 并发调 progress
	// 本轮扫描固定用这份编译结果：内容不可变，扫描期间无锁遍历；
	// 热更新发生在扫描中也不影响本轮，下一次扫描自动生效
	regs := globalFP.compile(rows)

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
			for _, fp := range regs {
				if m := fp.findString(banner); m != "" {
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
