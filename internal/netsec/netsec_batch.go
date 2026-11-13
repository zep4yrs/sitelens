// NS-02 批量网络层入口：端口/服务探测、单主机组合检测、多主机批量。
//
// 只读语义：端口探测仅做 TCP connect + 被动读取 banner（≤256B），不发送
// 任何 payload；HTTP 由 CheckHTTP 复用一次只读 GET；TLS 只做握手。
package netsec

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPorts 常见端口默认集（CheckPorts 的 ports 为空时使用）。
// 调用方请勿原地修改；需要不同集合时显式传入 ports。
var DefaultPorts = []int{
	21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200,
}

// portService 常见端口 → 服务名（报告展示用；未知端口留空）。
var portService = map[int]string{
	21:    "ftp",
	22:    "ssh",
	25:    "smtp",
	80:    "http",
	443:   "https",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	27017: "mongodb",
	9200:  "elasticsearch",
}

// riskyPorts 数据/管理/明文服务端口：对外开放记为 low；其余常见服务记 info。
var riskyPorts = map[int]bool{
	21:   true,             // FTP 明文
	3306: true, 5432: true, // 数据库
	6379: true, 27017: true, 9200: true, // Redis/Mongo/ES 常无鉴权或弱鉴权
}

// CheckPorts 端口/服务探测：对 host 的 ports 做只读 TCP connect（并发≤8），
// 连接成功后被动读取最多 256B banner（不发送任何数据）。
// ports 为空时使用 DefaultPorts；timeout≤0 时默认 1.5s（单端口连接超时）。
// 开放端口按入参端口序返回 finding（确定的输出顺序）。
func CheckPorts(host string, ports []int, timeout time.Duration) []Finding {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	// 去重 + 过滤非法端口，保持入参顺序
	seen := map[int]bool{}
	var list []int
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		list = append(list, p)
	}
	if len(list) == 0 {
		return nil
	}

	const maxPortWorkers = 8
	workers := len(list)
	if workers > maxPortWorkers {
		workers = maxPortWorkers
	}
	results := make([]*Finding, len(list))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(list) {
					return
				}
				results[i] = probePort(host, list[i], timeout)
			}
		}()
	}
	wg.Wait()

	hits := make([]Finding, 0, len(results))
	for _, f := range results {
		if f != nil {
			hits = append(hits, *f)
		}
	}
	return hits
}

// probePort 单端口探测：TCP connect + 被动 banner（≤256B，不写任何数据）。
func probePort(host string, port int, timeout time.Duration) *Finding {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// 被动读 banner：服务端先问候（SSH/SMTP/FTP 等）时能读到；
	// HTTP 等请求-响应型服务读不到（超时/无数据），属正常。
	var banner string
	readWait := time.Second
	if timeout < readWait {
		readWait = timeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(readWait))
	buf := make([]byte, 256)
	if n, _ := conn.Read(buf); n > 0 {
		banner = sanitizeBanner(buf[:n])
	}

	svc := portService[port]
	severity := "info"
	if riskyPorts[port] {
		severity = "low"
	}
	title := fmt.Sprintf("对外端口开放：%d", port)
	if svc != "" {
		title = fmt.Sprintf("对外端口开放：%d/%s", port, svc)
	}
	ev := "tcp " + addr + " 可连接"
	if banner != "" {
		ev += "; banner=" + banner
	}
	advice := "确认该端口为预期对外开放；非必要则限制访问来源"
	if riskyPorts[port] {
		advice = "数据/管理服务不要直接暴露公网：限制来源 IP 或关闭该端口"
	}
	return &Finding{
		Check: "net-port", Title: title, Severity: severity,
		URL: addr, Evidence: ev, Advice: advice,
	}
}

// sanitizeBanner banner 摘要：控制字符替换为 '.'，压缩空白，截断到 160 字节。
func sanitizeBanner(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r > 0x7e:
			b.WriteByte('.')
		default:
			b.WriteByte(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 160 {
		out = out[:160] + "…"
	}
	return out
}

// CheckHost 单主机组合网络层检测：TLS（证书/协议评级）+ 可选 DNS 邮件
// + HTTP（HSTS/跳转）。直接复用 CheckTLS/CheckDNSMail/CheckHTTP，避免
// 重复实现；只读、不发 payload。
func CheckHost(host string, port int, mailCheck bool) []Finding {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}
	if port <= 0 || port > 65535 {
		port = 443
	}
	var hits []Finding
	hits = append(hits, CheckTLS(host, port)...)
	if mailCheck {
		hits = append(hits, CheckDNSMail(host)...)
	}
	hits = append(hits, CheckHTTP(hostURL(host, port, "https"), nil)...) // 批量入口无配置上下文：不追加 allow_hosts（引擎扫描路径始终传 cfg.Scan.AllowHosts）
	return hits
}

// hostURL 把 host/port 拼成 scheme URL（默认端口省略；IPv6 加括号）。
func hostURL(host string, port int, scheme string) string {
	host = strings.Trim(host, "[]")
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		if strings.Contains(host, ":") { // IPv6
			return scheme + "://[" + host + "]/"
		}
		return scheme + "://" + host + "/"
	}
	h := net.JoinHostPort(host, strconv.Itoa(port))
	return scheme + "://" + h + "/"
}

// CheckHosts 多主机批量检测：对每个 host 调 CheckHost（workers≤4，默认 4）；
// 返回 host（去空白、去重保序）→ findings 的映射。无发现的 host 也会以
// nil 值出现在 map 里，便于上层区分「未检测」与「无发现」。
func CheckHosts(hosts []string, port int, mailCheck bool, workers int) map[string][]Finding {
	out := make(map[string][]Finding, len(hosts))
	var list []string
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		list = append(list, h)
		out[h] = nil
	}
	if len(list) == 0 {
		return out
	}
	if workers <= 0 {
		workers = 4
	}
	const maxHostWorkers = 4
	if workers > maxHostWorkers {
		workers = maxHostWorkers
	}
	if workers > len(list) {
		workers = len(list)
	}

	results := make([][]Finding, len(list))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(list) {
					return
				}
				results[i] = CheckHost(list[i], port, mailCheck)
			}
		}()
	}
	wg.Wait()
	for i, h := range list {
		out[h] = results[i]
	}
	return out
}

// SortFindings 按 check + title 排序（批量结果展示/对比时稳定输出用）。
// 不改变调用方数据语义，返回新切片。
func SortFindings(hits []Finding) []Finding {
	out := append([]Finding(nil), hits...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].Title < out[j].Title
	})
	return out
}
