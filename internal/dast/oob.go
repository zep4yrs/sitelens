// 出带回调（OOB）探测：把指向「外部接收端」的地址塞进候选参数，
// 目标侧若发起请求，接收端记下命中 → 我们轮询确认。
//
// 与 ssrf.go 的 beacon 方案的分工：beacon 要求目标能连回扫描器本机
// （局域网/自托管场景成立），公网靶场普遍不成立——所以 SSRF 长期
// "有能力、测不了"。本通道把接收端换成可公网访问的第三方或用本地
// CSV 落盘（供外部 dnslog/oast 同步），目标一旦外发即可确认。
//
// 用途：SSRF（HTTP 出带）、盲 XSS（浏览器侧加载外部资源）、
// XXE 出带实体、Log4Shell JNDI 出带——凡"无回显但会外发请求"的洞。
//
// 安全边界：默认关（主动外发）；只发一次探针；回调地址由使用者提供，
// 不内置任何第三方服务的隐式上传；csv 模式只写本地文件。
package dast

import (
	"bufio"
	"net/http"
	"os"
	"strings"
	"time"
)

// oobParams 命中记录的判定：回调日志里出现该 token 即确认。
type oobProbe struct {
	tgt   Target
	token string
	url   string
}

// OobConfig 出带回调运行参数（引擎从 config.Oob 映射过来）。
type OobConfig struct {
	Enabled   bool
	Mode      string // callback | csv
	Callback  string // callback 模式的日志拉取端点
	CSVPath   string
	TokenHost string // 触发用域名，如 abc.oast.pro
	MaxProbes int
}

// oobPayloads token 注入形态：裸 URL / 协议包装（SSRF 常见）/
// JNDI 形态（Log4Shell）/ XML 实体（XXE）——一处命中即该类短路。
func oobPayloads(host, token string) []string {
	base := strings.TrimRight(host, "/")
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return []string{
		base + "/" + token,
		"file://" + base + "/" + token,
		"gopher://" + strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://") + "/_" + token,
		"${jndi:ldap://" + strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://") + "/" + token + "}",
		"<!DOCTYPE r [<!ENTITY x SYSTEM \"" + base + "/" + token + "\">]>",
	}
}

// oobProbeAll 出带探测主流程：逐参数注入 → 轮询/读日志确认 → 出 Finding。
func (r *Runner) oobProbeAll(targets []Target, cfg OobConfig) []Finding {
	if !cfg.Enabled || cfg.TokenHost == "" || r.stopped() {
		return nil
	}
	cap := cfg.MaxProbes
	if cap <= 0 || cap > len(targets) {
		cap = len(targets)
	}
	var probes []oobProbe
	for i := 0; i < cap && !r.stopped(); i++ {
		tgt := targets[i]
		token := "sl" + randToken()[:16]
		payloads := oobPayloads(cfg.TokenHost, token)
		// 单参数只发第一形态（URL 形态覆盖面最广），长度超限时退到下一个形态。
		for _, pl := range payloads {
			u := setParam(tgt.URL, tgt.Param, pl)
			if len(u) > r.opts.MaxURLLen {
				continue
			}
			r.fetch.GetSmall(u)
			probes = append(probes, oobProbe{tgt: tgt, token: token, url: u})
			break
		}
	}
	if len(probes) == 0 {
		return nil
	}
	// 收窗：callback 模式轮询日志（最长 6s，全中提前退出）；csv 模式读文件。
	hits := r.collectOobHits(probes, cfg)
	var out []Finding
	for _, p := range probes {
		if !hits[p.token] {
			continue
		}
		f := Finding{
			Check: "oob-callback", Title: "出带回调确认（SSRF/盲 XSS/XXE 外发）",
			Severity: "high", URL: p.tgt.URL, Param: p.tgt.Param, Payload: p.url,
			Evidence: "参数 " + p.tgt.Param + " 注入出带地址后，接收端记录到回连令牌 " + p.token,
			Advice:   "对该参数的外发目标做白名单校验；禁止用户输入决定请求地址",
		}
		f.Signals = []string{"接收端记录到唯一令牌 " + p.token, "确认目标外发请求"}
		out = append(out, f)
	}
	return out
}

// collectOobHits 采集命中令牌集合。
func (r *Runner) collectOobHits(probes []oobProbe, cfg OobConfig) map[string]bool {
	want := map[string]bool{}
	for _, p := range probes {
		want[p.token] = true
	}
	switch cfg.Mode {
	case "csv":
		return readOobCSV(cfg.CSVPath, want)
	default:
		return r.pollOobCallback(cfg.Callback, want)
	}
}

// pollOobCallback 轮询 callback 日志端点（每 1.5s，最长 6s，全中提前退出）。
func (r *Runner) pollOobCallback(endpoint string, want map[string]bool) map[string]bool {
	hits := map[string]bool{}
	if endpoint == "" {
		return hits
	}
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(6 * time.Second)
	for {
		if r.stopped() {
			break
		}
		resp, err := client.Get(endpoint)
		if err == nil && resp != nil {
			body := readAllLimited(resp.Body, 1<<20)
			_ = resp.Body.Close()
			for tk := range want {
				if strings.Contains(body, tk) {
					hits[tk] = true
				}
			}
			if len(hits) == len(want) {
				break
			}
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return hits
}

// readOobCSV 读本地 CSV 落盘（列：时间,token,源IP,请求行；只匹配 token 列）。
func readOobCSV(path string, want map[string]bool) map[string]bool {
	hits := map[string]bool{}
	if path == "" {
		return hits
	}
	f, err := os.Open(path)
	if err != nil {
		return hits
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		for tk := range want {
			if strings.Contains(line, tk) {
				hits[tk] = true
			}
		}
	}
	return hits
}

// readAllLimited 有界读正文（回调日志可能很大）。
func readAllLimited(rc interface{ Read([]byte) (int, error) }, max int) string {
	var sb strings.Builder
	buf := make([]byte, 32*1024)
	for sb.Len() < max {
		n, err := rc.Read(buf)
		if n > 0 {
			sb.WriteString(string(buf[:n]))
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// URLTargets 导出给引擎用的参数目标采集（复用内部统一口径）。
func (r *Runner) URLTargets(links []string) []Target {
	return collectParams(links, r.opts.MaxParams)
}

// OobProbe 导出给引擎用的出带探测入口。
func (r *Runner) OobProbe(targets []Target, cfg OobConfig) []Finding {
	return r.oobProbeAll(targets, cfg)
}
