package dast

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// deepFetcher 模拟一个按路径分发的多漏洞靶场桩：
//
//	/ssti  回显模板求值结果   /cmd  sleep 延迟   /crlf 注入响应头
//	/nosql 数据层报错         /xpath XPath 报错  /ldap  LDAP 报错
//	/spel  表达式回显         /log4j JNDI 特征   /safe 无漏洞
type deepFetcher struct {
	delay time.Duration
	req   int
	// xxeResp 供 XXE 通道返回的响应（nil 表示不支持）
	xxeResp *Resp
}

func (f *deepFetcher) param(u string) (path, val string) {
	p, err := url.Parse(u)
	if err != nil {
		return "", ""
	}
	q := p.Query()
	for k := range q {
		return p.Path, q.Get(k)
	}
	return p.Path, ""
}

func (f *deepFetcher) GetSmall(u string) *Resp {
	f.req++
	path, v := f.param(u)
	switch path {
	case "/ssti":
		if strings.Contains(v, "7393*8453") {
			return &Resp{Status: 200, Body: "<html>Hello " + strings.ReplaceAll(v, "7393*8453", sstiResult) + "</html>"}
		}
		return &Resp{Status: 200, Body: "<html>Hello " + v + "</html>"}
	case "/spel":
		if strings.Contains(v, "7393*8453") {
			return &Resp{Status: 200, Body: "<html>" + sstiResult + "</html>"}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	case "/cmd":
		if strings.Contains(strings.ToLower(v), "sleep") {
			time.Sleep(f.delay)
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	case "/crlf":
		h := map[string]string{"Content-Type": "text/html"}
		if strings.Contains(v, crlfHeaderName) {
			h[crlfHeaderName] = "sl9z7"
		}
		return &Resp{Status: 200, Headers: h, Body: "<html>ok</html>"}
	case "/nosql":
		if strings.Contains(v, "$") {
			return &Resp{Status: 200, Body: "<html>MongoError: unknown operator</html>"}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	case "/xpath":
		if strings.Contains(v, "'") {
			return &Resp{Status: 200, Body: "<html>XPathException: invalid expression</html>"}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	case "/ldap":
		if strings.Contains(v, "*") {
			return &Resp{Status: 200, Body: "<html>LDAPException: bad search filter</html>"}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	case "/log4j":
		if strings.Contains(v, "jndi") {
			return &Resp{Status: 200, Body: "<html>javax.naming.CommunicationException</html>"}
		}
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	}
	return &Resp{Status: 200, Body: "<html>safe</html>"}
}

func (f *deepFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}

func (f *deepFetcher) PostRawSmall(u, ct, body string) *Resp { return f.xxeResp }

// PostMultipartSmall deepFetcher 桩：默认不支持，upload 测试单独定义。
func (f *deepFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp { return nil }

// TestDeepSSTI SSTI：模板表达式回显求值结果即命中。
func TestDeepSSTI(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/ssti?name=hi"})
	if !hasCheck(hits, "ssti") {
		t.Fatalf("SSTI 应命中: %+v", hits)
	}
}

// TestDeepExpressionSpEL 表达式注入：回显求值结果即命中。
func TestDeepExpressionSpEL(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/spel?q=x"})
	if !hasCheck(hits, "expression-inject") {
		t.Fatalf("表达式注入应命中: %+v", hits)
	}
}

// TestDeepCRLF CRLF：注入后响应头新增即命中。
func TestDeepCRLF(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/crlf?h=x"})
	if !hasCheck(hits, "crlf-inject") {
		t.Fatalf("CRLF 应命中: %+v", hits)
	}
}

// TestDeepNoSQL NoSQL：操作符注入触发数据层报错即命中。
func TestDeepNoSQL(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/nosql?n=1"})
	if !hasCheck(hits, "nosql-inject") {
		t.Fatalf("NoSQL 应命中: %+v", hits)
	}
}

// TestDeepXPath XPath：引号触发解析报错即命中。
func TestDeepXPath(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/xpath?x=1"})
	if !hasCheck(hits, "xpath-inject") {
		t.Fatalf("XPath 应命中: %+v", hits)
	}
}

// TestDeepLDAP LDAP：通配符触发解析报错即命中。
func TestDeepLDAP(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/ldap?l=1"})
	if !hasCheck(hits, "ldap-inject") {
		t.Fatalf("LDAP 应命中: %+v", hits)
	}
}

// TestDeepLog4j JNDI：注入 ${jndi:} 触发解析特征即命中。
func TestDeepLog4j(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/log4j?m=1"})
	if !hasCheck(hits, "log4j-inject") {
		t.Fatalf("Log4j 应命中: %+v", hits)
	}
}

// TestDeepCmdInject 命令注入：sleep 延迟 + 双确认即命中。
func TestDeepCmdInject(t *testing.T) {
	f := &deepFetcher{delay: 60 * time.Millisecond}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.BlindThresholdMS = 30
	hits := New(f, opts).Run([]string{"https://a.com/cmd?c=ls"})
	if !hasCheck(hits, "cmd-inject") {
		t.Fatalf("命令注入应命中: %+v", hits)
	}
}

// TestDeepNoFalsePositive 安全页面不应产生任何深度面误报。
func TestDeepNoFalsePositive(t *testing.T) {
	f := &deepFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/safe?q=1"})
	for _, h := range hits {
		switch h.Check {
		case "ssti", "expression-inject", "crlf-inject", "nosql-inject",
			"xpath-inject", "ldap-inject", "log4j-inject", "cmd-inject":
			t.Fatalf("安全页面误报 %s: %+v", h.Check, h)
		}
	}
}

// TestDeepDisabled 总闸关闭时不产生深度面发现、且不额外发请求。
func TestDeepDisabled(t *testing.T) {
	f := &deepFetcher{}
	off := false
	opts := DefaultOptions()
	opts.DeepProbes = &off
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{"https://a.com/ssti?name=hi"})
	if hasCheck(hits, "ssti") {
		t.Fatalf("总闸关闭时不应命中 SSTI: %+v", hits)
	}
}

// TestXXE XXE：XML 外部实体回显文件特征即命中。
func TestXXE(t *testing.T) {
	f := &deepFetcher{xxeResp: &Resp{Status: 200, Body: "<root>root:x:0:0:root:/root</root>"}}
	hits := newRunner(f).RunForms([]FormTarget{{Action: "https://a.com/xml", Fields: []string{"data"}}})
	if !hasCheck(hits, "xxe") {
		t.Fatalf("XXE 应命中: %+v", hits)
	}
}

func hasCheck(hits []Finding, id string) bool {
	for _, h := range hits {
		if h.Check == id {
			return true
		}
	}
	return false
}

// uploadFetcher 上传面桩：按路径决定受理/拒绝/无信号。
type uploadFetcher struct {
	deepFetcher
	mode string // accept | reject | none | echo
}

func (f *uploadFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	switch f.mode {
	case "accept":
		return &Resp{Status: 200, Body: "<html>upload success: /uploads/" + fn + "</html>"}
	case "reject":
		return &Resp{Status: 200, Body: "<html>error: file type not allowed</html>"}
	case "echo":
		return &Resp{Status: 200, Body: "<html>content=" + c + "</html>"}
	default:
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	}
}

func (f *uploadFetcher) PostRawSmall(u, ct, b string) *Resp { return nil }

// TestUploadSurfaceAccepted 上传受理信号出现即命中。
func TestUploadSurfaceAccepted(t *testing.T) {
	f := &uploadFetcher{mode: "accept"}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/upload", Fields: []string{"desc"}, FileFields: []string{"file"}},
	})
	if !hasCheck(hits, "upload-surface") {
		t.Fatalf("上传受理面应命中: %+v", hits)
	}
}

// TestUploadSurfaceRejected 拒绝信号出现时不命中（不误报）。
func TestUploadSurfaceRejected(t *testing.T) {
	f := &uploadFetcher{mode: "reject"}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/upload", FileFields: []string{"file"}},
	})
	if hasCheck(hits, "upload-surface") {
		t.Fatalf("被拒绝的上传不应命中: %+v", hits)
	}
}

// TestUploadSurfaceEcho 回显文件内容标记即命中（保守通道）。
func TestUploadSurfaceEcho(t *testing.T) {
	f := &uploadFetcher{mode: "echo"}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/upload", FileFields: []string{"file"}},
	})
	if !hasCheck(hits, "upload-surface") {
		t.Fatalf("回显文件内容应命中上传面: %+v", hits)
	}
}

// TestUploadSurfaceNoSignal 无受理信号不命中。
func TestUploadSurfaceNoSignal(t *testing.T) {
	f := &uploadFetcher{mode: "none"}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/upload", FileFields: []string{"file"}},
	})
	if hasCheck(hits, "upload-surface") {
		t.Fatalf("无受理信号不应命中: %+v", hits)
	}
}

// headerFetcher 头注入桩：Cookie/UA 带单引号时返回 SQL 报错,
// 头值含 XSS 标记时原样回显。
type headerFetcher struct {
	deepFetcher
}

func (f *headerFetcher) GetWithHeaders(u string, headers map[string]string) *Resp {
	// 只有 /page 是脆弱的；/safe 对头注入无反应（负样本）。
	if !strings.Contains(u, "/page") {
		return &Resp{Status: 200, Body: "<html>ok</html>"}
	}
	for k, v := range headers {
		low := strings.ToLower(v)
		if strings.Contains(v, "'") && (strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "User-Agent")) {
			return &Resp{Status: 200, Body: "<html>Error: you have an error in your SQL syntax</html>"}
		}
		if strings.Contains(low, "svg/onload") {
			return &Resp{Status: 200, Body: "<html>echo: " + v + "</html>"}
		}
	}
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}

// TestCookieInjection Cookie 通道报错 SQLi 命中。
func TestCookieInjection(t *testing.T) {
	f := &headerFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/page?v=1"})
	if !hasCheck(hits, "sqli-error-cookie") {
		t.Fatalf("Cookie 注入应命中: %+v", hits)
	}
}

// TestHeaderInjection User-Agent 通道报错 SQLi 命中。
func TestHeaderInjection(t *testing.T) {
	f := &headerFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).Run([]string{"https://a.com/page?v=1"})
	if !hasCheck(hits, "sqli-error-header") {
		t.Fatalf("头注入应命中: %+v", hits)
	}
}

// TestCookieHeaderNoFP 无注入特征时不应命中。
func TestCookieHeaderNoFP(t *testing.T) {
	f := &headerFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	// 用不含单引号回显逻辑的普通 deepFetcher 语义：headerFetcher 对 "1" 返回 ok
	hits := New(f, opts).Run([]string{"https://a.com/safe?x=1"})
	// safe 路径 deal：headerFetcher.GetSmall 走 deepFetcher（/safe → ok）
	for _, h := range hits {
		if h.Check == "sqli-error-cookie" || h.Check == "sqli-error-header" {
			t.Fatalf("无特征不应误报: %+v", h)
		}
	}
}

// --- PR #29 增量层：判定单测、预算口径、遍历多形态 ------------------------

// countingFetcher 计数桩（恒定干净响应，不命中）。
type countingFetcher struct{ n int }

func (f *countingFetcher) GetSmall(string) *Resp { f.n++; return &Resp{Status: 200, Body: "ok"} }
func (f *countingFetcher) PostFormSmall(string, map[string]string) *Resp {
	f.n++
	return &Resp{Status: 200, Body: "ok"}
}
func (f *countingFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *countingFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// TestSSTIJudge 直接打 judgeDeep：乘积回显即命中。
func TestSSTIJudge(t *testing.T) {
	hit := judgeDeep("ssti", &Resp{Status: 200, Body: "calc=" + sstiResult}, "",
		Target{URL: "https://a.com/p?t=1", Param: "t"})
	if hit == nil || hit.Check != "ssti" {
		t.Fatalf("SSTI 乘积回显应命中: %+v", hit)
	}
}

// TestSSTIProbesMultiEngine 四族模板语法均注册。
func TestSSTIProbesMultiEngine(t *testing.T) {
	if len(sstiProbes) < 4 {
		t.Fatalf("SSTI 探针应覆盖 ≥4 语法族，实际 %d", len(sstiProbes))
	}
}

// TestCRLFJudge 响应头新增即命中。
func TestCRLFJudge(t *testing.T) {
	resp := &Resp{Status: 200, Headers: map[string]string{crlfHeaderName: "sl9z7"}}
	hit := judgeDeep("crlf", resp, "", Target{URL: "https://a.com/p?u=1", Param: "u"})
	if hit == nil || hit.Check != "crlf-inject" {
		t.Fatalf("CRLF 响应头注入应命中: %+v", hit)
	}
}

// TestNoSQLJudge 数据层报错命中；只回显操作符不命中。
func TestNoSQLJudge(t *testing.T) {
	resp := &Resp{Status: 500, Body: "MongoError: unexpected token $ne"}
	if hit := judgeDeep("nosql", resp, "", Target{URL: "https://a.com/p?q=1", Param: "q"}); hit == nil {
		t.Fatal("NoSQL 操作符注入应命中")
	}
	resp2 := &Resp{Status: 200, Body: "search: $ne"}
	if hit := judgeDeep("nosql", resp2, "", Target{URL: "https://a.com/p?q=1", Param: "q"}); hit != nil {
		t.Fatalf("无数据层特征不应命中: %+v", hit)
	}
}

// TestXPathJudge 解析报错命中。
func TestXPathJudge(t *testing.T) {
	resp := &Resp{Status: 500, Body: "XPathException: invalid expression"}
	hit := judgeDeep("xpath", resp, "", Target{URL: "https://a.com/p?n=1", Param: "n"})
	if hit == nil || hit.Check != "xpath-inject" {
		t.Fatalf("XPath 注入应命中: %+v", hit)
	}
}

// TestCmdTimeDiffHit 时间差分命中 critical。
func TestCmdTimeDiffHit(t *testing.T) {
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "sleep") {
				time.Sleep(25 * time.Millisecond)
			}
			return &Resp{Status: 200, Body: "ok"}
		},
	}}
	opts := DefaultOptions()
	opts.BlindThresholdMS = 10
	hit := New(f, opts).cmdInject(Target{URL: "https://a.com/p?ip=1.1.1.1", Param: "ip"}, "ip", new(int), 0)
	if hit == nil || hit.Check != "cmd-inject" || hit.Severity != "critical" {
		t.Fatalf("命令注入时间差分应命 critical: %+v", hit)
	}
}

// TestCmdTimeNoDiffNoHit 无延迟差不命中。
func TestCmdTimeNoDiffNoHit(t *testing.T) {
	opts := DefaultOptions()
	opts.BlindThresholdMS = 100
	if hit := New(&fakeFetch{}, opts).cmdInject(
		Target{URL: "https://a.com/p?ip=1", Param: "ip"}, "ip", new(int), 0); hit != nil {
		t.Fatalf("无延迟差不应命中: %+v", hit)
	}
}

// TestTraversalCoversMultiFileMultiEncoding 遍历探针 = 文件数 × 编码数。
func TestTraversalCoversMultiFileMultiEncoding(t *testing.T) {
	if len(traversalProbes) != len(traversalFiles)*len(traversalEncodings) {
		t.Fatalf("遍历探针应 %d 条，实际 %d", len(traversalFiles)*len(traversalEncodings), len(traversalProbes))
	}
	if len(traversalEncodings) < 6 {
		t.Fatalf("编码形态应 ≥6，实际 %d", len(traversalEncodings))
	}
	joined := strings.Join(traversalProbes, "\n")
	for _, want := range []string{"/etc/passwd", "win.ini", "%2e%2e%2f", "....//", "%252e%252e"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("遍历探针缺形态 %q", want)
		}
	}
}

// TestTraversalJudgeWinINI Windows win.ini 内容命中遍历。
func TestTraversalJudgeWinINI(t *testing.T) {
	resp := &Resp{Status: 200, Body: "[fonts]\r\n[extensions]\r\n"}
	if hit := judge("traversal", resp, "", Target{URL: "https://a.com/f?p=1", Param: "p"}); hit == nil {
		t.Fatal("win.ini 内容应命中")
	}
}

// TestMaxProbesPerClassCap 单类上限生效（无命中时不超过上界）。
func TestMaxProbesPerClassCap(t *testing.T) {
	f := &countingFetcher{}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	opts.CRLF = false
	r := New(f, opts)
	r.probeSequences(Target{URL: "https://a.com/p?q=1", Param: "q"}, "", new(int), 0)
	maxReq := maxURLRequestsPerParam(opts)
	if f.n > maxReq {
		t.Fatalf("请求数应不超过预算口径上界 %d，实际 %d", maxReq, f.n)
	}
}

// TestDeepProbesOffGate 关闭深度面：仅核心四类请求。
func TestDeepProbesOffGate(t *testing.T) {
	f := &countingFetcher{}
	off := false
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.DeepProbes = &off
	r := New(f, opts)
	r.probeSequences(Target{URL: "https://a.com/p?q=1", Param: "q"}, "", new(int), 0)
	if f.n > 1+len(xssProbes)+len(sqliErrorAll())+len(redirProbes)+len(traversalProbes) {
		t.Fatalf("关闭深度面后请求应只剩核心四类，实际 %d", f.n)
	}
}

var _ = url.Parse
