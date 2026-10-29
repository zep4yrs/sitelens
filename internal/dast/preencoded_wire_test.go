// 预编码载荷的字节级回归测试（BUG-017 / BUG-029）。
//
// 为什么必须起真实 net/http 服务端：旧单测（deep_test.go 的 /crlf 桩）按
// 头名子串匹配，双重编码后的 "%250d%250aX-Sitelens-Crlf…" 里仍含
// "X-Sitelens-Crlf"，桩件照样回注入头 → 伪绿。这里断言的是服务端**真正
// 收到的 query 原始字节**与单次解码后的内容。
package dast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// wireFetcher 用真实 net/http 客户端实现 dast.Fetcher（单请求不跟重定向），
// 与引擎 dastFetcher 同语义：探针 URL 原样上线。
type wireFetcher struct{ c *http.Client }

func (f wireFetcher) GetSmall(rawURL string) *Resp {
	resp, err := f.c.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(body)}
}

func (f wireFetcher) PostFormSmall(string, map[string]string) *Resp { return nil }
func (f wireFetcher) PostRawSmall(string, string, string) *Resp     { return nil }
func (f wireFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// wireCapture 记录服务端收到的原始 query 与单次解码后的参数值。
type wireCapture struct {
	mu   sync.Mutex
	raw  []string
	vals []string
}

func (c *wireCapture) add(raw, val string) {
	c.mu.Lock()
	c.raw = append(c.raw, raw)
	c.vals = append(c.vals, val)
	c.mu.Unlock()
}

// rawContaining 返回第一条包含 needle 的原始 query（无则空串）。
func (c *wireCapture) rawContaining(needle string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, raw := range c.raw {
		if strings.Contains(raw, needle) {
			return raw
		}
	}
	return ""
}

// TestPreEncodedPayloadsArriveAsRawBytes BUG-017 验收：CRLF 与反序列化两条
// 通道的预编码载荷必须以原样字节到达服务端，单次解码后得到真 CR/LF 与
// Java 序列化魔数 aced0005；命中证据链里的复现命令同样携带原始字节。
func TestPreEncodedPayloadsArriveAsRawBytes(t *testing.T) {
	var cap wireCapture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		cap.add(r.URL.RawQuery, q)
		// CRLF 通道：只有服务端真收到 CR/LF 才会新增响应头（模拟头注入命中）。
		if strings.Contains(q, "\r\n"+crlfHeaderName) {
			w.Header().Set(crlfHeaderName, "sl9z7")
		}
		// 反序列化通道：只有真收到魔数字节才回反序列化报错特征。
		if strings.HasPrefix(q, "\xac\xed\x00\x05") {
			_, _ = w.Write([]byte("java.io.StreamCorruptedException: invalid stream header"))
			return
		}
		_, _ = w.Write([]byte("<html>safe</html>"))
	}))
	defer srv.Close()

	// 探针 URL 只留一个参数：collectParams 的 map 迭代无序，多参数会随机选目标。
	probeURL := srv.URL + "/probe?q=1"
	opts := DefaultOptions()
	opts.TimeBlind = false // 时间盲注对本用例无意义，且会拖慢
	opts.CmdInject = false // 命令注入重类与本用例无关
	f := wireFetcher{c: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
	hits := New(f, opts).Run([]string{probeURL})

	// 1) 字节级断言：服务端收到的原始 query 必须含未二次编码的预编码载荷。
	crlfRaw := cap.rawContaining("%0d%0a" + crlfHeaderName)
	if crlfRaw == "" {
		t.Fatalf("服务端未收到原样 %%0d%%0a 序列（二次编码?）——原始 query 样本：%v", cap.raw)
	}
	if strings.Contains(crlfRaw, "%250d%250a") {
		t.Fatalf("CRLF 载荷被二次编码（%%25 形态）：%q", crlfRaw)
	}
	deserRaw := cap.rawContaining(deserPayload)
	if deserRaw == "" {
		t.Fatalf("服务端未收到原样 %s（二次编码?）——原始 query 样本：%v", deserPayload, cap.raw)
	}
	if strings.Contains(deserRaw, "%25AC%25ED") {
		t.Fatalf("反序列化载荷被二次编码（%%25 形态）：%q", deserRaw)
	}

	// 2) 单次解码断言：服务端只用一次解码就拿到真字节，而不是字面文本。
	var crlfVal, deserVal string
	cap.mu.Lock()
	for i, raw := range cap.raw {
		switch {
		case strings.Contains(raw, "%0d%0a"+crlfHeaderName):
			crlfVal = cap.vals[i]
		case strings.Contains(raw, deserPayload):
			deserVal = cap.vals[i]
		}
	}
	cap.mu.Unlock()
	if want := "\r\n" + crlfHeaderName + ": sl9z7"; crlfVal != want {
		t.Fatalf("服务端单次解码应得到真 CR/LF，实际 %q（期望 %q）", crlfVal, want)
	}
	if want := "\xac\xed\x00\x05sl"; deserVal != want {
		t.Fatalf("服务端单次解码应得到序列化魔数字节，实际 %q（期望 %q）", deserVal, want)
	}

	// 3) 通道判定：真字节到达后两条通道均应命中（修复前是静默漏报）。
	var crlfHit, deserHit *Finding
	for i := range hits {
		switch hits[i].Check {
		case "crlf-inject":
			crlfHit = &hits[i]
		case "deser-surface":
			deserHit = &hits[i]
		}
	}
	if crlfHit == nil {
		t.Fatalf("收到真 CR/LF 后 CRLF 通道应命中，实际命中：%+v", hits)
	}
	if deserHit == nil {
		t.Fatalf("收到真序列化魔数后反序列化通道应命中，实际命中：%+v", hits)
	}

	// 4) 证据链可复现：复现命令 / 重放请求必须携带原始编码字节。
	if !strings.Contains(crlfHit.Replay, "%0d%0a"+crlfHeaderName) {
		t.Fatalf("CRLF 复现命令未携带原样载荷：%q", crlfHit.Replay)
	}
	if !strings.Contains(crlfHit.Request, "%0d%0a"+crlfHeaderName) {
		t.Fatalf("CRLF 重放请求未携带原样载荷：%q", crlfHit.Request)
	}
	if crlfHit.Payload != crlfInject {
		t.Fatalf("CRLF 命中载荷被改写：%q != %q", crlfHit.Payload, crlfInject)
	}
	if !strings.Contains(deserHit.Replay, deserPayload) {
		t.Fatalf("反序列化复现命令未携带原样载荷：%q", deserHit.Replay)
	}
}

// TestRawSetParamPreservesRawEncoding rawSetParam 语义：值原样写入、其余参数
// 不重排不重编码；参数不存在时追加。
func TestRawSetParamPreservesRawEncoding(t *testing.T) {
	got := rawSetParam("https://a.com/p?x=1&q=old&y=%20z", "q", "%0d%0aX-Test:%20v")
	if !strings.Contains(got, "q=%0d%0aX-Test:%20v") {
		t.Fatalf("预编码值未原样保留：%s", got)
	}
	if strings.Contains(got, "%250d") {
		t.Fatalf("预编码值被二次编码：%s", got)
	}
	if !strings.Contains(got, "x=1") || !strings.Contains(got, "y=%20z") {
		t.Fatalf("其余参数应原样保留（不重排/不重编码）：%s", got)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("构造出的 URL 不可解析：%v", err)
	}
	if v := u.Query().Get("q"); v != "\r\nX-Test: v" {
		t.Fatalf("单次解码应得到 CR/LF，实际 %q", v)
	}

	// 参数不存在：追加（语义与 setParam 一致）。
	appended := rawSetParam("https://a.com/p?x=1", "q", "%AC%ED")
	if !strings.Contains(appended, "x=1&q=%AC%ED") {
		t.Fatalf("缺失参数应追加：%s", appended)
	}
}

// TestFormProbeURLEncodesQuery BUG-029：表单探针的 URL 形态必须按表单编码
// 规则转义，载荷里的 & / = / 空格 / % 不能改坏 query 结构。
func TestFormProbeURLEncodesQuery(t *testing.T) {
	const action = "https://a.com/search?lang=zh"
	const field = "q"
	const value = `a&b=c d%e#f'x`
	u, err := url.Parse(formProbeURL(action, field, value))
	if err != nil {
		t.Fatalf("构造出的探针 URL 不可解析：%v", err)
	}
	if got := u.Query().Get(field); got != value {
		t.Fatalf("载荷未原样往返：%q != %q（URL=%s）", got, value, u.String())
	}
	if got := u.Query().Get("lang"); got != "zh" {
		t.Fatalf("action 原有 query 应保留：%q（URL=%s）", got, u.String())
	}
	if strings.Contains(formProbeURL(action, field, value), "a&b=c") {
		t.Fatalf("载荷里的 & / = 未被编码：%s", formProbeURL(action, field, value))
	}
	// 无 query 的 action 也要正确拼接。
	plain := formProbeURL("https://a.com/search", field, value)
	if p, perr := url.Parse(plain); perr != nil || p.Query().Get(field) != value {
		t.Fatalf("无 query 的 action 拼接失败：%s", plain)
	}
}

// TestRunFormsEvidenceStaysPOST 表单命中证据链回归（BUG-018 不回退）：
// probeURL 改为编码构造后，复现命令仍是 POST 表单语义。
func TestRunFormsEvidenceStaysPOST(t *testing.T) {
	hits := newRunner(&fakeFetch{}).RunForms([]FormTarget{
		{Action: "https://a.com/search?lang=zh", Fields: []string{"q"}},
	})
	var hit *Finding
	for i := range hits {
		if hits[i].Check == "xss-reflect" && hits[i].Param == "q" {
			hit = &hits[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("表单反射 XSS 应命中：%+v", hits)
	}
	if !strings.HasPrefix(hit.Request, "POST ") {
		t.Fatalf("表单命中 Request 应为 POST 语义：%q", hit.Request)
	}
	if !strings.Contains(hit.Replay, "-d ") {
		t.Fatalf("表单命中 Replay 应带 -d（表单体）：%q", hit.Replay)
	}
	if hit.Response == nil || len(hit.Signals) == 0 {
		t.Fatalf("证据链四件套不完整：%+v", hit)
	}
}
