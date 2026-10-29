// 表单 POST 通道 CRLF 预编码修复的字节级回归测试（BUG-017 表单残留）。
//
// 表单普通探针经 PostFormSmall → url.Values.Encode，对预编码载荷会二次编码
// （%0d%0a → %250d%250a），服务端单次解码只拿到字面文本——表单侧 CRLF 注入
// 实际不生效。修复后该探针走可选「原始表单体」通道（rawFormPoster）：
// 目标字段值原样写入请求体，其余字段照常表单编码。
//
// 这里起真实 net/http 服务端断言收到的字节与解码结果，替代桩件按子串匹配
// 的伪断言；同时断言普通表单探针仍按表单编码发送、证据链与真实请求一致、
// 拿不到原始通道时探针跳过（宁少报）。
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

// rawFormWireFetcher 真实 net/http 适配器：普通表单走标准表单编码 POST
// （与引擎 dastFetcher.PostFormSmall 同语义），并实现 rawFormPoster 原始
// 表单体通道（与 dastFetcher.PostFormRawSmall 同语义）。
type rawFormWireFetcher struct{ c *http.Client }

func (f *rawFormWireFetcher) do(rawURL, contentType, body string) *Resp {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := f.c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(b)}
}

func (f *rawFormWireFetcher) GetSmall(rawURL string) *Resp {
	resp, err := f.c.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(b)}
}

func (f *rawFormWireFetcher) PostFormSmall(rawURL string, data map[string]string) *Resp {
	v := url.Values{}
	for k, val := range data {
		v.Set(k, val)
	}
	return f.do(rawURL, "application/x-www-form-urlencoded", v.Encode())
}

// PostFormRawSmall 原始表单体通道：body 原样发出，不再做表单编码。
func (f *rawFormWireFetcher) PostFormRawSmall(rawURL, body string) *Resp {
	return f.do(rawURL, "application/x-www-form-urlencoded", body)
}

func (f *rawFormWireFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *rawFormWireFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// formWireRecord 服务端实际收到的 POST 体与单次解码后的字段值。
type formWireRecord struct {
	rawBody  string
	decodedQ string
}

// formWireServer 起真实桩服务：解析 POST 体，只有解出真 CR/LF 才新增
// X-Sitelens-Crlf 响应头（模拟表单字段拼进响应头的注入命中）。
type formWireServer struct {
	*httptest.Server
	mu      sync.Mutex
	records []formWireRecord
	crlfRaw string // 触发注入的那次请求原始体
}

func newFormWireServer(t *testing.T) *formWireServer {
	t.Helper()
	fs := &formWireServer{}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		vals, _ := url.ParseQuery(string(raw))
		q := vals.Get("q")
		fs.mu.Lock()
		fs.records = append(fs.records, formWireRecord{rawBody: string(raw), decodedQ: q})
		if strings.Contains(q, "\r\n"+crlfHeaderName) {
			fs.crlfRaw = string(raw)
			w.Header().Set(crlfHeaderName, "sl9z7")
		}
		fs.mu.Unlock()
		_, _ = w.Write([]byte("<html>safe</html>"))
	}))
	return fs
}

// TestFormCRLFRawChannelBytes BUG-017 表单残留验收：
//   - 服务端收到原样 %0d%0a 序列（不是 %25 形态），单次解码得到真 CR/LF；
//   - CRLF 表单探针命中，证据链 Request/Replay 与真实发出的 body 逐字节一致；
//   - 普通表单探针仍走 url.Values.Encode（编码语义不变，避免误报）。
func TestFormCRLFRawChannelBytes(t *testing.T) {
	srv := newFormWireServer(t)
	defer srv.Close()

	f := &rawFormWireFetcher{c: &http.Client{}}
	opts := DefaultOptions()
	opts.TimeBlind = false
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := New(f, opts).RunForms([]FormTarget{
		{Action: srv.URL + "/form?lang=zh", Fields: []string{"q"}},
	})

	// 1) 字节级断言：服务端收到的原始体里 %0d%0a 未被二次编码。
	srv.mu.Lock()
	records := append([]formWireRecord(nil), srv.records...)
	crlfRaw := srv.crlfRaw
	srv.mu.Unlock()
	if crlfRaw == "" {
		t.Fatalf("服务端未收到原始 CRLF 载荷（表单通道未生效）——共收到 %d 个 POST，样本：%+v",
			len(records), records)
	}
	if !strings.Contains(crlfRaw, "q=%0d%0a"+crlfHeaderName) {
		t.Fatalf("CRLF 载荷未以原样字节到达服务端：%q", crlfRaw)
	}
	if strings.Contains(crlfRaw, "%250d%250a") {
		t.Fatalf("CRLF 载荷被二次编码（%%25 形态）：%q", crlfRaw)
	}
	if !strings.Contains(crlfRaw, "lang") && !strings.Contains(crlfRaw, "q=") {
		t.Fatalf("原始表单体形态异常：%q", crlfRaw)
	}

	// 2) 单次解码断言：服务端只解码一次就拿到真 CR/LF，而不是字面文本。
	var decoded string
	for _, rec := range records {
		if strings.Contains(rec.rawBody, "%0d%0a"+crlfHeaderName) {
			decoded = rec.decodedQ
		}
	}
	if want := "\r\n" + crlfHeaderName + ": sl9z7"; decoded != want {
		t.Fatalf("服务端单次解码应得到真 CR/LF，实际 %q（期望 %q）", decoded, want)
	}

	// 3) 命中与证据链：Request/Replay 必须携带真实发出的原始 body。
	var crlfHit *Finding
	for i := range hits {
		if hits[i].Check == "crlf-inject" {
			crlfHit = &hits[i]
			break
		}
	}
	if crlfHit == nil {
		t.Fatalf("收到真 CR/LF 后 CRLF 表单通道应命中，实际命中：%+v", hits)
	}
	if crlfHit.Payload != crlfInject {
		t.Fatalf("命中载荷被改写：%q != %q", crlfHit.Payload, crlfInject)
	}
	if crlfHit.Response == nil || len(crlfHit.Signals) == 0 {
		t.Fatalf("证据链四件套不完整：%+v", crlfHit)
	}
	parts := strings.SplitN(crlfHit.Request, "\r\n\r\n", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "POST ") {
		t.Fatalf("Request 应为 POST 语义报文：%q", crlfHit.Request)
	}
	if parts[1] != crlfRaw {
		t.Fatalf("证据链 Request body 与实际发出的请求不一致：%q != %q", parts[1], crlfRaw)
	}
	if !strings.Contains(crlfHit.Replay, crlfRaw) {
		t.Fatalf("Replay 复现命令未携带真实 body：%q（body=%q）", crlfHit.Replay, crlfRaw)
	}
	if !strings.Contains(crlfHit.Replay, "curl ") || !strings.Contains(crlfHit.Replay, "-d ") {
		t.Fatalf("Replay 应为 curl POST 复现命令：%q", crlfHit.Replay)
	}

	// 4) 普通表单探针不受影响：XSS 探针仍按 url.Values.Encode 发送。
	wantXSSBody := url.Values{"q": {xssProbes[0]}}.Encode()
	var sawEncodedXSS bool
	for _, rec := range records {
		if rec.rawBody == wantXSSBody && rec.decodedQ == xssProbes[0] {
			sawEncodedXSS = true
		}
	}
	if !sawEncodedXSS {
		t.Fatalf("普通表单探针应仍按表单编码发送（期望 body %q），实际样本：%+v",
			wantXSSBody, records)
	}
}

// TestFormCRLFSkippedWithoutRawChannel 拿不到原始表单体通道时不发 CRLF 探针
// （宁少报，而不是发一个注定被编码的无效请求）；其余表单探针照常。
func TestFormCRLFSkippedWithoutRawChannel(t *testing.T) {
	var mu sync.Mutex
	rawSent := 0
	f := &fakeFetch{postRules: []func(u string, data map[string]string) *Resp{
		func(_ string, data map[string]string) *Resp {
			for _, v := range data {
				if v == crlfInject {
					mu.Lock()
					rawSent++
					mu.Unlock()
				}
			}
			return nil // 其余交给 fakeFetch 默认回显
		},
	}}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/form", Fields: []string{"q"}},
	})
	if rawSent != 0 {
		t.Fatalf("无原始表单体通道时不得发送 CRLF 预编码探针，实际发送 %d 次", rawSent)
	}
	for _, h := range hits {
		if h.Check == "crlf-inject" {
			t.Fatalf("无原始通道时不应产生 CRLF 表单命中（宁少报）：%+v", h)
		}
	}
	// 其余表单探测照常跑（反射 XSS 桩仍应命中）。
	found := false
	for _, h := range hits {
		if h.Check == "xss-reflect" {
			found = true
		}
	}
	if !found {
		t.Fatalf("普通表单探针不应因 CRLF 通道缺失而停摆：%+v", hits)
	}
}
