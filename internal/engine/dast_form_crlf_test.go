// 表单 POST 通道 CRLF 预编码修复的引擎侧端到端回归（BUG-017 表单残留）。
//
// 走完整生产装配链路：dast.RunForms 的表单 CRLF 探针 →
// dastFetcher.PostFormRawSmall（原始表单体可选通道）→ httpx.PostRaw →
// 真实 net/http 服务端。断言服务端单次解码拿到真 CR/LF，且命中证据链
// Request/Replay 与真实发出的请求体逐字节一致。
package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func TestDastFormCRLFRawChannelEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var decoded, rawBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		vals, _ := url.ParseQuery(string(body))
		q := vals.Get("q")
		// 只有真收到 CR/LF（服务端单次解码后）才新增注入头。
		if strings.Contains(q, "\r\nX-Sitelens-Crlf") {
			mu.Lock()
			decoded = q
			rawBody = string(body)
			mu.Unlock()
			w.Header().Set("X-Sitelens-Crlf", "sl9z7")
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	opts := dast.DefaultOptions()
	opts.TimeBlind = false // 本用例只关心表单侧，减少无关请求
	opts.BoolBlind = false
	opts.CmdInject = false
	hits := dast.New(dastFetcher{c: httpx.New(0)}, opts).RunForms([]dast.FormTarget{
		{Action: srv.URL + "/form", Fields: []string{"q"}},
	})

	mu.Lock()
	gotDecoded, gotRaw := decoded, rawBody
	mu.Unlock()
	if gotRaw == "" {
		t.Fatalf("服务端未收到原始表单体通道的 CRLF 请求（engine 适配层未接通）")
	}
	if want := "\r\nX-Sitelens-Crlf: sl9z7"; gotDecoded != want {
		t.Fatalf("服务端单次解码应得到真 CR/LF，实际 %q（期望 %q）", gotDecoded, want)
	}
	if !strings.Contains(gotRaw, "q=%0d%0aX-Sitelens-Crlf") {
		t.Fatalf("CRLF 载荷未以原样字节到达服务端：%q", gotRaw)
	}
	if strings.Contains(gotRaw, "%250d%250a") {
		t.Fatalf("CRLF 载荷被二次编码（%%25 形态）：%q", gotRaw)
	}

	var hit *dast.Finding
	for i := range hits {
		if hits[i].Check == "crlf-inject" {
			hit = &hits[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("服务端确认注入后应产出 crlf-inject 发现，实际命中：%+v", hits)
	}
	if !strings.HasSuffix(hit.Request, gotRaw) {
		t.Fatalf("证据链 Request 与真实发出的请求不一致：%q（raw=%q）", hit.Request, gotRaw)
	}
	if !strings.Contains(hit.Replay, gotRaw) {
		t.Fatalf("Replay 复现命令未携带真实 body：%q", hit.Replay)
	}
	if !strings.Contains(hit.Replay, "-d ") || !strings.Contains(hit.Replay, "curl ") {
		t.Fatalf("Replay 应为 curl POST 复现命令：%q", hit.Replay)
	}
	if hit.Response == nil || len(hit.Signals) == 0 || hit.Payload == "" {
		t.Fatalf("证据链四件套不完整：%+v", hit)
	}
}
