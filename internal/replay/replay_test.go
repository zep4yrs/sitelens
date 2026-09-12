package replay

import (
	"html"
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/dast"
)

type noRedirect struct{ client *http.Client }

func newFetcher() noRedirect {
	return noRedirect{client: &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (f noRedirect) GetSmall(rawURL string) *dast.Resp {
	resp, err := f.client.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	n, _ := resp.Body.Read(tmp)
	buf = append(buf, tmp[:n]...)
	return &dast.Resp{Status: resp.StatusCode, Headers: map[string]string{
		"Location": resp.Header.Get("Location"),
	}, Body: string(buf)}
}

func (f noRedirect) PostFormSmall(rawURL string, data map[string]string) *dast.Resp {
	return f.GetSmall(rawURL)
}

func TestOnePresentAndGone(t *testing.T) {
	mode := "vuln"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("p")
		if mode == "vuln" {
			// 原样回显 → xss 命中
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>" + p + "</html>"))
			return
		}
		// fixed：真实转义 payload
		_, _ = w.Write([]byte("<html>" + html.EscapeString(p) + "</html>"))
	}))
	defer srv.Close()
	f := newFetcher()

	v := map[string]any{
		"check": "xss-reflect", "src": "dast", "url": srv.URL + "/?p=1",
		"param": "p", "payload": "<script>sitelens-old()</script>",
	}
	s, note := One(f, v)
	if s != Present {
		t.Errorf("vuln 态应 present: %s %s", s, note)
	}
	mode = "fixed"
	s, _ = One(f, v)
	if s != Gone {
		t.Errorf("fixed 态应 gone: %s", s)
	}
}

func TestOneOpenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		if u != "" {
			w.Header().Set("Location", u)
			w.WriteHeader(302)
		}
	}))
	defer srv.Close()
	v := map[string]any{
		"check": "open-redirect", "src": "dast", "url": srv.URL + "/go?u=x",
		"param": "u", "payload": "https://evil.example",
	}
	s, _ := One(newFetcher(), v)
	if s != Present {
		t.Errorf("302 带原 payload 应 present: %s", s)
	}
}

func TestBatchSkipsUnsupportedAndNonDast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	}))
	defer srv.Close()
	entries := []map[string]any{
		{"src": "dast", "check": "lfi-passwd", "url": srv.URL + "/?f=", "param": "f",
			"payload": "../../../../etc/passwd"},
		{"src": "dast", "check": "sqli-blind-time", "url": srv.URL + "/?q=1", "param": "q",
			"payload": "' OR SLEEP(4) -- -"}, // 不可单请求复现
		{"src": "nuclei", "check": "some-tpl", "url": srv.URL, "param": "x",
			"payload": "y"}, // 非 dast 来源不进分母
	}
	st, results := Batch(newFetcher(), entries)
	if st.Total != 2 || st.Present != 1 || st.Unsupported != 1 || st.Gone != 0 {
		t.Errorf("统计不对: %+v", st)
	}
	if len(results) != 2 {
		t.Errorf("明细应只有 2 条 dast 条目: %d", len(results))
	}
	if r := st.RegressionRate(); r != 1.0 {
		t.Errorf("全在回归率应 1.0: %v", r)
	}
}

func TestMissingPayloadIsUnsupported(t *testing.T) {
	s, _ := One(newFetcher(), map[string]any{
		"check": "xss-reflect", "url": "http://x/?p=1", "param": "p",
	})
	if s != Unsupported {
		t.Errorf("缺 payload 应 unsupported: %s", s)
	}
}
