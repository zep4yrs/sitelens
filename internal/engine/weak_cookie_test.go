package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestWeakSessionCookieFromStateChangeForm DVWA Weak Session IDs 形态：
// 「只有 submit 按钮」的 POST 表单提交后下发递增整数会话 Cookie。
// 该表单没有可注入字段、也不含密码框，此前整块不可见。
func TestWeakSessionCookieFromStateChangeForm(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.Header().Set("Set-Cookie", "dvwaSession=1")
			w.Write([]byte("<html>new session</html>"))
			return
		}
		w.Write([]byte(`<html><form method="post"><input type="submit" value="Generate" /></form></html>`))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/weak_id/", Options{Deep: true, DAST: true}, nil, nil)

	if posts == 0 {
		t.Fatal("无字段 POST 表单未进入状态变更探测队列")
	}
	for _, v := range res.Verified {
		if v["check"] == "weak-session-id" {
			return
		}
	}
	t.Fatalf("弱会话 Cookie 应进 verified: %+v", res.Verified)
}

// TestWeakSessionCookieStrongSilent 下发强随机会话 Cookie 时不报。
func TestWeakSessionCookieStrongSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Set-Cookie", "PHPSESSID=9f8e7d6c5b4a39281706f5e4d3c2b1a0")
			w.Write([]byte("<html>ok</html>"))
			return
		}
		w.Write([]byte(`<html><form method="post"><input type="submit" value="Go" /></form></html>`))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/x/", Options{Deep: true, DAST: true}, nil, nil)

	for _, v := range res.Verified {
		if v["check"] == "weak-session-id" {
			t.Fatalf("强随机会话 Cookie 不应报: %+v", v)
		}
	}
}
