package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

func TestPageCacheable(t *testing.T) {
	cases := []struct {
		h    map[string]string
		want bool
	}{
		{map[string]string{}, true},
		{map[string]string{"Cache-Control": "public, max-age=3600"}, true},
		{map[string]string{"Cache-Control": "no-store"}, false},
		{map[string]string{"Cache-Control": "private, no-cache"}, false},
	}
	for _, c := range cases {
		if got, _ := pageCacheable(c.h); got != c.want {
			t.Errorf("pageCacheable(%v) = %v，期望 %v", c.h, got, c.want)
		}
	}
}

func TestPageLooksSensitive(t *testing.T) {
	if !pageLooksSensitive("https://a.com/login.php") {
		t.Fatal("login 应判敏感页")
	}
	if !pageLooksSensitive("https://a.com/account/profile") {
		t.Fatal("account/profile 应判敏感页")
	}
	if pageLooksSensitive("https://a.com/index.php") {
		t.Fatal("普通首页不应判敏感页")
	}
}

// TestCSPFromNonHomePath DVWA 只在某个子路径上设 CSP——只评首页会整块漏掉。
func TestCSPFromNonHomePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "csp") {
			w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
			w.Write([]byte("<html>csp module</html>"))
			return
		}
		w.Write([]byte(`<html><a href="/vulnerabilities/csp/">csp</a></html>`))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/", Options{Deep: true, Passive: true}, nil, nil)

	for _, v := range res.Verified {
		if v["check"] == "csp-weak-directive" {
			return
		}
	}
	t.Fatalf("子路径 CSP 弱点应进 verified: %+v", res.Verified)
}
