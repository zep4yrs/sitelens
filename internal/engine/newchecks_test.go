package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestCacheableSensitivePageVerified 会话/账户类页面缺 no-store 时报 verified。
func TestCacheableSensitivePageVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "account") {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write([]byte("<html>account</html>"))
			return
		}
		w.Write([]byte(`<html><a href="/account.php">a</a></html>`))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/", Options{Deep: true, Passive: true}, nil, nil)

	found := false
	for _, v := range res.Verified {
		if v["check"] == "cacheable-sensitive" {
			found = true
		}
	}
	if !found {
		t.Fatalf("敏感页可缓存应进 verified: %+v", res.Verified)
	}
}

// TestCacheableSensitiveNoStoreSilent 有 no-store 时不报。
func TestCacheableSensitiveNoStoreSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "account") {
			w.Header().Set("Cache-Control", "no-store")
			w.Write([]byte("<html>account</html>"))
			return
		}
		w.Write([]byte(`<html><a href="/account.php">a</a></html>`))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/", Options{Deep: true, Passive: true}, nil, nil)

	for _, v := range res.Verified {
		if v["check"] == "cacheable-sensitive" {
			t.Fatalf("no-store 页面不应报: %+v", v)
		}
	}
}
