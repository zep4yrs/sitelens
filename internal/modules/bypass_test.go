package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// bypassCfg 打开 403 绕过开关的配置。
func bypassCfg(wordlistDir string) config.ActiveConfig {
	cfg := benchCfg(wordlistDir)
	cfg.DirBypass403 = true
	return cfg
}

// bypassStatus 单字路径 → 指定状态码 + 正文。
func bypassStatus(mux *http.ServeMux, path string, code int, body string) {
	mux.HandleFunc("/"+path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	})
}

func TestTryBypass403PathTrailingSlash(t *testing.T) {
	mux := http.NewServeMux()
	bypassStatus(mux, "admin", http.StatusForbidden, "denied")
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>后台</title>admin dashboard real content</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	attempts := 0
	resp, via := tryBypass403(client(), srv.URL+"/admin", "/admin", srv.URL, 0,
		map[int]bool{19: true}, &attempts, nil)
	if resp == nil {
		t.Fatal("尾斜杠变体应命中")
	}
	if via != "path:/" {
		t.Fatalf("技术名 = %q, 期望 path:/", via)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, 期望 200", resp.Status)
	}
}

func TestTryBypass403TrustHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			fmt.Fprint(w, "secret internal panel content")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	attempts := 0
	resp, via := tryBypass403(client(), srv.URL+"/secret", "/secret", srv.URL, 0,
		map[int]bool{19: true}, &attempts, nil)
	if resp == nil {
		t.Fatal("信任头变体应命中")
	}
	if via != "header:X-Forwarded-For" {
		t.Fatalf("技术名 = %q, 期望 header:X-Forwarded-For", via)
	}
}

func TestTryBypass403RewriteHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-URL") == "/console" {
			fmt.Fprint(w, "console dashboard widget")
			return
		}
		fmt.Fprint(w, strings.Repeat("roothome", 12)) // 固定根页尺寸，异于基线
	})
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 根页尺寸由调用方传入（DirScan 语义）
	root := client()
	rootResp, err := root.GetFollow(srv.URL + "/")
	if err != nil || rootResp == nil {
		t.Fatal("取根页基线失败")
	}
	attempts := 0
	resp, via := tryBypass403(root, srv.URL+"/console", "/console", srv.URL,
		len(rootResp.Body), map[int]bool{19: true}, &attempts, nil)
	if resp == nil {
		t.Fatal("改写头变体应命中")
	}
	if via != "rewrite:X-Original-URL" {
		t.Fatalf("技术名 = %q, 期望 rewrite:X-Original-URL", via)
	}
	if !strings.Contains(strings.ToLower(resp.Body), "console") {
		t.Fatalf("rewrite 命中正文应含路径段关键词，got: %.60s", resp.Body)
	}
}

func TestTryBypass403HeadMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/panel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	attempts := 0
	resp, via := tryBypass403(client(), srv.URL+"/panel", "/panel", srv.URL, 0,
		map[int]bool{19: true}, &attempts, nil)
	if resp == nil {
		t.Fatal("HEAD 方法变体应命中")
	}
	if via != "method:HEAD" {
		t.Fatalf("技术名 = %q, 期望 method:HEAD", via)
	}
}

func TestTryBypass403AllFail(t *testing.T) {
	mux := http.NewServeMux()
	bypassStatus(mux, "locked", http.StatusForbidden, "denied")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	attempts := 0
	if resp, _ := tryBypass403(client(), srv.URL+"/locked", "/locked", srv.URL, 0,
		map[int]bool{19: true}, &attempts, nil); resp != nil {
		t.Fatal("全部失败时不应返回命中")
	}
	want := len(buildBypassVariants(srv.URL+"/locked", "/locked", srv.URL, 0))
	if attempts != want {
		t.Fatalf("attempts = %d, 期望 %d（变体总数）", attempts, want)
	}
}

func TestTryBypass403AttemptsCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	}))
	defer srv.Close()

	attempts := bypassMaxAttempts - 2 // 已接近上限
	if resp, _ := tryBypass403(client(), srv.URL+"/x", "/x", srv.URL, 0,
		map[int]bool{}, &attempts, nil); resp != nil {
		t.Fatal("不应命中")
	}
	if attempts > bypassMaxAttempts {
		t.Fatalf("attempts = %d 超过硬上限 %d", attempts, bypassMaxAttempts)
	}
}

func TestDirScanBypassRecordsTechnique(t *testing.T) {
	dir := writeWordlist(t, "dir_default.txt", []string{"admin", "sl-nope-probe"})
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			fmt.Fprint(w, "<html><title>后台</title>admin dashboard</html>")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "denied")
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>后台</title>admin dashboard</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hits := DirScan(client(), srv.URL, bypassCfg(dir), nil, nil)
	var admin *PageHit
	for i := range hits {
		if hits[i].Path == "/admin" {
			admin = &hits[i]
		}
	}
	if admin == nil {
		t.Fatal("应命中 /admin")
	}
	if admin.Bypass == "" {
		t.Fatal("绕过成功应记录技术名")
	}
	if admin.Status != 200 {
		t.Fatalf("绕过后 status = %d, 期望 200", admin.Status)
	}
}

func TestMethodFollowWithRejectsUnsafeMethods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("不应真正发出 %s 请求", r.Method)
	}))
	defer srv.Close()

	for _, m := range []string{"PUT", "POST", "DELETE", "TRACE", "PATCH"} {
		if _, err := httpx.New(0).MethodFollowWith(m, srv.URL, nil); err == nil {
			t.Fatalf("%s 应被无害化红线拒绝", m)
		}
	}
}
