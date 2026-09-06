package loginbrute

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func TestBasicAuthBruteHits(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == "admin123" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	users := []string{"root", "admin"}
	pwds := []string{"123456", "admin123", "password"}
	hits := BasicAuthBrute(httpx.New(0), []string{srv.URL + "/admin"}, users, pwds, 400, 0, nil)
	if len(hits) != 1 || hits[0].User != "admin" || hits[0].Password != "admin123" {
		t.Fatalf("basic 认证命中失败: %+v", hits)
	}
	if hits[0].Type != "basic-auth" {
		t.Fatalf("类型标记缺失: %+v", hits[0])
	}
}

func TestBasicAuthBruteNoHit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hits := BasicAuthBrute(httpx.New(0), []string{srv.URL + "/x"},
		[]string{"a"}, []string{"b"}, 400, 0, nil)
	if len(hits) != 0 {
		t.Fatalf("不应命中: %+v", hits)
	}
}
