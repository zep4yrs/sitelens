package captcha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// B16 容错回归：Health 探测不再依赖「地址以 /ocr 结尾」的猜测——
// 带后缀、裸地址、带其他路径、尾斜杠，任一写法都能找到 /health。
func TestHealthPathVariants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	for _, url := range []string{
		srv.URL + "/ocr",  // 常规：剥 /ocr 后拼 /health
		srv.URL,           // 裸地址：直接拼 /health
		srv.URL + "/api",  // 其他路径：回落到根 /health
		srv.URL + "/ocr/", // 尾斜杠
	} {
		if !NewClient(url, 0).Health() {
			t.Errorf("Health(%q) 应可用", url)
		}
	}
}

// 全部候选路径都不通时明确 false，不误报可用。
func TestHealthAllMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	if NewClient(srv.URL+"/ocr", 0).Health() {
		t.Fatal("无 /health 时应返回 false")
	}
}
