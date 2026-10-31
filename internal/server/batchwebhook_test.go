package server

// BT-03 webhook 通知测试：成功 POST JSON、非 2xx 报错、空地址跳过、
// 非法地址报错、超时（缩短包级超时避免等 3s）、nil 载荷发送 {}。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotifyBatchSuccess(t *testing.T) {
	var (
		hit        bool
		gotMethod  string
		gotCT      string
		gotPayload map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	payload := map[string]any{"event": "batch.done", "job_id": "j1", "total": 3}
	if err := NotifyBatch(srv.URL, payload); err != nil {
		t.Fatalf("成功通知不应报错: %v", err)
	}
	if !hit {
		t.Fatal("webhook 未被调用")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("方法应为 POST，实得 %s", gotMethod)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("Content-Type 应为 application/json，实得 %q", gotCT)
	}
	if gotPayload["event"] != "batch.done" || gotPayload["job_id"] != "j1" {
		t.Fatalf("载荷未按 JSON 传递: %+v", gotPayload)
	}
	if total, _ := gotPayload["total"].(float64); total != 3 {
		t.Fatalf("载荷 total 应保留为 3，实得 %v", gotPayload["total"])
	}
}

func TestNotifyBatchNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	err := NotifyBatch(srv.URL, map[string]any{"a": 1})
	if err == nil {
		t.Fatal("非 2xx 应返回错误")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("错误应带状态码，实得 %v", err)
	}
}

func TestNotifyBatchEmptyURLSkipped(t *testing.T) {
	if err := NotifyBatch("", map[string]any{"a": 1}); err != nil {
		t.Fatalf("空地址应静默跳过，实得 %v", err)
	}
	if err := NotifyBatch("   ", nil); err != nil {
		t.Fatalf("空白地址应静默跳过，实得 %v", err)
	}
}

func TestNotifyBatchInvalidURL(t *testing.T) {
	if err := NotifyBatch("://bad", map[string]any{"a": 1}); err == nil {
		t.Fatal("非法地址应返回错误")
	}
}

func TestNotifyBatchTimeout(t *testing.T) {
	old := batchWebhookTimeout
	batchWebhookTimeout = 40 * time.Millisecond
	t.Cleanup(func() { batchWebhookTimeout = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond) // 慢于超时
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	start := time.Now()
	err := NotifyBatch(srv.URL, map[string]any{"a": 1})
	if err == nil {
		t.Fatal("慢响应应超时返回错误")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("应≈40ms 级超时返回，实得 %v", elapsed)
	}
}

func TestNotifyBatchNilPayload(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NotifyBatch(srv.URL, nil); err != nil {
		t.Fatalf("nil 载荷应发送 {} 并成功: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("请求体应是合法 JSON 对象: %v（%q）", err, raw)
	}
	if len(m) != 0 {
		t.Fatalf("nil 载荷应编码为空对象，实得 %+v", m)
	}
}
