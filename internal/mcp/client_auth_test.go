package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestClientSendsBearerAndXToken V-17：MCP 客户端同时发 X-Token（none 模式）
// 与 Authorization: Bearer（token/RBAC 模式），两种服务端鉴权模式都能用。
func TestClientSendsBearerAndXToken(t *testing.T) {
	var gotAuth, gotToken, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotToken = r.Header.Get("X-Token")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"test"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "tok-abc123", 2*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.getJSON(context.Background(), "/api/version", nil); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if gotPath != "/api/version" {
		t.Fatalf("路径 = %q", gotPath)
	}
	if gotToken != "tok-abc123" {
		t.Errorf("X-Token = %q, want tok-abc123", gotToken)
	}
	if gotAuth != "Bearer tok-abc123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok-abc123")
	}

	// 无 token 时两个头都不发（避免给服务端塞空凭据）
	gotAuth, gotToken = "", ""
	c2, err := NewClient(srv.URL, "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.getJSON(context.Background(), "/api/version", nil); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" || gotToken != "" {
		t.Errorf("无 token 时不应发凭据头：Authorization=%q X-Token=%q", gotAuth, gotToken)
	}
}

// TestResolveSpecPath V-16：MCP apispec 的 path 限定在允许根目录内。
func TestResolveSpecPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SITELENS_SPEC_ROOT", root)

	inside := filepath.Join(root, "openapi.json")
	if err := os.WriteFile(inside, []byte(`{"openapi":"3.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSpecPath(inside)
	if err != nil {
		t.Fatalf("根目录内路径应放行: %v", err)
	}
	if got != inside {
		t.Fatalf("path = %q, want %q", got, inside)
	}

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSpecPath(outside); err == nil {
		t.Fatal("根目录外绝对路径应被拒绝（防任意文件读取）")
	}
	if _, err := resolveSpecPath(filepath.Join(root, "..", "x.json")); err == nil {
		t.Fatal("../ 穿越应被拒绝")
	}
	if _, err := resolveSpecPath(root); err == nil {
		t.Fatal("根目录本身（是目录）应被拒绝")
	}
}
