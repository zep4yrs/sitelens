package server

import "testing"

// TestAdminReleaseIntel：POST /api/admin/release-intel 释放情报常驻并返回堆指标。
func TestAdminReleaseIntel(t *testing.T) {
	_, api := newServer(t)
	code, body := postJSON(t, api.URL+"/api/admin/release-intel", `{}`)
	if code != 200 {
		t.Fatalf("release %d: %v", code, body)
	}
	if body["released"] != true {
		t.Fatalf("应返回 released=true: %v", body)
	}
	if _, ok := body["heap_before_mb"].(float64); !ok {
		t.Fatalf("缺 heap_before_mb: %v", body)
	}
	if _, ok := body["heap_after_mb"].(float64); !ok {
		t.Fatalf("缺 heap_after_mb: %v", body)
	}
	// 释放后引擎仍可用：版本端点正常（情报表会在下次访问自动重载）
	code, v := getJSON(t, api.URL+"/api/version")
	if code != 200 || v["name"] != "SiteLens" {
		t.Fatalf("释放后 version 端点异常: %v", v)
	}
}
