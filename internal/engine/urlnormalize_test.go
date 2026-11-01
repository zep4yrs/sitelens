package engine

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// URL 自动修正接入扫描入口：脏输入（hxxp + 末尾中文句号）应被归一化后真实扫描，
// 并在结果 extras 留痕，供前端/报告回显。
func TestScanAppliesURLNormalize(t *testing.T) {
	srv := newEngineSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	e := New(cfg, loadMatcher(t), nil)

	dirty := "hxxp://" + strings.TrimPrefix(srv.URL, "http://") + "。"
	res := e.Scan(dirty, Options{Passive: true, Checks: "none"}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错: %s", res.Error)
	}
	if res.Status != 200 {
		t.Fatalf("归一化后应真实命中目标，status=%d", res.Status)
	}

	raw, _ := res.Extras["url_input"].(string)
	if raw != dirty {
		t.Fatalf("url_input = %q, want %q", raw, dirty)
	}
	norm, _ := res.Extras["url_normalized"].(string)
	if norm != srv.URL {
		t.Fatalf("url_normalized = %q, want %q", norm, srv.URL)
	}
	corr, ok := res.Extras["url_corrections"].([]string)
	if !ok || len(corr) == 0 {
		t.Fatalf("url_corrections 缺失或类型错误: %v", res.Extras["url_corrections"])
	}
	joined := strings.Join(corr, "｜")
	if !strings.Contains(joined, "hxxp") || !strings.Contains(joined, "末尾标点") {
		t.Fatalf("修正说明不完整: %v", corr)
	}
}

// 关闭 auto_normalize 时必须回到旧行为：hxxp 直接拒绝，不做任何修正。
func TestScanURLNormalizeCanBeDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Target.AutoNormalize = false
	e := New(cfg, loadMatcher(t), nil)

	res := e.Scan("hxxp://127.0.0.1:1", Options{Passive: true, Checks: "none"}, nil, nil)
	if !strings.Contains(res.Error, "仅支持 http/https") {
		t.Fatalf("关闭归一化后应拒绝 hxxp，实际 error=%q", res.Error)
	}
	if _, ok := res.Extras["url_corrections"]; ok {
		t.Fatalf("关闭归一化后不应产生修正留痕: %v", res.Extras)
	}
}

// 预检缓存 key 必须先做输入修正，否则 hxxp/[.]/全角等写法会绕过 30s 去重。
func TestNormalizePreflightURLAppliesInputCorrection(t *testing.T) {
	dirty := NormalizePreflightURL("hxxp://Example[.]COM/path#frag")
	clean := NormalizePreflightURL("http://example.com/path")
	if dirty != clean {
		t.Fatalf("预检 key 未归一化: dirty=%q clean=%q", dirty, clean)
	}
}

// 预检响应也要带修正字段，供前端建议卡/扫描计划展示。
func TestPreflightReportsURLCorrections(t *testing.T) {
	srv := newEngineSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	e := New(cfg, loadMatcher(t), nil)

	dirty := "hxxp://" + strings.TrimPrefix(srv.URL, "http://") + "。"
	pf, err := e.Preflight(dirty, Options{})
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if pf.InputURL != dirty {
		t.Fatalf("InputURL = %q, want %q", pf.InputURL, dirty)
	}
	if pf.NormalizedURL != srv.URL {
		t.Fatalf("NormalizedURL = %q, want %q", pf.NormalizedURL, srv.URL)
	}
	if len(pf.URLCorrections) == 0 {
		t.Fatalf("URLCorrections 为空: %+v", pf)
	}
	if pf.Status != 200 {
		t.Fatalf("预检 status = %d", pf.Status)
	}
}
