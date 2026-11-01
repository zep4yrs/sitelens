// G09/G10 接线回归：开关默认全关（零请求零输出）、deser/proto 发现、
// logic/upload dry-run 只出计划、无会话跳过 IDOR。
package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
)

// webAdvancedConfig 基线配置：本机靶场、无限速、精简 DAST（测试确定性）。
func webAdvancedConfig() *config.Config {
	cfg := config.Default()
	cfg.Target.AllowPrivate = true
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.DAST.MaxParams = 1
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	cfg.DAST.DeepProbes = false
	cfg.DAST.UploadBypass = false
	cfg.DAST.MaxProbesPerClass = 1
	return cfg
}

// webAdvancedExtras 读取 res.Extras["web_advanced"]。
func webAdvancedExtras(t *testing.T, res *Result) map[string]any {
	t.Helper()
	raw, ok := res.Extras["web_advanced"]
	if !ok {
		t.Fatalf("缺少 extras.web_advanced：%v", res.Extras)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("web_advanced 类型异常：%T", raw)
	}
	return m
}

// hasVerifiedCheck 是否包含指定 check 的 verified 条目。
func hasVerifiedCheck(res *Result, check string) (map[string]any, bool) {
	for _, v := range res.Verified {
		if c, _ := v["check"].(string); c == check {
			return v, true
		}
	}
	return nil, false
}

// TestWebAdvancedSwitchesOffNoWork 全关时 runWebAdvanced 立即返回：零请求、
// 零输出（nil client 不会被解引用）。
func TestWebAdvancedSwitchesOffNoWork(t *testing.T) {
	cfg := webAdvancedConfig()
	if cfg.DAST.Proto || cfg.DAST.Deser || cfg.DAST.Logic || cfg.DAST.Upload || cfg.DAST.IDOR {
		t.Fatal("默认配置应全关")
	}
	e := New(cfg, nil, nil)
	res := &Result{Extras: map[string]any{}}
	e.runWebAdvanced(nil, nil, nil, nil, nil, "http://example.com", res, Options{}, nil, nil, nil, nil)
	if _, ok := res.Extras["web_advanced"]; ok {
		t.Fatal("全关时不应写 web_advanced")
	}
	if len(res.Verified) != 0 {
		t.Fatalf("全关时不应产生 verified：%v", res.Verified)
	}
}

// TestWebAdvancedDeserFinding 开启 deser：对已抓取页面识别 __VIEWSTATE 标记，
// 输出低危入口面 Finding（零额外请求：与关闭时请求数一致）。
func TestWebAdvancedDeserFinding(t *testing.T) {
	page := `<html><body><form><input type="hidden" name="__VIEWSTATE" value="x" /></form></body></html>`
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	// 关闭：请求数基线
	offCfg := webAdvancedConfig()
	New(offCfg, nil, nil).Scan(srv.URL+"/", Options{DAST: true}, nil, nil)
	off := atomic.SwapInt32(&requests, 0)

	// 开启：有 deser Finding，请求数与关闭一致（纯识别）
	onCfg := webAdvancedConfig()
	onCfg.DAST.Deser = true
	res := New(onCfg, nil, nil).Scan(srv.URL+"/", Options{DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	v, ok := hasVerifiedCheck(res, "deser-surface-dotnet")
	if !ok {
		t.Fatalf("未产出 deser-surface-dotnet：%v", res.Verified)
	}
	for _, key := range []string{"check", "title", "severity", "url", "evidence"} {
		if s, _ := v[key].(string); s == "" {
			t.Fatalf("Finding 缺统一字段 %s：%v", key, v)
		}
	}
	if src, _ := v["src"].(string); src != "dast" {
		t.Fatalf("src 应为 dast：%q", src)
	}
	if on := atomic.LoadInt32(&requests); on != off {
		t.Fatalf("deser 不应新增请求：off=%d on=%d", off, on)
	}
	info := webAdvancedExtras(t, res)
	if n, _ := info["deser_findings"].(int); n == 0 {
		t.Fatalf("deser_findings 计数异常：%v", info)
	}
}

// TestWebAdvancedProtoFinding 开启 proto：入口 URL 的 h2c Upgrade 被接受时
// 产出 proto-h2c-enabled（统一 Finding 字段）。
func TestWebAdvancedProtoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "h2c") {
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "h2c")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	cfg := webAdvancedConfig()
	cfg.DAST.Proto = true
	res := New(cfg, nil, nil).Scan(srv.URL+"/", Options{DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	v, ok := hasVerifiedCheck(res, "proto-h2c-enabled")
	if !ok {
		t.Fatalf("未产出 proto-h2c-enabled：%v", res.Verified)
	}
	for _, key := range []string{"check", "title", "severity", "url", "evidence"} {
		if s, _ := v[key].(string); s == "" {
			t.Fatalf("proto Finding 缺统一字段 %s：%v", key, v)
		}
	}
	info := webAdvancedExtras(t, res)
	if n, _ := info["proto_findings"].(int); n != 1 {
		t.Fatalf("proto_findings = %v，期望 1", info["proto_findings"])
	}
}

// TestWebAdvancedDryRunPlans 开启 logic/upload：只生成计划写入
// extras.web_advanced，不执行（无 biz-* 发现、进阶面请求数 0）。
func TestWebAdvancedDryRunPlans(t *testing.T) {
	page := `<html><body><form action="/cart" method="post">
		<input name="qty" value="1">
		<input name="price" value="100">
		<input name="coupon" value="C1">
		<input name="idempotency_key" value="ID1">
		<input type="file" name="upload">
		<input type="submit" value="buy">
	</form></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	cfg := webAdvancedConfig()
	cfg.DAST.Logic = true
	cfg.DAST.Upload = true
	res := New(cfg, nil, nil).Scan(srv.URL+"/", Options{DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	info := webAdvancedExtras(t, res)
	if dry, _ := info["dry_run"].(bool); !dry {
		t.Fatalf("dry_run 标记异常：%v", info)
	}
	if reqs, _ := info["requests"].(int); reqs != 0 {
		t.Fatalf("dry-run 进阶面不应有请求：%d", reqs)
	}
	plan, ok := info["logic"].([]dast.LogicProbe)
	if !ok || len(plan) == 0 {
		t.Fatalf("logic 计划缺失/类型异常：%T %v", info["logic"], info["logic"])
	}
	classes := map[string]bool{}
	for _, p := range plan {
		classes[p.Class] = true
		if p.Replay == "" {
			t.Errorf("计划缺 replay：%+v", p)
		}
	}
	for _, want := range []string{dast.LogicClassQuantity, dast.LogicClassPrice, dast.LogicClassCoupon, dast.LogicClassRace} {
		if !classes[want] {
			t.Errorf("计划缺少 %s 类：%v", want, classes)
		}
	}
	up, ok := info["upload"].(dast.UploadPlan)
	if !ok || !up.DryRun || up.Endpoint == "" || up.FieldName != "upload" {
		t.Fatalf("upload 计划异常：%T %+v", info["upload"], info["upload"])
	}
	for _, v := range res.Verified {
		if c, _ := v["check"].(string); strings.HasPrefix(c, "biz-") {
			t.Fatalf("dry-run 不应执行逻辑探测：%v", v)
		}
	}
}

// TestWebAdvancedIDORSkipsWithoutSessions 开启 idor 但无 Sessions：跳过且零请求。
func TestWebAdvancedIDORSkipsWithoutSessions(t *testing.T) {
	page := `<html><body><a href="/user/1">u1</a><a href="/user/2">u2</a></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	cfg := webAdvancedConfig()
	cfg.DAST.IDOR = true
	res := New(cfg, nil, nil).Scan(srv.URL+"/", Options{DAST: true}, nil, nil)
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	info := webAdvancedExtras(t, res)
	if got, _ := info["idor"].(string); got != "skipped: no sessions" {
		t.Fatalf("无会话应跳过 IDOR：%v", info["idor"])
	}
	if reqs, _ := info["requests"].(int); reqs != 0 {
		t.Fatalf("跳过 IDOR 不应有请求：%d", reqs)
	}
	for _, v := range res.Verified {
		if c, _ := v["check"].(string); strings.HasPrefix(c, "idor-") {
			t.Fatalf("无会话不应有 IDOR 发现：%v", v)
		}
	}
}

// TestIDORTemplatesFromLinks 纯函数：同域数字 ID 链接 → {id} 模板、去重、限 5 条。
func TestIDORTemplatesFromLinks(t *testing.T) {
	links := []string{
		"http://t.example/user/1", "http://t.example/user/2",
		"http://t.example/order/99/edit", "http://other.example/user/3",
		"http://t.example/user/7", "http://t.example/a/1", "http://t.example/b/2",
		"http://t.example/c/3", "http://t.example/d/4",
	}
	got := idorTemplatesFromLinks(links, "http://t.example/")
	if len(got) != 5 {
		t.Fatalf("模板数 = %d，期望 5：%v", len(got), got)
	}
	if got[0] != "/user/{id}" || got[1] != "/order/{id}/edit" {
		t.Fatalf("模板推导异常：%v", got)
	}
	if got := idorTemplatesFromLinks(nil, "http://t.example/"); got != nil {
		t.Fatalf("空链接应返回 nil：%v", got)
	}
}

// TestBuildLogicTargetsClassify 纯函数：字段名启发式分类 + AllowWrite 恒 false。
func TestBuildLogicTargetsClassify(t *testing.T) {
	forms := []dast.FormTarget{
		{Method: "post", Action: "http://t.example/cart",
			Fields: []string{"qty", "price", "coupon", "idempotency_key", "note"}},
		{Method: "post", Action: "http://t.example/cart", Fields: []string{"qty"}}, // 去重
		{Action: "", Fields: []string{"qty"}},                                      // 空 action 跳过
	}
	targets := buildLogicTargets(forms)
	if len(targets) != 1 {
		t.Fatalf("targets = %d，期望 1：%+v", len(targets), targets)
	}
	tg := targets[0]
	if tg.AllowWrite || tg.Method != "POST" || tg.URL != "http://t.example/cart" {
		t.Fatalf("BizTarget 基础字段异常：%+v", tg)
	}
	if tg.QuantityField != "qty" || tg.PriceField != "price" ||
		tg.CouponField != "coupon" || tg.IdempotencyField != "idempotency_key" {
		t.Fatalf("字段分类异常：%+v", tg)
	}
	// 没有文件字段 → 无上传计划
	if _, ok := buildUploadPlan(forms); ok {
		t.Fatal("无文件字段不应生成上传计划")
	}
	upForms := []dast.FormTarget{{Action: "http://t.example/upload", Fields: []string{"csrf"}, FileFields: []string{"file"}}}
	up, ok := buildUploadPlan(upForms)
	if !ok || !up.DryRun || up.Endpoint != "http://t.example/upload" || up.FieldName != "file" {
		t.Fatalf("上传计划异常：%+v ok=%v", up, ok)
	}
}
