// G09 回归：业务逻辑探测计划（默认 dry-run / 上限）、异常判定、
// 显式允许执行与只用无害值。
package dast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// logicTestFetcher 基于 httptest 的 Fetcher 实现（记录请求数）。
type logicTestFetcher struct {
	posts, gets int32
}

func readResp(resp *http.Response) *Resp {
	if resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	headers := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(body)}
}

func (f *logicTestFetcher) GetSmall(rawURL string) *Resp {
	atomic.AddInt32(&f.gets, 1)
	resp, err := http.Get(rawURL)
	if err != nil {
		return nil
	}
	return readResp(resp)
}

func (f *logicTestFetcher) PostFormSmall(rawURL string, data map[string]string) *Resp {
	atomic.AddInt32(&f.posts, 1)
	v := url.Values{}
	for k, val := range data {
		v.Set(k, val)
	}
	resp, err := http.PostForm(rawURL, v)
	if err != nil {
		return nil
	}
	return readResp(resp)
}

func (f *logicTestFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *logicTestFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// logicExampleTarget 覆盖全部四类的显式允许端点。
func logicExampleTarget(rawURL string, allowWrite bool) BizTarget {
	return BizTarget{
		Method: "POST", URL: rawURL,
		Fields: map[string]string{
			"qty":    "1",
			"price":  "100",
			"coupon": "COUPON-1",
			"idem":   "IDEM-1",
		},
		QuantityField: "qty", PriceField: "price",
		CouponField: "coupon", IdempotencyField: "idem",
		AllowWrite: allowWrite,
	}
}

func planClasses(plan []LogicProbe) map[string]int {
	m := map[string]int{}
	for _, p := range plan {
		m[p.Class]++
	}
	return m
}

// TestBuildLogicPlanDryRunCaps 计划生成：四类齐全、每类 ≤2、总数 ≤8、
// replay 可复制、不改调用方字段。
func TestBuildLogicPlanDryRunCaps(t *testing.T) {
	target := logicExampleTarget("https://shop.example/cart", true)
	plan := BuildLogicPlan([]BizTarget{target}, LogicOptions{})
	classes := planClasses(plan)
	if classes[LogicClassQuantity] != 2 || classes[LogicClassPrice] != 2 ||
		classes[LogicClassCoupon] != 1 || classes[LogicClassRace] != 1 {
		t.Fatalf("计划类别数异常：%v（plan=%+v）", classes, plan)
	}
	if len(plan) > defaultLogicMaxProbes {
		t.Fatalf("计划总数 %d 超过默认上限 %d", len(plan), defaultLogicMaxProbes)
	}
	for _, p := range plan {
		if p.Replay == "" || !strings.HasPrefix(p.Replay, "curl ") {
			t.Errorf("探针缺可复制 replay：%+v", p)
		}
		if p.Baseline == nil || p.Baseline[target.QuantityField] == "" {
			t.Errorf("探针缺基线字段：%+v", p)
		}
		if p.Class == LogicClassQuantity && p.Value != "-1" && p.Value != "999999999" {
			t.Errorf("数量探针值异常：%q", p.Value)
		}
		if p.Class == LogicClassPrice && p.Value != "0.01" && p.Value != "1" {
			t.Errorf("价格探针值异常：%q", p.Value)
		}
	}
	// 调用方字段不被改写（探针字段是副本）
	if target.Fields["qty"] != "1" {
		t.Fatalf("基线字段被改写：%v", target.Fields)
	}
	// 无字段/空 URL 不生成计划
	if got := BuildLogicPlan([]BizTarget{{URL: "https://x/"}}, LogicOptions{}); len(got) != 0 {
		t.Fatalf("无字段端点不应生成计划：%+v", got)
	}
	if got := BuildLogicPlan([]BizTarget{{Fields: map[string]string{"qty": "1"}, QuantityField: "qty"}}, LogicOptions{}); len(got) != 0 {
		t.Fatalf("空 URL 不应生成计划：%+v", got)
	}
}

// TestBuildLogicPlanCaps 每类/总数上限可调小（不能突破硬上限 2）。
func TestBuildLogicPlanCaps(t *testing.T) {
	target := logicExampleTarget("https://shop.example/cart", true)
	plan := BuildLogicPlan([]BizTarget{target}, LogicOptions{MaxPerClass: 1})
	if c := planClasses(plan); c[LogicClassQuantity] != 1 || c[LogicClassPrice] != 1 {
		t.Fatalf("MaxPerClass=1 未生效：%v", c)
	}
	plan = BuildLogicPlan([]BizTarget{target}, LogicOptions{MaxProbes: 2})
	if len(plan) != 2 {
		t.Fatalf("MaxProbes=2 未生效：len=%d", len(plan))
	}
	// 硬上限：配置 99 也只能每类 2
	plan = BuildLogicPlan([]BizTarget{target}, LogicOptions{MaxPerClass: 99})
	if c := planClasses(plan); c[LogicClassQuantity] > hardLogicMaxPerClass {
		t.Fatalf("每类硬上限被突破：%v", c)
	}
}

// TestRunLogicDefaultDryRun 默认 dry-run：不发任何请求、无发现。
func TestRunLogicDefaultDryRun(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte("order created"))
	}))
	defer srv.Close()

	f := &logicTestFetcher{}
	hits := RunLogic(f, []BizTarget{logicExampleTarget(srv.URL, true)}, LogicOptions{})
	if len(hits) != 0 {
		t.Fatalf("dry-run 不应有发现：%+v", hits)
	}
	if n := atomic.LoadInt32(&requests) + atomic.LoadInt32(&f.posts) + atomic.LoadInt32(&f.gets); n != 0 {
		t.Fatalf("dry-run 不应发请求，实际 %d", n)
	}
}

// TestRunLogicTargetNotAllowed 端点未显式允许：即使 AllowWrites=true 也不发请求。
func TestRunLogicTargetNotAllowed(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte("order created"))
	}))
	defer srv.Close()

	hits := RunLogic(&logicTestFetcher{}, []BizTarget{logicExampleTarget(srv.URL, false)},
		LogicOptions{AllowWrites: true})
	if len(hits) != 0 || atomic.LoadInt32(&requests) != 0 {
		t.Fatalf("未允许端点不应执行：hits=%d requests=%d", len(hits), requests)
	}
}

// TestRunLogicQuantityAnomaly 负数量/超大数量被受理 → biz-quantity 命中；
// 请求数 = 基线 1 + 计划内数量探针 2。
func TestRunLogicQuantityAnomaly(t *testing.T) {
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		qty := r.FormValue("qty")
		if qty == "1" {
			_, _ = w.Write([]byte("order created total ¥100"))
			return
		}
		_, _ = w.Write([]byte("order created")) // 未校验数量边界
	}))
	defer srv.Close()

	target := BizTarget{Method: "POST", URL: srv.URL, Fields: map[string]string{"qty": "1"},
		QuantityField: "qty", AllowWrite: true}
	hits := RunLogic(&logicTestFetcher{}, []BizTarget{target}, LogicOptions{AllowWrites: true})
	if len(hits) != 2 {
		t.Fatalf("应命中 2 条数量异常，实际 %d：%+v", len(hits), hits)
	}
	for _, h := range hits {
		if h.Check != "biz-quantity" || h.Severity != "medium" ||
			h.Replay == "" || h.Request == "" || h.Evidence == "" {
			t.Fatalf("命中字段不完整：%+v", h)
		}
	}
	if got := atomic.LoadInt32(&posts); got != 3 { // 基线 1 + 2 探针
		t.Fatalf("请求数 = %d，期望 3（基线+每类上限 2）", got)
	}
}

// TestRunLogicQuantityRejected 服务端校验拒绝时不得误报。
func TestRunLogicQuantityRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("qty") == "1" {
			_, _ = w.Write([]byte("order created"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid quantity: must be positive"))
	}))
	defer srv.Close()

	target := BizTarget{Method: "POST", URL: srv.URL, Fields: map[string]string{"qty": "1"},
		QuantityField: "qty", AllowWrite: true}
	hits := RunLogic(&logicTestFetcher{}, []BizTarget{target}, LogicOptions{AllowWrites: true})
	if len(hits) != 0 {
		t.Fatalf("校验拒绝不应命中：%+v", hits)
	}
}

// TestRunLogicPriceAnomaly 价格篡改被受理且金额下降 → biz-price（high）。
func TestRunLogicPriceAnomaly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		price := r.FormValue("price")
		if price == "100" {
			_, _ = w.Write([]byte("order created total ¥100.00"))
			return
		}
		_, _ = w.Write([]byte("order created total ¥" + price))
	}))
	defer srv.Close()

	target := BizTarget{Method: "POST", URL: srv.URL,
		Fields: map[string]string{"price": "100"}, PriceField: "price", AllowWrite: true}
	hits := RunLogic(&logicTestFetcher{}, []BizTarget{target}, LogicOptions{AllowWrites: true})
	if len(hits) == 0 {
		t.Fatal("价格篡改应命中")
	}
	for _, h := range hits {
		if h.Check != "biz-price" || h.Severity != "high" ||
			!strings.Contains(h.Evidence, "金额") {
			t.Fatalf("价格命中字段异常：%+v", h)
		}
	}
}

// TestRunLogicCouponReplay 优惠券重放：服务端拒绝（已使用）不报；
// 重复受理则报 biz-coupon。
func TestRunLogicCouponReplay(t *testing.T) {
	couponTarget := func(rawURL string) BizTarget {
		return BizTarget{Method: "POST", URL: rawURL,
			Fields: map[string]string{"coupon": "COUPON-1"}, CouponField: "coupon", AllowWrite: true}
	}
	// 严格服务端：第二次返回已使用
	strict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("coupon already used"))
	}))
	defer strict.Close()
	hits := RunLogic(&logicTestFetcher{}, []BizTarget{couponTarget(strict.URL)},
		LogicOptions{AllowWrites: true})
	if len(hits) != 0 {
		t.Fatalf("优惠券已使用不应命中：%+v", hits)
	}
	// 脆弱服务端：重复受理
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("order created"))
	}))
	defer vuln.Close()
	hits = RunLogic(&logicTestFetcher{}, []BizTarget{couponTarget(vuln.URL)},
		LogicOptions{AllowWrites: true})
	if len(hits) != 1 || hits[0].Check != "biz-coupon" {
		t.Fatalf("优惠券重放应命中：%+v", hits)
	}
}

// TestRunLogicIdempotencyAnomaly 同一幂等键重复提交均受理且响应不同 → biz-race。
func TestRunLogicIdempotencyAnomaly(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddInt32(&n, 1)
		_, _ = w.Write([]byte("order created order id " + string(rune('0'+id))))
	}))
	defer srv.Close()

	target := BizTarget{Method: "POST", URL: srv.URL,
		Fields: map[string]string{"idem": "IDEM-1"}, IdempotencyField: "idem", AllowWrite: true}
	hits := RunLogic(&logicTestFetcher{}, []BizTarget{target}, LogicOptions{AllowWrites: true})
	if len(hits) != 1 || hits[0].Check != "biz-race" || hits[0].Severity != "high" {
		t.Fatalf("幂等失效应命中：%+v", hits)
	}

	// 幂等生效：两次响应一致 → 不报
	strictN := int32(0)
	strict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&strictN, 1)
		_, _ = w.Write([]byte("order created order id 1"))
	}))
	defer strict.Close()
	hits = RunLogic(&logicTestFetcher{}, []BizTarget{{Method: "POST", URL: strict.URL,
		Fields: map[string]string{"idem": "IDEM-1"}, IdempotencyField: "idem", AllowWrite: true}},
		LogicOptions{AllowWrites: true})
	if len(hits) != 0 {
		t.Fatalf("幂等生效不应命中：%+v", hits)
	}
}

// TestExtractAmounts 金额提取（货币符号/单位/两位小数）。
func TestExtractAmounts(t *testing.T) {
	cases := map[string][]float64{
		"total ¥100.00":       {100},
		"金额 ￥1,234.50 元":      {1234.5},
		"price usd 99.9":      {99.9},
		"no money here":       nil,
		"only digits 123456":  nil, // 无小数/货币标记不当金额
		"mixed ¥0.01 and $88": {0.01, 88},
	}
	for body, want := range cases {
		got := ExtractAmounts(body)
		if len(got) != len(want) {
			t.Errorf("ExtractAmounts(%q) = %v，期望 %v", body, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("ExtractAmounts(%q)[%d] = %v，期望 %v", body, i, got[i], want[i])
			}
		}
	}
}

// TestJudgeLogicAnomalyNilSafety 空响应判定安全（不 panic、不命中）。
func TestJudgeLogicAnomalyNilSafety(t *testing.T) {
	for _, class := range []string{LogicClassQuantity, LogicClassPrice, LogicClassCoupon, LogicClassRace} {
		if ok, _ := JudgeLogicAnomaly(class, nil, nil, "-1"); ok {
			t.Errorf("%s 空响应不应命中", class)
		}
		if ok, _ := JudgeLogicAnomaly("unknown", nil, nil, ""); ok {
			t.Error("未知类别不应命中")
		}
	}
}
