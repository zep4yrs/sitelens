package dast

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeFetch 按注册规则响应探测请求；未命中规则时回显参数值（模拟反射页面）。
type fakeFetch struct {
	rules     []func(u string) *Resp
	postRules []func(u string, data map[string]string) *Resp
	delay     time.Duration
	request   int
}

func (f *fakeFetch) GetSmall(rawURL string) *Resp {
	f.request++
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	for _, r := range f.rules {
		if resp := r(rawURL); resp != nil {
			return resp
		}
	}
	if u, err := url.Parse(rawURL); err == nil && u.RawQuery != "" {
		var parts []string
		for k, vs := range u.Query() {
			parts = append(parts, k+"="+strings.Join(vs, ","))
		}
		return &Resp{Status: 200, Body: "<html>q=" + strings.Join(parts, "&") + "</html>"}
	}
	return &Resp{Status: 200, Body: "<html>index</html>"}
}

// PostFormSmall 表单探测桩：回显全部字段值（不转义 → XSS/报错注入可命中），
// postRules 注册的规则优先。
func (f *fakeFetch) PostFormSmall(rawURL string, data map[string]string) *Resp {
	f.request++
	for _, r := range f.postRules {
		if resp := r(rawURL, data); resp != nil {
			return resp
		}
	}
	var parts []string
	for k, v := range data {
		parts = append(parts, k+"="+v)
	}
	return &Resp{Status: 200, Body: "<html>f=" + strings.Join(parts, "&") + "</html>"}
}

func newRunner(f Fetcher) *Runner {
	r := New(f, DefaultOptions())
	return r
}

func TestCollectParams(t *testing.T) {
	links := []string{
		"https://a.com/list?page=1&q=x",
		"https://a.com/list?page=2",       // page 重复：去重
		"https://a.com/list?page=3&cat=5", // cat 新参数
		"https://b.com/search?kw=z",       // 不同主机
		"https://c.com/noparam",           // 无参数：跳过
		"://bad",                          // 解析失败：跳过
	}
	targets := collectParams(links, 100)
	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.Param] = true
	}
	if len(targets) != 4 || !got["page"] || !got["q"] || !got["cat"] || !got["kw"] {
		t.Fatalf("collectParams 去重/过滤失败: %+v", targets)
	}
	capped := collectParams(links, 2)
	if len(capped) != 2 {
		t.Fatalf("cap 上限未生效: %+v", capped)
	}
}

func TestSetParamKeepsOthers(t *testing.T) {
	out := setParam("https://a.com/p?x=1&y=2", "y", "INJ")
	if !strings.Contains(out, "x=1") || !strings.Contains(out, "y=INJ") {
		t.Fatalf("setParam 应保留其余参数: %s", out)
	}
}

func TestXSSReflected(t *testing.T) {
	hits := newRunner(&fakeFetch{}).Run([]string{"https://a.com/list?q=1"})
	found := false
	for _, h := range hits {
		if h.Check == "xss-reflect" && h.Param == "q" {
			found = true
		}
	}
	if !found {
		t.Fatalf("反射 XSS 未命中: %+v", hits)
	}
}

func TestSQLiBaselineSuppression(t *testing.T) {
	// 页面本来就含 "postgresql"：注入单引号不应命中（基线剔除）
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			return &Resp{Status: 200, Body: "powered by postgresql v15"}
		},
	}}
	hits := newRunner(f).Run([]string{"https://a.com/list?id=1"})
	for _, h := range hits {
		if h.Check == "sqli-error" {
			t.Fatalf("基线已有特征不应命中: %+v", h)
		}
	}
	// 基线干净、注入后报错：应命中
	f2 := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "%27") || strings.Contains(u, "'") {
				return &Resp{Status: 500, Body: "Warning: mysql_fetch_array() expects"}
			}
			return nil
		},
	}}
	hits = newRunner(f2).Run([]string{"https://a.com/list?id=1"})
	ok := false
	for _, h := range hits {
		if h.Check == "sqli-error" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("报错 SQLi 未命中: %+v", hits)
	}
}

func TestOpenRedirect(t *testing.T) {
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "sitelens-dt.example.com") {
				return &Resp{Status: 302,
					Headers: map[string]string{"Location": "https://sitelens-dt.example.com/ok"},
					Body:    ""}
			}
			return nil
		},
	}}
	hits := newRunner(f).Run([]string{"https://a.com/go?to=/home"})
	ok := false
	for _, h := range hits {
		if h.Check == "open-redirect" && h.Severity == "medium" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("开放重定向未命中: %+v", hits)
	}
}

func TestTraversalBaseline(t *testing.T) {
	// 回显 ../ 但不回显文件内容：不命中（正文无 root:x:0:0:）
	hits := newRunner(&fakeFetch{}).Run([]string{"https://a.com/dl?f=readme.txt"})
	for _, h := range hits {
		if h.Check == "lfi-passwd" {
			t.Fatalf("无文件内容不应命中遍历: %+v", h)
		}
	}
	// 注入后返回 passwd 内容：命中
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "etc%2Fpasswd") || strings.Contains(u, "etc/passwd") {
				return &Resp{Status: 200, Body: "root:x:0:0:root:/root:/bin/bash"}
			}
			return nil
		},
	}}
	hits = newRunner(f).Run([]string{"https://a.com/dl?f=readme.txt"})
	ok := false
	for _, h := range hits {
		if h.Check == "lfi-passwd" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("目录遍历未命中: %+v", hits)
	}
}

func TestTimeBlindDoubleConfirm(t *testing.T) {
	// 注入 SLEEP 后延迟超过阈值且复测一致 → 命中；基线快（0 延迟）
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "SLEEP") {
				return &Resp{Status: 200, Body: "ok"}
			}
			return nil
		},
	}}
	f.delay = 20 * time.Millisecond // 全局慢一点，SLEEP 无额外延迟 → 不该命中
	opts := DefaultOptions()
	opts.BlindThresholdMS = 100
	hits := New(f, opts).Run([]string{"https://a.com/list?id=1"})
	for _, h := range hits {
		if h.Check == "sqli-blind-time" {
			t.Fatalf("未注入延迟不应命中盲注: %+v", h)
		}
	}
}

func TestCancelStops(t *testing.T) {
	calls := 0
	r := newRunner(&fakeFetch{})
	r.SetCancel(func() bool { calls++; return calls > 2 })
	hits := r.Run([]string{
		"https://a.com/a?x=1", "https://a.com/b?y=1", "https://a.com/c?z=1",
	})
	_ = hits // 取消后应提前返回，不 panic 即可
}

func TestMaxParamsCap(t *testing.T) {
	f := &fakeFetch{}
	opts := DefaultOptions()
	opts.MaxParams = 1
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).Run([]string{
		"https://a.com/a?x=1", "https://a.com/b?y=1",
	})
	// 1 目标 × （基线 1 + 四类探针序列 + 反序列化 1 + 深度探测面预算）；
	// 探针序列条数受常量控制，这里只断言「上限生效」而非写死数值。
	// 预算口径收敛到 maxURLRequestsPerParam（与生产同源，避免两处漂移）。
	capN := maxURLRequestsPerParam(opts)
	if f.request > capN {
		t.Fatalf("MaxParams=1 应只探测 1 个参数（≤%d 请求），实际 %d", capN, f.request)
	}
	if f.request <= 1 {
		t.Fatalf("应至少发出探测请求，实际 %d", f.request)
	}
	_ = hits
}

// TestRunFormsReflectXSS 表单字段反射型 XSS：注入标记未经转义回显即命中。
func TestRunFormsReflectXSS(t *testing.T) {
	f := &fakeFetch{}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/search", Fields: []string{"q", "cat"}},
	})
	if len(hits) == 0 {
		t.Fatalf("反射 XSS 应命中（桩回显不转义）: %v", hits)
	}
	found := false
	for _, h := range hits {
		if h.Param == "q" && h.Check == "xss-reflect" {
			found = true
		}
	}
	if !found {
		t.Fatalf("q 字段的 XSS 命中缺失: %+v", hits)
	}
}

// TestRunFormsBudget 字段预算：MaxParams=1 时多字段表单只探测 1 个字段。
func TestRunFormsBudget(t *testing.T) {
	f := &fakeFetch{}
	opts := DefaultOptions()
	opts.MaxParams = 1
	opts.TimeBlind = false
	opts.BoolBlind = false
	hits := New(f, opts).RunForms([]FormTarget{
		{Action: "https://a.com/reg", Fields: []string{"u", "e", "n"}},
	})
	// 1 字段 × （基线 1 + 四类探针序列 + 表单侧深度面 + 布尔盲注）；预算生效即不超过。
	// 预算口径收敛到 maxFormRequestsPerField（与生产同源）。
	capN := maxFormRequestsPerField(opts)
	if f.request > capN {
		t.Fatalf("MaxParams=1 应只探测 1 字段（≤%d 请求），实际 %d", capN, f.request)
	}
	_ = hits
}

// TestRunFormsBaselineError 页面天然报错特征不算命中（基线求差语义）。
func TestRunFormsBaselineError(t *testing.T) {
	f := &fakeFetch{postRules: []func(u string, data map[string]string) *Resp{
		func(u string, data map[string]string) *Resp {
			// 无论注入什么都返回含 SQL 报错特征的页面
			return &Resp{Status: 200, Body: "<html>mysql_fetch error always</html>"}
		},
	}}
	hits := newRunner(f).RunForms([]FormTarget{
		{Action: "https://a.com/l", Fields: []string{"q"}},
	})
	for _, h := range hits {
		if h.Check == "sqli-error" {
			t.Fatalf("基线已含报错特征不应命中 SQLi: %+v", hits)
		}
	}
}

// B11 复扫收口：时间盲注证据链必须与 boolBlind 同规格——
// Request（重放请求文本）此前缺失，命中时一并断言其余链字段。
func TestTimeBlindEvidenceChainComplete(t *testing.T) {
	f := &fakeFetch{rules: []func(u string) *Resp{
		func(u string) *Resp {
			if strings.Contains(u, "SLEEP") {
				time.Sleep(25 * time.Millisecond) // 仅 SLEEP 请求慢
				return &Resp{Status: 200, Body: "ok"}
			}
			return nil
		},
	}}
	opts := DefaultOptions()
	opts.BlindThresholdMS = 10
	hits := New(f, opts).Run([]string{"https://a.com/list?id=1"})
	var found *Finding
	for i := range hits {
		if hits[i].Check == "sqli-blind-time" {
			found = &hits[i]
		}
	}
	if found == nil {
		t.Fatalf("SLEEP 慢响应应命中时间盲注: %+v", hits)
	}
	if found.Request == "" || !strings.HasPrefix(found.Request, "GET ") {
		t.Fatalf("证据链缺 Request: %+v", found)
	}
	if found.Payload == "" || found.Replay == "" || found.Response == nil || len(found.Signals) == 0 {
		t.Fatalf("证据链不完整: %+v", found)
	}
}

// B19 收窗回归：取消后立即收窗，不再吃满 4s 轮询窗。
func TestSSRFProbeCancelQuick(t *testing.T) {
	r := newRunner(&fakeFetch{})
	r.opts.BeaconBase = "http://127.0.0.1:1" // 不可达 beacon，必然无回连
	r.SetCancel(func() bool { return true })
	start := time.Now()
	got := r.ssrfProbe([]Target{{URL: "https://a.com/a?x=1", Param: "x"}})
	if el := time.Since(start); el > time.Second {
		t.Fatalf("取消后应立即收窗，实际耗时 %v", el)
	}
	if len(got) != 0 {
		t.Fatalf("无回连不应出发现: %+v", got)
	}
}

// B19：未配置 beacon 时零开销直接返回，不进入轮询。
func TestSSRFProbeNoBeaconNoWait(t *testing.T) {
	r := newRunner(&fakeFetch{})
	start := time.Now()
	got := r.ssrfProbe([]Target{{URL: "https://a.com/a?x=1", Param: "x"}})
	if got != nil {
		t.Fatalf("未配置 beacon 应无发现: %+v", got)
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Fatalf("未配置 beacon 不应等待，实际 %v", el)
	}
}

// PostRawSmall 测试桩：fakeFetch 不支持原始体 POST。
func (f *fakeFetch) PostRawSmall(rawURL, contentType, body string) *Resp { return nil }

// PostMultipartSmall 测试桩：默认不支持多段上传。
func (f *fakeFetch) PostMultipartSmall(rawURL, fileField, fileName, content string, extra map[string]string) *Resp {
	return nil
}

// statusFlipFetcher 模拟 Acunetix testasp 的 Search.asp 行为：参数正常
// 时 200 且正文健康，注入引号后翻成通用 500 页（正文无任何数据库报错
// 特征）。报错特征表再宽也命不中——只能靠状态码翻转判定。
type statusFlipFetcher struct{ n int }

func (f *statusFlipFetcher) GetSmall(u string) *Resp {
	f.n++
	q := u
	if i := strings.Index(u, "?"); i >= 0 {
		q = u[i:]
	}
	decoded, _ := url.QueryUnescape(q)
	if strings.Contains(decoded, "'") {
		return &Resp{Status: 500, Body: "<title>500 - Internal server error.</title>"}
	}
	return &Resp{Status: 200, Body: "<html>search results ok</html>"}
}

func (f *statusFlipFetcher) PostFormSmall(u string, d map[string]string) *Resp {
	return &Resp{Status: 200, Body: "<html>ok</html>"}
}

func TestSQLErrorStatusFlipDetected(t *testing.T) {
	opts := DefaultOptions()
	r := New(&statusFlipFetcher{}, opts)
	hits := r.Run([]string{"http://t/Search.asp?tfSearch=forum"})
	found := false
	for _, h := range hits {
		if h.Check == "sqli-error" && h.Param == "tfSearch" {
			found = true
			if !strings.Contains(h.Evidence, "500") {
				t.Fatalf("证据应含状态码: %s", h.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("注入引号触发 500 应命中 sqli-error，实际命中 %d 条", len(hits))
	}
}

// healthyNoFlipFetcher 参数注入后仍 200：不得凭状态码误报。
type healthyNoFlipFetcher struct{}

func (f *healthyNoFlipFetcher) GetSmall(u string) *Resp {
	return &Resp{Status: 200, Body: "<html>fine</html>"}
}
func (f *healthyNoFlipFetcher) PostFormSmall(u string, d map[string]string) *Resp {
	return &Resp{Status: 200, Body: "<html>fine</html>"}
}

func TestSQLErrorStatusNoFalsePositive(t *testing.T) {
	r := New(&healthyNoFlipFetcher{}, DefaultOptions())
	for _, h := range r.Run([]string{"http://t/x?a=1"}) {
		if h.Check == "sqli-error" {
			t.Fatalf("健康站点不应命中报错 SQLi: %+v", h)
		}
	}
}

// always500Fetcher 整站 5xx：基线本身不健康，不得据此判注入。
type always500Fetcher struct{}

func (f *always500Fetcher) GetSmall(u string) *Resp {
	return &Resp{Status: 500, Body: "<html>broken</html>"}
}
func (f *always500Fetcher) PostFormSmall(u string, d map[string]string) *Resp {
	return &Resp{Status: 500, Body: "<html>broken</html>"}
}

func TestSQLErrorStatusBaselineUnhealthySkipped(t *testing.T) {
	r := New(&always500Fetcher{}, DefaultOptions())
	for _, h := range r.Run([]string{"http://t/x?a=1"}) {
		if h.Check == "sqli-error" {
			t.Fatalf("基线即 5xx 时不得报状态差分: %+v", h)
		}
	}
}

// 测试桩补齐 Fetcher 可选通道（返回 nil = 不支持，相应对探测自动跳过）。
func (f *statusFlipFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *statusFlipFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}
func (f *healthyNoFlipFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *healthyNoFlipFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}
func (f *always500Fetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *always500Fetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}
