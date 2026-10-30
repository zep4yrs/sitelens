// DAST benign 基线跨通道复用的回归测试（task-13 E2）：
//   - 同一 target 的 benign 基线 GET/POST 只实际发一次（Run baseline 与
//     deepResidual / cmdEchoInject / boolBlind / RunForms 基线共享）；
//   - payload 请求绝不复用（同一 payload URL 出现几次就发几次）；
//   - 复用 vs 不复用（baseCacheOff）命中结果逐字段一致；
//   - 表单侧多字段共享同一份 benign 基线体。
package dast

import (
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// reuseFetcher 计数桩：GET 回显 query 值（未转义 → 反射 XSS 可命中），
// POST 回显全部字段值；默认页面安全的路径（无查询）返回静态页。
type reuseFetcher struct {
	mu          sync.Mutex
	counts      map[string]int // method+"\x00"+url(or action)+"\x00"+body
	reflectBody bool           // true = 回显输入（可命中）; false = 恒定安全页
}

func newReuseFetcher(reflectBody bool) *reuseFetcher {
	return &reuseFetcher{counts: map[string]int{}, reflectBody: reflectBody}
}

func (f *reuseFetcher) note(method, u, body string) {
	f.mu.Lock()
	f.counts[method+"\x00"+u+"\x00"+body]++
	f.mu.Unlock()
}

func (f *reuseFetcher) count(method, u, body string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[method+"\x00"+u+"\x00"+body]
}

func (f *reuseFetcher) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.counts {
		n += c
	}
	return n
}

func (f *reuseFetcher) GetSmall(rawURL string) *Resp {
	f.note("GET", rawURL, "")
	if !f.reflectBody {
		return &Resp{Status: 200, Body: "<html>safe</html>"}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return &Resp{Status: 200, Body: "<html>safe</html>"}
	}
	return &Resp{Status: 200, Body: "<html>" + u.Query().Get("q") + u.Query().Get("id") + "</html>"}
}

func (f *reuseFetcher) PostFormSmall(rawURL string, data map[string]string) *Resp {
	v := url.Values{}
	for k, val := range data {
		v.Set(k, val)
	}
	f.note("POST", rawURL, v.Encode())
	if !f.reflectBody {
		return &Resp{Status: 200, Body: "<html>safe</html>"}
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("<html>")
	for _, k := range keys {
		b.WriteString(k + "=" + data[k] + "&")
	}
	b.WriteString("</html>")
	return &Resp{Status: 200, Body: b.String()}
}

func (f *reuseFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *reuseFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// quietOpts 只留参数注入通道，避免时间盲注/表单侧额外请求干扰计数。
func quietOpts() Options {
	o := DefaultOptions()
	o.TimeBlind = false
	o.BoolBlind = true
	o.CmdInject = false
	o.RandomDiff = false // 随机差分按设计需要两次真实取样，不复用
	return o
}

// TestBaselineGETReusedAcrossChannels benign 基线 GET 跨通道只发一次。
func TestBaselineGETReusedAcrossChannels(t *testing.T) {
	const base = "https://a.com/x?id=1"
	f := newReuseFetcher(false)
	New(f, quietOpts()).Run([]string{base})

	if got := f.count("GET", base, ""); got != 1 {
		t.Fatalf("benign 基线 GET 应只实际发送一次（Run/deepResidual/cmdEchoInject/boolBlind 复用），实际 %d 次", got)
	}
}

// TestPayloadNotReused payload 请求绝不复用：跨类同 payload 各发各的。
func TestPayloadNotReused(t *testing.T) {
	// sqli 类与 xpath 类都会发单引号 payload → 同一 URL 应出现 ≥2 次。
	base := "https://a.com/x?id=1"
	probeURL := setParam(base, "id", "'")
	f := newReuseFetcher(false)
	New(f, quietOpts()).Run([]string{base})
	if got := f.count("GET", probeURL, ""); got < 2 {
		t.Fatalf("payload 请求不得被复用：同一 payload URL 应至少发送 2 次（sqli+xpath），实际 %d", got)
	}
}

// TestBaselineFormReusedAcrossChannels 表单 benign 基线 POST 跨字段/通道只发一次。
func TestBaselineFormReusedAcrossChannels(t *testing.T) {
	f := newReuseFetcher(false)
	opts := quietOpts()
	r := New(f, opts)
	r.RunForms([]FormTarget{{Action: "https://a.com/f", Fields: []string{"a", "b"}}})

	baseBody := url.Values{"a": {"sl-dast-base"}, "b": {"sl-dast-base"}}.Encode()
	if got := f.count("POST", "https://a.com/f", baseBody); got != 1 {
		t.Fatalf("表单 benign 基线 POST 应跨字段/通道只发一次，实际 %d 次", got)
	}
}

// findingSig 命中签名：排除每次运行天然不同的随机标记（存储型 XSS 的
// slstored<hex>z9 标记按设计每次随机）与指针地址（Response 结构体指针），
// 其余判定要素逐字段比较。
func findingSig(f Finding) string {
	storedMarkRE := regexp.MustCompile(`slstored[0-9a-f]+z9`)
	norm := func(s string) string { return storedMarkRE.ReplaceAllString(s, "slstored<rand>z9") }
	resp := ""
	if f.Response != nil {
		resp = fmt.Sprintf("%d/%d/%s", f.Response.Status, f.Response.Size, norm(f.Response.Snippet))
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%v|%s|%s",
		f.Check, f.Title, f.Severity, f.URL, f.Param,
		norm(f.Payload), norm(f.Evidence), norm(f.Replay), norm(f.Request),
		f.Signals, resp, norm(f.Advice))
}

func findingSigs(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = findingSig(f)
	}
	return out
}

// TestBaselineReuseFindingsEquivalent 复用 vs 不复用：命中结果逐字段一致。
func TestBaselineReuseFindingsEquivalent(t *testing.T) {
	base := []string{"https://a.com/x?id=1", "https://a.com/y?q=v"}
	forms := []FormTarget{{Action: "https://a.com/f", Fields: []string{"q", "w"}}}

	run := func(off bool) []Finding {
		f := newReuseFetcher(true)
		opts := quietOpts()
		r := New(f, opts)
		r.baseCacheOff = off
		var out []Finding
		out = append(out, r.Run(base)...)
		out = append(out, r.RunForms(forms)...)
		return out
	}
	cached, nocache := findingSigs(run(false)), findingSigs(run(true))
	if !reflect.DeepEqual(cached, nocache) {
		t.Fatalf("基线复用改变了命中结果：\ncached=%v\nnocache=%v", cached, nocache)
	}
	if len(cached) == 0 {
		t.Fatal("测试桩应产生命中（反射 XSS/XSS 表单），实际 0 条")
	}
	// 复用后请求数必须严格更少（否则复用没生效）。
	fc, fn := newReuseFetcher(true), newReuseFetcher(true)
	rc := New(fc, quietOpts())
	_ = append(append([]Finding{}, rc.Run(base)...), rc.RunForms(forms)...)
	rn := New(fn, quietOpts())
	rn.baseCacheOff = true
	_ = append(append([]Finding{}, rn.Run(base)...), rn.RunForms(forms)...)
	if fc.total() >= fn.total() {
		t.Fatalf("基线复用后请求数应更少：cached=%d nocache=%d", fc.total(), fn.total())
	}
}

// TestBenignCacheUnit benignGET 基本语义（含 baseCacheOff 关闭）。
func TestBenignCacheUnit(t *testing.T) {
	f := newReuseFetcher(false)
	r := New(f, DefaultOptions())
	_ = r.benignGET("https://a.com/u?x=1")
	_ = r.benignGET("https://a.com/u?x=1")
	if got := f.count("GET", "https://a.com/u?x=1", ""); got != 1 {
		t.Fatalf("benignGET 应复用，实际请求 %d 次", got)
	}
	r.baseCacheOff = true
	_ = r.benignGET("https://a.com/u?x=1")
	if got := f.count("GET", "https://a.com/u?x=1", ""); got != 2 {
		t.Fatalf("baseCacheOff 时应直发，实际请求 %d 次（%s）", got, fmt.Sprint(f.counts))
	}
}

// TestTimedBaselineReused 时间差分通道（timeBlind / cmdInject）复用同一 benign
// 基线及其真实 RTT：原值 URL 只实际请求一次（不重复发同一请求），
// 也不会因复用把基线耗时测成 ~0（RTT 取自首次真实请求）。
func TestTimedBaselineReused(t *testing.T) {
	const base = "https://a.com/t?id=1"
	f := newReuseFetcher(false)
	opts := DefaultOptions()
	opts.RandomDiff = false // 随机差分需两次真实取样（本身不是重复请求）
	r := New(f, opts)
	r.Run([]string{base})
	if got := f.count("GET", base, ""); got != 1 {
		t.Fatalf("timeBlind/cmdInject 的 benign 基线应复用首次真实请求，实际同一 URL 请求 %d 次", got)
	}
}

// TestAuthzBaselineReused authz 通道取值 1 若等于 target 原值，复用已抓的
// benign 基线，不再重发同一 GET。
func TestAuthzBaselineReused(t *testing.T) {
	const base = "https://a.com/u?id=1"
	f := newReuseFetcher(false)
	opts := DefaultOptions()
	opts.RandomDiff = false
	opts.TimeBlind = false
	opts.CmdInject = false
	opts.AuthzBypass = true
	r := New(f, opts)
	r.Run([]string{base})
	r.RunAuthz([]string{base})
	if got := f.count("GET", base, ""); got != 1 {
		t.Fatalf("authz 取值 1 等于原值时应复用 benign 基线，实际同一 URL 请求 %d 次", got)
	}
}
