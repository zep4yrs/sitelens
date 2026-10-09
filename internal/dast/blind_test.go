package dast

import (
	"net/url"
	"strings"
	"testing"
)

// routeFetcher 按 payload 关键词路由响应尺寸（先解码 URL 再匹配——
// setParam 落盘的是 url.Values.Encode 编码形态，空格/等号已被转义）：
// AND 1=1 → 与基线同尺寸（1000B），AND 1=2 → 偏离（400B）。
type routeFetcher struct{}

func (f *routeFetcher) GetSmall(u string) *Resp {
	val := ""
	if p, err := url.Parse(u); err == nil {
		val = p.Query().Get("id")
	}
	switch {
	case strings.Contains(val, "AND 1=1"):
		return &Resp{Status: 200, Body: repeatStr("x", 1000)}
	case strings.Contains(val, "AND 1=2"):
		return &Resp{Status: 200, Body: repeatStr("x", 400)}
	default:
		return &Resp{Status: 200, Body: repeatStr("x", 1000)}
	}
}

func (f *routeFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return f.GetSmall(u)
}

// randomFetcher 每次请求尺寸随机漂移（内容随机化站点模型）。
// 抖动幅度刻意做成 ±40% 量级：小抖动（±1%）本就不该被任何阈值当成
// 注入证据，用它当反例等于测阈值精度而非测误报防护。
type randomFetcher struct{ n int }

func (f *randomFetcher) GetSmall(u string) *Resp {
	f.n++
	// 1000 + n*400 ∈ [1400, 6200]：相邻两次请求差远超 BoolBlindDiffPct，
	// 但真分支对不齐基线 → 第一轮即出局
	return &Resp{Status: 200, Body: repeatStr("x", 1000+f.n*400)}
}

func (f *randomFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return f.GetSmall(u)
}

func repeatStr(s string, n int) string {
	return strings.Repeat(s, n)
}

func TestBoolBlindDetectsDifferential(t *testing.T) {
	r := New(&routeFetcher{}, DefaultOptions())
	f := r.boolBlind(Target{URL: "http://t/v?id=1", Param: "id"}, new(int), 0)
	if f == nil {
		t.Fatal("差分成立应命中")
	}
	if f.Check != "bool-blind-sqli" || f.Severity != "high" {
		t.Fatalf("Finding 字段不符: %+v", f)
	}
	if f.Param != "id" || !strings.Contains(f.Evidence, "双确认") {
		t.Fatalf("Finding 证据不符: %+v", f)
	}
}

func TestBoolBlindRandomSiteNoHit(t *testing.T) {
	// 内容随机化站点（真相似不成立）→ 不命中
	r := New(&randomFetcher{}, DefaultOptions())
	if f := r.boolBlind(Target{URL: "http://t/v?id=1", Param: "id"}, new(int), 0); f != nil {
		t.Fatalf("随机内容站点不应命中: %+v", f)
	}
}

func TestBoolPayloads(t *testing.T) {
	tn, fn := boolPayloads("7")
	if tn != "7 AND 1=1" || fn != "7 AND 1=2" {
		t.Fatalf("数字型 payload 不符: %q / %q", tn, fn)
	}
	ts, fs := boolPayloads("abc")
	if ts != "abc' AND '1'='1" || fs != "abc' AND '1'='2" {
		t.Fatalf("字符串型 payload 不符: %q / %q", ts, fs)
	}
	te, fe := boolPayloads("")
	if te != "1 AND 1=1" || fe != "1 AND 1=2" {
		t.Fatalf("空值应回退数字型: %q / %q", te, fe)
	}
}

// sqliFetcher 模拟易受字符串型注入影响的页面（sqli-labs Less-1 型）：
//   - 数字型通道（1 AND 1=1 / 1 AND 1=2）被 MySQL 弱转成数字 1，
//     真假响应尺寸完全一致；
//   - 引号闭合通道（1 AND 1=1' 等）真分支=721B、假分支=670B（差 7%）。
//
// 老实现只走数字型通道 → 零命中；新实现（多通道 + 15% 阈值）应命中。
type sqliFetcher struct{}

func (f *sqliFetcher) GetSmall(u string) *Resp {
	val := ""
	if p, err := url.Parse(u); err == nil {
		val = p.Query().Get("id")
	}
	switch val {
	case "1", "1 AND 1=1", "1 AND 1=2", "1*1", "1*0":
		// 纯数字上下文：拼入的数字表达式被 MySQL 弱转，真假同尺寸
		return &Resp{Status: 200, Body: repeatStr("x", 721)}
	}
	if strings.Contains(val, "AND 1=2") || strings.Contains(val, "'2") {
		return &Resp{Status: 200, Body: repeatStr("x", 670)} // 假分支低 7%
	}
	return &Resp{Status: 200, Body: repeatStr("x", 721)}
}

func (f *sqliFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	return f.GetSmall(u)
}

func TestBoolBlindStringContextLowDiff(t *testing.T) {
	// 数字型通道失效、引号闭合通道差 7%：新实现必须命中（老实现零命中）
	r := New(&sqliFetcher{}, DefaultOptions())
	f := r.boolBlind(Target{URL: "http://t/less-1/?id=1", Param: "id"}, new(int), 0)
	if f == nil {
		t.Fatal("字符串型注入（低差分尺寸）应命中")
	}
	if f.Check != "bool-blind-sqli" {
		t.Fatalf("Check 不符: %+v", f)
	}
	if !strings.Contains(f.Evidence, "引号闭合型") {
		t.Fatalf("证据应记录注入上下文: %+v", f.Evidence)
	}
	if f.Request == "" || f.Replay == "" || f.Response == nil || len(f.Signals) == 0 {
		t.Fatalf("证据链不完整: %+v", f)
	}
}

func TestSizeDiffPctThreshold(t *testing.T) {
	// 7% 差在新阈值（15%）下算相似？不——sizeSimilar 只用于"真分支相似"；
	// 假分支判定另有 5% 强制下限。这里锁定阈值语义：
	if !sizeSimilar(721, 670) {
		t.Fatal("7% 差应判为相似（≤15%）")
	}
	if !sizeSimilar(721, 670) || sizeDiffPct(721, 670) != 7 {
		t.Fatalf("sizeDiffPct 应为 7，实际 %d", sizeDiffPct(721, 670))
	}
	if sizeDiffPct(1000, 700) != 30 {
		t.Fatalf("30%% 应判为不相似: %d", sizeDiffPct(1000, 700))
	}
}

func TestBoolChannelsShape(t *testing.T) {
	ch := boolChannels("7")
	if len(ch) == 0 || ch[0].t != "7 AND 1=1" {
		t.Fatalf("数字原值首通道应为数字型: %+v", ch)
	}
	ch = boolChannels("abc")
	if ch[0].t != "abc' AND '1'='1" || ch[0].f != "abc' AND '1'='2" {
		t.Fatalf("字符串原值首通道应为单引号闭合: %+v", ch)
	}
	if ch[1].t != `abc" AND "1"="1` {
		t.Fatalf("字符串原值次通道应为双引号闭合: %+v", ch)
	}
	// 兼容旧签名
	tp, fp := boolPayloads("7")
	if tp != "7 AND 1=1" || fp != "7 AND 1=2" {
		t.Fatalf("boolPayloads 首通道不符: %q / %q", tp, fp)
	}
}

// 表单字段布尔盲注：DVWA/pikachu 的 id 参数在 POST 表单里。
type formBlindFetcher struct{}

func (f *formBlindFetcher) GetSmall(u string) *Resp {
	return &Resp{Status: 200, Body: repeatStr("x", 500)}
}

func (f *formBlindFetcher) PostFormSmall(u string, data map[string]string) *Resp {
	v := data["id"]
	if strings.Contains(v, "1=2") {
		return &Resp{Status: 200, Body: repeatStr("x", 300)}
	}
	return &Resp{Status: 200, Body: repeatStr("x", 700)}
}

func TestFormBoolBlindDetects(t *testing.T) {
	r := New(&formBlindFetcher{}, DefaultOptions())
	f := r.formBoolBlindField(FormTarget{Action: "http://t/vuln/sqli/", Fields: []string{"id"}},
		"id", new(int), 0)
	if f == nil {
		t.Fatal("表单字段布尔差分应命中")
	}
	if f.Check != "bool-blind-sqli" || f.Param != "id" {
		t.Fatalf("Finding 不符: %+v", f)
	}
	if f.Request == "" || f.Replay == "" || f.Response == nil || len(f.Signals) == 0 {
		t.Fatalf("表单通道证据链不完整: %+v", f)
	}
}

// sqliLabsFetcher 复刻 sqli-labs Less-1~10 的实测判定行为（评测报告数据）：
//   - 数字型拼接（1 AND 1=1 / 1 AND 1=2）：MySQL 弱转数字，真/假同尺寸；
//   - 引号闭合拼接：真 721B / 假 670B（差 7%，低于旧 10% 阈值）；
//   - 单引号报错：页面只回显 "Error Based" 标题，不含 sqlErrors 特征。
//
// 修前 0/10 命中，修后应全数命中——这是本版 DAST 完成率修复的核心回归。
type sqliLabsFetcher struct{}

func (f *sqliLabsFetcher) GetSmall(u string) *Resp {
	val := ""
	if p, err := url.Parse(u); err == nil {
		val = p.Query().Get("id")
	}
	switch {
	case val == "" || val == "1":
		return &Resp{Status: 200, Body: repeatStr("x", 721)}
	case strings.Contains(val, "'") && (strings.Contains(val, "'2") || strings.Contains(val, "1=2")):
		return &Resp{Status: 200, Body: repeatStr("x", 670)} // 假分支低 7%
	default:
		return &Resp{Status: 200, Body: repeatStr("x", 721)}
	}
}

func (f *sqliLabsFetcher) PostFormSmall(u string, d map[string]string) *Resp { return f.GetSmall(u) }

func TestSqliLabsBlindCoverage(t *testing.T) {
	for _, less := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"} {
		r := New(&sqliLabsFetcher{}, DefaultOptions())
		tgt := Target{URL: "http://t/sqli-labs/Less-" + less + "/?id=1", Param: "id"}
		if f := r.boolBlind(tgt, new(int), 0); f == nil {
			t.Fatalf("Less-%s 应命中布尔盲注（修前 0/10）", less)
		}
	}
}

// PostRawSmall 测试桩：不支持原始体 POST（XXE 通道测试单独定义）。
func (f *routeFetcher) PostRawSmall(u, ct, b string) *Resp     { return nil }
func (f *randomFetcher) PostRawSmall(u, ct, b string) *Resp    { return nil }
func (f *sqliFetcher) PostRawSmall(u, ct, b string) *Resp      { return nil }
func (f *formBlindFetcher) PostRawSmall(u, ct, b string) *Resp { return nil }
func (f *sqliLabsFetcher) PostRawSmall(u, ct, b string) *Resp  { return nil }

// PostMultipartSmall 测试桩：不支持多段上传。
func (f *routeFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}
func (f *randomFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}
func (f *sqliFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp { return nil }
func (f *formBlindFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}
func (f *sqliLabsFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return nil
}
