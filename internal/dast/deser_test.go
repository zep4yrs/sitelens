// G10 回归：Java/PHP/.NET/Python 反序列化标记识别、Finding 输出、
// 无害探测计划（默认关闭/上限）与标记回显确认（不做真实利用）。
package dast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// deserTestFetcher 基于 httptest 的 Fetcher（记录请求数与请求 URL）。
type deserTestFetcher struct {
	gets int32
	last string
}

func (f *deserTestFetcher) GetSmall(rawURL string) *Resp {
	atomic.AddInt32(&f.gets, 1)
	f.last = rawURL
	resp, err := http.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &Resp{Status: resp.StatusCode, Body: string(body)}
}

func (f *deserTestFetcher) PostFormSmall(string, map[string]string) *Resp { return nil }
func (f *deserTestFetcher) PostRawSmall(string, string, string) *Resp     { return nil }
func (f *deserTestFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return nil
}

// markerTechs 标记去重后的技术族集合。
func markerTechs(ms []DeserMarker) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		out[m.Tech] = true
	}
	return out
}

// TestDetectDeserMarkers 四类技术标记识别（Java/PHP/.NET/Python）。
func TestDetectDeserMarkers(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		want    []string
	}{
		{name: "java contentType",
			headers: map[string]string{"Content-Type": "application/x-java-serialized-object"},
			want:    []string{DeserTechJava}},
		{name: "java magic base64",
			body: "data=rO0ABXNyABFqYXZh...", want: []string{DeserTechJava}},
		{name: "php object",
			body: `x=O:8:"stdClass":1:{s:1:"a";s:1:"b";}`, want: []string{DeserTechPHP}},
		{name: "dotnet viewstate",
			body: `<input type="hidden" name="__VIEWSTATE" value="abc" />`,
			want: []string{DeserTechDotNet}},
		{name: "dotnet aspnet header",
			headers: map[string]string{"X-AspNet-Version": "4.0.30319"},
			want:    []string{DeserTechDotNet}},
		{name: "python pickle",
			body: "blob=gASVAAAAAA...", want: []string{DeserTechPython}},
		{name: "plain html no marker",
			body: "<html><body>hello object world</body></html>", want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectDeserMarkers(c.headers, c.body)
			if c.want == nil {
				if len(got) != 0 {
					t.Fatalf("普通页面不应识别出标记：%+v", got)
				}
				return
			}
			techs := markerTechs(got)
			for _, want := range c.want {
				if !techs[want] {
					t.Errorf("未识别 %s 标记：%+v", want, got)
				}
			}
			for _, m := range got {
				if m.Marker == "" || m.Evidence == "" || m.Where == "" {
					t.Errorf("标记字段不完整：%+v", m)
				}
			}
		})
	}
}

// TestDeserFindings 标记 → 低危 Finding（入口面提示，非漏洞确认）。
func TestDeserFindings(t *testing.T) {
	markers := []DeserMarker{
		{Tech: DeserTechJava, Where: "content-type", Marker: "application/x-java-serialized-object",
			Evidence: "Content-Type 声明 java 序列化"},
		{Tech: DeserTechPHP, Where: "body", Marker: `O:8:"stdClass"`, Evidence: "PHP 序列化对象"},
	}
	url := "https://t.example/api"
	fs := DeserFindings(markers, url)
	if len(fs) != 2 {
		t.Fatalf("Finding 数 = %d，期望 2", len(fs))
	}
	for _, f := range fs {
		if f.Severity != "low" || !strings.HasPrefix(f.Check, "deser-surface-") {
			t.Errorf("Finding 档位/类型异常：%+v", f)
		}
		if f.Evidence == "" || f.Replay == "" || f.URL != url {
			t.Errorf("Finding 证据/复现缺失：%+v", f)
		}
	}
	// 重复标记去重
	if got := DeserFindings([]DeserMarker{markers[0], markers[0]}, url); len(got) != 1 {
		t.Errorf("重复标记应去重：%d", len(got))
	}
	// 空 URL 不臆造 Replay
	if got := DeserFindings(markers[:1], ""); len(got) != 1 || got[0].Replay != "" {
		t.Errorf("空 URL 时 Replay 应留空：%+v", got)
	}
}

// TestBuildDeserProbesDefaultOff 默认关闭：即使有标记也不生成探测计划。
func TestBuildDeserProbesDefaultOff(t *testing.T) {
	markers := DetectDeserMarkers(nil, "rO0ABXNy gASV")
	if len(markers) == 0 {
		t.Fatal("样本应识别出标记")
	}
	if got := BuildDeserProbes(markers, "https://t.example/api", DeserProbeOptions{}); got != nil {
		t.Fatalf("默认应关闭：%+v", got)
	}
	if got := RunDeserProbes(&deserTestFetcher{}, nil); got != nil {
		t.Fatalf("空探测计划不应有 Finding：%+v", got)
	}
}

// TestBuildDeserProbesEnabled 开启后每技术族至多 1 条、总数 ≤2、仅含无害
// 标记（无利用链/DNS+时间标记可配置）。
func TestBuildDeserProbesEnabled(t *testing.T) {
	markers := []DeserMarker{
		{Tech: DeserTechJava, Where: "body", Marker: "rO0AB", Evidence: "java"},
		{Tech: DeserTechPHP, Where: "body", Marker: `O:8:"stdClass"`, Evidence: "php"},
		{Tech: DeserTechPython, Where: "body", Marker: "gASV", Evidence: "py"},
	}
	opts := DeserProbeOptions{Enable: true, DNSMarkerDomain: "oob.example.test", TimeDelayMS: 1500}
	probes := BuildDeserProbes(markers, "https://t.example/api", opts)
	if len(probes) != 2 { // 默认 MaxProbes=2
		t.Fatalf("探测数 = %d，期望 2：%+v", len(probes), probes)
	}
	for _, p := range probes {
		if !strings.Contains(p.Payload, "SLENS_DESER_PROBE") {
			t.Errorf("载荷缺无害标记：%q", p.Payload)
		}
		if !strings.Contains(p.Payload, "oob.example.test") {
			t.Errorf("DNS 标记未注入：%q", p.Payload)
		}
		if p.Replay == "" {
			t.Errorf("探测缺 replay：%+v", p)
		}
		low := strings.ToLower(p.Payload)
		for _, bad := range []string{"ysoserial", "runtime.exec", "processbuilder", "base64.decode"} {
			if strings.Contains(low, bad) {
				t.Errorf("载荷命中利用链特征 %q：%q", bad, p.Payload)
			}
		}
	}
	// 上限可调小；硬上限 4
	one := BuildDeserProbes(markers, "https://t.example/api", DeserProbeOptions{Enable: true, MaxProbes: 1})
	if len(one) != 1 {
		t.Fatalf("MaxProbes=1 未生效：%d", len(one))
	}
	many := BuildDeserProbes(markers, "https://t.example/api", DeserProbeOptions{Enable: true, MaxProbes: 99})
	if len(many) > hardDeserMaxProbes {
		t.Fatalf("硬上限被突破：%d", len(many))
	}
}

// TestRunDeserProbesEcho 无害探测执行：只做标记回显确认（httptest 回显
// 请求参数），默认关闭时零请求。
func TestRunDeserProbesEcho(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte("echo:" + r.URL.Query().Get("sl_deser_probe")))
	}))
	defer srv.Close()

	// 关闭：不生成计划 → 不执行、零请求
	markers := DetectDeserMarkers(nil, "rO0ABXNy")
	off := BuildDeserProbes(markers, srv.URL, DeserProbeOptions{})
	if got := RunDeserProbes(&deserTestFetcher{}, off); len(got) != 0 || atomic.LoadInt32(&requests) != 0 {
		t.Fatalf("默认关闭不应发请求：findings=%d requests=%d", len(got), requests)
	}

	// 开启：按计划发送，回显标记 → 低危 Finding；请求数 = 计划数（≤2）
	on := BuildDeserProbes(markers, srv.URL, DeserProbeOptions{Enable: true})
	if len(on) == 0 {
		t.Fatal("开启后应生成探测计划")
	}
	fs := RunDeserProbes(&deserTestFetcher{}, on)
	if len(fs) == 0 {
		t.Fatal("标记回显应输出 Finding")
	}
	for _, f := range fs {
		if f.Severity != "low" || !strings.Contains(f.Check, "deser-probe-echo") ||
			f.Evidence == "" || f.Replay == "" {
			t.Errorf("探测 Finding 异常：%+v", f)
		}
	}
	if got := atomic.LoadInt32(&requests); got != int32(len(on)) || got > 2 {
		t.Fatalf("请求数 = %d，期望 %d（≤2）", got, len(on))
	}
}

// TestRunDeserProbesHeaderWithoutCapability HEADER 型探测在 Fetcher 不支持
// HeaderFetcher 时跳过（不误报、不 panic）。
func TestRunDeserProbesHeaderWithoutCapability(t *testing.T) {
	probes := []DeserProbe{{Tech: DeserTechJava, URL: "https://t.example/", Param: "X-Probe",
		Method: "HEADER", Payload: "SLENS_DESER_PROBE", MarkerKind: "echo"}}
	if got := RunDeserProbes(&deserTestFetcher{}, probes); len(got) != 0 {
		t.Fatalf("无头注入能力应跳过：%+v", got)
	}
}
