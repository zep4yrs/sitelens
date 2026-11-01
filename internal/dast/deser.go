// 反序列化入口面探测（低危面信号，非漏洞确认）：
// 注入 Java 序列化魔数（aced0005）的 URL 编码形态，响应出现反序列化
// 报错特征即提示该参数可能进入反序列化处理链。判定保守：只认具体的
// 序列化异常类名，普通报错不报。
//
// G10 在此基础上追加「Java/PHP/.NET/Python 标记识别 + 无害探测计划」
// （见文件下半部分，默认关闭、不做真实利用）。
package dast

import (
	"fmt"
	"regexp"
	"strings"
)

// deserPayload Java 序列化流魔数 aced0005 的 URL 编码形态。
// 必须走 rawSetParam 原样上线：经 setParam 会被 url.Values.Encode 二次编码
// （%AC%ED → %25AC%ED），服务端单次解码拿到字面文本而非序列化魔数字节，
// 反序列化入口面探测因此永远不触发（BUG-017）。
const deserPayload = "%AC%ED%00%05sl"

// deserMarkers Java 反序列化处理链的报错特征（出现即说明走了反序列化路径）。
var deserMarkers = []string{
	"StreamCorruptedException",
	"InvalidClassException",
	"InvalidObjectException",
	"java.io.EOFException",
	" org.hibernate.InstantiationException",
}

func (r *Runner) deserProbe(tgt Target, done *int, total int) *Finding {
	u := rawSetParam(tgt.URL, tgt.Param, deserPayload)
	if len(u) > r.opts.MaxURLLen {
		return nil
	}
	resp := r.fetch.GetSmall(u)
	*done++
	if r.prog != nil {
		r.prog(*done, total, shortLabel(tgt))
	}
	if resp == nil {
		return nil
	}
	for _, marker := range deserMarkers {
		if strings.Contains(resp.Body, marker) {
			return &Finding{
				Check:    "deser-surface",
				Title:    "疑似 Java 反序列化入口（报错特征）",
				Severity: "low",
				URL:      tgt.URL,
				Param:    tgt.Param,
				Payload:  deserPayload,
				Evidence: "响应出现序列化处理链特征：" + marker,
				Replay:   curlReplay(u),
				Advice:   "确认该入口是否对用户输入做反序列化；优先白名单校验与签名机制",
			}
		}
	}
	return nil
}

// ---- G10 反序列化标记识别（Java/PHP/.NET/Python）与无害探测（additive） ----
//
// 与上方 Java 魔数探测（deserProbe，已接入 Run）并列：
//   - DetectDeserMarkers 识别响应/header 中的反序列化入口标记（纯函数）；
//   - DeserFindings 把标记转成低危 Finding（只提示入口面，不构成漏洞确认）；
//   - BuildDeserProbes 生成无害探测计划（**默认关闭**：Enable=false 返回 nil）；
//   - RunDeserProbes 只做「标记回显」确认，不做真实利用（无 gadget 链）。
//
// 红线：不做真实利用。探测载荷只含随机标记 token（可选 DNS 回连域名 /
// 时间延迟标记，供外部回连观测），不含 ysoserial 链、不含命令执行/文件读写。

// 反序列化标记技术族。
const (
	DeserTechJava   = "java"
	DeserTechPHP    = "php"
	DeserTechDotNet = "dotnet"
	DeserTechPython = "python"
)

// DeserMarker 一条反序列化入口标记（识别结果，非漏洞确认）。
type DeserMarker struct {
	Tech     string `json:"tech"`     // java/php/dotnet/python
	Where    string `json:"where"`    // header/content-type/body
	Marker   string `json:"marker"`   // 命中标记（截断展示）
	Evidence string `json:"evidence"` // 证据说明
}

// DeserProbeOptions 无害探测参数（零值 = 关闭，零请求）。
type DeserProbeOptions struct {
	Enable          bool   // 总闸：默认 false → 只做标记识别，不生成/不发送探测
	DNSMarkerDomain string // 可配置 DNS 回连标记域名（空 = 不生成 DNS 标记）
	TimeDelayMS     int    // >0：附加时间延迟标记（毫秒；仅标记，不执行休眠）
	MaxProbes       int    // 上限（默认 2，硬上限 4）
}

// logicDeserMaxProbes 默认探测上限 / 硬上限。
const (
	defaultDeserMaxProbes = 2
	hardDeserMaxProbes    = 4
)

// deserPHPObjectRe PHP 序列化对象形态：O:<len>:"Class":... / a:<len>:{（纯识别，不利用）。
var deserPHPObjectRe = regexp.MustCompile(`(?i)O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*"|a:\d+:\{`)

// deserMarkerPrefix 原始序列化字节的可见前缀（不可见字节以转义形式到达时）。
var (
	deserJavaMagicPrefixes = []string{"rO0AB", "\xac\xed", "%AC%ED", "ACED 0005"}
	deserPyPicklePrefixes  = []string{"gASV", "gAJ", "\x80\x04", "\x80\x05", "c__builtin__", "cos\nsystem"}
)

// DetectDeserMarkers 识别反序列化入口标记（headers 含 Content-Type 等；
// body 为响应正文）。纯函数，不做任何请求。
func DetectDeserMarkers(headers map[string]string, body string) []DeserMarker {
	var out []DeserMarker
	add := func(tech, where, marker, evidence string) {
		if marker == "" {
			return
		}
		out = append(out, DeserMarker{
			Tech: tech, Where: where, Marker: truncateMarker(marker), Evidence: evidence,
		})
	}
	lowBody := strings.ToLower(body)

	// header / Content-Type 通道
	for k, v := range headers {
		if v == "" {
			continue
		}
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		if strings.Contains(lv, "java-serialized") || strings.Contains(lk, "java-serialized") {
			add(DeserTechJava, "content-type", k+": "+v,
				"Content-Type/头声明 java 序列化对象（ysoserial 类入口形态）")
		}
		if strings.Contains(lv, "ysoserial") || strings.Contains(lk, "ysoserial") {
			add(DeserTechJava, "header", k+": "+v, "响应头出现 ysoserial 类标记")
		}
		if strings.Contains(lk, "x-aspnet-version") {
			add(DeserTechDotNet, "header", k+": "+v, "ASP.NET 框架头（ViewState 形态的站点特征）")
		}
		if strings.Contains(lv, "multipart/form-data") && strings.Contains(lowBody, "__viewstate") {
			add(DeserTechDotNet, "body", "__VIEWSTATE", "multipart 表单含 .NET ViewState 字段")
		}
	}

	// body 通道：Java 序列化魔数（base64/转义形态）
	for _, p := range deserJavaMagicPrefixes {
		if strings.Contains(body, p) {
			add(DeserTechJava, "body", p, "正文含 Java 序列化魔数（aced0005）的 base64/转义形态")
			break
		}
	}
	// body 通道：PHP 序列化对象
	if m := deserPHPObjectRe.FindString(body); m != "" {
		add(DeserTechPHP, "body", m, "正文含 PHP 序列化对象/数组形态（O:/a:）")
	}
	// body 通道：.NET ViewState
	for _, mark := range []string{"__viewstate", "__eventvalidation"} {
		if strings.Contains(lowBody, mark) {
			add(DeserTechDotNet, "body", strings.ToUpper(mark), ".NET WebForms ViewState 字段（反序列化入口面）")
			break
		}
	}
	// body 通道：Python pickle（base64/原始 opcode 前缀）
	for _, p := range deserPyPicklePrefixes {
		if strings.Contains(body, p) {
			add(DeserTechPython, "body", p, "正文含 Python pickle 序列化前缀/opcode")
			break
		}
	}
	return out
}

// truncateMarker 标记截断（避免把整段响应/凭据写进报告）。
func truncateMarker(s string) string {
	r := []rune(s)
	if len(r) > 120 {
		return string(r[:120]) + "…"
	}
	return s
}

// DeserFindings 把识别到的标记转成低危 Finding（入口面提示，非漏洞确认）。
// rawURL 为空时 Replay 留空（没有可复现 URL 就不臆造）。
func DeserFindings(markers []DeserMarker, rawURL string) []Finding {
	out := make([]Finding, 0, len(markers))
	seen := map[string]bool{}
	for _, m := range markers {
		key := m.Tech + "\x00" + m.Where + "\x00" + m.Marker
		if seen[key] {
			continue
		}
		seen[key] = true
		f := Finding{
			Check:    "deser-surface-" + m.Tech,
			Title:    "疑似反序列化入口（" + deserTechName(m.Tech) + " 标记）",
			Severity: "low",
			URL:      rawURL,
			Evidence: m.Evidence + "：标记 " + m.Marker,
			Advice:   "确认该入口是否对不可信数据做反序列化；使用白名单/签名校验，禁止原生反序列化",
			Signals:  []string{"反序列化标记识别：" + m.Tech + "/" + m.Where},
		}
		if rawURL != "" {
			f.Replay = curlReplay(rawURL)
		}
		out = append(out, f)
	}
	return out
}

// deserTechName 技术族展示名。
func deserTechName(tech string) string {
	switch tech {
	case DeserTechJava:
		return "Java"
	case DeserTechPHP:
		return "PHP"
	case DeserTechDotNet:
		return ".NET"
	case DeserTechPython:
		return "Python"
	}
	return tech
}

// DeserProbe 一条无害探测计划（默认不生成；Replay 可复制复核）。
type DeserProbe struct {
	Tech       string `json:"tech"`
	URL        string `json:"url"`
	Param      string `json:"param"`
	Method     string `json:"method"` // GET（URL 参数）/ HEADER（可选 HeaderFetcher）
	Payload    string `json:"payload"`
	MarkerKind string `json:"marker_kind"` // echo/dns/time
	Note       string `json:"note,omitempty"`
	Replay     string `json:"replay,omitempty"`
}

// BuildDeserProbes 纯函数：按标记生成无害探测计划。
// **默认关闭**（opts.Enable=false → 返回 nil，零请求）；开启后每技术族至多
// 1 条、总数 ≤ MaxProbes（默认 2，硬上限 4）。载荷只含随机标记 token 与
// 可选 DNS/时间标记，不含任何利用链。
func BuildDeserProbes(markers []DeserMarker, rawURL string, opts DeserProbeOptions) []DeserProbe {
	if !opts.Enable || rawURL == "" || len(markers) == 0 {
		return nil
	}
	maxProbes := opts.MaxProbes
	if maxProbes <= 0 || maxProbes > hardDeserMaxProbes {
		maxProbes = defaultDeserMaxProbes
	}
	var out []DeserProbe
	seenTech := map[string]bool{}
	for _, m := range markers {
		if len(out) >= maxProbes {
			break
		}
		if seenTech[m.Tech] {
			continue
		}
		seenTech[m.Tech] = true
		payload, kind, note := deserProbePayload(m.Tech, opts)
		if payload == "" {
			continue
		}
		p := DeserProbe{
			Tech: m.Tech, URL: rawURL, Param: "sl_deser_probe", Method: "GET",
			Payload: payload, MarkerKind: kind, Note: note,
		}
		p.Replay = curlReplay(setParam(rawURL, p.Param, payload))
		out = append(out, p)
	}
	return out
}

// deserProbePayload 各技术族无害标记载荷（纯标记，不构成利用）。
func deserProbePayload(tech string, opts DeserProbeOptions) (payload, kind, note string) {
	const token = "SLENS_DESER_PROBE"
	var base string
	switch tech {
	case DeserTechJava:
		base = "rO0AB-" + token // Java 序列化魔数 base64 前缀 + 随机标记（非 gadget 链）
	case DeserTechPHP:
		base = `O:8:"stdClass":1:{s:5:"probe";s:17:"` + token + `";}`
	case DeserTechDotNet:
		base = "__VIEWSTATE=" + token
	case DeserTechPython:
		base = "gASV-" + token
	default:
		return "", "", ""
	}
	kind = "echo"
	payload = base
	if opts.DNSMarkerDomain != "" {
		payload += ".oob." + strings.TrimSpace(opts.DNSMarkerDomain)
		kind = "dns"
		note = "含 DNS 回连标记：" + opts.DNSMarkerDomain + "（需外部回连观测，默认不判定）"
	}
	if opts.TimeDelayMS > 0 {
		payload += fmt.Sprintf(";delay=%dms", opts.TimeDelayMS)
		if kind == "echo" {
			kind = "time"
		}
		note = "含时间延迟标记 " + fmt.Sprint(opts.TimeDelayMS) + "ms（仅标记，不会真实休眠）"
	}
	return payload, kind, note
}

// RunDeserProbes 执行探测计划：只做「标记回显」确认，不做真实利用。
// 计划为空（默认关闭）时返回 nil 且零请求。
func RunDeserProbes(f Fetcher, probes []DeserProbe) []Finding {
	if f == nil || len(probes) == 0 {
		return nil
	}
	var out []Finding
	for _, p := range probes {
		var resp *Resp
		switch p.Method {
		case "HEADER":
			hf, ok := f.(HeaderFetcher)
			if !ok {
				continue // 无头注入能力：跳过，不误报
			}
			resp = hf.GetWithHeaders(p.URL, map[string]string{p.Param: p.Payload})
		default:
			resp = f.GetSmall(setParam(p.URL, p.Param, p.Payload))
		}
		if resp == nil || !strings.Contains(resp.Body, "SLENS_DESER_PROBE") {
			continue
		}
		out = append(out, Finding{
			Check:    "deser-probe-echo-" + p.Tech,
			Title:    "反序列化探测标记被回显（入口面待复核）",
			Severity: "low",
			URL:      p.URL,
			Param:    p.Param,
			Payload:  p.Payload,
			Evidence: "无害探测标记在响应中原样回显（marker=" + p.MarkerKind + "），提示该参数进入序列化处理链",
			Replay:   p.Replay,
			Advice:   "确认入口是否反序列化不可信数据；使用白名单/签名校验，禁止原生反序列化",
			Signals:  []string{"反序列化无害探测：标记回显"},
		})
	}
	return out
}
