package dast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// uploadBypassFetcher 模拟一个「只做扩展名黑名单，且黑名单漏了 .phtml 与
// 双扩展名」的上传端点；同时验证 Content-Type 伪造会被放行。
type uploadBypassFetcher struct{ badExts map[string]bool }

func (f *uploadBypassFetcher) GetSmall(string) *Resp { return nil }
func (f *uploadBypassFetcher) PostFormSmall(string, map[string]string) *Resp {
	return nil
}
func (f *uploadBypassFetcher) PostRawSmall(string, string, string) *Resp { return nil }
func (f *uploadBypassFetcher) PostMultipartSmall(url, ff, fn, c string, ex map[string]string) *Resp {
	return f.PostMultipartSmallCT(url, ff, fn, c, "application/octet-stream", ex)
}
func (f *uploadBypassFetcher) PostMultipartSmallCT(url, ff, fn, c, ct string, ex map[string]string) *Resp {
	low := strings.ToLower(fn)
	switch {
	case strings.HasSuffix(low, ".jpg") && !strings.Contains(low, ".php"):
		return &Resp{Status: 200, Body: "upload success: file saved"}
	case strings.HasSuffix(low, ".php") && ct == "image/png":
		return &Resp{Status: 200, Body: "upload success: file saved"} // MIME 只看类型
	case f.badExts[extOf(low)]:
		return &Resp{Status: 200, Body: "upload success: file saved"}
	default:
		return &Resp{Status: 200, Body: "invalid file extension, not allowed"}
	}
}

func extOf(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[i:]
}

// TestUploadBypassDetectsMissedExtension 黑名单漏掉 .phtml → 应报绕过。
func TestUploadBypassDetectsMissedExtension(t *testing.T) {
	f := &uploadBypassFetcher{badExts: map[string]bool{".phtml": true, ".php.jpg": true}}
	r := New(f, DefaultOptions())
	got := r.uploadBypassProbe(FormTarget{Action: "https://a.com/upload"}, "file", map[string]string{})
	if len(got) == 0 {
		t.Fatal("漏掉的扩展名应报上传绕过")
	}
	// 至少有一条是 .phtml
	found := false
	for _, g := range got {
		if strings.Contains(g.Payload, ".phtml") {
			found = true
		}
		if g.Check != "upload-bypass" {
			t.Fatalf("check = %q, 期望 upload-bypass", g.Check)
		}
	}
	if !found {
		t.Fatalf(".phtml 绕过未报出: %+v", got)
	}
}

// TestUploadBypassContentTypeSpoof 只查 MIME 的目标：.php + image/png 应报。
func TestUploadBypassContentTypeSpoof(t *testing.T) {
	f := &uploadBypassFetcher{badExts: map[string]bool{}}
	r := New(f, DefaultOptions())
	got := r.uploadBypassProbe(FormTarget{Action: "https://a.com/upload"}, "file", nil)
	hit := false
	for _, g := range got {
		if strings.Contains(g.Title, "Content-Type") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("Content-Type 伪造绕过未报出: %+v", got)
	}
}

// TestUploadBypassRejectAll 拒绝一切扩展名的表单不应误报。
func TestUploadBypassRejectAll(t *testing.T) {
	f := &rejectAllUploadFetcher{}
	r := New(f, DefaultOptions())
	if got := r.uploadBypassProbe(FormTarget{Action: "https://a.com/upload"}, "file", nil); len(got) != 0 {
		t.Fatalf("全拒表单不应报绕过: %+v", got)
	}
}

type rejectAllUploadFetcher struct{}

func (f *rejectAllUploadFetcher) GetSmall(string) *Resp                         { return nil }
func (f *rejectAllUploadFetcher) PostFormSmall(string, map[string]string) *Resp { return nil }
func (f *rejectAllUploadFetcher) PostRawSmall(string, string, string) *Resp     { return nil }
func (f *rejectAllUploadFetcher) PostMultipartSmall(string, string, string, string, map[string]string) *Resp {
	return &Resp{Status: 200, Body: "invalid file extension, not allowed"}
}
func (f *rejectAllUploadFetcher) PostMultipartSmallCT(string, string, string, string, string, map[string]string) *Resp {
	return &Resp{Status: 200, Body: "invalid file extension, not allowed"}
}

// TestUploadBypassGateOff 总闸关闭时通道不产出发起。
func TestUploadBypassGateOff(t *testing.T) {
	f := &uploadBypassFetcher{badExts: map[string]bool{".php": true}}
	opts := DefaultOptions()
	opts.UploadBypass = false
	r := New(f, opts)
	got := r.RunForms([]FormTarget{{
		Action: "https://a.com/upload", FileFields: []string{"file"},
	}})
	for _, g := range got {
		if g.Check == "upload-bypass" {
			t.Fatalf("总闸关闭仍产出绕过: %+v", g)
		}
	}
}

// TestUploadAcceptReasonPrefersReject 拒绝特征优先于受理特征。
func TestUploadAcceptReasonPrefersReject(t *testing.T) {
	resp := &Resp{Status: 200, Body: "upload success but invalid file extension"}
	if uploadAccepted(resp) {
		t.Fatal("含拒绝特征时不得判为受理")
	}
}

// ============================================================================
// G10 上传绕过检测原语测试（计划生成 / 上限 / dry-run / 成功判定 / 只读验证）
// ============================================================================

// TestG10PlanGeneration 计划生成：类型/扩展名变体齐全，内容必须无害。
func TestG10PlanGeneration(t *testing.T) {
	plan := BuildUploadPlan(UploadBypassOptions{
		Endpoint: "https://t.example.com/upload", FieldName: "file", Token: "tok123",
	})
	if !plan.DryRun {
		t.Fatal("默认必须 dry-run")
	}
	if plan.Cap != G10MaxAttempts {
		t.Fatalf("默认 cap = %d, 期望 %d", plan.Cap, G10MaxAttempts)
	}
	if len(plan.Candidates) < 12 {
		t.Fatalf("候选太少: %d", len(plan.Candidates))
	}
	if len(plan.Attempts()) != G10MaxAttempts {
		t.Fatalf("默认执行窗口 = %d, 期望 %d", len(plan.Attempts()), G10MaxAttempts)
	}
	kinds := map[UploadKind]bool{}
	for _, c := range plan.Candidates {
		kinds[c.Kind] = true
	}
	for _, k := range []UploadKind{
		UploadKindBaseline, UploadKindExt, UploadKindDoubleExt, UploadKindCase,
		UploadKindNullByte, UploadKindSemicolon, UploadKindHtaccess,
		UploadKindMagicBytes, UploadKindContentType,
	} {
		if !kinds[k] {
			t.Fatalf("缺绕过类型 %s", k)
		}
	}
	var names []string
	for _, c := range plan.Candidates {
		names = append(names, c.FileName)
	}
	for _, want := range []string{
		".php", ".phtml", ".jsp", ".aspx", ".php.jpg", ".PhP",
		".php%00.jpg", ".php;.jpg", ".htaccess",
	} {
		found := false
		for _, n := range names {
			if strings.Contains(n, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺扩展名变体 %q: %v", want, names)
		}
	}
	// 内容安全：全部为无害文本（魔数候选只有 GIF89a 前缀）
	badTokens := []string{"<?php", "<?=", "<%", "<script", "system(", "exec(", "eval(", "base64_decode", "shell_exec", "Runtime."}
	for _, c := range plan.Candidates {
		low := strings.ToLower(string(c.Content))
		for _, bad := range badTokens {
			if strings.Contains(low, bad) {
				t.Fatalf("候选 %s 含可执行内容 %q", c.FileName, bad)
			}
		}
		if !strings.Contains(string(c.Content), plan.Token) {
			t.Fatalf("候选 %s 缺唯一标记（无法验证回显）", c.FileName)
		}
	}
}

// TestG10CapBounds 上限：默认 8、显式更小生效、超过硬上限被钳制。
func TestG10CapBounds(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, G10MaxAttempts}, {-3, G10MaxAttempts}, {1, 1}, {3, 3}, {8, 8}, {9, G10MaxAttempts}, {99, G10MaxAttempts},
	}
	for _, c := range cases {
		plan := BuildUploadPlan(UploadBypassOptions{
			Endpoint: "https://t.example.com/upload", FieldName: "file", MaxAttempts: c.in,
		})
		if plan.Cap != c.want {
			t.Fatalf("MaxAttempts=%d → cap=%d, 期望 %d", c.in, plan.Cap, c.want)
		}
		if got := len(plan.Attempts()); got > G10MaxAttempts {
			t.Fatalf("执行窗口 %d 超过硬上限 %d", got, G10MaxAttempts)
		}
	}
}

// TestG10KindsFilter 只保留指定类型（基线始终保留）。
func TestG10KindsFilter(t *testing.T) {
	plan := BuildUploadPlan(UploadBypassOptions{
		Endpoint: "https://t.example.com/upload", FieldName: "file",
		Kinds: []UploadKind{UploadKindExt},
	})
	if len(plan.Candidates) != 1+4 { // 基线 + .php/.phtml/.jsp/.aspx
		t.Fatalf("类型过滤后候选 = %d, 期望 5", len(plan.Candidates))
	}
	if plan.Candidates[0].Kind != UploadKindBaseline {
		t.Fatal("基线必须保留在首位")
	}
}

// TestG10DryRunNoRequests 默认 dry-run：零请求；非 dry-run 缺 Poster 报错。
func TestG10DryRunNoRequests(t *testing.T) {
	p := &g10CountingPoster{}
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: "https://t.example.com/upload", FieldName: "file", Poster: p,
	})
	if err != nil {
		t.Fatalf("dry-run 不应报错: %v", err)
	}
	if p.posts != 0 || p.gets != 0 {
		t.Fatalf("dry-run 不应发请求: posts=%d gets=%d", p.posts, p.gets)
	}
	if len(res.Attempts) != 0 || len(res.Findings) != 0 {
		t.Fatal("dry-run 不应有尝试/发现")
	}
	no := false
	if _, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: "https://t.example.com/upload", FieldName: "file", DryRun: &no,
	}); err == nil {
		t.Fatal("非 dry-run 缺 Poster 应报错")
	}
}

// g10CountingPoster 计数桩（dry-run / 上限断言用）。
type g10CountingPoster struct {
	posts, gets int
	reject      bool
}

func (p *g10CountingPoster) PostMultipart(_, _, _, _ string, _ []byte, _ map[string]string) *UploadHTTPResp {
	p.posts++
	if p.reject {
		return &UploadHTTPResp{Status: 200, Body: []byte(`{"ok":false,"msg":"invalid file extension, not allowed"}`)}
	}
	return &UploadHTTPResp{Status: 200, Body: []byte(`{"ok":true,"msg":"upload success: file saved"}`)}
}
func (p *g10CountingPoster) Get(string) *UploadHTTPResp {
	p.gets++
	return &UploadHTTPResp{Status: 200, Header: map[string]string{"Content-Type": "text/html"}, Body: []byte("probe")}
}

// g10TestServer 模拟上传端点：可配置「全拒 / 按后缀拒（大小写敏感）」；
// GET /uploads/* 与 /check 返回最近一次上传内容（text/html）。
type g10TestServer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	posts, gets  int
	lastName     string
	lastContent  []byte
	lastExtra    string
	rejectAll    bool
	rejectSuffix string
}

func newG10TestServer(t *testing.T, rejectAll bool, rejectSuffix string) *g10TestServer {
	t.Helper()
	s := &g10TestServer{rejectAll: rejectAll, rejectSuffix: rejectSuffix}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *g10TestServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		s.gets++
		content := s.lastContent
		s.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/uploads/") || r.URL.Path == "/check" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(content)
			return
		}
		http.NotFound(w, r)
	case http.MethodPost:
		_ = r.ParseMultipartForm(4 << 20)
		f, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing file", http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(f)
		_ = f.Close()
		s.mu.Lock()
		s.posts++
		s.lastName = hdr.Filename
		s.lastContent = data
		s.lastExtra = r.FormValue("csrf")
		reject := s.rejectAll || (s.rejectSuffix != "" && strings.HasSuffix(hdr.Filename, s.rejectSuffix))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if reject {
			_, _ = io.WriteString(w, `{"ok":false,"msg":"invalid file extension, not allowed"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"msg":"upload success: file saved","url":"/uploads/`+hdr.Filename+`"}`)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (s *g10TestServer) counts() (posts, gets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts, s.gets
}

// TestG10BypassDetected 端到端：服务端按后缀拒 .php（大小写敏感），
// .phtml/.jsp/.aspx/双扩展/大小写变体应判绕过；plain .php 不应误报。
func TestG10BypassDetected(t *testing.T) {
	s := newG10TestServer(t, false, ".php")
	no := false
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: s.srv.URL + "/upload", FieldName: "file", Token: "g10t",
		DryRun: &no, Poster: NewHTTPUploader(s.srv.Client()),
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !res.BaselineAccepted {
		t.Fatal("基线 .jpg 应被受理")
	}
	if len(res.Attempts) != G10MaxAttempts {
		t.Fatalf("尝试数 = %d, 期望 %d（上限）", len(res.Attempts), G10MaxAttempts)
	}
	if posts, _ := s.counts(); posts != G10MaxAttempts {
		t.Fatalf("实际 POST = %d, 期望 %d（上限）", posts, G10MaxAttempts)
	}
	if len(res.Findings) == 0 {
		t.Fatal("应检出绕过")
	}
	hit := map[string]bool{}
	for _, f := range res.Findings {
		if f.Check != "upload-bypass" {
			t.Fatalf("check = %q", f.Check)
		}
		if f.Replay == "" || !strings.Contains(f.Replay, "curl") || !strings.Contains(f.Replay, "/upload") {
			t.Fatalf("复现 curl 缺失/不含 endpoint: %q", f.Replay)
		}
		if f.Payload == "" || f.Evidence == "" {
			t.Fatalf("证据链字段缺失: %+v", f)
		}
		if f.Severity != "high" && f.Severity != "critical" {
			t.Fatalf("severity = %q", f.Severity)
		}
		hit[f.Payload] = true
	}
	if hit["sl_probe_g10t.php"] {
		t.Fatalf("plain .php 被拒却报了绕过: %+v", hit)
	}
	for _, want := range []string{".phtml", ".jsp", ".aspx", ".php.jpg", ".PhP"} {
		found := false
		for p := range hit {
			if strings.Contains(p, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("绕过 %q 未检出: %v", want, hit)
		}
	}
}

// TestG10BaselineRejectedNoFalsePositive 基线被拒（网关全拒）→ 不产出绕过。
func TestG10BaselineRejectedNoFalsePositive(t *testing.T) {
	s := newG10TestServer(t, true, "")
	no := false
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: s.srv.URL + "/upload", FieldName: "file", Token: "g10b",
		DryRun: &no, Poster: NewHTTPUploader(s.srv.Client()),
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if res.BaselineAccepted {
		t.Fatal("全拒网关不应判基线受理")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("基线被拒不应产出绕过: %+v", res.Findings)
	}
	if posts, _ := s.counts(); posts != 1 {
		t.Fatalf("基线被拒后应停止，POST = %d", posts)
	}
}

// TestG10AccessibleParsed 只读验证：响应 URL 可访问且返回 text/html → 疑似被解析。
func TestG10AccessibleParsed(t *testing.T) {
	s := newG10TestServer(t, false, "")
	no := false
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: s.srv.URL + "/upload", FieldName: "file", Token: "g10p",
		DryRun: &no, Poster: NewHTTPUploader(s.srv.Client()),
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if _, gets := s.counts(); gets == 0 {
		t.Fatal("受理后应做只读 GET 验证")
	}
	var parsed *UploadAttemptResult
	for i := range res.Attempts {
		if res.Attempts[i].Parsed {
			parsed = &res.Attempts[i]
			break
		}
	}
	if parsed == nil {
		t.Fatalf("应有疑似被解析的尝试: %+v", res.Attempts)
	}
	if !parsed.Accessible || parsed.URL == "" {
		t.Fatalf("可访问标记/URL 缺失: %+v", parsed)
	}
	critical := false
	for _, f := range res.Findings {
		if f.Severity == "critical" && strings.Contains(f.Title, "疑似被解析") {
			critical = true
		}
		if !strings.Contains(f.Evidence, "疑似被解析") && !strings.Contains(f.Evidence, "可访问") {
			t.Fatalf("证据缺只读验证说明: %s", f.Evidence)
		}
	}
	if !critical {
		t.Fatal("疑似解析应产出 critical 且标题标注")
	}
}

// TestG10CustomVerifyURL 调用方提供 URL 模板时优先使用。
func TestG10CustomVerifyURL(t *testing.T) {
	s := newG10TestServer(t, false, "")
	no := false
	verifyCalls := 0
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: s.srv.URL + "/upload", FieldName: "file", Token: "g10u",
		DryRun: &no, Poster: NewHTTPUploader(s.srv.Client()),
		VerifyURL: func(string) string {
			verifyCalls++
			return s.srv.URL + "/check"
		},
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if verifyCalls == 0 {
		t.Fatal("VerifyURL 未被调用")
	}
	for _, a := range res.Attempts {
		if a.Candidate.Kind == UploadKindBaseline {
			continue // 基线只判受理，不做 URL 验证
		}
		if a.Accepted && a.URL != s.srv.URL+"/check" {
			t.Fatalf("未使用模板 URL: %q", a.URL)
		}
	}
}

// TestG10MaxAttemptsRequests 显式上限：请求数 = 上限。
func TestG10MaxAttemptsRequests(t *testing.T) {
	s := newG10TestServer(t, false, "")
	no := false
	res, err := RunUploadBypass(UploadBypassOptions{
		Endpoint: s.srv.URL + "/upload", FieldName: "file", Token: "g10m",
		MaxAttempts: 3, DryRun: &no, Poster: NewHTTPUploader(s.srv.Client()),
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if len(res.Attempts) != 3 {
		t.Fatalf("尝试数 = %d, 期望 3", len(res.Attempts))
	}
	if posts, _ := s.counts(); posts != 3 {
		t.Fatalf("POST = %d, 期望 3", posts)
	}
}

// TestG10CurlReplay 复现命令：含 endpoint/文件名/字段名，且 shell 引号安全。
func TestG10CurlReplay(t *testing.T) {
	plan := BuildUploadPlan(UploadBypassOptions{
		Endpoint: "https://t.example.com/up'load", FieldName: "my file", Token: "g10c",
	})
	c := plan.Candidates[1] // Content-Type 伪造候选（.php）
	cmd := plan.CurlFor(c)
	if !strings.Contains(cmd, "curl -sk -X POST") || !strings.Contains(cmd, "printf %s") {
		t.Fatalf("复现命令形态异常: %q", cmd)
	}
	if !strings.Contains(cmd, "up'\\''load") {
		t.Fatalf("endpoint 单引号未转义: %q", cmd)
	}
	if !strings.Contains(cmd, c.FileName) {
		t.Fatalf("缺文件名: %q", cmd)
	}
}

// TestG10HTTPUploaderMultipart 真实 multipart：字段名/文件名/类型/内容/额外字段。
func TestG10HTTPUploaderMultipart(t *testing.T) {
	s := newG10TestServer(t, false, "")
	up := NewHTTPUploader(s.srv.Client())
	resp := up.PostMultipart(s.srv.URL+"/upload", "file", "sl_probe_x.phtml",
		"application/octet-stream", []byte("marker-body"), map[string]string{"csrf": "tok-1"})
	if resp == nil || resp.Status != 200 {
		t.Fatalf("上传失败: %+v", resp)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastName != "sl_probe_x.phtml" {
		t.Fatalf("服务端收到文件名 = %q", s.lastName)
	}
	if string(s.lastContent) != "marker-body" {
		t.Fatalf("服务端收到内容 = %q", s.lastContent)
	}
	if s.lastExtra != "tok-1" {
		t.Fatalf("额外字段未送达: %q", s.lastExtra)
	}
}

// TestG10ReadBack 只读验证判定矩阵（纯函数）。
func TestG10ReadBack(t *testing.T) {
	c := UploadCandidate{FileName: "x.php"}
	marker := "SLMARK"
	cases := []struct {
		name       string
		resp       *UploadHTTPResp
		accessible bool
		parsed     bool
	}{
		{"200 html 脚本", &UploadHTTPResp{Status: 200, Header: map[string]string{"Content-Type": "text/html"}, Body: []byte("SLMARK")}, true, true},
		{"200 plain 脚本", &UploadHTTPResp{Status: 200, Header: map[string]string{"Content-Type": "text/plain"}, Body: []byte("SLMARK")}, true, false},
		{"404", &UploadHTTPResp{Status: 404, Body: []byte("SLMARK")}, false, false},
		{"200 无标记", &UploadHTTPResp{Status: 200, Header: map[string]string{"Content-Type": "text/html"}, Body: []byte("other")}, false, false},
	}
	for _, tc := range cases {
		a, p := g10ReadBack(tc.resp, marker, c)
		if a != tc.accessible || p != tc.parsed {
			t.Fatalf("%s: accessible=%v parsed=%v, 期望 %v/%v", tc.name, a, p, tc.accessible, tc.parsed)
		}
	}
	if a, _ := g10ReadBack(nil, marker, c); a {
		t.Fatal("nil 响应不得判可访问")
	}
}

// TestG10UploadAcceptedMatrix 受理判定：4xx/拒绝特征优先；仅回显标记不再算受理。
//
// B-13 语义变更：`g10UploadAccepted` 现在是**严格**受理判定，只有命中受理
// 特征才算受理；「响应回显上传内容」降级为未定（由 g10Acceptance 用只读
// 回读补证）。故本表第一行期望值由 true 更正为 false——这不是弱化断言，
// 而是把断言改到修正后的语义上；三值判定另有 TestG10UploadVerdictTriState
// 覆盖（覆盖只增不减）。
func TestG10UploadAcceptedMatrix(t *testing.T) {
	marker := "SLMARK"
	cases := []struct {
		name   string
		resp   *UploadHTTPResp
		accept bool
	}{
		{"2xx 仅回显标记（未定，不算受理）", &UploadHTTPResp{Status: 200, Body: []byte("ok SLMARK")}, false},
		{"2xx 受理特征", &UploadHTTPResp{Status: 200, Body: []byte("upload success: file saved")}, true},
		{"2xx 拒绝特征", &UploadHTTPResp{Status: 200, Body: []byte("invalid file extension")}, false},
		{"4xx", &UploadHTTPResp{Status: 403, Body: []byte("SLMARK")}, false},
		{"无信号", &UploadHTTPResp{Status: 200, Body: []byte("nothing")}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		got, _ := g10UploadAccepted(tc.resp, marker)
		if got != tc.accept {
			t.Fatalf("%s: got %v, 期望 %v", tc.name, got, tc.accept)
		}
	}
}

// TestG10UploadVerdictTriState 三值受理判定（B-13）：回显 → 未定，受理特征 → 受理。
func TestG10UploadVerdictTriState(t *testing.T) {
	marker := "SLMARK"
	cases := []struct {
		name string
		resp *UploadHTTPResp
		want g10Verdict
	}{
		{"仅回显标记", &UploadHTTPResp{Status: 200, Body: []byte("ok SLMARK")}, g10VerdictUndetermined},
		{"受理特征", &UploadHTTPResp{Status: 200, Body: []byte("upload success")}, g10VerdictAccepted},
		{"拒绝特征", &UploadHTTPResp{Status: 200, Body: []byte("invalid file extension")}, g10VerdictRejected},
		{"4xx", &UploadHTTPResp{Status: 403, Body: []byte("SLMARK")}, g10VerdictRejected},
		{"无信号", &UploadHTTPResp{Status: 200, Body: []byte("nothing")}, g10VerdictUndetermined},
	}
	for _, tc := range cases {
		if got, _ := g10UploadVerdict(tc.resp, marker); got != tc.want {
			t.Fatalf("%s: verdict=%v, 期望 %v", tc.name, got, tc.want)
		}
	}
}

// TestG10AcceptanceReadBackConfirms 未定（仅回显）时，只读回读取到标记才算受理；
// 回读取不到则不算（错误页/预览页不得算成上传绕过）。
func TestG10AcceptanceReadBackConfirms(t *testing.T) {
	marker := "SLMARK"
	c := UploadCandidate{FileName: "x.php"}
	echoResp := &UploadHTTPResp{Status: 200, Body: []byte("preview: SLMARK")}

	// 回读成功 → 受理。
	ok, why := g10Acceptance(echoResp, marker, "https://a.com/upload", c,
		func(string) string { return "https://a.com/uploads/x.php" },
		func(string) *UploadHTTPResp {
			return &UploadHTTPResp{Status: 200, Header: map[string]string{"Content-Type": "text/plain"}, Body: []byte("SLMARK")}
		})
	if !ok {
		t.Fatalf("回读取到标记应判受理: %s", why)
	}
	// 回读取不到 → 不受理。
	ok, _ = g10Acceptance(echoResp, marker, "https://a.com/upload", c,
		func(string) string { return "https://a.com/uploads/x.php" },
		func(string) *UploadHTTPResp { return &UploadHTTPResp{Status: 404} })
	if ok {
		t.Fatal("回读 404 不得判受理")
	}
	// 无回读地址 → 不受理。
	if ok, _ := g10Acceptance(echoResp, marker, "https://a.com/upload", c, nil, nil); ok {
		t.Fatal("无可回读地址不得判受理")
	}
	// 明确受理特征 → 直接受理，不需要回读。
	ok, _ = g10Acceptance(&UploadHTTPResp{Status: 200, Body: []byte("upload success")}, marker,
		"https://a.com/upload", c, nil, nil)
	if !ok {
		t.Fatal("受理特征应直接判受理")
	}
}
