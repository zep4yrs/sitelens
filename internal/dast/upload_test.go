package dast

import (
	"strings"
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
