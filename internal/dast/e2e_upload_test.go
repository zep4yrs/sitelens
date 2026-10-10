package dast

import (
	"strings"
	"testing"
)

// e2eUploadFetcher 模拟 upload-labs Pass-03 型：黑名单只拦 .php/.asp，
// 漏了 .phtml；且只查扩展名不查 MIME。
type e2eUploadFetcher struct{}

func (f *e2eUploadFetcher) GetSmall(string) *Resp                         { return nil }
func (f *e2eUploadFetcher) PostFormSmall(string, map[string]string) *Resp { return nil }
func (f *e2eUploadFetcher) PostRawSmall(string, string, string) *Resp     { return nil }
func (f *e2eUploadFetcher) PostMultipartSmall(u, ff, fn, c string, ex map[string]string) *Resp {
	return f.PostMultipartSmallCT(u, ff, fn, c, "application/octet-stream", ex)
}
func (f *e2eUploadFetcher) PostMultipartSmallCT(u, ff, fn, c, ct string, ex map[string]string) *Resp {
	low := strings.ToLower(fn)
	switch {
	case strings.HasSuffix(low, ".jpg") || strings.HasSuffix(low, ".png") || strings.HasSuffix(low, ".txt"):
		return &Resp{Status: 200, Body: "your image was uploaded successfully"}
	case strings.HasSuffix(low, ".php"):
		return &Resp{Status: 200, Body: "not allowed, invalid file"}
	case strings.HasSuffix(low, ".phtml"):
		return &Resp{Status: 200, Body: "your image was uploaded successfully"}
	default:
		return &Resp{Status: 200, Body: "not allowed, invalid file"}
	}
}

func TestE2EUploadBypassPipeline(t *testing.T) {
	r := New(&e2eUploadFetcher{}, DefaultOptions())
	got := r.RunForms([]FormTarget{{Action: "http://x/upload", FileFields: []string{"file"}}})
	var bypass, surface []Finding
	for _, g := range got {
		switch g.Check {
		case "upload-bypass":
			bypass = append(bypass, g)
		case "upload-surface":
			surface = append(surface, g)
		}
	}
	if len(surface) == 0 {
		t.Fatal("受理面未命中")
	}
	if len(bypass) == 0 {
		t.Fatal("绕过未命中(.phtml)")
	}
	t.Logf("surface=%d bypass=%d sample=%s", len(surface), len(bypass), bypass[0].Payload)
}
