package jsmap

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

// fakeFetcher bundle 内容表。
type fakeFetcher struct {
	responses map[string]string
}

func (f *fakeFetcher) FetchBytes(rawURL string) ([]byte, error) {
	if body, ok := f.responses[rawURL]; ok {
		return []byte(body), nil
	}
	return nil, nil
}

const bundleJS = `var x=1;//# sourceMappingURL=app.js.map
fetch("/api/v1/users");axios.post("/rest/orders/create");var p="/api/v2/profile";`

const mapJSON = `{"version":3,"sources":["src/index.ts"],"mappings":"AAAA"}`

func TestRunDetectsSourcemapAndEndpoints(t *testing.T) {
	f := &fakeFetcher{responses: map[string]string{
		"http://t.local/static/app.js":     bundleJS,
		"http://t.local/static/app.js.map": mapJSON,
	}}
	doc := htmlx.Parse(`<html><script src="/static/app.js"></script></html>`)
	findings, endpoints := Run(f, "http://t.local/", doc, 4)

	foundMap := false
	for _, fd := range findings {
		if fd.Check == "sourcemap-leak" && fd.Src == "js" {
			foundMap = true
			if fd.URL != "http://t.local/static/app.js.map" {
				t.Fatalf("map URL 解析失败: %s", fd.URL)
			}
		}
	}
	if !foundMap {
		t.Fatalf("sourcemap 泄露未命中: %+v", findings)
	}
	apiCount, smCount := 0, 0
	for _, ep := range endpoints {
		switch ep.Kind {
		case "api":
			apiCount++
		case "sourcemap":
			smCount++
		}
	}
	if apiCount != 3 {
		t.Fatalf("API 端点应为 3: %+v", endpoints)
	}
	if smCount != 1 {
		t.Fatalf("sourcemap 端点应为 1: %+v", endpoints)
	}
}

func TestRunMissingMapIsSilent(t *testing.T) {
	f := &fakeFetcher{responses: map[string]string{
		"http://t.local/static/app.js": `//# sourceMappingURL=missing.js.map`,
	}}
	doc := htmlx.Parse(`<html><script src="/static/app.js"></script></html>`)
	findings, _ := Run(f, "http://t.local/", doc, 4)
	if len(findings) != 0 {
		t.Fatalf("map 拉取失败不应误报: %+v", findings)
	}
}

func TestRunCapBundles(t *testing.T) {
	f := &fakeFetcher{responses: map[string]string{}}
	var page strings.Builder
	page.WriteString("<html>")
	for i := 0; i < 10; i++ {
		page.WriteString(`<script src="/static/b` + string(rune('a'+i)) + `.js"></script>`)
	}
	page.WriteString("</html>")
	doc := htmlx.Parse(page.String())
	requests := 0
	counting := countingFetcher{inner: f, n: &requests}
	_, _ = Run(&counting, "http://t.local/", doc, 4)
	if requests != 4 {
		t.Fatalf("bundle 上限应为 4 次拉取: %d", requests)
	}
}

type countingFetcher struct {
	inner Fetcher
	n     *int
}

func (c *countingFetcher) FetchBytes(u string) ([]byte, error) {
	*c.n++
	return c.inner.FetchBytes(u)
}
