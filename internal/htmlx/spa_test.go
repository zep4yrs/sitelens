package htmlx

import (
	"strings"
	"testing"
)

func TestParseSPAJetRoutes(t *testing.T) {
	page := `<html><head></head><body>
<script id="__NEXT_DATA__" type="application/json">
{"page":"/spa/next-1","props":{"route":"/spa/next-2"},"deep":{"page":"/spa/next-3"},"junk":"not-a-path"}
</script>
<script>window.__NUXT__=(function(a,b){return {routes:["/spa/nuxt-1"]}})</script>
</body></html>`
	d := Parse(page)
	joined := strings.Join(d.NextRoutes, ",")
	for _, want := range []string{"/spa/next-1", "/spa/next-2", "/spa/next-3", "/spa/nuxt-1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺少路由 %s: %v", want, d.NextRoutes)
		}
	}
	if len(d.NextRoutes) > 200 {
		t.Fatal("路由数应受限")
	}
}

func TestParseNoSPAJet(t *testing.T) {
	d := Parse("<html><title>普通页</title></html>")
	if len(d.NextRoutes) != 0 {
		t.Fatalf("普通页不应有 SPA 路由: %v", d.NextRoutes)
	}
}
