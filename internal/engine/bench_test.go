package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// benchPage 拟真页面：足量正文 + 常见指纹特征。
var benchPage = func() string {
	head := `<html><head><title>基准测试站</title>
<meta name="generator" content="WordPress 6.4.2">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body>`
	body := strings.Repeat(`<div class="wp-block-group"><p>段落内容，用于模拟真实页面正文体量。</p></div>`, 60)
	return head + body + `</body></html>`
}()

func newBenchSite(b *testing.B) *httptest.Server {
	b.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, benchPage)
	})
	srv := httptest.NewServer(mux)
	b.Cleanup(srv.Close)
	return srv
}

func benchMatcher(b *testing.B) *sitelens.Matcher {
	b.Helper()
	m, err := sitelens.LoadMatcher("../../data/go/technologies.json")
	if err != nil {
		b.Skip("指纹库不可用:", err)
	}
	return m
}

func benchKB(b *testing.B) *intel.KB {
	b.Helper()
	kb, err := intel.Load("../../data/intel_dump.json.gz", "../../data/affected_ranges.json")
	if err != nil {
		b.Skip("知识库不可用:", err)
	}
	return kb
}

func benchEvidence(b *testing.B, m *sitelens.Matcher) *sitelens.Evidence {
	b.Helper()
	return sitelens.Extract(&httpx.Response{
		Status: 200, Headers: map[string]string{"Server": "nginx/1.24.0"},
		Body: benchPage, FinalURL: "http://bench.local/",
	})
}

// BenchmarkFingerprint 单页指纹匹配成本（370 规则全量应用）。
func BenchmarkFingerprint(b *testing.B) {
	m := benchMatcher(b)
	b.SetBytes(int64(len(benchPage)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := benchEvidence(b, m)
		hits := m.Match(ev)
		if len(hits) == 0 {
			b.Fatal("拟真页面应命中 WordPress")
		}
	}
}

// BenchmarkKBMatch 情报关联成本。
func BenchmarkKBMatch(b *testing.B) {
	kb := benchKB(b)
	techs := []intel.TechHit{
		{Name: "WordPress", Version: "6.4.2"},
		{Name: "Nginx", Version: "1.24.0"},
		{Name: "jQuery", Version: "3.7.1"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kb.Match(techs)
	}
}

// BenchmarkFullPipeline 全流水线单站扫描。
func BenchmarkFullPipeline(b *testing.B) {
	srv := newBenchSite(b)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	eng := New(cfg, benchMatcher(b), nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := eng.Scan(srv.URL, Options{Deep: true}, nil, nil)
		if res.Error != "" {
			b.Fatal(res.Error)
		}
	}
}

// BenchmarkConcurrentScans 并发 8 路全流水线（信号量与内存行为观测）。
func BenchmarkConcurrentScans(b *testing.B) {
	srv := newBenchSite(b)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	eng := New(cfg, benchMatcher(b), nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if res := eng.Scan(srv.URL, Options{Deep: true}, nil, nil); res.Error != "" {
					b.Error(res.Error)
				}
			}()
		}
		wg.Wait()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.HeapAlloc)/1024/1024, "heap-MB")
}
