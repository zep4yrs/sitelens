package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestGraphOverheadAcceptance 是 4.0 P10 的**性能验收**：开启结构化事实图
// 相比关闭，扫描耗时的增量必须 < 1%（开发文档第 21 节验收口径）。
//
// 方法：同一靶站交替跑「关图 / 开图」各 N 轮，取中位数比较。用中位数而非均值
// 抗偶发抖动；阈值取 1% 并留一点抖动余量（用 max(1%, 2ms) 保底，避免
// 极短扫描下 1% 落在计时噪声里——那种情况本身不构成回退）。
//
// 该测试是**验收性质**：失败即视为违反 P10 口径，需查 graph 收集是否引入
// 额外请求或重活（当前实现只做内存聚合，无额外网络请求）。
func TestGraphOverheadAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("验收测试：-short 下跳过")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>perf</title></head>
<body><a href="/?id=1">x</a><a href="/a">a</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.Crawler.MaxPages = 3
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	cfg.Checks.Level = "core"
	e := New(cfg, nil, nil)

	base := Options{Deep: true, Passive: true, Checks: "core"}
	withGraph := base
	withGraph.Graph = true

	const rounds = 7
	med := func(opts Options) time.Duration {
		ds := make([]time.Duration, 0, rounds)
		for i := 0; i < rounds; i++ {
			t0 := time.Now()
			res := e.Scan(srv.URL, opts, nil, nil)
			if res.Error != "" {
				t.Fatalf("扫描失败：%s", res.Error)
			}
			ds = append(ds, time.Since(t0))
		}
		// 插入排序取中位
		for i := 1; i < len(ds); i++ {
			for j := i; j > 0 && ds[j] < ds[j-1]; j-- {
				ds[j], ds[j-1] = ds[j-1], ds[j]
			}
		}
		return ds[len(ds)/2]
	}

	dOff := med(base)
	dOn := med(withGraph)
	delta := dOn - dOff
	pct := 0.0
	if dOff > 0 {
		pct = float64(delta) / float64(dOff) * 100
	}
	t.Logf("扫描耗时中位数：关图 %v / 开图 %v（增量 %v，%.2f%%）", dOff, dOn, delta, pct)

	// 阈值：1% 与 2ms 取大——极短扫描的 1% 会落进计时噪声，不构成真实回退。
	budget := time.Duration(float64(dOff) * 0.01)
	if budget < 2*time.Millisecond {
		budget = 2 * time.Millisecond
	}
	if delta > budget {
		t.Errorf("graph 增量 %v 超出预算 %v（P10 口径 <1%%）：开图 %.2f%%", delta, budget, pct)
	}
}
