package engine

// A-09 回归：引擎配置快照语义与并发换枪。
//
// 背景：cfg 曾是 *config.Config 裸指针，设置页热更新原地改字段 → 与扫描期
// 读 cfg 构成数据竞争（Wave-1 已复现）。现 cfg 改为 atomic.Pointer 快照：
// 写侧 SetConfig 换枪、读侧 Config() 取指针；Scan 入口取一次并贯穿全流程。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// testEngine 构造引擎并注入配置快照（A-09 后 cfg 为 atomic.Pointer，
// 测试不能再以复合字面量 &Engine{cfg: ...} 直接写入）。
func testEngine(cfg *config.Config) *Engine {
	e := &Engine{}
	e.SetConfig(cfg)
	return e
}

// TestConfigSnapshotSemantics 快照语义：SetConfig 只换枪、不原地改旧结构；
// 旧快照（= 进行中扫描持有的那份）保持原值，下一次读取拿到新值。
func TestConfigSnapshotSemantics(t *testing.T) {
	oldCfg := config.Default()
	oldCfg.Scan.TimeoutSec = 15
	oldCfg.Scan.AllowHosts = []string{"a.example.com"}
	oldCfg.Crawler.MaxPages = 4
	e := New(oldCfg, nil, nil)

	old := e.Config()
	if old == nil {
		t.Fatal("New 后应能取到配置快照")
	}
	if old.Scan.TimeoutSec != 15 || old.Crawler.MaxPages != 4 {
		t.Fatalf("初始快照值错误: %+v", old.Scan)
	}

	next := config.Default()
	next.Scan.TimeoutSec = 3
	next.Crawler.MaxPages = 9
	next.Scan.AllowHosts = []string{"b.example.com"}
	e.SetConfig(next)

	// 旧快照必须原封不动（进行中的扫描全程读它）。
	if got := old.Scan.TimeoutSec; got != 15 {
		t.Fatalf("旧快照被原地修改：timeout_sec=%d，应为 15", got)
	}
	if got := old.Crawler.MaxPages; got != 4 {
		t.Fatalf("旧快照被原地修改：crawler.max_pages=%d，应为 4", got)
	}
	if len(old.Scan.AllowHosts) != 1 || old.Scan.AllowHosts[0] != "a.example.com" {
		t.Fatalf("旧快照切片被改写: %v", old.Scan.AllowHosts)
	}

	// 下一次读取拿到新快照。
	if got := e.Config(); got != next {
		t.Fatal("SetConfig 后 Config() 应返回新快照")
	}
	if got := e.Config().Scan.TimeoutSec; got != 3 {
		t.Fatalf("新快照 timeout_sec=%d，应为 3", got)
	}

	// 新旧快照的切片互不影响（快照之间必须完全独立）。
	next.Scan.AllowHosts = append(next.Scan.AllowHosts, "c.example.com")
	if len(old.Scan.AllowHosts) != 1 {
		t.Fatalf("新快照切片修改污染了旧快照: %v", old.Scan.AllowHosts)
	}
}

// TestConfigSnapshotConcurrentSwap 并发换枪 × 读快照（-race 下必须无竞争）。
// 读侧模拟进行中的扫描：进循环前取一次指针，全程只读该快照。
func TestConfigSnapshotConcurrentSwap(t *testing.T) {
	e := New(config.Default(), nil, nil)
	e.SetConfig(config.Default())
	held := e.Config() // 模拟一次扫描入口捕获的快照

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 写侧：模拟设置页反复保存（每次都是新配置对象）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c := config.Default()
			c.Scan.TimeoutSec = 3 + i%5
			c.Crawler.MaxPages = 4 + i%3
			c.ML.SevONNX = i%2 == 0
			e.SetConfig(c)
		}
	}()

	// 读侧 1：新请求取最新快照读字段。
	// 读侧 2：进行中的扫描只读入口持有的旧快照。
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(hold bool) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if hold {
					_ = held.Scan.TimeoutSec
					_ = held.Crawler.MaxPages
					_ = len(held.Scan.AllowHosts)
					continue
				}
				snap := e.Config()
				_ = snap.Scan.TimeoutSec
				_ = snap.Crawler.MaxPages
				_ = snap.ML.SevONNX
			}
		}(r == 0)
	}

	time.Sleep(120 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestScanUsesEntryConfigSnapshot 扫描入口取一次快照并贯穿全流程：
// 扫描进行中经 SetConfig 换枪，不得影响本次扫描（用 pages_retained 观测：
// 旧实现按调用点反复取配置，中途换枪会让截断阈值变化）。
func TestScanUsesEntryConfigSnapshot(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><head><title>snap</title></head><body>`+
				`<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a></body></html>`)
			return
		}
		fmt.Fprint(w, `<html><head><title>page</title></head><body>ok</body></html>`)
	}))
	defer site.Close()

	newCfg := func(pagesRetained int) *config.Config {
		c := config.Default()
		c.Scan.Resolve = false // 允许 127.0.0.1 夹具
		c.Scan.RateIntervalMS = 0
		c.Crawler.MaxPages = 4
		c.Scan.PagesRetained = pagesRetained
		return c
	}

	// 对照组：不换枪时页面清单不做截断（证明下面 len==1 是截断生效而非只爬了 1 页）。
	base := New(newCfg(100), nil, nil)
	baseRes := base.Scan(site.URL, Options{Deep: true, Checks: "none"}, nil, nil)
	if baseRes.Error != "" {
		t.Fatalf("对照扫描失败: %s", baseRes.Error)
	}
	if len(baseRes.Pages) < 2 {
		t.Fatalf("对照扫描应抓到多页（否则本回归不具区分度），实得 %d", len(baseRes.Pages))
	}

	// 实验组：入口快照 pages_retained=1；扫描到 25%（首页采集完成）时换枪到 100。
	cfgA := newCfg(1)
	e := New(cfgA, nil, nil)
	cfgB := newCfg(100)

	swapped := false
	res := e.Scan(site.URL, Options{Deep: true, Checks: "none"}, func(pct int, msg string) {
		if !swapped && pct >= 25 {
			swapped = true
			e.SetConfig(cfgB) // 模拟设置页保存（扫描进行中）
		}
	}, nil)
	if res.Error != "" {
		t.Fatalf("扫描失败: %s", res.Error)
	}
	if !swapped {
		t.Fatal("扫描未到 25% 就无法触发换枪，用例失效")
	}
	if len(res.Pages) != 1 {
		t.Fatalf("本次扫描应全程用入口快照（pages_retained=1），实得 %d 页——说明扫描中途读到了新配置", len(res.Pages))
	}
	if e.Config() != cfgB {
		t.Fatal("扫描结束后引擎应持有设置页写入的新快照")
	}
}
