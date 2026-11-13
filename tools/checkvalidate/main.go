// Command checkvalidate 对本地靶场跑「全量内置验证 check」的误报/漏报验证。
//
// 背景：内置验证已扩到 1,000+ 条（手写核心 + 手写扩展 + 模板转译），离线门禁只能
// 证明「不命中通用页面样本」，真实 HTTP 行为（软 404 基线、二次确认、同路径聚类、
// 回显剔除）还需要端到端跑一遍。本工具就是那轮的驱动：
//
//  1. 通用站点靶场（任何路径都返回 200 + 通用 HTML）→ 期望 0 命中（误报门禁）；
//  2. 故意暴露靶场（.git/.env/actuator 等被真实暴露）→ 期望命中对应 check（漏报门禁）；
//  3. 也可指向真实授权目标，人工核对命中是否可信。
//
// 用法：
//
//	go run ./tools/checkvalidate -target http://127.0.0.1:18081 -expect-zero
//	go run ./tools/checkvalidate -target http://127.0.0.1:18082 -expect-hits git-leak,env-leak
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

func main() {
	var targets multiFlag
	flag.Var(&targets, "target", "目标 base URL（可重复）")
	expectZero := flag.Bool("expect-zero", false, "命中任何 check 即视为失败（通用站点误报门禁）")
	var expectHits multiFlag
	flag.Var(&expectHits, "expect-hits", "期望命中的 check ID（逗号分隔，可重复）")
	workers := flag.Int("workers", 8, "并发 worker 数")
	intervalMS := flag.Int("interval", 120, "每主机请求最小间隔（毫秒）")
	timeoutS := flag.Int("timeout", 15, "单请求超时（秒）")
	maxChecks := flag.Int("limit", 0, "只跑前 N 条（0=全量，调试用）")
	var only multiFlag
	flag.Var(&only, "only", "只跑指定 check ID（逗号分隔，调试用）")
	flag.Parse()

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "至少一个 -target")
		os.Exit(2)
	}

	all := checks.AllChecks()
	if len(only) > 0 {
		want := make(map[string]bool, len(only))
		for _, id := range only {
			want[id] = true
		}
		filtered := make([]checks.Check, 0, len(only))
		for _, c := range all {
			if want[c.ID] {
				filtered = append(filtered, c)
			}
		}
		all = filtered
	}
	if *maxChecks > 0 && *maxChecks < len(all) {
		all = all[:*maxChecks]
	}
	fmt.Printf("check 总数：%d（手写核心/扩展 + 模板转译）\n", len(all))

	exit := 0
	for _, target := range targets {
		client := httpx.NewWithOptions(httpx.ClientOptions{
			Interval: time.Duration(*intervalMS) * time.Millisecond,
			Timeout:  time.Duration(*timeoutS) * time.Second,
		})
		start := time.Now()
		hits := checks.RunList(client, target, all, *workers, nil,
			func(done, total int, msg string) {
				if done%100 == 0 {
					fmt.Printf("  %s 进度 %d/%d\n", target, done, total)
				}
			}, nil)
		stats := client.Stats()
		fmt.Printf("\n=== %s：%d 条 check，请求 %d，命中 %d，耗时 %s\n",
			target, len(all), stats.Requests, len(hits), time.Since(start).Round(time.Millisecond))

		sort.Slice(hits, func(i, j int) bool { return hits[i].Check < hits[j].Check })
		for _, h := range hits {
			fmt.Printf("  [%s] %-28s %s  %s\n", h.Severity, h.Check, h.URL, h.Title)
		}

		if *expectZero && len(hits) > 0 {
			fmt.Printf("× 误报门禁失败：通用站点不应有命中\n")
			exit = 1
		}
		if len(expectHits) > 0 {
			got := make(map[string]bool, len(hits))
			for _, h := range hits {
				got[h.Check] = true
			}
			for _, want := range expectHits {
				if !got[want] {
					fmt.Printf("× 漏报门禁失败：期望命中 %s 未命中\n", want)
					exit = 1
				}
			}
		}
	}
	os.Exit(exit)
}

// multiFlag 支持逗号分隔与重复传入。
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*m = append(*m, s)
		}
	}
	return nil
}
