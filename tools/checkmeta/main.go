// Command checkmeta 导出内置验证 check 的复核元数据（CSV），供人工抽样核对。
//
// 用法：
//
//	go run ./tools/checkmeta > /tmp/checks-meta.csv
//	go run ./tools/checkmeta -summary
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

func main() {
	summary := flag.Bool("summary", false, "只打印分布摘要（不输出 CSV）")
	flag.Parse()

	all := checks.AllChecks()
	rows := make([]checks.Check, len(all))
	copy(rows, all)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	noise := map[string]int{}
	safety := map[string]int{}
	attack := map[string]int{}
	for _, c := range rows {
		m := checks.MetaOf(c)
		noise[m.Noise]++
		safety[m.Safety]++
		for _, id := range m.ATTACK {
			attack[id]++
		}
	}
	fmt.Fprintf(os.Stderr, "check 总数：%d\n", len(rows))
	fmt.Fprintf(os.Stderr, "噪声分布：low=%d medium=%d high=%d\n", noise["low"], noise["medium"], noise["high"])
	fmt.Fprintf(os.Stderr, "安全等级：read_only=%d active=%d exploit=%d\n", safety["read_only"], safety["active"], safety["exploit"])
	ids := make([]string, 0, len(attack))
	for id := range attack {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id+"="+strconv.Itoa(attack[id]))
	}
	fmt.Fprintf(os.Stderr, "ATT&CK 分布：%s\n", strings.Join(parts, " "))

	if *summary {
		return
	}
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"id", "lv", "path", "severity", "attack", "noise", "safety", "reason", "title"})
	for _, c := range rows {
		m := checks.MetaOf(c)
		_ = w.Write([]string{
			c.ID, strconv.Itoa(c.Lv), c.Path, c.Sev,
			strings.Join(m.ATTACK, ";"), m.Noise, m.Safety, m.Reason, c.Title,
		})
	}
	w.Flush()
}
