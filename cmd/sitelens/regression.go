// regression 子命令（3.0 P3 验证回归）：按历史扫描 ID 重放全部 dast 类
// 已验证发现，统计「仍在/已修复/不可复现」。退出码：0=无回归（gone=0）、
// 1=存在回归（目标已修复或不可达，攻防口径即发现失效）、2=记录不存在。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/replay"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

func regressionCommand(cfg *config.Config, idStr string) int {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描 ID 不合法：", idStr)
		return 2
	}
	maxRec := cfg.Store.MaxRecords
	if maxRec <= 0 {
		maxRec = 500
	}
	st, err := store.New(cfg.Store.DataDir, maxRec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "历史库打开失败：", err)
		return 2
	}
	rec := st.Get(id)
	if rec == nil || rec.Result == nil {
		fmt.Fprintln(os.Stderr, "扫描记录不存在：", id)
		return 2
	}
	stats, details := replay.Batch(replay.NewFetcher(cfg.Active.ProbeTimeoutMS),
		rec.Result.Verified)
	fmt.Fprintf(os.Stderr, "重放完成：%d 条可重放（仍在 %d / 已修复 %d / 不可复现 %d），回归率 %.0f%%\n",
		stats.Total, stats.Present, stats.Gone, stats.Unsupported,
		stats.RegressionRate()*100)
	for _, d := range details {
		fmt.Fprintf(os.Stderr, "  [%s] #%d %s — %s\n", d.Status, d.Idx, d.Check, d.Note)
	}
	out, _ := json.Marshal(map[string]any{"stats": stats, "details": details})
	fmt.Println(string(out))
	if stats.Gone > 0 {
		return 1
	}
	return 0
}
