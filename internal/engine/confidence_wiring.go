// CP-11 置信度接线 + CP-05 页面批次分片（additive）。
//
// CP-11：把逐页指纹命中（sitelens.MatchHit）转成置信信号，按技术聚合后
// 调 sitelens.CalibrateTechs 校准，再用 ConfidenceToConf 回写
// Tech.Confidence，并把校准 reasons 追加到 Tech.Evidence（结果 JSON 的
// 既有字段内容更丰富，字段集合只增不减）。
//
// CP-05：页面批次收集可选走 shard.SplitShards+RunShards（ShardWorkers>0）；
// 默认 0 走串行，与旧版顺序/结果逐项一致。分片结果是纯内存 reduce，合并
// 严格按页序，因此两种路径输出等价（有测试锚定）。
package engine

import (
	"context"
	"strconv"

	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// collectFingerprintSignals 按页序收集指纹置信信号（CP-11）。
//
// shardWorkers<=0：串行路径（旧行为，无额外 goroutine）。
// shardWorkers>0：CP-05 页面批次分片执行（并发由 RunShards 夹到 ≤4），
// 每片只做纯内存信号抽取，按分片 ID（=页序区间）顺序合并，保证与串行
// 路径完全一致的信号顺序。
func collectFingerprintSignals(pages []crawlPage, fpHits [][]sitelens.MatchHit,
	shardWorkers int) ([]sitelens.ConfidenceSignal, *ShardStats) {
	n := len(fpHits)
	if n == 0 {
		return nil, nil
	}
	pageURL := func(i int) string {
		if i >= 0 && i < len(pages) && pages[i].resp != nil {
			return pages[i].resp.FinalURL
		}
		return ""
	}
	if shardWorkers <= 0 {
		out := make([]sitelens.ConfidenceSignal, 0, n*2)
		for i := 0; i < n; i++ {
			out = append(out, sitelens.SignalsFromMatchHits(pageURL(i), fpHits[i])...)
		}
		return out, nil
	}

	items := make([]string, n)
	for i := range items {
		items[i] = strconv.Itoa(i)
	}
	plan := SplitShards(items, shardWorkers)
	perShard := make([][]sitelens.ConfidenceSignal, len(plan))
	stats, err := RunShards(context.Background(), plan, ShardOptions{Concurrency: shardWorkers},
		func(_ context.Context, sh Shard) error {
			// 分片内按页序抽取；每片写自己的槽位（不同 goroutine 无共享写）。
			var acc []sitelens.ConfidenceSignal
			for _, item := range sh.Items {
				idx, cerr := strconv.Atoi(item)
				if cerr != nil || idx < 0 || idx >= n {
					continue
				}
				acc = append(acc, sitelens.SignalsFromMatchHits(pageURL(idx), fpHits[idx])...)
			}
			perShard[sh.ID] = acc
			return nil
		})
	if err != nil {
		// 纯内存 reduce 理论上不失败；万一失败回退串行，保证扫描不受影响。
		out := make([]sitelens.ConfidenceSignal, 0, n*2)
		for i := 0; i < n; i++ {
			out = append(out, sitelens.SignalsFromMatchHits(pageURL(i), fpHits[i])...)
		}
		return out, &stats
	}

	var out []sitelens.ConfidenceSignal
	for _, part := range perShard {
		out = append(out, part...)
	}
	return out, &stats
}

// calibrateTechnologies CP-11：按技术聚合信号 → CalibrateTechs → 回写
// Confidence(0-100) 并追加 reasons 到 Evidence。
//
// 输入顺序保持 techAcc 的技术首次出现顺序（既有输出顺序不变）；某技术没有
// 对应信号时保持原 Confidence（不把有命中的技术误降为 0）。
func calibrateTechnologies(techs []Tech, signals []sitelens.ConfidenceSignal) []Tech {
	if len(techs) == 0 {
		return techs
	}
	byName := make(map[string][]sitelens.ConfidenceSignal, len(techs))
	for _, s := range signals {
		byName[s.Name] = append(byName[s.Name], s)
	}
	inputs := make([]sitelens.TechConfidenceInput, 0, len(techs))
	for _, t := range techs {
		sigs := byName[t.Name]
		base := 0
		if len(sigs) > 0 {
			base = sigs[0].BaseConf
		}
		inputs = append(inputs, sitelens.TechConfidenceInput{
			Name: t.Name, Signals: sigs, BaseConf: base,
		})
	}
	results := sitelens.CalibrateTechs(inputs)
	out := make([]Tech, len(techs))
	for i, t := range techs {
		out[i] = t
		if len(byName[t.Name]) == 0 {
			continue // 无信号：保持既有置信度
		}
		out[i].Confidence = sitelens.ConfidenceToConf(results[i].Confidence)
		if len(results[i].Reasons) > 0 {
			ev := make([]string, 0, len(t.Evidence)+len(results[i].Reasons))
			ev = append(ev, t.Evidence...)
			ev = append(ev, results[i].Reasons...)
			out[i].Evidence = ev
		}
	}
	return out
}
