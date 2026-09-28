// mlprior.go 5.0 深度融合前置通道：cve-tech 对「标题 + 检出技术 +
// 首页正文头部」做 affected-product 预测，达标产品映射到相关 check——
// 提权排序（改变执行顺序）+ 核心档位扩展集增量纳入（改变覆盖面）。
// 铁律（只增不删/静默跳过/总闸）与三通道分工见 ml.go 文件头与 §10.7。
package engine

import (
	"math"
	"regexp"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// 先验参数：概率门槛 / 参与映射的产品数上限 / 正文头部截断（rune）。
// cve-tech 概率为 196 类行归一口径，站点文本驱动的 Top-1 常在 0.1~0.6，
// 0.08 挡住长尾噪声、放过强信号。
var (
	mlPriorMinProb     = 0.08
	mlPriorMaxProducts = 3
	mlPriorTextCap     = 1200
)

var reHTMLTags = regexp.MustCompile(`<[^>]*>`)

// mlPrior 计算产品先验。返回：
//
//	prior    — check 提权表（nil = 本次无有效先验，调用方按 4.0 原样执行）
//	promoted — 核心档位下增量纳入的扩展集 check id（非规则联动部分）
//	info     — 落 Extras["ml_prior"] 的可解释信息（含 Top-5 产品与概率）
func (e *Engine) mlPrior(res *Result, home *httpx.Response, level string,
	cmsIDs []string) (*checks.Prior, []string, map[string]any) {
	assets := e.mlFor()
	if assets == nil {
		return nil, nil, nil
	}
	text := mlPriorText(res, home)
	if strings.TrimSpace(text) == "" {
		return nil, nil, nil
	}
	prior := &checks.Prior{Boost: map[string]float64{}}
	linked := map[string]bool{}
	for _, id := range cmsIDs {
		linked[id] = true
	}
	promotedSet := map[string]bool{}
	var promoted []string
	var prods []map[string]any
	mapped := 0
	for _, p := range assets.Tech.ProbaTopK(text, 5) {
		prods = append(prods, map[string]any{"product": p.Class, "prob": mlRound3(p.Score)})
		if mapped >= mlPriorMaxProducts || p.Score < mlPriorMinProb {
			continue
		}
		mapped++
		for _, id := range checks.MLProductChecks(p.Class) {
			if prior.Boost[id] < p.Score {
				prior.Boost[id] = p.Score
			}
			// 增量纳入：非规则联动、扩展集、低档位（all 档全集已跑，无增量）
			if !linked[id] && level != "all" && !promotedSet[id] && checks.IsExtended(id) {
				promotedSet[id] = true
				promoted = append(promoted, id)
			}
		}
	}
	if len(prior.Boost) == 0 {
		return nil, nil, nil
	}
	info := map[string]any{
		"products":    prods,
		"boosted":     len(prior.Boost),
		"family_link": true,
	}
	if len(promoted) > 0 {
		info["promoted"] = promoted
	}
	return prior, promoted, info
}

// mlPriorText 组装先验输入文本：标题 + 检出技术清单 + 首页正文头部（去标签）。
// cve-tech 训练语料是 CVE 描述、特征是词级 tf-idf——站点文本里出现的
// 产品词（wordpress/tomcat/…）即足以驱动预测，不要求句法相似。
func mlPriorText(res *Result, home *httpx.Response) string {
	var b strings.Builder
	if res.Title != "" {
		b.WriteString(res.Title)
		b.WriteByte('\n')
	}
	for _, t := range res.Technologies {
		b.WriteString(t.Name)
		if t.Version != "" {
			b.WriteString(" " + t.Version)
		}
		b.WriteByte('\n')
	}
	if home != nil && home.Body != "" {
		stripped := reHTMLTags.ReplaceAllString(home.Body, " ")
		n := 0
		for _, f := range strings.Fields(stripped) {
			if n >= mlPriorTextCap {
				break
			}
			b.WriteString(f)
			b.WriteByte(' ')
			n += len([]rune(f)) + 1
		}
	}
	return b.String()
}

// mlRound3 概率展示取 3 位小数。
func mlRound3(x float64) float64 { return math.Round(x*1000) / 1000 }
