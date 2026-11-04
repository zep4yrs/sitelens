// mlprior.go 5.0 深度融合前置通道（5.2 阶段 2 起改为「指纹优先」）：
//
//	① 确定性指纹先验：检出技术名（res.Technologies）→ 产品映射表 →
//	   相关 check 提权 + 低档位扩展集增量纳入。**不加载模型资产、不读正文**：
//	   指纹已经确认站点跑的是 WordPress/Tomcat/PHP…，直接映射比让 TF-IDF
//	   从正文里猜产品更准，也让该通道在无模型资产时依然可用。
//	② 文本模型先验（兼容路径）：指纹无命中时才走旧 5.0 行为——cve-tech 对
//	   「标题 + 检出技术 + 首页正文头部」做产品预测（需模型资产）。
//
// 铁律（只增不删/静默跳过/总闸）与三通道分工见 ml.go 文件头与 §10.7。
package engine

import (
	"math"
	"regexp"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// 先验参数：概率门槛 / 参与映射的产品数上限 / 正文头部截断（rune）。
// cve-tech 概率为 196 类行归一口径，站点文本驱动的 Top-1 常在 0.1~0.6，
// 0.08 挡住长尾噪声、放过强信号。
var (
	mlPriorMinProb     = 0.08
	mlPriorMaxProducts = 3
	mlPriorTextCap     = 1200
)

// mlPriorFingerprintBoost 指纹先验权重：确定性命中（指纹已确认技术名），
// 给固定高分；只影响排序，不改变任何 check 的命中判定。
var mlPriorFingerprintBoost = 0.9

var reHTMLTags = regexp.MustCompile(`<[^>]*>`)

// mlPrior 计算产品先验（独立入口用：取当前配置快照）。返回：
//
//	prior    — check 提权表（nil = 本次无有效先验，调用方按 4.0 原样执行）
//	promoted — 核心档位下增量纳入的扩展集 check id（非规则联动部分）
//	info     — 落 Extras["ml_prior"] 的可解释信息（含产品、概率与来源）
func (e *Engine) mlPrior(res *Result, home *httpx.Response, level string,
	cmsIDs []string) (*checks.Prior, []string, map[string]any) {
	return e.mlPriorWith(e.Config(), res, home, level, cmsIDs)
}

// mlPriorWith 用显式配置快照计算产品先验（扫描内部调用，A-09：
// 模型资产目录与入口快照一致）。
func (e *Engine) mlPriorWith(cfg *config.Config, res *Result, home *httpx.Response,
	level string, cmsIDs []string) (*checks.Prior, []string, map[string]any) {
	linked := make(map[string]bool, len(cmsIDs))
	for _, id := range cmsIDs {
		linked[id] = true
	}

	// ① 指纹先验（确定性；无需模型资产）。
	if prior, promoted, info := mlPriorFromTech(res.Technologies, level, linked); prior != nil {
		return prior, promoted, info
	}

	// ② 文本模型先验（旧路径，指纹无命中时兜底）。
	assets := e.mlForWith(cfg)
	if assets == nil {
		return nil, nil, nil
	}
	text := mlPriorText(res, home)
	if strings.TrimSpace(text) == "" {
		return nil, nil, nil
	}
	return mlPriorFromText(assets, text, level, linked)
}

// mlPriorApply 统一处理提权与低档位增量纳入（两条通道共用，保证语义一致）。
// 返回更新后的 promoted 列表。
func mlPriorApply(boost map[string]float64, ids []string, weight float64,
	level string, linked, promotedSet map[string]bool, promoted []string) []string {
	for _, id := range ids {
		if boost[id] < weight {
			boost[id] = weight
		}
		// 增量纳入：非规则联动、扩展集、低档位（all 档全集已跑，无增量）
		if !linked[id] && level != "all" && !promotedSet[id] && checks.IsExtended(id) {
			promotedSet[id] = true
			promoted = append(promoted, id)
		}
	}
	return promoted
}

// mlPriorFromTech 指纹技术名 → 产品映射表 → check 先验（5.2 阶段 2 主路径）。
func mlPriorFromTech(techs []Tech, level string, linked map[string]bool) (*checks.Prior, []string, map[string]any) {
	boost := map[string]float64{}
	promotedSet := map[string]bool{}
	var promoted []string
	var prods []map[string]any
	for _, t := range techs {
		matches := checks.MLProductChecksForTech(t.Name)
		if len(matches) == 0 {
			continue
		}
		// 同一技术名命中多个 key 时取映射表首个（如 phpMyAdmin 先于 PHP），
		// 避免同一技术重复计数。
		m := matches[0]
		prods = append(prods, map[string]any{
			"product": t.Name,
			"prob":    mlRound3(mlPriorFingerprintBoost),
			"source":  "fingerprint",
			"key":     m.Key,
		})
		promoted = mlPriorApply(boost, m.IDs, mlPriorFingerprintBoost,
			level, linked, promotedSet, promoted)
		if len(prods) >= mlPriorMaxProducts {
			break
		}
	}
	if len(boost) == 0 {
		return nil, nil, nil
	}
	info := map[string]any{
		"products":    prods,
		"boosted":     len(boost),
		"family_link": false,
		"source":      "fingerprint",
	}
	if len(promoted) > 0 {
		info["promoted"] = promoted
	}
	return &checks.Prior{Boost: boost}, promoted, info
}

// mlPriorFromText 旧文本模型先验：cve-tech 概率 Top-5 → 映射表。
func mlPriorFromText(assets *ml.Assets, text, level string,
	linked map[string]bool) (*checks.Prior, []string, map[string]any) {
	boost := map[string]float64{}
	promotedSet := map[string]bool{}
	var promoted []string
	var prods []map[string]any
	mapped := 0
	for _, p := range assets.Tech.ProbaTopK(text, 5) {
		prods = append(prods, map[string]any{
			"product": p.Class,
			"prob":    mlRound3(p.Score),
			"source":  "model",
		})
		if mapped >= mlPriorMaxProducts || p.Score < mlPriorMinProb {
			continue
		}
		mapped++
		promoted = mlPriorApply(boost, checks.MLProductChecks(p.Class), p.Score,
			level, linked, promotedSet, promoted)
	}
	if len(boost) == 0 {
		return nil, nil, nil
	}
	info := map[string]any{
		"products":    prods,
		"boosted":     len(boost),
		"family_link": true,
		"source":      "model",
	}
	if len(promoted) > 0 {
		info["promoted"] = promoted
	}
	return &checks.Prior{Boost: boost}, promoted, info
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
