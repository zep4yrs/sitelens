// ml.go 5.0 ML 引擎融合接线——共享资产加载（mlFor）+ 后置预测富化通道
// （mlEnrich）。前置通道（cve-tech 产品先验 → check 提权调度）在
// mlprior.go；中段家族联动在 internal/checks/prior.go。
//
// 三通道共用铁律（开发文档-5.0-ML预训练.md §10.7）：ML 只增不删——
// 只影响执行顺序与低档位增量纳入，绝不从执行集剔除任何 check，命中
// 判定与 severity 展示来源不变；无先验时调度严格清单序（与 4.0 逐字节
// 一致）；资产缺失/加载失败/推理异常一律静默跳过，主流程零影响。
// ml.predict 总闸（config）同时管辖三通道。
package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// mlFor 惰性取 ML 资产：首次预测才读 coef（cve-tech 196×120k = 94MB）。
// 相对路径相对进程 cwd（与 data/ 其他默认路径同约定）。
//
// 两种静默出口语义不同：
//   - 目录/任一关键文件不存在 → 返回 nil 不置死标记（资产可能随后补齐
//     或分步部署，每次扫描只付一次 stat 的代价）；
//   - 加载失败（文件损坏/维度不符）→ 置 mlDead 本进程永久禁用：
//     损坏不会自愈，重试只会每次扫描反复重读 94MB。
func (e *Engine) mlFor() *ml.Assets {
	e.mlMu.Lock()
	defer e.mlMu.Unlock()
	if e.mlDead {
		return nil
	}
	if e.mlAssets != nil {
		return e.mlAssets
	}
	// 资产目录候选：配置优先 → cwd 常规路径 → 仓库内建 ml/models/ →
	// 可执行文件相对路径（CLI/壳从任意 cwd 启动时兜底）。候选表收敛在
	// ml.AssetCandidates，诊断（internal/diag）引用同一份，避免两处漂移。
	dir := ml.LocateAssetsDir(ml.AssetCandidates(e.cfg.ML.AssetsDir)...)
	if dir == "" {
		return nil
	}
	a, err := ml.LoadAssets(dir)
	if err != nil {
		e.mlDead = true
		return nil
	}
	e.mlAssets = a
	return a
}

// sevAssetsDir 解析 sev-prior ONNX 资产目录：与 mlFor 同源候选
// （配置优先 → 运行时常规路径 → 仓库内建 ml/models/）。
//
// BUG-019：原实现直接用 e.cfg.ML.AssetsDir——默认值 data/go/ml_assets
// 在仓内不存在（资产随「模型进仓库本体」迁到 ml/models/go/ml_assets），
// 于是 ONNX glob 恒落空、sev_onnx 通道恒不可用并静默回退 NVD 先验。
// 与 mlFor 一样收敛到 ml.LocateAssetsDir，避免两处各自维护候选表。
// 候选全不合格时退回配置值：自定义部署可能只投放 ONNX 文件（无线性
// 模型成套资产），保持其原路径语义。
func (e *Engine) sevAssetsDir() string {
	if e.cfg == nil {
		return ""
	}
	if dir := ml.LocateAssetsDir(ml.AssetCandidates(e.cfg.ML.AssetsDir)...); dir != "" {
		return dir
	}
	return e.cfg.ML.AssetsDir
}

// mlSevScorer 惰性取 sev-prior ONNX 打分器（阶段 B，§10.8）。一次尝试：
// 未启用/无 onnx 构建标签/资产或共享库缺失，返回 nil 并带降级原因
// （引擎回退 NVD CVSS 先验；原因落 extras["ml_sev"] 可解释）。
func (e *Engine) mlSevScorer() *ml.SevScorer {
	e.mlMu.Lock()
	defer e.mlMu.Unlock()
	if e.mlSevTried {
		return e.mlSev
	}
	e.mlSevTried = true
	if !e.cfg.ML.SevONNX {
		e.mlSevReason = "sev_onnx 未启用"
		return nil
	}
	assets := e.sevAssetsDir()
	// 集成清单：双种子 fp32 对 → int8 对 → 旧单文件（兼容既往资产布局）
	var onnx []string
	for _, pat := range []string{"sev-prior-v3.1-[ab].onnx", "sev-prior-v3.1-[ab]-int8.onnx"} {
		if m, _ := filepath.Glob(filepath.Join(assets, pat)); len(m) > 0 {
			onnx = m
			break
		}
	}
	if len(onnx) == 0 {
		single := filepath.Join(assets, "sev-prior-v3.1.onnx")
		if _, err := os.Stat(single); err == nil {
			onnx = []string{single}
		} else {
			onnx = []string{filepath.Join(assets, "sev-prior-v3.1-int8.onnx")}
		}
	}
	vocab := filepath.Join(assets, "sev-prior-v3.1.vocab.txt")
	// 共享库候选：配置 → 运行时路径 → 仓库内建 ml/models/（克隆即用）
	dll := e.cfg.ML.OnnxrtDLL
	dllCands := []string{dll, filepath.Join("data", "onnxruntime", "onnxruntime.dll"),
		filepath.Join("ml", "models", "onnxruntime", "onnxruntime.dll")}
	dll = ""
	for _, cand := range dllCands {
		if cand != "" {
			if _, err := os.Stat(cand); err == nil {
				dll = cand
				break
			}
		}
	}
	if dll == "" {
		e.mlSevReason = "onnxruntime 共享库缺失"
		return nil
	}
	s, err := ml.NewSevScorer(vocab, dll, onnx)
	if err != nil {
		e.mlSevReason = err.Error()
		return nil
	}
	e.mlSev = s
	return s
}

// InvalidateMLSev 作废 sev 打分器的一次性尝试缓存（设置页翻转
// sev_onnx 后调用）：下次扫描按新开关重建或跳过。
func (e *Engine) InvalidateMLSev() {
	e.mlMu.Lock()
	e.mlSevTried = false
	e.mlSev = nil
	e.mlSevReason = ""
	e.mlMu.Unlock()
}

// mlEnrich 扫描收尾的 ML 富化：对 res.Vulnerabilities 中出现过的
// 不重复 CVE id 组装 Prediction。5.2 阶段 2 起字段一律「查表优先」：
//
//	tech_top5  — NVD CPE（nvd）/ finding 自带 product（intel）→ 模型（model）
//	cwe_type   — NVD weaknesses / finding CWEs（nvd）→ 模型（model）
//	sev_score  — 查表（nvd）→ sev-linear（linear）→ 可选 ONNX（onnx）
//
// 只有当对应字段查不到时才惰性加载模型资产；查表全覆盖时不读 94MB
// cve-tech。无描述且无任何查表字段的 CVE 跳过（不臆造）；一条预测都
// 组不出来时不挂字段。
func (e *Engine) mlEnrich(res *Result, kb *intel.KB) {
	// 先收集 CVE：无 CVE 的结果在此即返回，连资产目录都不触碰——
	// cve-tech coef（94MB）读入后没有任何卸载路径，不能为空结果白付常驻。
	var cves []string
	seen := map[string]bool{}
	for _, f := range res.Vulnerabilities {
		c := strings.TrimSpace(f.CVE)
		if !cveIDRe.MatchString(strings.ToUpper(c)) {
			continue // 整体形态校验：只认 CVE-年份-序号，拒收带尾巴等杂质形态
		}
		key := strings.ToUpper(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		cves = append(cves, c) // 保留原始形态：与 vulnerabilities.cve 一致，消费方按 cve 精确关联不 miss
	}
	if len(cves) == 0 {
		return
	}
	techKeys := mlTechKeys(res.Technologies)
	// 5.2 阶段 2：产品/CWE/严重度一律「查表优先」——NVD 镜像与 finding
	// 自带字段能答的条目直接出结论；模型资产按需惰性加载（查表全覆盖时
	// 连 cve-tech 94MB 都不读），把模型价值区间压到真盲区。
	var assets *ml.Assets
	assetsTried := false
	getAssets := func() *ml.Assets {
		if !assetsTried {
			assetsTried = true
			assets = e.mlFor()
		}
		return assets
	}
	sevScorer := e.mlSevScorer() // nil = ONNX 未启用/不可用
	sevBroken := false
	sevStats := map[string]int{"nvd": 0, "linear": 0, "onnx": 0, "none": 0}
	techStats := map[string]int{"nvd": 0, "intel": 0, "model": 0, "none": 0}
	cweStats := map[string]int{"nvd": 0, "model": 0, "none": 0}
	preds := make([]ml.Prediction, 0, len(cves))
	for _, cve := range cves {
		info := mlCVEInfoOf(kb, res.Vulnerabilities, cve)
		if info.Descr == "" && len(info.Prods) == 0 && len(info.CWEs) == 0 && info.Score == 0 {
			continue // 无描述、无查表字段：不臆造
		}
		// 产品 Top-5：CPE / 情报行 product 查表优先，模型只补盲区。
		var tp []ml.TechPred
		techSrc := ""
		if len(info.Prods) > 0 {
			for i, p := range info.Prods {
				if i >= 5 {
					break
				}
				tp = append(tp, ml.TechPred{
					Product:   p,
					Prob:      1, // 查表结果不是概率，固定 1 并由 TechSource 标注来源
					Relevance: mlRelevance(p, techKeys),
				})
			}
			techSrc = info.ProdSource
		} else if a := getAssets(); a != nil && info.Descr != "" {
			for _, t := range a.Tech.ProbaTopK(info.Descr, 5) {
				tp = append(tp, ml.TechPred{
					Product:   t.Class,
					Prob:      t.Score,
					Relevance: mlRelevance(t.Class, techKeys),
				})
			}
			techSrc = "model"
		}
		if techSrc == "" {
			techStats["none"]++
		} else {
			techStats[techSrc]++
		}
		// CWE：NVD weaknesses（或 finding 回填的 CWEs）查表优先，模型兜底。
		cweType, cweSrc := "", ""
		if len(info.CWEs) > 0 {
			cweType, cweSrc = info.CWEs[0], "nvd"
		} else if a := getAssets(); a != nil && info.Descr != "" {
			cweType, _ = a.Cwe.ArgMax(info.Descr)
			cweSrc = "model"
		}
		if cweSrc == "" {
			cweStats["none"]++
		} else {
			cweStats[cweSrc]++
		}
		// 严重度：查表 → sev-linear → 可选 ONNX → 无先验。
		sev, sevSrc := 0.0, ""
		if info.Score > 0 {
			sev, sevSrc = info.Score, "nvd"
		}
		if sevSrc == "" && e.cfg != nil && e.cfg.ML.SevLinear && info.Descr != "" {
			if a := getAssets(); a != nil && a.Sev != nil {
				if s, err := a.Sev.RegressionScore(info.Descr); err == nil {
					sev, sevSrc = s, "linear"
				}
			}
		}
		if sevSrc == "" && sevScorer != nil && !sevBroken && info.Descr != "" {
			if s, serr := sevScorer.Score(info.Descr); serr == nil {
				sev, sevSrc = s, "onnx"
			} else {
				sevBroken = true
			}
		}
		if sevSrc == "" {
			sevStats["none"]++
		} else {
			sevStats[sevSrc]++
		}
		preds = append(preds, ml.Prediction{
			CVE:        cve,
			TechTop5:   tp,
			CWEType:    cweType,
			SevScore:   sev,
			SevSource:  sevSrc,
			TechSource: techSrc,
			CWESource:  cweSrc,
		})
	}
	// extras.ml_sev：严重度来源可解释信息（web 摘要区/诊断用）。
	// active 表示本次是否有"模型推理"型严重度（线性/ONNX）；nvd 查表属
	// 权威数据，不算模型推理。旧字段与旧取值（onnx/nvd）继续输出 SevSource。
	info := map[string]any{
		"active": sevStats["linear"]+sevStats["onnx"] > 0,
		"nvd":    sevStats["nvd"],
		"linear": sevStats["linear"],
		"onnx":   sevStats["onnx"],
		"none":   sevStats["none"],
		"tech":   techStats, // 5.2 阶段 2：产品来源计数（nvd/intel/model/none）
		"cwe":    cweStats,  // 5.2 阶段 2：CWE 来源计数（nvd/model/none）
	}
	if e.cfg != nil && e.cfg.ML.SevONNX && sevScorer == nil {
		info["reason"] = e.mlSevReason
	} else if sevBroken {
		info["reason"] = "onnx 推理失败，已回退线性/NVD"
	}
	if assets != nil && assets.SevErr != "" {
		info["linear_reason"] = assets.SevErr
	}
	if res.Extras == nil { // 防御：测试/嵌入调用可能未初始化 extras
		res.Extras = map[string]any{}
	}
	res.Extras["ml_sev"] = info
	if len(preds) > 0 {
		res.Predictions = preds
	}
}

// cveIDRe CVE 编号整体形态（年份 4 位 + 序号 >= 4 位）。收集时只认整体
// 合法形态：此前仅 strings.HasPrefix(c, "CVE-")，"CVE-2021-1002 (PoC)"
// 这类带尾杂质会通过收集并原样进 predictions，fallback 通道还会与之
// 相互命中。
var cveIDRe = regexp.MustCompile(`^CVE-\d{4,}-\d{4,}$`)

// mlCVEInfo CVE 的权威字段：NVD 镜像优先，回退 findings 自带字段。
// 5.2 阶段 2 起 mlEnrich 的产品/CWE/严重度都先查这里，查不到才用模型。
type mlCVEInfo struct {
	Descr      string
	Score      float64
	Prods      []string // NVD CPE vendor/product；回退 finding.Product（单值）
	CWEs       []string
	ProdSource string // nvd = NVD CPE；intel = finding.Product；空 = 无
}

// mlCVEInfoOf 取 CVE 的查表字段。NVD 镜像**仅在索引已解码常驻时**顺带
// 查询（NVDLoaded 不触发加载）：cveMs-only 等未拉起场景若在此首次拉起
// 全量索引（实测 3.46s / 37 万条 / ≈1.7GB 常驻），会同步阻塞扫描收尾、
// 抬高常驻内存并让后续 overBudget 更易降档——违背「模型不改变扫描
// 行为」原则，与 cwe.Relate 的 A3 惰性纪律（engine.go「只判断是否配置，
// 不拉起索引」）对齐。镜像未拉起或未知 CVE 时，回退到扫描结果中该 CVE
// 情报行自带的描述/CVSS/CWE/产品（数据已在结果里，不新增数据源）。
func mlCVEInfoOf(kb *intel.KB, findings []intel.Finding, cve string) mlCVEInfo {
	var info mlCVEInfo
	if kb != nil && kb.NVDLoaded() {
		// 索引已常驻：ByCVE 精确查询（NVDStore 为 nil 安全）
		if e, ok := kb.NVD().ByCVE(cve); ok {
			info.Descr = e.Descr
			info.Score = e.Score
			info.CWEs = e.CWEs
			for _, p := range e.Prods {
				if p.VP != "" {
					info.Prods = append(info.Prods, p.VP)
				}
			}
			if len(info.Prods) > 0 {
				info.ProdSource = "nvd"
			}
			return info
		}
	}
	// NVD 未常驻或未知 CVE：合并同 CVE 的多条 finding 自带字段。
	seenCWE := map[string]bool{}
	for _, f := range findings {
		if !strings.EqualFold(strings.TrimSpace(f.CVE), cve) {
			continue
		}
		if info.Descr == "" && f.Desc != "" {
			info.Descr = f.Desc
		}
		if info.Score == 0 && f.CVSSScore > 0 {
			info.Score = f.CVSSScore
		}
		for _, c := range f.CWEs {
			if c != "" && !seenCWE[c] {
				seenCWE[c] = true
				info.CWEs = append(info.CWEs, c)
			}
		}
		if len(info.Prods) == 0 && strings.TrimSpace(f.Product) != "" {
			info.Prods = []string{strings.TrimSpace(f.Product)}
			info.ProdSource = "intel"
		}
	}
	return info
}

// mlDescr 兼容旧接口：返回描述与 CVSS 分（内部走 mlCVEInfoOf）。
func mlDescr(kb *intel.KB, findings []intel.Finding, cve string) (string, float64) {
	info := mlCVEInfoOf(kb, findings, cve)
	return info.Descr, info.Score
}

// mlTechKeys 预计算检出技术的归一匹配键集合。
func mlTechKeys(techs []Tech) map[string]bool {
	keys := make(map[string]bool, len(techs))
	for _, t := range techs {
		if k := mlNorm(t.Name); k != "" {
			keys[k] = true
		}
	}
	return keys
}

// mlNorm 归一：小写、仅保留字母数字——对齐类别表的 vendor/product
// 形态（"Apache Tomcat" → "apachetomcat" 与 "apache/tomcat" 同键）。
func mlNorm(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mlRelevance tech_top5 条目与检出技术的交集标记（模型不输出，引擎组装）：
//   - hit：归一全串（vendor+product）与某检出技术键相等
//     （"Apache Tomcat" ↔ "apache/tomcat"）
//   - related：仅产品段相等（"PHP" ↔ "php/php"）——同产品弱证据
//   - ""：无交集（omitempty，不输出）
//
// 刻意只做等值匹配：代价是版本细分名（"Windows" ↔ "microsoft/windows_10"）
// 不标或标不上，但绝无跨版本/跨产品误标——relevance 是先验提示，
// 宽匹配的误标比窄匹配的漏标危害大。
func mlRelevance(class string, techKeys map[string]bool) string {
	if len(techKeys) == 0 {
		return ""
	}
	low := strings.ToLower(class)
	prod := low
	if i := strings.IndexByte(low, '/'); i >= 0 {
		prod = low[i+1:]
	}
	if techKeys[mlNorm(low)] {
		return ml.RelHit
	}
	if techKeys[mlNorm(prod)] {
		return ml.RelRelated
	}
	return ""
}
