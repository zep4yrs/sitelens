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
	dir := e.cfg.ML.AssetsDir
	if dir == "" {
		// 未配置资产目录：配置在本进程内不会变，置死避免反复空转
		//（区别于「配置了但尚未就绪」——那种情况绝不置死）。
		e.mlDead = true
		return nil
	}
	// 关键文件存在性全量预检（双模型 × meta/vocab/idf/coef）：任何一件
	// 缺失都算「资产未就绪」，返回 nil 不置死。此前只 Stat cve-tech.coef.f32
	// 一件，其余文件缺失会落进 LoadAssets 的报错分支被当作「损坏」永久
	// 禁用——资产分步部署/更新窗口内一次扫描就把 ML 打死到进程重启。
	for _, name := range []string{"cve-tech", "cwe-type"} {
		for _, ext := range []string{".meta.json", ".vocab.txt", ".idf.f32", ".coef.f32"} {
			if _, err := os.Stat(filepath.Join(dir, name+ext)); err != nil {
				return nil
			}
		}
	}
	a, err := ml.LoadAssets(dir)
	if err != nil {
		e.mlDead = true
		return nil
	}
	e.mlAssets = a
	return a
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
	assets := e.cfg.ML.AssetsDir
	onnx := filepath.Join(assets, "sev-prior-v3.1.onnx")
	if _, err := os.Stat(onnx); err != nil { // fp32 缺失退 int8（低配形态）
		onnx = filepath.Join(assets, "sev-prior-v3.1-int8.onnx")
	}
	vocab := filepath.Join(assets, "sev-prior-v3.1.vocab.txt")
	dll := e.cfg.ML.OnnxrtDLL
	if dll == "" {
		dll = filepath.Join("data", "onnxruntime", "onnxruntime.dll")
	}
	s, err := ml.NewSevScorer(onnx, vocab, dll)
	if err != nil {
		e.mlSevReason = err.Error()
		return nil
	}
	e.mlSev = s
	return s
}

// mlEnrich 扫描收尾的 ML 富化：对 res.Vulnerabilities 中出现过的
// 不重复 CVE id——从 NVD 镜像取描述 → 双模型推理 → 组装 Prediction
// （tech_top5 含与检出技术的 relevance 交集标记；sev_score 以 NVD
// CVSS 先验填充，sev-prior ONNX 回归头为阶段 B）。无描述的 CVE 跳过
// （模型输入是英文描述，不臆造）；一条预测都组不出来时不挂字段。
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
	assets := e.mlFor()
	if assets == nil {
		return
	}
	techKeys := mlTechKeys(res.Technologies)
	// sev-prior 模型分（阶段 B）：nil = 回退 NVD 先验；首次推理失败后
	// 本次扫描余下 CVE 全走回退（模型级故障不会因重试自愈）
	sevScorer := e.mlSevScorer()
	sevBroken := false
	sevFallback := 0
	preds := make([]ml.Prediction, 0, len(cves))
	for _, cve := range cves {
		descr, sev := mlDescr(kb, res.Vulnerabilities, cve)
		if descr == "" {
			continue
		}
		top5 := assets.Tech.ProbaTopK(descr, 5)
		tp := make([]ml.TechPred, len(top5))
		for i, t := range top5 {
			tp[i] = ml.TechPred{
				Product:   t.Class,
				Prob:      t.Score,
				Relevance: mlRelevance(t.Class, techKeys),
			}
		}
		cweType, _ := assets.Cwe.ArgMax(descr)
		sevSrc := ""
		if sevScorer != nil && !sevBroken {
			if s, serr := sevScorer.Score(descr); serr == nil {
				sev, sevSrc = s, "onnx"
			} else {
				sevBroken = true
			}
		}
		if sevSrc == "" {
			sevSrc = "nvd"
			sevFallback++
		}
		preds = append(preds, ml.Prediction{
			CVE:       cve,
			TechTop5:  tp,
			CWEType:   cweType,
			SevScore:  sev,
			SevSource: sevSrc,
		})
	}
	if e.cfg.ML.SevONNX {
		info := map[string]any{"active": sevScorer != nil && !sevBroken}
		if sevScorer == nil {
			info["reason"] = e.mlSevReason
		} else if sevBroken {
			info["reason"] = "推理失败，回退 NVD 先验"
		}
		if sevFallback > 0 {
			info["nvd_fallback"] = sevFallback
		}
		res.Extras["ml_sev"] = info
	}
	if len(preds) > 0 {
		res.Predictions = preds
	}
}

// cveIDRe CVE 编号整体形态（年份 4 位 + 序号 >= 4 位）。收集时只认整体
// 合法形态：此前仅 strings.HasPrefix(c, "CVE-")，"CVE-2021-1002 (PoC)"
// 这类带尾杂质会通过收集并原样进 predictions，fallback 通道还会与之
// 相互命中。
var cveIDRe = regexp.MustCompile(`^CVE-\d{4,}-\d{4,}$`)

// mlDescr CVE 描述与 CVSS 先验。NVD 镜像**仅在索引已解码常驻时**顺带
// 查询（NVDLoaded 不触发加载）：cveMs-only 等未拉起场景若在此首次拉起
// 全量索引（实测 3.46s / 37 万条 / ≈1.7GB 常驻），会同步阻塞扫描收尾、
// 抬高常驻内存并让后续 overBudget 更易降档——违背「模型不改变扫描
// 行为」原则，与 cwe.Relate 的 A3 惰性纪律（engine.go「只判断是否配置，
// 不拉起索引」）对齐。镜像未拉起或未知 CVE 时，回退到扫描结果中该 CVE
// 情报行自带的英文描述与 CVSS 分（数据已在结果里，不新增数据源）。
func mlDescr(kb *intel.KB, findings []intel.Finding, cve string) (string, float64) {
	if kb.NVDLoaded() {
		// 索引已常驻：ByCVE 精确查询（NVDStore 为 nil 安全）
		if e, ok := kb.NVD().ByCVE(cve); ok {
			return e.Descr, e.Score
		}
	}
	for _, f := range findings {
		if strings.EqualFold(strings.TrimSpace(f.CVE), cve) && f.Desc != "" {
			return f.Desc, f.CVSSScore
		}
	}
	return "", 0
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
