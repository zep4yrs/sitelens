// ml.go 5.0 ML 推理富化接线（L3 阶段 A：cve-tech + cwe-type 线性模型）。
//
// 原则（开发文档-5.0-ML预训练.md §10）：模型只提供先验参考，不改变
// 扫描行为与判定结果；资产缺失/加载失败/推理异常一律静默跳过——
// predictions 字段缺席，主流程零影响（§10.5「预测失败静默降级」）。
package engine

import (
	"os"
	"path/filepath"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// mlFor 惰性取 ML 资产：首次预测才读 coef（cve-tech 196×120k = 94MB）。
// 相对路径相对进程 cwd（与 data/ 其他默认路径同约定）。
//
// 两种静默出口语义不同：
//   - 目录/关键文件不存在 → 返回 nil 不置死标记（资产可能随后补齐，
//     每次扫描只付一次 stat 的代价）；
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
		e.mlDead = true
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, "cve-tech.coef.f32")); err != nil {
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

// mlEnrich 扫描收尾的 ML 富化：对 res.Vulnerabilities 中出现过的
// 不重复 CVE id——从 NVD 镜像取描述 → 双模型推理 → 组装 Prediction
// （tech_top5 含与检出技术的 relevance 交集标记；sev_score 以 NVD
// CVSS 先验填充，sev-prior ONNX 回归头为阶段 B）。无描述的 CVE 跳过
// （模型输入是英文描述，不臆造）；一条预测都组不出来时不挂字段。
func (e *Engine) mlEnrich(res *Result, kb *intel.KB) {
	assets := e.mlFor()
	if assets == nil {
		return
	}
	var cves []string
	seen := map[string]bool{}
	for _, f := range res.Vulnerabilities {
		c := strings.ToUpper(strings.TrimSpace(f.CVE))
		if !strings.HasPrefix(c, "CVE-") || seen[c] {
			continue
		}
		seen[c] = true
		cves = append(cves, c)
	}
	if len(cves) == 0 {
		return
	}
	techKeys := mlTechKeys(res.Technologies)
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
		preds = append(preds, ml.Prediction{
			CVE:      cve,
			TechTop5: tp,
			CWEType:  cweType,
			SevScore: sev,
		})
	}
	if len(preds) > 0 {
		res.Predictions = preds
	}
}

// mlDescr CVE 描述与 CVSS 先验。NVD 镜像优先（复用 intel 既有入口：
// KB.NVD() 触发惰性解码 + NVDStore.ByCVE 精确查询）；镜像未挂载或
// 未知 CVE 时，回退到扫描结果中该 CVE 情报行自带的英文描述与 CVSS
// 分（数据已在结果里，不新增数据源）。
func mlDescr(kb *intel.KB, findings []intel.Finding, cve string) (string, float64) {
	if kb != nil {
		// kb/NVDStore 为 nil（未挂载 NVD）时 ByCVE 返回 false，安全
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
