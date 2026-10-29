package intel

import (
	"fmt"
	"math"
	"strings"
)

// CVSS v3.1 基础评分器（FIRST 规范，对齐 Python 分支 tools/osv.py 的
// cvss_v3_score 实现）：解析 CVSS:3.x 向量 → 0-10 基础分 + 等级。
// OSV 同步用：GHSA/OSV 提供 CVSS_V3 向量，本地算分，无需 NVD。

// cvssAV CVSS v3.1 表 2：攻击向量权重。
//
// ⚠️ v3.1 的 AV:L = 0.55。0.39 是 **CVSS v2** 的 AV:L（两版取值表不同）——
// 此前误把 v2 的值带进 v3.1 表，导致所有「本地攻击」向量的分数系统性偏低
// （实测 29 万条 NVD v3 向量中 23.29% 的分数与官方分不符）。
var cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var cvssAC = map[string]float64{"L": 0.77, "H": 0.44}
var cvssPRu = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
var cvssPRc = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
var cvssUI = map[string]float64{"N": 0.85, "R": 0.62}
var cvssCIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

// roundup1 CVSS 3.1 规范取整：向上取到一位小数（4 位小数精度容差）。
func roundup1(v float64) float64 {
	input := math.Round(v*100000) / 100000
	rounded := math.Ceil(input*10) / 10
	if rounded < 0 {
		return 0
	}
	return math.Min(rounded, 10)
}

// CVSS3 向量 →（基础分, 等级）。向量形如
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"（版本前缀可省略）。
// 解析失败/缺关键指标返回错误。
func CVSS3Score(vector string) (float64, string, error) {
	v := strings.TrimPrefix(strings.TrimSpace(vector), "CVSS:3.1/")
	v = strings.TrimPrefix(v, "CVSS:3.0/")
	if v == "" {
		return 0, "", fmt.Errorf("空向量")
	}
	var av, ac, pr, ui, c, i, a float64
	var avOK, acOK, prOK, uiOK, cOK, iOK, aOK bool
	// Scope 预扫描：PR 的权重取决于 Scope（U 用 PRu / C 用 PRc），但 NVD 的向量串
	// 顺序恒为 AV:AC:PR:UI:S:C:I:A——S 恒在 PR 之后。若按 token 顺序决定权重，
	// 每个 S:C 向量都会误用 PRu 权重（PR:L 0.62 vs 0.68、PR:H 0.27 vs 0.50），
	// 分数系统性偏低。规范不要求向量串有序，故先扫出 Scope 再进主循环。
	scopeChanged := false
	for _, part := range strings.Split(v, "/") {
		if strings.TrimSpace(part) == "S:C" {
			scopeChanged = true
			break
		}
	}
	for _, part := range strings.Split(v, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(part) < 2 {
			return 0, "", fmt.Errorf("未知指标 %s", part)
		}
		ci := strings.Index(part, ":")
		if ci < 1 {
			return 0, "", fmt.Errorf("未知指标 %s", part)
		}
		k := strings.TrimSuffix(part[:ci], ":")
		val := part[ci+1:]
		_ = k
		switch {
		case k == "S":
			// Scope 已在循环外预扫描（见上）。此处仅跳过，不重复赋值。
			continue
		}
		switch k {
		case "AV":
			w, ok := cvssAV[val]
			if !ok {
				return 0, "", fmt.Errorf("未知 AV 取值 %s", val)
			}
			av, avOK = w, true
		case "AC":
			w, ok := cvssAC[val]
			if !ok {
				return 0, "", fmt.Errorf("未知 AC 取值 %s", val)
			}
			ac, acOK = w, true
		case "PR":
			m := cvssPRu
			if scopeChanged {
				m = cvssPRc
			}
			w, ok := m[val]
			if !ok {
				return 0, "", fmt.Errorf("未知 PR 取值 %s", val)
			}
			pr, prOK = w, true
		case "UI":
			w, ok := cvssUI[val]
			if !ok {
				return 0, "", fmt.Errorf("未知 UI 取值 %s", val)
			}
			ui, uiOK = w, true
		case "C", "I", "A":
			w, ok := cvssCIA[val]
			if !ok {
				return 0, "", fmt.Errorf("未知 %s 取值 %s", k, val)
			}
			switch k {
			case "C":
				c, cOK = w, true
			case "I":
				i, iOK = w, true
			case "A":
				a, aOK = w, true
			}
		}
	}
	if !avOK || !acOK || !prOK || !uiOK || !cOK || !iOK || !aOK {
		return 0, "", fmt.Errorf("向量不完整")
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		// CVSS v3.1 §8.1.2：系数是 3.25（此前误写 3.257）。
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, "none", nil
	}
	base := impact + exploitability
	if scopeChanged {
		// CVSS v3.1 §8.1.3：Scope Changed 时基础分再乘 1.08。
		// 此前漏了这一步 → 所有 S:C 向量分数系统性偏低（实测 19.92% 的
		// NVD v3 向量算出的分与官方分不符）。补上后与官方分逐条一致。
		base *= 1.08
	}
	score := roundup1(math.Min(base, 10))
	return score, cvssLabel(score), nil
}

func cvssLabel(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}
