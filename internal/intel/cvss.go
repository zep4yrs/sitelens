package intel

import (
	"fmt"
	"math"
	"strings"
)

// CVSS v3.1 基础评分器（FIRST 规范，对齐 Python 分支 tools/osv.py 的
// cvss_v3_score 实现）：解析 CVSS:3.x 向量 → 0-10 基础分 + 等级。
// OSV 同步用：GHSA/OSV 提供 CVSS_V3 向量，本地算分，无需 NVD。

var cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.39, "P": 0.2}
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
	scopeChanged := false
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
			if val == "C" {
				scopeChanged = true
			}
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
		impact = 7.52*(iss-0.029) - 3.257*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, "none", nil
	}
	score := roundup1(math.Min(impact+exploitability, 10))
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
