// OSV.dev 情报同步（1.0 运营链路）：为 vuln_kb 的 CVE 补全受影响区间
// 与 CVSS 评分。公开 API（api.osv.dev）无需凭据；结果写入 overrides
// 文件，intel.Load 启动时合并——静态情报快照保持不可变，更新走旁路。
package intel

import (
	"encoding/json"
	"sort"
	"strings"
)

// OsvVuln OSV API v1 响应（/v1/vulns/{id}）的建模（仅消费所需字段）。
type OsvVuln struct {
	ID       string `json:"id"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// OsvAffectedFromVuln 从 OSV 响应提取区间串（ECOSYSTEM/GIT 优先，
// ">=introduced,<fixed" 逗号条件，直接兼容 versioncmp.VersionIn）。
// 返回空串表示无可提取区间。
func OsvAffectedFromVuln(v OsvVuln) string {
	var conds []string
	for _, aff := range v.Affected {
		for _, rg := range aff.Ranges {
			if rg.Type != "ECOSYSTEM" && rg.Type != "GIT" {
				continue
			}
			var introduced string
			for _, ev := range rg.Events {
				if ev.Introduced != "" {
					introduced = ev.Introduced
				}
				if ev.Fixed != "" && introduced != "" {
					conds = append(conds, ">="+introduced, "<"+ev.Fixed)
				}
			}
		}
	}
	if len(conds) == 0 {
		return ""
	}
	// 去重保序
	seen := map[string]bool{}
	var out []string
	for _, c := range conds {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return strings.Join(out, ",")
}

// OsvCVSSFromVuln 取 CVSS_V3 向量并本地算分；无向量返回零值。
func OsvCVSSFromVuln(v OsvVuln) (float64, string) {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if score, sev, err := CVSS3Score(s.Score); err == nil {
				return score, sev
			}
		}
	}
	return 0, ""
}

// Override 单条 CVE 覆盖（区间补全 + CVSS 评分）。
type Override struct {
	Affected  string  `json:"affected,omitempty"`
	CVSSScore float64 `json:"cvss_score,omitempty"`
	CVSSSev   string  `json:"cvss_sev,omitempty"`
}

// ParseOverrides 解析 overrides 文件内容。
func ParseOverrides(data []byte) (map[string]Override, error) {
	var m map[string]Override
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// MergeOverrides 把覆盖合并进 vuln_kb 条目：Affected 追加去重、
// CVSS 空位补齐。返回生效条数。
func MergeOverrides(vulns []Entry, ov map[string]Override) int {
	n := 0
	// CVE 索引：同 CVE 可能多条情报
	byCVE := map[string][]int{}
	for i := range vulns {
		c := strings.ToUpper(strings.TrimSpace(vulns[i].CVE))
		if c != "" {
			byCVE[c] = append(byCVE[c], i)
		}
	}
	for cve, o := range ov {
		idx, ok := byCVE[strings.ToUpper(strings.TrimSpace(cve))]
		if !ok {
			continue
		}
		for _, i := range idx {
			changed := false
			if o.Affected != "" && !strings.Contains(vulns[i].Affected, o.Affected) {
				if vulns[i].Affected == "" {
					vulns[i].Affected = o.Affected
				} else {
					vulns[i].Affected += "|" + o.Affected
				}
				changed = true
			}
			if vulns[i].CVSSScore == 0 && o.CVSSScore > 0 {
				vulns[i].CVSSScore = o.CVSSScore
				vulns[i].CVSSSev = o.CVSSSev
				changed = true
			}
			if changed {
				n++
			}
		}
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID }) // 稳定输出
	return n
}
