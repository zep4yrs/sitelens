// AU-02 审计结果 diff：与上一次审计 JSON 报告按指纹对比，输出新增/已修复。
//
// 指纹口径与 baseline/SARIF 完全一致（见 Fingerprint），因此「基线忽略的
// 告警」与「diff 判定为未变的告警」是同一套身份语义。
package audit

// DiffResult 两次审计报告的差异（按发现指纹）。
type DiffResult struct {
	New   int `json:"new"`
	Fixed int `json:"fixed"`
	// NewFindings 本轮新增（旧报告没有的指纹），保持报告内顺序。
	NewFindings []Finding `json:"new_findings,omitempty"`
	// FixedFindings 已修复（旧报告有、本轮没有的指纹），保持旧报告内顺序。
	FixedFindings []Finding `json:"fixed_findings,omitempty"`
}

// DiffReports 对比当前报告与旧报告，返回新增/已修复（按指纹去重）。
// cur/old 为 nil 时按空报告处理。
func DiffReports(cur, old *Report) *DiffResult {
	res := &DiffResult{}
	oldSet := map[string]bool{}
	if old != nil {
		for _, f := range old.Findings {
			oldSet[Fingerprint(f)] = true
		}
	}
	curSet := map[string]bool{}
	if cur != nil {
		seen := map[string]bool{}
		for _, f := range cur.Findings {
			fp := Fingerprint(f)
			curSet[fp] = true
			if oldSet[fp] || seen[fp] {
				continue
			}
			seen[fp] = true
			res.NewFindings = append(res.NewFindings, f)
		}
	}
	if old != nil {
		seen := map[string]bool{}
		for _, f := range old.Findings {
			fp := Fingerprint(f)
			if curSet[fp] || seen[fp] {
				continue
			}
			seen[fp] = true
			res.FixedFindings = append(res.FixedFindings, f)
		}
	}
	res.New = len(res.NewFindings)
	res.Fixed = len(res.FixedFindings)
	return res
}
