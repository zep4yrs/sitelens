package intel

import (
	"testing"
)

// 官方 FIRST 规范示例与 Python osv.py 已验证向量。
//
// ⚠️ 本表此前把**错误分数**写成了期望值（`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
// 期望 4.8，官方为 5.4），于是 CVSS 的三处计算缺陷被测试"保护"了下来——
// CI 全绿而 41% 的分数与 NVD 官方分不符。期望值已按 FIRST 规范订正。
func TestCVSS3Score(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
		label  string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"},
		{"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"}, // 无版本前缀
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "high"},
		// AV:L 权重必须是 v3.1 的 0.55（此前误用 v2 的 0.39 → 官方 5.5，算出 4.9）
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "medium"},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L", 1.6, "low"},
		// 官方值 5.4（此前断言 4.8 —— 把缺陷的输出当成了期望值）
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "medium"},
		{"CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, "none"},
		// AV:L 权重必须是 v3.1 的 0.55（此前误用 v2 的 0.39 → 官方 8.4，算出 7.7）
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, "high"},
	}
	for _, tc := range cases {
		score, label, err := CVSS3Score(tc.vector)
		if err != nil {
			t.Errorf("%s: err %v", tc.vector, err)
			continue
		}
		if score != tc.score || label != tc.label {
			t.Errorf("%s = %v/%s, want %v/%s", tc.vector, score, label, tc.score, tc.label)
		}
	}
}

// TestCVSS3ScoreOrderIndependent 向量串的**书写顺序**不得影响分数。
//
// 规范不要求指标有序，而 NVD 的规范顺序恒为 AV:AC:PR:UI:S:C:I:A（S 在 PR 之后）。
// 此前按 token 顺序决定 PR 权重，导致同一组指标换序即差 0.3 分（8.9 vs 9.2），
// 且每个 S:C 向量都错——回归守卫。
func TestCVSS3ScoreOrderIndependent(t *testing.T) {
	pairs := [][2]string{
		{
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			"CVSS:3.1/AV:N/AC:L/S:C/PR:L/UI:N/C:H/I:H/A:H",
		},
		{
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			"CVSS:3.1/S:C/AV:N/AC:L/PR:N/UI:R/C:L/I:L/A:N",
		},
	}
	for _, p := range pairs {
		s1, l1, err := CVSS3Score(p[0])
		if err != nil {
			t.Fatalf("%s: %v", p[0], err)
		}
		s2, l2, err := CVSS3Score(p[1])
		if err != nil {
			t.Fatalf("%s: %v", p[1], err)
		}
		if s1 != s2 || l1 != l2 {
			t.Errorf("同组指标换序得分不同：%s=%v/%s vs %s=%v/%s",
				p[0], s1, l1, p[1], s2, l2)
		}
	}
}

func TestCVSS3ScoreErrors(t *testing.T) {
	for _, v := range []string{
		"", "CVSS:3.1", "AV:N/AC:L", // 缺指标
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 未知取值
	} {
		if _, _, err := CVSS3Score(v); err == nil {
			t.Errorf("%q 应报错", v)
		}
	}
}
