package intel

import (
	"testing"
)

// 官方 FIRST 规范示例与 Python osv.py 已验证向量。
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
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.9, "medium"},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L", 1.6, "low"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.8, "medium"},
		{"CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, "none"},
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
