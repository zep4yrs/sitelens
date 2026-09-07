package nuclei

import "testing"

// FuzzConvert 用随机字节与真实模板变形轰击转换漏斗——模板库内容
// 来自互联网（不可信输入），Convert 必须做到只产出 check 或安全拒绝，
// 任何 panic 都是缺陷。种子覆盖 supported/unsupported 真实形态。
func FuzzConvert(f *testing.F) {
	f.Add([]byte(goodTpl))
	f.Add([]byte(dslTpl))
	f.Add([]byte(dslExclusionOnlyTpl))
	f.Add([]byte(dslExoticTpl))
	f.Add([]byte(regexOnlyTpl))
	f.Add([]byte(multiGroupTpl))
	f.Add([]byte("id: x\nhttp:\n  - path: '{{BaseURL}}'\n    matchers:\n      - type: dsl\n        dsl:\n          - 'status_code == "))
	f.Add([]byte("id: y\nhttp: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		cs := Convert(data)
		for _, c := range cs {
			if c.ID == "" {
				t.Fatalf("转换产物缺少 ID: %+v", c)
			}
		}
	})
}
