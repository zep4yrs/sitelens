package rex

import (
	"encoding/json"
	"os"
	"testing"
)

// goldenCase python re 生成的单条期望。
type goldenCase struct {
	S      string   `json:"s"`
	Hit    bool     `json:"hit"`
	Text   string   `json:"text"`
	Groups []string `json:"groups"`
}

type goldenVec struct {
	P     string       `json:"p"`
	Cases []goldenCase `json:"cases"`
}

// TestServiceFPGolden 交叉验证：702 条 RE2 拒收模式在 rex 与 python re
// （独立回溯实现）下的 匹配存在性/整体匹配/捕获组 结论一致。
func TestServiceFPGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/service_fp_golden.json")
	if err != nil {
		t.Skipf("golden 向量不可用（%v）", err)
	}
	var vecs []goldenVec
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("golden 解析: %v", err)
	}
	if len(vecs) < 600 {
		t.Fatalf("golden 规模异常: %d", len(vecs))
	}
	checked, hits := 0, 0
	for _, v := range vecs {
		re, err := Compile(v.P)
		if err != nil {
			t.Errorf("模式 rex 编译失败: %q: %v", v.P, err)
			continue
		}
		for _, c := range v.Cases {
			checked++
			m := re.FindStringSubmatch(c.S)
			if !c.Hit {
				if m != nil {
					t.Errorf("误报 %q on %.60q:\n  rex = %q\n  期望不匹配", v.P, c.S, m[0])
				}
				continue
			}
			hits++
			if m == nil {
				t.Errorf("漏报 %q on %.60q:\n  python re 命中 %q", v.P, c.S, c.Text)
				continue
			}
			if m[0] != c.Text {
				t.Errorf("匹配文本不一致 %q on %.60q:\n  rex    = %q\n  python = %q", v.P, c.S, m[0], c.Text)
				continue
			}
			if len(m) != len(c.Groups)+1 {
				t.Errorf("组数不一致 %q: rex %d 组, python %d 组", v.P, len(m)-1, len(c.Groups))
				continue
			}
			for g := range c.Groups {
				if m[g+1] != c.Groups[g] {
					t.Errorf("组 %d 不一致 %q on %.60q: rex %q, python %q",
						g+1, v.P, c.S, m[g+1], c.Groups[g])
				}
			}
		}
	}
	t.Logf("golden 交叉验证 %d 条模式 / %d 用例（命中 %d）", len(vecs), checked, hits)
	if hits < 300 {
		t.Fatalf("命中用例过少，验证强度不足: %d", hits)
	}
}
