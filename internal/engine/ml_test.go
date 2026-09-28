package engine

import (
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// TestMLNormRelevance 归一键与交集标记三档：hit / related / 空。
func TestMLNormRelevance(t *testing.T) {
	if mlNorm("Apache Tomcat") != "apachetomcat" || mlNorm("php/php") != "phpphp" {
		t.Fatalf("mlNorm 归一口径错误: %q %q", mlNorm("Apache Tomcat"), mlNorm("php/php"))
	}
	keys := mlTechKeys([]Tech{
		{Name: "Apache Tomcat"}, {Name: "PHP"}, {Name: "Microsoft Windows"},
	})
	if got := mlRelevance("apache/tomcat", keys); got != ml.RelHit {
		t.Errorf("apache/tomcat → %q, 期望 hit", got)
	}
	if got := mlRelevance("php/php", keys); got != ml.RelRelated {
		t.Errorf("php/php → %q, 期望 related", got)
	}
	if got := mlRelevance("oracle/mysql", keys); got != "" {
		t.Errorf("oracle/mysql → %q, 期望空", got)
	}
	if got := mlRelevance("apache/tomcat", nil); got != "" {
		t.Errorf("无检出技术时应为空, got %q", got)
	}
}

// TestMLForSilentSemantics mlFor 的两种静默出口：
// 目录缺失 → nil 不死；资产损坏 → nil 且本进程禁用。
func TestMLForSilentSemantics(t *testing.T) {
	// 目录不存在：nil，且不置死标记（资产可能后补）
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "no-such-dir")
	if a := e.mlFor(); a != nil {
		t.Fatalf("目录缺失应返回 nil, got %v", a)
	}
	if e.mlDead {
		t.Error("目录缺失不应置死标记")
	}

	// 资产损坏（meta 合法、coef 字节数不足）：nil 且永久禁用
	bad := t.TempDir()
	meta := `{"name":"cve-tech","classes":["x"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`
	for fn, b := range map[string][]byte{
		"cve-tech.meta.json":  []byte(meta),
		"cve-tech.vocab.txt":  []byte("aa\nbb\ncc"),
		"cve-tech.idf.f32":    make([]byte, 12),
		"cve-tech.coef.f32":   make([]byte, 4), // 期望 1×3×4=12 字节，故意短
		"cwe-type.meta.json":  []byte(`{"name":"cwe-type","classes":["CWE-79"],"n_features":3,"n_classes":1,
"intercept":[0],"sublinear_tf":true,"lowercase":true,
"token_pattern":"(?u)\\b\\w\\w+\\b","l2_norm":true}`),
		"cwe-type.vocab.txt":  []byte("aa\nbb\ncc"),
		"cwe-type.idf.f32":    make([]byte, 12),
		"cwe-type.coef.f32":   make([]byte, 12),
	} {
		if err := os.WriteFile(filepath.Join(bad, fn), b, 0o644); err != nil {
			t.Fatalf("写 %s: %v", fn, err)
		}
	}
	e2 := &Engine{cfg: config.Default()}
	e2.cfg.ML.AssetsDir = bad
	if a := e2.mlFor(); a != nil {
		t.Fatalf("损坏资产应返回 nil, got %v", a)
	}
	if !e2.mlDead {
		t.Error("损坏资产应置死标记（本进程静默禁用）")
	}
	if a := e2.mlFor(); a != nil {
		t.Error("禁用后再次请求仍应为 nil")
	}
}

// TestMLEnrichSilentSkip mlEnrich 全链静默语义：资产缺失时 predictions
// 缺席（nil），既不 panic 也不产生空数组。
func TestMLEnrichSilentSkip(t *testing.T) {
	e := &Engine{cfg: config.Default()}
	e.cfg.ML.AssetsDir = filepath.Join(t.TempDir(), "absent")
	res := &Result{Vulnerabilities: []intel.Finding{{CVE: "CVE-2024-1234"}}}
	e.mlEnrich(res, nil)
	if res.Predictions != nil {
		t.Errorf("资产缺失时 predictions 应缺席, got %v", res.Predictions)
	}
	// 无 CVE 的结果在 CVE 收集阶段即返回，连资产目录都不触碰
	res2 := &Result{}
	e2 := &Engine{cfg: config.Default()}
	e2.mlEnrich(res2, nil)
	if res2.Predictions != nil {
		t.Errorf("无 CVE 时 predictions 应缺席, got %v", res2.Predictions)
	}
}
