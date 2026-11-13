package checks

import (
	"strings"
	"testing"
)

// TestEveryCheckHasValidMeta 全量 1,010 条 check 都必须有可复核的元数据：
// ATT&CK 非空且在白名单内、noise/safety 合法、reason 非空。
func TestEveryCheckHasValidMeta(t *testing.T) {
	all := AllChecks()
	if len(all) < 1000 {
		t.Fatalf("check 数量不足：%d", len(all))
	}
	noiseCount := map[string]int{}
	for _, c := range all {
		m := MetaOf(c)
		if len(m.ATTACK) == 0 {
			t.Fatalf("%s 缺少 ATT&CK 技术编号", c.ID)
		}
		if !attackIDsValid(m.ATTACK) {
			t.Fatalf("%s ATT&CK 编号不在复核白名单内：%v", c.ID, m.ATTACK)
		}
		switch m.Noise {
		case NoiseLow, NoiseMedium, NoiseHigh:
		default:
			t.Fatalf("%s noise 非法：%q", c.ID, m.Noise)
		}
		switch m.Safety {
		case SafetyReadOnly, SafetyActive, SafetyExploit:
		default:
			t.Fatalf("%s safety 非法：%q", c.ID, m.Safety)
		}
		if strings.TrimSpace(m.Reason) == "" {
			t.Fatalf("%s 缺少归类依据", c.ID)
		}
		noiseCount[m.Noise]++
	}
	// 噪声分布合理性：内置验证集以只读单请求为主，high 应占少数（大文件下载）。
	if high := noiseCount[NoiseHigh]; high > len(all)/10 {
		t.Fatalf("high 噪声占比异常：%d/%d（应 <10%%）", high, len(all))
	}
	if low := noiseCount[NoiseLow]; low < len(all)/2 {
		t.Fatalf("low 噪声应占多数：%d/%d", low, len(all))
	}
}

// TestMetaSpotChecks 代表性 check 的人工复核断言。
func TestMetaSpotChecks(t *testing.T) {
	cases := []struct {
		id        string
		wantNoise string
		wantATT   string
	}{
		{"heapdump", NoiseHigh, "T1552"},
		{"aws-credentials", NoiseLow, "T1552.001"},
		{"ssh-private-key", NoiseLow, "T1552.004"},
		{"swagger-json", NoiseMedium, "T1592"},
		{"k8s-namespaces", NoiseLow, "T1613"},
		{"actuator-env-root", NoiseMedium, "T1552"},
		{"backup-sql", NoiseHigh, "T1005"},
		{"tomcat-manager", NoiseLow, "T1133"},
		{"server-status", NoiseLow, "T1592"},
	}
	byID := map[string]Check{}
	for _, c := range AllChecks() {
		byID[c.ID] = c
	}
	for _, tc := range cases {
		c, ok := byID[tc.id]
		if !ok {
			t.Fatalf("缺少代表性 check：%s", tc.id)
		}
		m := MetaOf(c)
		if m.Noise != tc.wantNoise {
			t.Fatalf("%s noise=%q 期望 %q（reason=%s）", tc.id, m.Noise, tc.wantNoise, m.Reason)
		}
		found := false
		for _, id := range m.ATTACK {
			if id == tc.wantATT {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s ATT&CK=%v 期望包含 %s", tc.id, m.ATTACK, tc.wantATT)
		}
	}
}

// TestMetaAllReadOnly 内置验证集必须全部 read_only（GET + 静态路径、无 payload）。
func TestMetaAllReadOnly(t *testing.T) {
	for _, c := range AllChecks() {
		if m := MetaOf(c); m.Safety != SafetyReadOnly {
			t.Fatalf("%s safety=%q，内置验证集应为 read_only", c.ID, m.Safety)
		}
	}
}
