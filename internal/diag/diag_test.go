package diag

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestConfigSummaryNeverLeaksSecrets 诊断包**绝不能**含 API Token、登录凭证
// 等秘密值——它会被用户贴到公开 Issue 上。
//
// 这是本包存在的前提：用户能放心把诊断包发出来，靠的就是这条不变量。
func TestConfigSummaryNeverLeaksSecrets(t *testing.T) {
	cfg := config.Default()
	cfg.Web.APIToken = "SUPER-SECRET-TOKEN-12345"
	cfg.Auth.Username = "admin-user"
	cfg.Auth.Password = "P@ssw0rd-SECRET"
	cfg.Auth.LoginURL = "https://target.example/login"
	cfg.Store.DataDir = `C:\Users\realname\secret-path\state`
	cfg.Intel.DumpPath = `C:\Users\realname\secret-path\data\intel_dump.json.gz`

	rep := Build("5.2.0", cfg, nil)
	blob := rep.Text
	// 结构化摘要同样要过一遍
	for _, v := range rep.Config {
		blob += dump(v)
	}

	for _, secret := range []string{
		"SUPER-SECRET-TOKEN-12345",
		"P@ssw0rd-SECRET",
		"admin-user",
		`C:\Users\realname`,
		"realname",
	} {
		if strings.Contains(blob, secret) {
			t.Errorf("诊断包泄露了敏感内容 %q：\n%s", secret, rep.Text)
		}
	}
	// 但「是否已设置」这类事实要保留（否则用户没法判断自己配没配）
	if !strings.Contains(blob, "api_token_set") && !strings.Contains(rep.Text, "true") {
		t.Errorf("配置摘要应保留 api_token_set 这类布尔事实")
	}
}

// TestMaskPathOnlyBaseName 路径只保留最后一段，不暴露本机目录结构。
func TestMaskPathOnlyBaseName(t *testing.T) {
	cases := map[string]string{
		`C:\Users\realname\state`:   "state",
		"/home/user/data/state":     "state",
		"data/go/technologies.json": "technologies.json",
		"":                          "",
	}
	for in, want := range cases {
		if got := maskPath(in); got != want {
			t.Errorf("maskPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAssetsReportsMissing 缺失资产要被标出来，并说明受影响的��力。
func TestAssetsReportsMissing(t *testing.T) {
	cfg := config.Default()
	cfg.Intel.TechnologiesPath = `C:\definitely\not\here\technologies.json`
	cfg.Checks.NucleiDir = `C:\definitely\not\here\nuclei`

	assets := Assets(cfg)
	byName := map[string]Asset{}
	for _, a := range assets {
		byName[a.Name] = a
	}
	if a := byName["指纹库"]; a.Present {
		t.Errorf("不存在的指纹库应报缺失")
	} else if a.Note == "" {
		t.Errorf("缺失资产应说明受影响的能力")
	}
	if a := byName["模板池"]; a.Present {
		t.Errorf("不存在的模板池应报缺失")
	}
}

// dump 把任意值转成字符串（用于扫描结构化摘要里的秘密值）。
func dump(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		s := ""
		for k, vv := range t {
			s += k + dump(vv)
		}
		return s
	case []any:
		s := ""
		for _, vv := range t {
			s += dump(vv)
		}
		return s
	default:
		return ""
	}
}
