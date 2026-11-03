package diag

import (
	"os"
	"path/filepath"
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
//
// 诊断包跨平台使用（Windows 采集 → Linux 分析，反之亦然），所以两种
// 分隔符都要按分隔符处理：在 Linux 上跑本用例时必须也能脱掉 `C:\...`。
func TestMaskPathOnlyBaseName(t *testing.T) {
	cases := map[string]string{
		`C:\Users\realname\state`:   "state",
		"/home/user/data/state":     "state",
		"data/go/technologies.json": "technologies.json",
		`C:\mixed/sep\path/data`:    "data",
		`C:\Users\realname\state\`:  "state", // 尾部分隔符
		"/":                         "",      // 根路径没有可展示段
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

// TestAssetsMLUsesCandidateResolution 诊断必须与引擎 mlFor 同源解析 ML 资产：
// 配置值是相对路径（ml_assets）且 cwd 下不存在时，应继续找 cwd 的
// ml/models/go/ml_assets / data/go/ml_assets 等候选，而不是直接报缺失。
// 旧实现只 stat cfg.ML.AssetsDir，会把「资产在别处、进程 cwd 不在安装目录」
// 误报为「ML 模型资产缺失」。
func TestAssetsMLUsesCandidateResolution(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // 模拟从仓库根/任意 cwd 启动
	assets := filepath.Join(dir, "ml", "models", "go", "ml_assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"cve-tech.meta.json", "cve-tech.vocab.txt", "cve-tech.idf.f32", "cve-tech.coef.f32",
		"cwe-type.meta.json", "cwe-type.vocab.txt", "cwe-type.idf.f32", "cwe-type.coef.f32",
	} {
		if err := os.WriteFile(filepath.Join(assets, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.ML.AssetsDir = "ml_assets" // 故意指向不存在的相对路径

	for _, a := range Assets(cfg) {
		if a.Name == "ML 模型资产" {
			if !a.Present {
				t.Fatalf("cwd 存在 ml/models/go/ml_assets 时应判就位，得到：%+v", a)
			}
			return
		}
	}
	t.Fatal("诊断结果缺少「ML 模型资产」条目")
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
