package usercfg

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 契约：所有「运行期会写」的路径必须落在用户数据区，绝不落在安装目录。
// 回归来源：Electron 壳 v3.0.0 首启写安装目录 EPERM 起不来；Wails 壳
// 若只写 web.listen，扫描历史/情报会写进 $PROGRAMFILES64（只读）。
func TestWritablePathsAreUnderUserData(t *testing.T) {
	userData := filepath.Join("C:", "Users", "u", "AppData", "Roaming", "SiteLens-Wails")
	engineDir := filepath.Join("C:", "Program Files", "SiteLens", "engine")
	m := Resolve(userData, engineDir)

	for name, p := range map[string]string{
		"DataDir":       m.DataDir,
		"OverridesPath": m.OverridesPath,
		"PoolsDir":      m.PoolsDir,
		"PluginsDir":    m.PluginsDir,
	} {
		if !strings.HasPrefix(p, userData) {
			t.Errorf("%s=%q 必须落在用户数据区 %q 下", name, p, userData)
		}
		if strings.HasPrefix(p, engineDir) {
			t.Errorf("%s=%q 不得落在安装目录（只读）", name, p)
		}
	}
}

// 只读资产仍指安装目录（随包整体替换，不进用户区）。
func TestReadonlyAssetsStayInInstallDir(t *testing.T) {
	userData := filepath.Join("C:", "Users", "u", "AppData", "Roaming", "SiteLens-Wails")
	engineDir := filepath.Join("C:", "Program Files", "SiteLens", "engine")
	m := Resolve(userData, engineDir)

	for name, p := range map[string]string{
		"SeedDir":          m.SeedDir,
		"TechnologiesPath": m.TechnologiesPath,
		"MLAssetsDir":      m.MLAssetsDir,
		"OnnxRuntimeDLL":   m.OnnxRuntimeDLL,
	} {
		if !strings.HasPrefix(p, engineDir) {
			t.Errorf("%s=%q 应在安装目录 %q 下", name, p, engineDir)
		}
	}
	// 种子目录必须是 <engine>/data —— update-seed 的 --seed-dir 直接吃这个值。
	if want := filepath.Join(engineDir, "data"); m.SeedDir != want {
		t.Errorf("SeedDir=%q，期望 %q", m.SeedDir, want)
	}
}

func TestWritableDirsAreUnderUserDataAndNonEmpty(t *testing.T) {
	userData := filepath.Join("C:", "Users", "u", "AppData", "Roaming", "SiteLens-Wails")
	m := Resolve(userData, filepath.Join("C:", "Program Files", "SiteLens", "engine"))
	dirs := m.WritableDirs()
	if len(dirs) == 0 {
		t.Fatal("WritableDirs 不得为空（启动前要建齐目录骨架）")
	}
	for _, d := range dirs {
		if d == "" {
			t.Error("WritableDirs 含空路径")
		}
		if !strings.HasPrefix(d, userData) {
			t.Errorf("目录 %q 必须落在用户数据区", d)
		}
	}
}

// 契约：受管键名必须与引擎 yaml tag 逐字对齐（写错键名等于没写），
// 且所有可写路径为落在用户数据区的绝对路径。
func TestApplyManagedWritesEngineKeyNames(t *testing.T) {
	userData := filepath.Join(t.TempDir(), "SiteLens-Wails")
	engineDir := filepath.Join(t.TempDir(), "Program Files", "SiteLens", "engine")
	m := Resolve(userData, engineDir)

	cfg := map[string]any{"scan": map[string]any{"deep": true}} // 用户既有键
	ApplyManaged(cfg, "127.0.0.1:5087", m)

	// 形状检查用引擎真实的 tag 名回读，键名写错这里就抓得到
	type shape struct {
		Web struct {
			Listen string `yaml:"listen"`
		} `yaml:"web"`
		Store struct {
			DataDir string `yaml:"data_dir"`
		} `yaml:"store"`
		Intel struct {
			Ovr string `yaml:"overrides_path"`
		} `yaml:"intel"`
		Checks struct {
			NucleiDir string `yaml:"nuclei_dir"`
			PluginDir string `yaml:"plugin_dir"`
		} `yaml:"checks"`
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got shape
	if err := yaml.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Web.Listen != "127.0.0.1:5087" {
		t.Errorf("web.listen=%q", got.Web.Listen)
	}
	for name, p := range map[string]string{
		"store.data_dir":       got.Store.DataDir,
		"intel.overrides_path": got.Intel.Ovr,
		"checks.nuclei_dir":    got.Checks.NucleiDir,
		"checks.plugin_dir":    got.Checks.PluginDir,
	} {
		if p == "" {
			t.Errorf("%s 未写入（键名与引擎 tag 不一致？）", name)
			continue
		}
		if !filepath.IsAbs(p) {
			t.Errorf("%s=%q 必须是绝对路径（相对路径被引擎按 cwd=安装目录解析）", name, p)
		}
		if !strings.HasPrefix(p, userData) {
			t.Errorf("%s=%q 必须落在用户数据区", name, p)
		}
	}
	if cfg["scan"] == nil {
		t.Error("ApplyManaged 抹掉了用户的 scan 键")
	}
}
