// Package usercfg 生成桌面壳管理的引擎配置受管键（纯函数，可跨平台单测）。
//
// 职责边界：只决定「哪些路径必须落在用户数据区」，不碰文件 IO，
// 也不做 YAML 合并（合并在壳的 config 层，键值形状由本包给出）。
//
// 为什么必须归到用户数据区（不是风格问题，是 EPERM 事故）：
// 引擎以其工作目录（安装目录 engine/）解析相对路径，默认
// store.data_dir="data/state"、intel.nvd_path="data/nvd_cves.json.gz"。
// 壳把引擎 cwd 设为安装目录、又只写 web.listen 时，扫描历史与情报写入
// 全部落在 $PROGRAMFILES64\SiteLens\engine\data —— 该目录对普通用户只读，
// 写入即失败（Electron 壳 v3.0.0 踩过同一个坑：首启写配置 EPERM 起不来）。
package usercfg

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// Managed 受管键的键值对（点分键 → 值）。值一律用绝对路径：
// 安装目录的只读资产经 cwd 解析，可写数据经绝对路径归到用户区。
type Managed struct {
	// 可写数据（用户数据区）
	DataDir       string
	OverridesPath string
	PoolsDir      string
	PluginsDir    string

	// 只读资产（安装目录，随包更新整体替换）
	SeedDir          string // <install>/engine/data
	TechnologiesPath string
	MLAssetsDir      string
	OnnxRuntimeDLL   string

	// APIToken 引擎的 web.api_token（A-01/D-02：壳自动注入的本地进程防护令牌）。
	// 空 = 不写该键（保持引擎"不鉴权"语义）。
	APIToken string
}

// APITokenLen 壳注入的 API token 长度（32 字节随机 → 64 个 hex 字符）。
const APITokenLen = 64

// ValidAPIToken 判定是否为本壳注入格式的 token（恰好 64 个 hex 字符）。
// 用户手填的其它格式 token 视为"非本壳管理"，壳不改写它（见 main.writeUserConfig）。
func ValidAPIToken(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != APITokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// NewAPIToken 生成 32 字节随机数的 hex（64 字符）。
// 日志/错误信息中绝不打印该值（调用方负责）。
func NewAPIToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// APITokenOf 从已解析的配置 map 里取 web.api_token（无则空串）。
func APITokenOf(cfg map[string]any) string {
	web, ok := cfg["web"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := web["api_token"].(string)
	return strings.TrimSpace(s)
}


// Resolve 由「用户数据区 userData」与「安装目录引擎目录 engineDir」算出受管路径。
func Resolve(userData, engineDir string) Managed {
	seedDir := filepath.Join(engineDir, "data")
	return Managed{
		// 可写：扫描历史、情报覆盖、模板池、插件
		DataDir:       filepath.Join(userData, "state"),
		OverridesPath: filepath.Join(userData, "data", "intel_overrides.json"),
		PoolsDir:      filepath.Join(userData, "pools", "nuclei"),
		PluginsDir:    filepath.Join(userData, "plugins"),
		// 只读：随包资产（不随用户数据区，升级整体替换）
		SeedDir:          seedDir,
		TechnologiesPath: filepath.Join(seedDir, "go", "technologies.json"),
		MLAssetsDir:      filepath.Join(seedDir, "go", "ml_assets"),
		OnnxRuntimeDLL:   filepath.Join(seedDir, "onnxruntime", "onnxruntime.dll"),
	}
}

// WritableDirs 需要在启动前建齐的目录（用户数据区，全部可写）。
func (m Managed) WritableDirs() []string {
	return []string{
		filepath.Dir(m.DataDir),
		m.DataDir,
		filepath.Dir(m.OverridesPath),
		m.PoolsDir,
		m.PluginsDir,
	}
}

// ApplyManaged 把受管键就地写入配置 map（保留其余键，含用户自定义）。
//
// 键名必须与引擎的 yaml tag 逐字对齐（web.listen / store.data_dir /
// intel.overrides_path / checks.nuclei_dir / checks.plugin_dir）——写错键名
// 等于没写，引擎仍按 cwd 的默认相对路径解析，可写数据又落回安装目录。
//
// 只读资产（指纹库 / ML 资产 / onnxruntime）刻意不写：引擎默认值
// `data/go/...` 已是相对 cwd 的正确值，显式写绝对路径反而会把开发态
// （cwd=仓库 build/engine）钉死在某个构建产物目录上。
func ApplyManaged(cfg map[string]any, listen string, m Managed) {
	web := sub(cfg, "web")
	web["listen"] = listen
	// A-01/D-02：壳注入的本地进程防护令牌（非空才写，空 = 保持"不鉴权"语义）。
	if strings.TrimSpace(m.APIToken) != "" {
		web["api_token"] = strings.TrimSpace(m.APIToken)
	}

	sub(cfg, "store")["data_dir"] = m.DataDir
	sub(cfg, "intel")["overrides_path"] = m.OverridesPath
	checks := sub(cfg, "checks")
	checks["nuclei_dir"] = m.PoolsDir
	checks["plugin_dir"] = m.PluginsDir
}

// sub 取（必要时建）顶层段 map，保留已有内容。
func sub(cfg map[string]any, key string) map[string]any {
	if m, ok := cfg[key].(map[string]any); ok && m != nil {
		return m
	}
	m := map[string]any{}
	cfg[key] = m
	return m
}
