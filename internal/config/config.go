// Package config 提供 .sitelens.yml 用户配置：检测规则/等级/限速可选。
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config 用户可配置项（.sitelens.yml 或默认值）。
type Config struct {
	Scan    ScanConfig    `yaml:"scan"`
	Checks  ChecksConfig  `yaml:"checks"`
	Web     WebConfig     `yaml:"web"`
	Intel   IntelConfig   `yaml:"intel"`
	DAST    DASTConfig    `yaml:"dast"`
	Modules ModulesConfig `yaml:"modules"`
}

type ScanConfig struct {
	RateIntervalMS int    `yaml:"rate_interval_ms"` // 请求最小间隔（毫秒）
	TimeoutSec     int    `yaml:"timeout_sec"`      // 请求超时（秒）
	MaxHops        int    `yaml:"max_hops"`         // 重定向最大跳数
	UserAgent      string `yaml:"user_agent"`       // 自定义 UA（默认 SiteLens/x.y）
	MaxParams      int    `yaml:"max_params"`       // DAST 参数探测上限
}

type ChecksConfig struct {
	Level       string   `yaml:"level"`        // core | all
	DisabledIDs []string `yaml:"disabled_ids"` // 禁用的 check id 列表
	PluginDir   string   `yaml:"plugin_dir"`   // 用户自定义 check 目录
}

type WebConfig struct {
	Listen string `yaml:"listen"` // 监听地址（默认 127.0.0.1:5000）
}

type IntelConfig struct {
	DumpPath   string `yaml:"dump_path"`   // 知识库数据包路径
	RangesPath string `yaml:"ranges_path"` // 精选区间文件路径
}

type DASTConfig struct {
	Enabled   bool `yaml:"enabled"`    // 是否启用 DAST
	MaxParams int  `yaml:"max_params"` // 参数探测上限
}

type ModulesConfig struct {
	Subdomain  bool `yaml:"subdomain"`  // 子域名枚举
	DirScan    bool `yaml:"dir_scan"`   // 目录探测
	Webshell   bool `yaml:"webshell"`   // WebShell 探测
	ServiceProbe bool `yaml:"service_probe"` // 端口服务识别
	Netsec     bool `yaml:"netsec"`     // TLS/DNS 安全
	BrowserUA  bool `yaml:"browser_ua"` // 浏览器 UA
}

// Default 返回默认配置。
func Default() *Config {
	return &Config{
		Scan: ScanConfig{
			RateIntervalMS: 400,
			TimeoutSec:     15,
			MaxHops:        6,
			UserAgent:      "",
			MaxParams:      15,
		},
		Checks: ChecksConfig{
			Level:     "all",
			PluginDir: "data/plugins",
		},
		Web:  WebConfig{Listen: "127.0.0.1:5000"},
		Intel: IntelConfig{
			DumpPath:   "data/intel_dump.json.gz",
			RangesPath: "data/affected_ranges.json",
		},
		DAST: DASTConfig{Enabled: true, MaxParams: 15},
		Modules: ModulesConfig{
			Subdomain: false, DirScan: false, Webshell: false,
			ServiceProbe: false, Netsec: false, BrowserUA: false,
		},
	}
}

// Load 从 YAML 文件加载配置（文件不存在或解析失败返回默认值）。
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// LoadOrDefault 加载配置；出错时静默使用默认值。
func LoadOrDefault(path string) *Config {
	cfg, _ := Load(path)
	return cfg
}
