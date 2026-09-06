// Package config 提供 .sitelens.yml 用户配置。
//
// 设计约定：所有阈值/超时/并发/上限统一定义在本包，各 internal 包从这里取值，
// 不再各自硬编码。默认值 = 最佳实践；用户可在 .sitelens.yml 覆盖任意子集，
// 未设置的项（零值）自动回退默认值。
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config 用户可配置项（.sitelens.yml 或默认值）。
type Config struct {
	Scan       ScanConfig       `yaml:"scan"`
	Checks     ChecksConfig     `yaml:"checks"`
	Crawler    CrawlerConfig    `yaml:"crawler"`
	DAST       DASTConfig       `yaml:"dast"`
	Intel      IntelConfig      `yaml:"intel"`
	Netsec     NetsecConfig     `yaml:"netsec"`
	LoginBrute LoginBruteConfig `yaml:"loginbrute"`
	Audit      AuditConfig      `yaml:"audit"`
	Batch      BatchConfig      `yaml:"batch"`
	Web        WebConfig        `yaml:"web"`
	Store      StoreConfig      `yaml:"store"`
	Active     ActiveConfig     `yaml:"active"`
	Modules    ModulesConfig    `yaml:"modules"`
}

// StoreConfig 历史持久化（文件式，替代 Python 版的 PG 依赖）。
type StoreConfig struct {
	DataDir    string `yaml:"data_dir"`    // 状态目录（history.json 所在）
	MaxRecords int    `yaml:"max_records"` // 历史记录留存上限（超出裁掉最旧）
}

// ActiveConfig 主动探测模块阈值（默认关，仅限授权目标）。
type ActiveConfig struct {
	DirMaxPaths   int    `yaml:"dir_max_paths"`   // 目录探测路径上限
	DirBypass403  bool   `yaml:"dir_bypass_403"`  // 403 绕过重试（伪造来源头）
	SubMaxWords   int    `yaml:"sub_max_words"`   // 子域名字典截取上限
	SubWorkers    int    `yaml:"sub_workers"`     // 子域名并发解析数
	ShellMaxPaths int    `yaml:"shell_max_paths"` // WebShell 探测路径上限
	WordlistDir   string `yaml:"wordlist_dir"`    // 字典目录
}

// ScanConfig HTTP 采集与扫描全局阈值。
type ScanConfig struct {
	RateIntervalMS int    `yaml:"rate_interval_ms"` // 请求最小间隔（毫秒），0=不限速
	TimeoutSec     int    `yaml:"timeout_sec"`      // 单请求超时（秒）
	MaxHops        int    `yaml:"max_hops"`         // 重定向最大跳数
	MaxBodyMB      int    `yaml:"max_body_mb"`      // 正文留存上限（MB）
	UserAgent      string `yaml:"user_agent"`       // 自定义 UA（空 = SiteLens/x.y）
	Deep           bool   `yaml:"deep"`             // 默认开启同域浅爬取
	Resolve        bool   `yaml:"resolve"`          // 目标校验时是否做 DNS 解析（SSRF 防护强度）
	MaxConcurrent  int    `yaml:"max_concurrent"`   // 同时进行的扫描任务数（信号量）
}

// ChecksConfig 验证型 check 引擎。
type ChecksConfig struct {
	Level       string   `yaml:"level"`        // none | core | all
	DisabledIDs []string `yaml:"disabled_ids"` // 禁用的 check id 列表
	PluginDir   string   `yaml:"plugin_dir"`   // 用户自定义 check 插件目录
	NucleiCap   int      `yaml:"nuclei_cap"`   // Nuclei 模板子集数量上限
}

// CrawlerConfig 同域爬取。
type CrawlerConfig struct {
	MaxPages        int  `yaml:"max_pages"`          // 最多爬取的页面数
	RespectRobots   bool `yaml:"respect_robots"`     // 是否遵循 robots.txt
	MaxLinksPerPage int  `yaml:"max_links_per_page"` // 每页最多提取的链接数
	TimeoutSec      int  `yaml:"timeout_sec"`        // 爬取阶段总时长上限（秒），0=不限
}

// DASTConfig 参数级注入探测。
type DASTConfig struct {
	MaxParams        int   `yaml:"max_params"`         // 最多探测的参数个数
	TimeBlind        bool  `yaml:"time_blind"`         // 时间盲注开关
	BlindThresholdMS int64 `yaml:"blind_threshold_ms"` // 延迟判定阈值（毫秒）
	SleepSeconds     int   `yaml:"sleep_seconds"`      // 注入的 SLEEP 秒数
	MaxURLLen        int   `yaml:"max_url_len"`        // 探测 URL 长度上限
}

// IntelConfig 漏洞情报知识库。
type IntelConfig struct {
	DumpPath         string `yaml:"dump_path"`         // 知识库数据包路径
	RangesPath       string `yaml:"ranges_path"`       // 精选区间文件路径
	TechnologiesPath string `yaml:"technologies_path"` // 指纹规则文件路径
	SearchLimit      int    `yaml:"search_limit"`      // /api/vuln-search 返回上限
	UpdateHours      int    `yaml:"update_hours"`      // KEV 自动更新间隔（小时，0=关闭）
}

// NetsecConfig TLS/DNS 网络层检测。
type NetsecConfig struct {
	TLSTimeoutSec int  `yaml:"tls_timeout_sec"` // TLS 握手超时（秒）
	MailCheck     bool `yaml:"mail_check"`      // SPF/DMARC/MX 检查开关
}

// LoginBruteConfig 登录爆破（仅限授权目标）。
type LoginBruteConfig struct {
	MaxTries      int `yaml:"max_tries"`      // 总尝试次数上限
	MaxUsers      int `yaml:"max_users"`      // 用户名字典截取上限
	MaxPasswords  int `yaml:"max_passwords"`  // 密码字典截取上限
	IntervalMS    int `yaml:"interval_ms"`    // 相邻尝试间隔（毫秒）
	MaxConcurrent int `yaml:"max_concurrent"` // 并发尝试数
}

// AuditConfig 源码审计。
type AuditConfig struct {
	MaxArchiveMB       int `yaml:"max_archive_mb"`        // 上传压缩包大小上限（MB）
	MaxFiles           int `yaml:"max_files"`             // 最多审计的文件数
	MaxFileKB          int `yaml:"max_file_kb"`           // 单文件大小上限（KB）
	MaxFindingsPerRule int `yaml:"max_findings_per_rule"` // 单规则命中上限
}

// BatchConfig 批量扫描。
type BatchConfig struct {
	MaxURLs int `yaml:"max_urls"` // 单批 URL 数上限
	Workers int `yaml:"workers"`  // 并发扫描 worker 数
}

// WebConfig 内置 Web 服务。
type WebConfig struct {
	Listen       string `yaml:"listen"`        // 监听地址
	APIToken     string `yaml:"api_token"`     // 非空则 /api/* 需 X-Token 头（可用环境变量 SLENS_API_TOKEN）
	HistoryLimit int    `yaml:"history_limit"` // /api/history 默认返回条数
	HistoryCap   int    `yaml:"history_cap"`   // limit 参数硬上限
	ShutdownSec  int    `yaml:"shutdown_sec"`  // 优雅关闭等待秒数
}

// ModulesConfig 可选模块默认开关（每次扫描请求仍可单独指定）。
type ModulesConfig struct {
	Subdomain    bool `yaml:"subdomain"`     // 子域名枚举
	DirScan      bool `yaml:"dir_scan"`      // 目录探测
	Webshell     bool `yaml:"webshell"`      // WebShell 探测
	ServiceProbe bool `yaml:"service_probe"` // 端口服务识别
	Netsec       bool `yaml:"netsec"`        // TLS/DNS 安全
	BrowserUA    bool `yaml:"browser_ua"`    // 浏览器 UA
	Passive      bool `yaml:"passive"`       // 被动安全检测
	ActiveFP     bool `yaml:"active_fp"`     // FingerDir 主动路径指纹
	WeakAudit    bool `yaml:"weak_audit"`    // 弱口令/敏感信息审计
}

// Default 返回默认配置（= 最佳实践值）。
func Default() *Config {
	return &Config{
		Scan: ScanConfig{
			RateIntervalMS: 400,
			TimeoutSec:     15,
			MaxHops:        6,
			MaxBodyMB:      3,
			Deep:           true,
			Resolve:        true,
			MaxConcurrent:  3,
		},
		Checks: ChecksConfig{
			Level:     "all",
			PluginDir: "data/plugins",
			NucleiCap: 300,
		},
		Crawler: CrawlerConfig{
			MaxPages:        4,
			RespectRobots:   true,
			MaxLinksPerPage: 80,
			TimeoutSec:      60,
		},
		DAST: DASTConfig{
			MaxParams:        24,
			TimeBlind:        true,
			BlindThresholdMS: 3500,
			SleepSeconds:     4,
			MaxURLLen:        2048,
		},
		Intel: IntelConfig{
			DumpPath:         "data/intel_dump.json.gz",
			RangesPath:       "data/affected_ranges.json",
			TechnologiesPath: "data/go/technologies.json",
			SearchLimit:      40,
			UpdateHours:      24,
		},
		Netsec: NetsecConfig{TLSTimeoutSec: 8, MailCheck: true},
		LoginBrute: LoginBruteConfig{
			MaxTries: 400, MaxUsers: 8, MaxPasswords: 50,
			IntervalMS: 150, MaxConcurrent: 2,
		},
		Audit: AuditConfig{
			MaxArchiveMB: 20, MaxFiles: 800, MaxFileKB: 512,
			MaxFindingsPerRule: 50,
		},
		Batch: BatchConfig{MaxURLs: 50, Workers: 3},
		Web: WebConfig{
			Listen: "127.0.0.1:5000", HistoryLimit: 50,
			HistoryCap: 200, ShutdownSec: 5,
		},
		Modules: ModulesConfig{},
		Store:   StoreConfig{DataDir: "data/state", MaxRecords: 500},
		Active: ActiveConfig{
			DirMaxPaths: 300, SubMaxWords: 2000, SubWorkers: 20,
			ShellMaxPaths: 200, WordlistDir: "data/wordlists",
		},
	}
}

// Load 从 YAML 文件加载配置；文件不存在返回默认值；解析出错返回默认值 + err。
// 加载后做零值回退：未设置（0/空）的数值项恢复默认，负值视为非法同样回退。
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
	cfg.fillDefaults()
	return cfg, nil
}

// LoadOrDefault 加载配置；出错时静默使用默认值。
func LoadOrDefault(path string) *Config {
	cfg, _ := Load(path)
	return cfg
}

// fillDefaults 零值/负值回退默认值。
// 布尔项不回退（false 是合法的"关"），仅处理数值与字符串。
func (c *Config) fillDefaults() {
	d := Default()
	fillInt(&c.Scan.RateIntervalMS, d.Scan.RateIntervalMS)
	fillInt(&c.Scan.TimeoutSec, d.Scan.TimeoutSec)
	fillInt(&c.Scan.MaxHops, d.Scan.MaxHops)
	fillInt(&c.Scan.MaxBodyMB, d.Scan.MaxBodyMB)
	fillInt(&c.Scan.MaxConcurrent, d.Scan.MaxConcurrent)
	if c.Scan.UserAgent == "" {
		c.Scan.UserAgent = ""
	}

	fillInt(&c.Checks.NucleiCap, d.Checks.NucleiCap)
	if c.Checks.Level == "" {
		c.Checks.Level = d.Checks.Level
	}
	if c.Checks.PluginDir == "" {
		c.Checks.PluginDir = d.Checks.PluginDir
	}

	fillInt(&c.Crawler.MaxPages, d.Crawler.MaxPages)
	fillInt(&c.Crawler.MaxLinksPerPage, d.Crawler.MaxLinksPerPage)
	fillInt(&c.Crawler.TimeoutSec, d.Crawler.TimeoutSec)

	fillInt(&c.DAST.MaxParams, d.DAST.MaxParams)
	fillInt64(&c.DAST.BlindThresholdMS, d.DAST.BlindThresholdMS)
	fillInt(&c.DAST.SleepSeconds, d.DAST.SleepSeconds)
	fillInt(&c.DAST.MaxURLLen, d.DAST.MaxURLLen)

	if c.Intel.DumpPath == "" {
		c.Intel.DumpPath = d.Intel.DumpPath
	}
	if c.Intel.RangesPath == "" {
		c.Intel.RangesPath = d.Intel.RangesPath
	}
	if c.Intel.TechnologiesPath == "" {
		c.Intel.TechnologiesPath = d.Intel.TechnologiesPath
	}
	fillInt(&c.Intel.SearchLimit, d.Intel.SearchLimit)
	fillInt(&c.Intel.UpdateHours, d.Intel.UpdateHours)

	fillInt(&c.Netsec.TLSTimeoutSec, d.Netsec.TLSTimeoutSec)

	fillInt(&c.LoginBrute.MaxTries, d.LoginBrute.MaxTries)
	fillInt(&c.LoginBrute.MaxUsers, d.LoginBrute.MaxUsers)
	fillInt(&c.LoginBrute.MaxPasswords, d.LoginBrute.MaxPasswords)
	fillInt(&c.LoginBrute.IntervalMS, d.LoginBrute.IntervalMS)
	fillInt(&c.LoginBrute.MaxConcurrent, d.LoginBrute.MaxConcurrent)

	fillInt(&c.Audit.MaxArchiveMB, d.Audit.MaxArchiveMB)
	fillInt(&c.Audit.MaxFiles, d.Audit.MaxFiles)
	fillInt(&c.Audit.MaxFileKB, d.Audit.MaxFileKB)
	fillInt(&c.Audit.MaxFindingsPerRule, d.Audit.MaxFindingsPerRule)

	fillInt(&c.Batch.MaxURLs, d.Batch.MaxURLs)
	fillInt(&c.Batch.Workers, d.Batch.Workers)

	if c.Web.Listen == "" {
		c.Web.Listen = d.Web.Listen
	}
	fillInt(&c.Web.HistoryLimit, d.Web.HistoryLimit)
	fillInt(&c.Web.HistoryCap, d.Web.HistoryCap)
	fillInt(&c.Web.ShutdownSec, d.Web.ShutdownSec)

	if c.Store.DataDir == "" {
		c.Store.DataDir = d.Store.DataDir
	}
	fillInt(&c.Store.MaxRecords, d.Store.MaxRecords)

	fillInt(&c.Active.DirMaxPaths, d.Active.DirMaxPaths)
	fillInt(&c.Active.SubMaxWords, d.Active.SubMaxWords)
	fillInt(&c.Active.SubWorkers, d.Active.SubWorkers)
	fillInt(&c.Active.ShellMaxPaths, d.Active.ShellMaxPaths)
	if c.Active.WordlistDir == "" {
		c.Active.WordlistDir = d.Active.WordlistDir
	}
}

func fillInt(v *int, def int) {
	if *v <= 0 {
		*v = def
	}
}

func fillInt64(v *int64, def int64) {
	if *v <= 0 {
		*v = def
	}
}
