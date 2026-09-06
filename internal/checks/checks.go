// Package checks 验证型 Check 引擎（移植自 scanner/checks.py）。
//
// 每条 check：一个请求 + 一组判定（状态码 / body 包含 / 排除 / 头包含）。
// 全部为只读类检测，命中即「已验证漏洞」，与情报关联分开呈现。
// 带：软 404 基线过滤、请求路径回显剔除、命中二次确认、extract 版本抽取。
package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Match 单条 check 的匹配条件。
type Match struct {
	Status      int      `json:"s"`              // 期望状态码（0 = 不限定）
	StatusAny   []int    `json:"sany,omitempty"` // 状态码任一命中（Nuclei 组转换用）
	Contains    []string `json:"c"`              // 正文须全部包含（AND）
	ContainsAny []string `json:"cany,omitempty"` // 正文任一包含（OR，Nuclei 组转换用）
	Extract     *struct {
		Keyword string `json:"keyword"`
	} `json:"extract"`
}

// Check 单条验证规则（id 唯一）。
type Check struct {
	ID     string
	Lv     int // 0 = 核心集（深度识别起运行），1 = 扩展集（全面识别运行）
	Path   string
	Match  Match
	Title  string
	Sev    string
	Advice string
}

// cmsChecks CMS 联动：指纹命中后强制调度的专项 check。
var cmsChecks = map[string][]string{
	"WordPress": {"wp-json", "wp-xmlrpc", "wp-readme", "wp-login"},
	"Joomla":    {"joomla-admin"},
	"Drupal":    {"drupal-login"},
	"Typecho":   {"typecho-login"},
}

func c(s int, contains ...string) Match {
	return Match{Status: s, Contains: contains}
}

func builtinChecks() []Check {
	return []Check{
		{"git-leak", 0, "/.git/HEAD", c(200, "ref: refs/"), "Git 仓库泄露", "high", "删除 Web 根下 .git 目录"},
		{"git-index", 0, "/.git/index", c(200, "DIRC"), "Git index 文件泄露", "high", "同上"},
		{"env-leak", 0, "/.env", c(200, "=", "\n"), ".env 环境变量泄露", "high", "移除 .env，配置走环境变量"},
		{"svn-leak", 1, "/.svn/entries", c(200, "dir"), "SVN 目录泄露", "high", "删除 .svn"},
		{"ds-store", 1, "/.DS_Store", c(200, "Bud1"), ".DS_Store 泄露目录结构", "low", "部署过滤点开头文件"},
		{"bak-dump", 0, "/dump.sql", c(200), "数据库 dump 文件暴露", "high", "删除备份文件"},
		{"bak-site", 1, "/www.zip", c(200), "站点源码打包暴露", "high", "删除源码包"},
		{"bak-config", 1, "/wp-config.php.bak", c(200), "配置备份文件泄露", "high", "删除编辑器备份"},
		{"phpinfo", 0, "/phpinfo.php", c(200, "phpinfo()"), "phpinfo 页面暴露", "high", "删除 phpinfo 探针"},
		{"adminer", 1, "/adminer.php", c(200, "Adminer"), "Adminer 数据库管理入口", "medium", "删除或加访问控制"},
		{"actuator", 0, "/actuator", c(200, "_links"), "Spring Actuator 未授权", "high", "关闭暴露端点或加鉴权"},
		{"actuator-env", 1, "/actuator/env", c(200), "Actuator env 端点暴露", "high", "同上"},
		{"swagger", 0, "/swagger-ui.html", c(200), "Swagger 文档暴露", "medium", "生产关闭或加鉴权"},
		{"api-docs", 1, "/v2/api-docs", c(200, "swagger"), "API 文档未授权访问", "medium", "同上"},
		{"druid", 1, "/druid/index.html", c(200, "Druid"), "Druid 控制台未授权", "high", "加访问控制"},
		{"tomcat-manager", 1, "/manager/html", c(401), "Tomcat Manager 暴露", "medium", "删除或强口令"},
		{"server-status", 1, "/server-status", c(200, "Apache"), "Apache server-status 暴露", "low", "关闭 mod_status 对外"},
		{"debug-page", 1, "/console", c(200, "console"), "调试控制台暴露", "medium", "生产关闭调试端点"},
		{"dir-list", 0, "/static/", c(200, "Parent Directory", "<h1>Index of", "Directory listing"), "目录列表开启", "medium", "关闭 autoindex"},
		{"wp-users", 1, "/?rest_route=/wp/v2/users", c(200, `"slug"`), "WP REST 用户枚举", "medium", "禁用 users 端点"},
		{"wp-xmlrpc", 1, "/xmlrpc.php", c(405, "XML-RPC"), "xmlrpc.php 开启", "low", "不需要时禁用"},
		{"wp-readme", 1, "/readme.html", m(200, "WordPress"), "WP 版本泄露(readme)", "low", "删除 readme.html"},
		{"composer", 1, "/composer.json", c(200, "require"), "composer.json 泄露", "low", "移除依赖清单"},
		{"package-json", 1, "/package.json", c(200, "dependencies"), "package.json 泄露", "low", "移除依赖清单"},
		{"webconfig", 1, "/web.config", c(200, "<configuration"), "IIS web.config 泄露", "medium", "禁止下载配置文件"},
		{"crossdomain", 1, "/crossdomain.xml", c(200, "<cross-domain-policy"), "过时跨域策略文件", "low", "删除 crossdomain.xml"},
		{"metrics", 1, "/metrics", c(200, "# HELP", "# TYPE"), "Prometheus metrics 暴露", "medium", "加内网访问限制"},
		{"admin-path", 0, "/admin/", c(200), "后台入口 /admin/", "info", "加访问控制与双因素"},
		{"login-root", 0, "/login", c(200), "登录入口 /login", "info", "加访问控制"},
		{"grafana", 1, "/grafana/login", c(200, "Grafana"), "Grafana 登录暴露", "low", "加访问控制"},
		{"kibana", 1, "/app/kibana", c(200), "Kibana 暴露", "medium", "加访问控制"},
		{"nacos", 1, "/nacos/", c(200, "nacos"), "Nacos 控制台暴露", "high", "开启鉴权"},
		{"jenkins", 1, "/jenkins/login", c(200, "Jenkins"), "Jenkins 暴露", "medium", "加访问控制"},
		{"solr", 1, "/solr/", c(200), "Solr 控制台暴露", "medium", "加访问控制"},
		{"eureka", 1, "/eureka/apps", c(200, "<application"), "Eureka 注册表未授权", "high", "开启鉴权"},
		{"harbor", 1, "/harbor/sign-in", c(200, "Harbor"), "Harbor 暴露", "low", "加访问控制"},
		{"wp-json", 1, "/wp-json/wp/v2/users", c(200, `"slug"`), "WP REST 用户泄露", "medium", "禁用 users 端点"},
		{"wp-login", 1, "/wp-login.php", c(200, "user_login", "wp-submit"), "WordPress 登录页", "info", "加访问控制"},
		{"joomla-admin", 1, "/administrator/", c(200, "Joomla"), "Joomla 后台入口", "info", "加访问控制"},
		{"drupal-login", 1, "/user/login", c(200, "Drupal"), "Drupal 登录页", "info", "加访问控制"},
		{"typecho-login", 1, "/admin/login.php", c(200, "Typecho"), "Typecho 登录页", "info", "加访问控制"},
		{"tp-admin", 1, "/admin.php", c(200), "后台入口 admin.php", "info", "加访问控制"},
	}
}

// m 带版本抽取条件的 Match 快捷构造。
func m(status int, contains ...string) Match {
	return Match{Status: status, Contains: contains}
}

// extractCheck 需要版本抽取的 check：check id → (关键词, 技术名)。
var extractChecks = map[string][2]string{
	"wp-readme": {"version", "WordPress"},
}

var allChecks = builtinChecks()

var pluginsOnce sync.Once

// ConfigurePlugins 加载用户自定义 check（进程内幂等：仅首次生效）。
// 服务启动 / CLI 入口调用一次即可。
func ConfigurePlugins(dir string) {
	pluginsOnce.Do(func() {
		RegisterPlugins(LoadPlugins(dir))
	})
}

// RegisterPlugins 合并用户自定义 check（规则用户化入口）。
func RegisterPlugins(checks []Check) {
	allChecks = append(allChecks, checks...)
}

// AllChecks 返回当前全量 check 集。
func AllChecks() []Check { return allChecks }

// LoadPlugins 热加载用户自定义 check（data/plugins/*.json）。
// 这是规则用户化的入口：用户按 JSON 格式投放即可扩展检测。
func LoadPlugins(dir string) []Check {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Check
	for _, f := range entries {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		var arr []struct {
			ID     string `json:"id"`
			Lv     int    `json:"lv"`
			P      string `json:"p"`
			M      Match  `json:"m"`
			Title  string `json:"title"`
			Sev    string `json:"sev"`
			Advice string `json:"advice"`
		}
		if json.Unmarshal(data, &arr) != nil {
			continue
		}
		for _, item := range arr {
			if item.ID == "" {
				continue
			}
			sev := item.Sev
			if sev == "" {
				sev = "medium"
			}
			title := item.Title
			if title == "" {
				title = item.ID
			}
			out = append(out, Check{
				ID: item.ID, Lv: item.Lv, Path: item.P, Match: item.M,
				Title: title, Sev: sev, Advice: item.Advice,
			})
		}
	}
	return out
}

// CMSTechChecks 返回某技术指纹触发的联动 check id 列表（无则 nil）。
func CMSTechChecks(tech string) []string { return cmsChecks[tech] }
