// Package checks 验证型 Check 引擎（移植自 scanner/checks.py）。
//
// 每条 check：一个请求 + 一组判定（状态码 / body 包含 / 排除 / 头包含）。
// 全部为只读类检测，命中即「已验证漏洞」，与情报关联分开呈现。
// 带：软 404 基线过滤、请求路径回显剔除、命中二次确认、extract 版本抽取。
package checks

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Match 单条 check 的匹配条件。
type Match struct {
	Status         int      `json:"s"`                // 期望状态码（0 = 不限定）
	StatusAny      []int    `json:"sany,omitempty"`   // 状态码任一命中（Nuclei 组转换用）
	Contains       []string `json:"c"`                // 正文须全部包含（AND）
	ContainsAny    []string `json:"cany,omitempty"`   // 正文任一包含（OR，Nuclei 组转换用）
	NotContains    []string `json:"nc,omitempty"`     // 正文任一包含即否决（弱断言收紧用）
	HeaderContains []string `json:"h,omitempty"`      // 响应头区须全部包含（Nuclei 头匹配）
	RegexBody      []string `json:"rxbody,omitempty"` // 正文任一正则命中（OR，Nuclei regex 转换）
	DSL            []string `json:"dsl,omitempty"`    // dsl 表达式须全部为真（安全子集，见 internal/dsl）
	// Expr afrog 经典 rules+expression 表达式（运行时求值，见 internal/afrogx）。
	// 与其它条件并存时同样必须全部满足；编译失败/求值失败一律不命中——
	// 宁少报不误报。仅 afrog 来源的模板会带这个字段。
	Expr        string        `json:"expr,omitempty"`
	Extracts    []ExtractSpec `json:"exs,omitempty"`    // 命名抽取变量（供 dsl 引用）
	Method      string        `json:"method,omitempty"` // POST 模板请求方法
	Body        string        `json:"body,omitempty"`   // POST 请求体
	ContentType string        `json:"ctype,omitempty"`  // POST Content-Type
	Extract     *struct {
		Keyword string `json:"keyword"`
	} `json:"extract"`
}

// hasAnyCondition 判定 Match 是否至少带一个有效判定条件。
//
// B-02：此前无条件（空 Match）的 check 会在 matchBodyReason 里「零条件
// 全部满足」直接命中——插件 JSON 少写/写错字段名即静默变成全站误报。
// 这里把「有条件」显式定义出来，加载期与判定期各用一次：
//   - LoadPlugins：无条件的插件 check 直接丢弃（并记 warning）；
//   - matchBodyReason：无条件的 check 一律不命中（宁少报不误报）。
func (m Match) hasAnyCondition() bool {
	return m.Status != 0 ||
		len(m.StatusAny) > 0 ||
		len(m.Contains) > 0 ||
		len(m.ContainsAny) > 0 ||
		len(m.NotContains) > 0 ||
		len(m.HeaderContains) > 0 ||
		len(m.RegexBody) > 0 ||
		len(m.DSL) > 0 ||
		m.Expr != ""
}

// ExtractSpec 命名抽取（nuclei extractors regex 形态）：从响应抽取变量
// 供 dsl 表达式引用（如版本号 → compare_versions 区间判断）。
type ExtractSpec struct {
	Name  string   `json:"n"`
	Part  string   `json:"part,omitempty"` // body(默认) | header
	Regex []string `json:"rx"`
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

// regexCache 正则编译缓存（pattern → 编译结果或 nil 表示不可编译）。
// B7：计数上限防长驻无界增长（超限后不缓存，仅当场编译）。
var (
	regexCache    sync.Map
	regexCacheN   atomic.Int64
	regexCacheMax = int64(8192)
)

// compileCached 编译正则并缓存；非法模式返回 nil。
func compileCached(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	if regexCacheN.Add(1) <= regexCacheMax {
		regexCache.Store(pattern, re)
	}
	return re
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

// envLeakMatch .env 泄露判据（B-14 收紧）。
//
// 旧判据是 c(200, "=", "\n")——正文同时含等号与换行，**任何 HTML 页面都满足**，
// 唯一挡住它的是软 404 总闸；总闸一旦失效（见 B-01）就是全站 high 级误报。
// 新判据要求「行首 KEY=VALUE」形态，并否决 HTML 文档。
//
// 取舍：只认大写键（12-factor 惯例）。小写键的 .env 会漏报——这是刻意的
// 「宁少报不误报」：把小写也放进来，`abc=1` 这类行在普通文本响应里太容易撞。
func envLeakMatch() Match {
	return Match{
		Status:      200,
		RegexBody:   []string{`(?m)^[A-Z][A-Z0-9_]{2,}=`},
		NotContains: []string{"<html", "<!doctype"},
	}
}

// jsonManifestMatch JSON 清单文件判据（composer.json / package.json，B-14 收紧）。
// 旧判据只找 "require" / "dependencies" 这类裸词，普通英文页面/JS bundle 里
// 到处都是；新判据要求行级 `"key":` 的 JSON 键形态，并否决 HTML 文档。
func jsonManifestMatch(keys ...string) Match {
	return Match{
		Status:      200,
		RegexBody:   []string{`(?m)^\s*"(` + strings.Join(keys, "|") + `)"\s*:`},
		NotContains: []string{"<html", "<!doctype"},
	}
}

// AllBuiltinPaths 返回内置 check 的路径集合（供 tools/tpl2check 转译管线去重）。
func AllBuiltinPaths() map[string]bool {
	list := builtinChecks()
	out := make(map[string]bool, len(list))
	for _, c := range list {
		out[c.Path] = true
	}
	return out
}
func builtinChecks() []Check {
	list := []Check{
		{"git-leak", 0, "/.git/HEAD", c(200, "ref: refs/"), "Git 仓库泄露", "high", "删除 Web 根下 .git 目录"},
		{"git-index", 0, "/.git/index", c(200, "DIRC"), "Git index 文件泄露", "high", "同上"},
		{"env-leak", 0, "/.env", envLeakMatch(), ".env 环境变量泄露", "high", "移除 .env，配置走环境变量"},
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
		{"composer", 1, "/composer.json", jsonManifestMatch("require", "require-dev", "autoload"), "composer.json 泄露", "low", "移除依赖清单"},
		{"package-json", 1, "/package.json", jsonManifestMatch("dependencies", "devDependencies"), "package.json 泄露", "low", "移除依赖清单"},
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
		// ---- 5.3 借鉴 ARES：验证型 check 扩容（扩展集，仅「全面」档运行）----
		// 判据一律用强特征（版本串/API 头/JSON 键），避免通用 200 误报；
		// Lv=1 表示只在 level=="all"（全面识别）或 CMS 联动时调度，默认扫描请求量不变。
		{"git-config", 1, "/.git/config", c(200, "[core]"), "Git config 泄露（含远程地址/凭据痕迹）", "high", "删除 Web 根下 .git 目录"},
		{"git-logs", 1, "/.git/logs/HEAD", c(200, "commit "), "Git 操作日志泄露（可还原历史与作者）", "high", "删除 Web 根下 .git 目录"},
		{"env-local", 1, "/.env.local", envLeakMatch(), ".env.local 环境变量泄露", "high", "移除 .env.local，配置走环境变量"},
		{"env-prod", 1, "/.env.production", envLeakMatch(), ".env.production 环境变量泄露", "high", "移除 .env.production，配置走环境变量"},
		{"backup-sql", 1, "/backup.sql", c(200, "INSERT INTO"), "数据库备份文件暴露", "high", "删除备份文件或移出 Web 根"},
		{"heapdump", 1, "/actuator/heapdump", c(200, "JAVA PROFILE"), "Actuator heapdump 可下载（内存/凭据泄露）", "critical", "关闭 heapdump 端点并轮换密钥"},
		{"actuator-health", 1, "/actuator/health", c(200, `"status":"UP"`), "Actuator health 端点暴露", "low", "生产关闭或加鉴权"},
		{"actuator-mappings", 1, "/actuator/mappings", c(200, `"mappings"`), "Actuator mappings 端点暴露（API 全图）", "medium", "关闭或加鉴权"},
		{"swagger-json", 1, "/swagger.json", c(200, `"swagger"`), "Swagger 规范文件暴露", "medium", "生产关闭或加鉴权"},
		{"openapi-json", 1, "/openapi.json", c(200, `"openapi"`), "OpenAPI 规范文件暴露", "medium", "生产关闭或加鉴权"},
		{"v3-api-docs", 1, "/v3/api-docs", c(200, `"openapi"`), "SpringDoc API 文档暴露", "medium", "生产关闭或加鉴权"},
		{"graphql-introspect", 1, "/graphql", Match{Status: 200, Method: "POST", Body: `{"query":"{__typename}"}`, ContentType: "application/json", Contains: []string{"__typename"}}, "GraphQL 内省未授权（可枚举 schema）", "medium", "生产关闭 introspection"},
		{"k8s-version", 1, "/version", c(200, `"gitVersion"`), "Kubernetes API 未授权（版本泄露）", "medium", "API Server 开启鉴权"},
		{"k8s-namespaces", 1, "/api/v1/namespaces", c(200, `"kind":"NamespaceList"`), "Kubernetes 命名空间未授权列举", "high", "API Server 开启鉴权/网络隔离"},
		{"docker-registry", 1, "/v2/", Match{Status: 200, HeaderContains: []string{"Docker-Distribution-Api-Version"}}, "Docker Registry 未授权访问", "medium", "开启鉴权或网络隔离"},
		{"nginx-status", 1, "/nginx_status", c(200, "Active connections"), "Nginx stub_status 暴露", "low", "限制 stub_status 来源"},
		{"phpmyadmin", 1, "/phpmyadmin/", c(200, "phpMyAdmin"), "phpMyAdmin 入口暴露", "medium", "加访问控制或删除"},
		{"gitlab", 1, "/users/sign_in", c(200, "GitLab"), "GitLab 登录入口暴露", "low", "加访问控制"},
	}
	return append(list, tplChecks...)
}

// m 带版本抽取条件的 Match 快捷构造。
func m(status int, contains ...string) Match {
	return Match{Status: status, Contains: contains}
}

// extractChecks 需要版本抽取的 check：check id → (关键词, 技术名)。
// 命中后从响应正文按关键词抽取版本，回填对应技术的版本号——
// 情报关联从 possible 升级为 confirmed 的关键链路。
var extractChecks = map[string][2]string{
	"wp-readme": {"version", "WordPress"},
}

// ExtractFor 返回 check 的版本抽取配置（关键词, 技术名, 是否存在）。
func ExtractFor(id string) (keyword, tech string, ok bool) {
	pair, exists := extractChecks[id]
	if !exists {
		return "", "", false
	}
	return pair[0], pair[1], true
}

var (
	checkMu      sync.RWMutex
	builtinList  = builtinChecks()
	userPlugins  []Check
	pluginMTime  int64 // 插件目录最新 mtime（0 = 从未加载）
	pluginLoaded bool
)

// ConfigurePlugins 加载/重载用户自定义 check（规则用户化入口）。
// 目录 mtime 未变化且已加载过时跳过——服务可在扫描提交时反复调用，
// 插件目录有变动才真正重载，实现插件热更新。
func ConfigurePlugins(dir string) {
	checkMu.Lock()
	defer checkMu.Unlock()
	mt := dirMaxMTime(dir)
	if pluginLoaded && mt == pluginMTime {
		return
	}
	pluginMTime = mt
	pluginLoaded = true
	userPlugins = LoadPlugins(dir)
	// 插件集换代：推进版本号使 IsExtended 的 checkIndex 快照失效
	// （BUG-013：不失效则新插件永久不被识别，静默漏检）。
	pluginGen.Add(1)
}

// dirMaxMTime 目录内 .json 文件的最大 mtime；目录缺失/无文件返回 0。
func dirMaxMTime(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var max int64
	for _, f := range entries {
		if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
			continue
		}
		if st, serr := f.Info(); serr == nil {
			if m := st.ModTime().UnixNano(); m > max {
				max = m
			}
		}
	}
	return max
}

// RegisterPlugins 直接注入用户自定义 check（编程入口）。
func RegisterPlugins(checks []Check) {
	checkMu.Lock()
	defer checkMu.Unlock()
	userPlugins = append(userPlugins, checks...)
	// 同 ConfigurePlugins：插件集变更须让 IsExtended 索引快照失效。
	pluginGen.Add(1)
}

// AllChecks 返回当前全量 check 集（内置 + 用户插件）。
func AllChecks() []Check {
	checkMu.RLock()
	defer checkMu.RUnlock()
	return append(append([]Check{}, builtinList...), userPlugins...)
}

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
			// B-02：无条件 / 无路径的插件 check 一律丢弃。空 Match 会在
			// matchBodyReason 里「零条件全满足」恒命中（插件 JSON 把 "c"
			// 写成 "contains" 就静默变成全站误报）；空 Path 会让探针落到
			// 站点根路径。这里宁可丢弃并留痕，不放进执行集。
			if !item.M.hasAnyCondition() {
				log.Printf("[checks] 插件 %s 丢弃：Match 无任何判定条件（字段名可能拼错，注意 json 标签是 s/sany/c/cany/nc/h/rxbody/dsl/expr）", item.ID)
				continue
			}
			if strings.TrimSpace(item.P) == "" {
				log.Printf("[checks] 插件 %s 丢弃：路径为空", item.ID)
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
