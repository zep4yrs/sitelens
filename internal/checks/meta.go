package checks

// 内置验证 check 的 ATT&CK / 噪声 / 安全等级元数据（5.3 M4 复核落地）。
//
// 复核原则（避免"拍脑袋填默认值"）：
//  1. 安全等级：内置验证集全部是 GET + 静态路径、无 payload、无变量，统一
//     read_only；模板转译阶段已拒绝 POST/payload/利用类模板。
//  2. 噪声：按"单次响应体量 + 是否大文件下载"分三档——普通 200 探测 low，
//     Actuator 配置/线程转储等中等体量 medium，heapdump/日志/数据库导出等
//     大文件 high。
//  3. ATT&CK：按"证据类型"归类（凭据文件/暴露面板/指纹/发现/大文件），
//     只用已核对的合法技术 ID（见 attackTechniques），不臆造子技术编号。
//
// 复核方式：关键字规则 + 少量显式覆盖（metaOverride），并用
// tools/checkmeta 导出全量 CSV 人工抽样核对（见 docs 内部复核记录）。

import "strings"

// Meta 单条 check 的元数据。
type Meta struct {
	ATTACK []string `json:"attack"` // ATT&CK 技术 ID（已核对）
	Noise  string   `json:"noise"`  // low | medium | high
	Safety string   `json:"safety"` // read_only | active | exploit
	Reason string   `json:"reason"` // 归类依据（便于复核/审计）
}

// 噪声/安全等级合法值。
const (
	NoiseLow    = "low"
	NoiseMedium = "medium"
	NoiseHigh   = "high"

	SafetyReadOnly = "read_only"
	SafetyActive   = "active"
	SafetyExploit  = "exploit"
)

// attackTechniques 复核时确认合法的 ATT&CK Enterprise 技术（只收录本表内的 ID）。
var attackTechniques = map[string]bool{
	"T1595":     true, // Active Scanning
	"T1592":     true, // Gather Victim Host Information
	"T1590":     true, // Gather Victim Network Information
	"T1552":     true, // Unsecured Credentials
	"T1552.001": true, // Credentials In Files
	"T1552.004": true, // Private Keys
	"T1133":     true, // External Remote Services
	"T1190":     true, // Exploit Public-Facing Application
	"T1613":     true, // Container and Resource Discovery
	"T1087":     true, // Account Discovery
	"T1046":     true, // Network Service Discovery
	"T1082":     true, // System Information Discovery
	"T1005":     true, // Data from Local System
	"T1213":     true, // Data from Information Repositories
	"T1530":     true, // Data from Cloud Storage
}

// attackIDs 校验技术 ID 是否在复核白名单内（测试门禁用）。
func attackIDsValid(ids []string) bool {
	for _, id := range ids {
		if !attackTechniques[id] {
			return false
		}
	}
	return true
}

// metaOverride 显式覆盖：规则容易误归类的代表性 check（人工复核确认）。
var metaOverride = map[string]Meta{
	"git-leak":               {ATTACK: []string{"T1552.001", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "仓库元数据泄露（可读提交历史/远程地址）"},
	"git-config":             {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Git 配置含远程地址/凭据痕迹"},
	"git-logs":               {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Git 操作日志泄露"},
	"env-leak":               {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: ".env 环境变量（数据库/API 凭据）"},
	"env-local":              {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: ".env.local 凭据泄露"},
	"env-prod":               {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: ".env.production 凭据泄露"},
	"aws-credentials":        {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "AWS 凭据文件"},
	"kube-config":            {ATTACK: []string{"T1552.001", "T1613"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Kubeconfig 集群凭据"},
	"ssh-private-key":        {ATTACK: []string{"T1552.004"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "SSH 私钥泄露"},
	"id-rsa":                 {ATTACK: []string{"T1552.004"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "私钥文件泄露"},
	"server-key":             {ATTACK: []string{"T1552.004"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "TLS 私钥泄露"},
	"heapdump":               {ATTACK: []string{"T1552", "T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "Actuator heapdump 大文件（内存/凭据）"},
	"actuator-logfile":       {ATTACK: []string{"T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "日志文件可下载（大文件）"},
	"actuator-env-root":      {ATTACK: []string{"T1552", "T1592"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "Actuator 环境变量（可能含凭据）"},
	"actuator-beans":         {ATTACK: []string{"T1592"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "Spring Bean 清单（内部结构）"},
	"actuator-configprops":   {ATTACK: []string{"T1552", "T1592"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "配置属性（可能含凭据）"},
	"actuator-threaddump":    {ATTACK: []string{"T1592"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "线程转储（内部结构）"},
	"actuator-sessions":      {ATTACK: []string{"T1087"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "会话枚举"},
	"es-cat-indices":         {ATTACK: []string{"T1213"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "ES 索引/数据仓库信息"},
	"k8s-namespaces":         {ATTACK: []string{"T1613"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "K8s 命名空间枚举"},
	"k8s-version":            {ATTACK: []string{"T1613", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "K8s 版本指纹"},
	"docker-registry":        {ATTACK: []string{"T1613"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "容器镜像仓库暴露"},
	"swagger-ui-index":       {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "API 文档暴露（接口清单）"},
	"swagger-json":           {ATTACK: []string{"T1592"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "OpenAPI 规范暴露"},
	"graphql-introspect":     {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "GraphQL 内省（schema 泄露）"},
	"phpinfo":                {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "phpinfo 系统信息暴露"},
	"server-status":          {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Apache 状态页（进程/请求信息）"},
	"tomcat-manager":         {ATTACK: []string{"T1133", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Tomcat 管理台暴露"},
	"jboss-jmx-console":      {ATTACK: []string{"T1133"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "JMX 控制台暴露"},
	"jolokia-list":           {ATTACK: []string{"T1133"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Jolokia MBean 列表"},
	"backup-sql":             {ATTACK: []string{"T1552.001", "T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "数据库导出文件（大文件/凭据）"},
	"backup-zip":             {ATTACK: []string{"T1552.001", "T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "备份压缩包暴露"},
	"tfstate":                {ATTACK: []string{"T1552.001", "T1530"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "Terraform state（云凭据/资源清单）"},
	"docker-config":          {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Docker 凭据配置"},
	"npmrc":                  {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "npm token 配置"},
	"laravel-log":            {ATTACK: []string{"T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "应用日志（大文件）"},
	"access-log":             {ATTACK: []string{"T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "访问日志（大文件）"},
	"mysql-history":          {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "MySQL 历史命令（可能含口令）"},
	"bash-history":           {ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Shell 历史（命令/凭据痕迹）"},
	"php-fpm-status":         {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "PHP-FPM 状态页"},
	"rabbitmq-api":           {ATTACK: []string{"T1133"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "RabbitMQ 管理 API 未授权"},
	"tpl-docker-compose-yml": {ATTACK: []string{"T1552.001"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "docker-compose 文件（数据库/服务凭据）"},
}

// 关键字分类（按顺序匹配，先命中先返回）。
type metaRule struct {
	keywords []string
	meta     Meta
}

var metaRules = []metaRule{
	{ // 私钥
		keywords: []string{"private-key", "id_rsa", "server.key", "privkey", "private_key"},
		meta:     Meta{ATTACK: []string{"T1552.004"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "私钥/证书私钥文件"},
	},
	{ // 大文件下载（先于普通凭据规则，噪声标 high）
		keywords: []string{"heapdump", "logfile", "backup.sql", "backup-sql", "backup.zip", "backup.tar", "dump.rdb", "database.sql", "users.sql"},
		meta:     Meta{ATTACK: []string{"T1552", "T1005"}, Noise: NoiseHigh, Safety: SafetyReadOnly, Reason: "大文件导出/下载（内存/数据/备份）"},
	},
	{ // 依赖清单/源码结构（指纹面，不是凭据）
		keywords: []string{"composer.json", "composer.lock", "package.json", "package-lock", "yarn.lock", "gemfile.lock", "requirements.txt", "go.mod", "pom.xml", "schema.rb", "db/schema"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "依赖清单/源码结构泄露（指纹）"},
	},
	{ // CI 配置（可能含密钥/部署凭据）
		keywords: []string{"circleci", ".gitlab-ci", "travis", "jenkinsfile", ".github/workflows", "gitlab-ci.yml", "jenkinsfile"},
		meta:     Meta{ATTACK: []string{"T1552.001", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CI 配置泄露（可能含部署凭据）"},
	},
	{ // 发布/部署脚本与备份残留
		keywords: []string{"shellscript", "setup.sh", "install.sh", "restore-info", "firebase.json", "wpeprivate", "wpengine"},
		meta:     Meta{ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "发布脚本/备份残留（可能含凭据）"},
	},
	{ // 凭据/配置文件
		keywords: []string{"credential", "aws", "kube", "dockercfg", "docker-config", ".env", "env-", "secrets", "npmrc", "pypirc", "git-config", "git-leak", "git-logs", "tfstate", "terraform", "wp-config", "config.php", "config.inc", "config.ini", "local.xml", "settings.py", "htpasswd", "my.cnf", "redis.conf", "mongod.conf", "nginx.conf", "httpd.conf", "php.ini", "context.xml", "application.ini", "config.xml", "parameters.yml", "config.yml", "config.yaml", "config.json", "app.config", "bzr", "svn", "idea-workspace", "workspace.xml", "wpeprivate", "web.config", "webconfig", "web.xml", "web-inf", "htaccess", "filezilla", "front-page", "_vti", "service.pwd", "database.create", "service-account", "serverless", "drupal-settings", "vscode-settings", "apcu", "rack-mini-profiler", "git-index", "hg-requires"},
		meta:     Meta{ATTACK: []string{"T1552.001"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "配置文件/凭据文件泄露"},
	},
	{ // API 文档 / schema（先于面板规则，避免 swagger-panel 被归为管理台）
		keywords: []string{"swagger", "openapi", "api-docs", "v2/api-docs", "v3/api-docs", "graphql", "introspect", "doc.html", "knife4j", "api/swagger", "swagger-resources"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "API 文档/schema 暴露（接口清单）"},
	},
	{ // 暴露的管理面板 / 控制台
		keywords: []string{"admin", "console", "manager", "dashboard", "jenkins", "gitlab", "gitea", "gogs", "jira", "confluence", "bitbucket", "portainer", "rancher", "kibana", "grafana", "zabbix", "nagios", "cacti", "phpmyadmin", "pma", "adminer", "webmin", "rabbitmq", "minio", "nexus", "artifactory", "harbor", "airflow", "superset", "metabase", "jupyter", "nifi", "nacos", "zipkin", "skywalking", "traefik", "kubernetes", "k8s-dashboard", "hudson", "teamcity", "bamboo", "sonar", "jolokia", "jmx", "web-console", "host-manager", "solr", "couchdb-fauxton", "prometheus-ui", "alertmanager", "login", "logon", "panel", "gateway", "vpn", "fortinet", "fortigate", "citrix", "pulse", "netscaler", "netscalar", "cisco", "juniper", "bigip", "sonicwall", "sophos", "globalprotect", "paloalto", "rdweb", "mlflow", "jellyfin", "axis2-detect", "drupal-install", "redcap-install", "tomcat-scripts", "profileservice", "install.php", "dashboard", "redash", "cxf", "axis2", "argo", "drone", "flower", "geoserver", "plesk", "roundcube", "squirrelmail", "druid", "eureka", "crxde", "munin", "siteminder", "saml"},
		meta:     Meta{ATTACK: []string{"T1133", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "管理面板/控制台暴露（远程服务）"},
	},
	{ // 容器/编排/数据平台发现面
		keywords: []string{"k8s", "kubernetes", "docker", "registry", "_cluster", "_nodes", "_cat", "elasticsearch", "es-", "couchdb", "couchbase", "clickhouse", "mongodb", "redis", "etcd", "consul", "nomad", "vault"},
		meta:     Meta{ATTACK: []string{"T1613", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "容器/数据平台发现面"},
	},
	{ // 系统/应用信息（phpinfo、状态页、日志、metrics）
		keywords: []string{"phpinfo", "status", "server-status", "nginx_status", "info.php", "metrics", "prometheus", "actuator", "threaddump", "env-root", "configprops", "beans", "loggers", "httptrace", "sessions", "startup", "sbom", "quartz", "scheduledtasks", "auditevents", "caches", "conditions", "flyway", "liquibase", "httpexchanges", "expvar", "pprof"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "系统/应用信息暴露"},
	},
	{ // 用户/账号枚举
		keywords: []string{"wp-json", "wp/v2/users", "user-enum", "users?context", "account-discovery"},
		meta:     Meta{ATTACK: []string{"T1087"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "用户/账号枚举"},
	},
	{ // 调试页/信息端点/组件指纹（T1592）
		keywords: []string{"jaeger", "loki", "clockwork", "debugmode", "debug-mode", "yii-debug", "elmah", "kronos", "cgi-test", "sony-bravia", "letter-opener", "search-for-ioc", "webeditors", "ckeditor", "fckeditor", "ueditor", "wp-readme", "wp-license", "wp-xmlrpc", "registrations", "crossdomain", ".ds-store", "cert.pem", "webpack-stats", "arcgis"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "调试页/信息端点/组件指纹暴露"},
	},
	{ // CVE 版本/文件检测（只读探测，不是利用）
		keywords: []string{"cve-"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CVE 相关组件/文件只读探测（非利用）"},
	},
	{ // 版本/指纹识别（只暴露技术栈版本）
		keywords: []string{"detect", "version", "fingerprint", "extractor", "tech-", "technology", "app-site-association"},
		meta:     Meta{ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "版本/技术栈指纹识别"},
	},
	{ // 目录列举
		keywords: []string{"dir-listing", "directory-listing", "dir-list", "index-of", "listing"},
		meta:     Meta{ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "目录列举（文件结构暴露）"},
	},
	{ // 日志/备份/残留文件
		keywords: []string{".log", "logfile", "access.log", "error.log", "debug.log", "php_errors", "history", "bak", ".old", ".swp", ".save", "backup", "dump", ".sql", ".zip", ".tar", ".rdb", "mysql-history", "bash-history", "zsh-history"},
		meta:     Meta{ATTACK: []string{"T1552.001"}, Noise: NoiseMedium, Safety: SafetyReadOnly, Reason: "日志/备份/残留文件"},
	},
}

// MetaOf 返回单条 check 的复核元数据。
func MetaOf(c Check) Meta {
	if m, ok := metaOverride[c.ID]; ok {
		return m
	}
	if m, ok := metaExtraOverride[c.ID]; ok {
		return m
	}
	key := strings.ToLower(c.ID + " " + c.Path + " " + c.Title)
	for _, r := range metaRules {
		for _, kw := range r.keywords {
			if strings.Contains(key, kw) {
				m := r.meta
				// 中等体量响应细化：Actuator 配置/线程转储/API 规范标 medium。
				if m.Noise == NoiseLow {
					switch {
					case strings.Contains(key, "configprops"), strings.Contains(key, "threaddump"),
						strings.Contains(key, "beans"), strings.Contains(key, "httptrace"),
						strings.Contains(key, "swagger"), strings.Contains(key, "openapi"),
						strings.Contains(key, "api-docs"), strings.Contains(key, "_cat"), strings.Contains(key, "nodes"):
						m.Noise = NoiseMedium
					}
				}
				return m
			}
		}
	}
	// 默认：单次只读 GET 探测（模板转译集绝大多数属此类）。
	return Meta{ATTACK: []string{"T1595"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "单次只读 GET 探测（暴露面扫描）"}
}

// AllMeta 返回全量 check 的元数据（测试/导出用）。
func AllMeta() map[string]Meta {
	all := AllChecks()
	out := make(map[string]Meta, len(all))
	for _, c := range all {
		out[c.ID] = MetaOf(c)
	}
	return out
}

// MetaForID 按 check ID 查元数据（报告/SARIF 侧按 ID 反查用）。
// 未知 ID 返回空 Meta（调用方按"无元数据"处理）。
func MetaForID(id string) Meta {
	for _, c := range AllChecks() {
		if c.ID == id {
			return MetaOf(c)
		}
	}
	return Meta{}
}
