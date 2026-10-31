// AU-02 规则扩展：Java/Go/TS 高频规则 + OWASP Top 10:2021 映射 + 密钥扫描增强
// （熵检测 + AWS/GCP/Azure/GitHub/Slack key 前缀）。
//
// 设计口径：
//   - 与既有 PY/JS/PHP 行级规则同构（正则 + 行号 + 修复建议），只增不改；
//   - 规则结构新增 OWASP 字段，Finding.owasp 与 SARIF rules[].properties.owasp
//     输出（additive，未映射规则省略字段）；
//   - 前缀类密钥规则是普通正则规则；高熵检测需要先取字面量再算熵，作为
//     行级动态规则（GEN-ENTROPY）在 run 循环内单独执行，同样受单规则上限约束；
//   - 熵命中不把密钥值写进 Match（避免报告二次泄露），Match 用「键名」。
package audit

import (
	"math"
	"regexp"
	"strings"
)

// OWASP Top 10:2021 分类（本项目只用到与审计规则相关的几类）。
const (
	owaspAccess    = "A01:2021 Broken Access Control"
	owaspCrypto    = "A02:2021 Cryptographic Failures"
	owaspInjection = "A03:2021 Injection"
	owaspConfig    = "A05:2021 Security Misconfiguration"
	owaspAuth      = "A07:2021 Identification and Authentication Failures"
	owaspIntegrity = "A08:2021 Software and Data Integrity Failures"
)

// ruleOWASP 规则 id → OWASP 映射（新增规则在此登记即可）。
var ruleOWASP = map[string]string{
	// 基础规则
	"PY-EVAL":      owaspInjection,
	"PY-EXEC":      owaspInjection,
	"PY-PICKLE":    owaspIntegrity,
	"PY-OSPOPEN":   owaspInjection,
	"PY-SQLFMT":    owaspInjection,
	"PY-MD5":       owaspCrypto,
	"PY-SECRET":    owaspAuth,
	"PY-DEBUG":     owaspConfig,
	"PY-TEMPFILE":  owaspCrypto,
	"PY-RAND":      owaspCrypto,
	"JS-EVAL":      owaspInjection,
	"JS-INNERHTML": owaspInjection,
	"JS-SECRET":    owaspAuth,
	"PHP-CMD":      owaspInjection,
	"PHP-INCLUDE":  owaspAccess,
	"GEN-IP":       owaspConfig,
	// AU-02 扩展规则
	"JAVA-SQLI":       owaspInjection,
	"JAVA-DESER":      owaspIntegrity,
	"JAVA-CMD":        owaspInjection,
	"JAVA-WEAKRAND":   owaspCrypto,
	"JAVA-SECRET":     owaspAuth,
	"JAVA-XSS":        owaspInjection,
	"JAVA-PATH":       owaspAccess,
	"GO-CMD":          owaspInjection,
	"GO-SQLI":         owaspInjection,
	"GO-WEAKRAND":     owaspCrypto,
	"GO-SECRET":       owaspAuth,
	"GO-TLS":          owaspCrypto,
	"GO-HASH":         owaspCrypto,
	"GO-TEMPLATE":     owaspInjection,
	"TS-EVAL":         owaspInjection,
	"TS-INNERHTML":    owaspInjection,
	"TS-SQLI":         owaspInjection,
	"TS-CMD":          owaspInjection,
	"TS-WEAKRAND":     owaspCrypto,
	"TS-SECRET":       owaspAuth,
	"TS-JWT":          owaspAuth,
	"TS-REDIRECT":     owaspAccess,
	"GEN-AWSKEY":      owaspAuth,
	"GEN-GCPKEY":      owaspAuth,
	"GEN-AZUREKEY":    owaspAuth,
	"GEN-GITHUBTOKEN": owaspAuth,
	"GEN-SLACKTOKEN":  owaspAuth,
	"GEN-ENTROPY":     owaspAuth,
}

// owaspOf 查规则 OWASP 映射（未登记返回空 → Finding/SARIF 省略该字段）。
func owaspOf(ruleID string) string { return ruleOWASP[ruleID] }

// au02Rules AU-02 扩展规则集：Java/Go/TS（各 ≥6 条）+ 云厂商 key 前缀。
var au02Rules = []rule{
	// ---- Java ----
	mustRule("JAVA-SQLI", "high", "java", "SQL 语句拼接（SQL 注入）",
		`\b(?:executeQuery|executeUpdate|execute)\s*\(\s*"[^"]*(?:select|insert|update|delete)[^"]*"\s*\+`,
		"改用 PreparedStatement 参数绑定（?），禁止拼接 SQL"),
	mustRule("JAVA-DESER", "high", "java", "Java 原生反序列化（ObjectInputStream）",
		`new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)`,
		"禁止反序列化不可信数据；改用 JSON 白名单反序列化"),
	mustRule("JAVA-CMD", "high", "java", "Runtime.exec/ProcessBuilder 命令执行",
		`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|new\s+ProcessBuilder\s*\(`,
		"参数白名单校验；优先使用 ProcessBuilder 参数列表而非 shell 字符串"),
	mustRule("JAVA-WEAKRAND", "medium", "java", "弱随机数（java.util.Random）",
		`new\s+Random\s*\(|\bMath\.random\s*\(`,
		"安全用途改 SecureRandom；令牌/密钥禁止用伪随机"),
	mustRule("JAVA-SECRET", "high", "java", "疑似硬编码密钥/口令",
		`(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\s*=\s*"[^"]{8,}"`,
		"凭据移入环境变量/密钥服务，代码不出现字面量"),
	mustRule("JAVA-XSS", "medium", "java", "响应输出未转义（XSS）",
		`getWriter\s*\(\s*\)\s*\.(?:print|write|println)\s*\(|\.print(?:ln)?\s*\(\s*request\.getParameter`,
		"输出编码（ESAPI/AntiSamy）或模板引擎自动转义"),
	mustRule("JAVA-PATH", "medium", "java", "路径拼接用户输入（路径穿越）",
		`new\s+File\s*\(\s*request\.getParameter|Paths\.get\s*\(\s*request\.getParameter`,
		"规范化后校验前缀，拒绝 .. 与绝对路径"),

	// ---- Go ----
	mustRule("GO-CMD", "high", "go", "exec.Command 调用 shell（命令注入）",
		`exec\.Command\s*\(\s*"(?:/bin/)?(?:sh|bash|cmd(?:\.exe)?)"`,
		"避免 shell -c 拼接；使用参数列表并白名单校验"),
	mustRule("GO-SQLI", "high", "go", "fmt.Sprintf 拼 SQL（SQL 注入）",
		`(?:db|tx|conn)\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*fmt\.Sprintf\s*\(\s*"(?:select|insert|update|delete)`,
		"使用占位符参数（?/$1），禁止 fmt.Sprintf 拼 SQL"),
	mustRule("GO-WEAKRAND", "medium", "go", "math/rand 用于安全场景（弱随机）",
		`\brand\.(?:Intn|Int63|Int31|Float64|Read)\s*\(`,
		"令牌/密钥类用途改 crypto/rand"),
	mustRule("GO-SECRET", "high", "go", "疑似硬编码密钥/口令",
		`(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token)\s*:?=\s*"[^"]{8,}"`,
		"凭据移入环境变量/密钥服务，代码不出现字面量"),
	mustRule("GO-TLS", "high", "go", "TLS 证书校验被关闭（InsecureSkipVerify）",
		`InsecureSkipVerify\s*:\s*true`,
		"禁止跳过证书校验；测试环境用自定义 CA"),
	mustRule("GO-HASH", "medium", "go", "弱哈希 MD5/SHA1",
		`\b(?:md5|sha1)\.(?:New|Sum)\s*\(`,
		"口令存储改 bcrypt/argon2；完整性校验改 SHA-256"),
	mustRule("GO-TEMPLATE", "high", "go", "template.HTML 等绕过自动转义（XSS）",
		`\btemplate\.(?:HTML|JS|URL|CSS|HTMLAttr)\s*\(`,
		"避免 template.HTML 包裹不可信输入；插入前先消毒"),

	// ---- TypeScript（tsx 归一到 ts） ----
	mustRule("TS-EVAL", "high", "ts", "eval/new Function 动态执行",
		`\beval\s*\(|new\s+Function\s*\(`,
		"改 JSON.parse 或显式逻辑，eval 是 XSS 注入终点"),
	mustRule("TS-INNERHTML", "medium", "ts", "innerHTML/dangerouslySetInnerHTML（XSS）",
		`\.innerHTML\s*=|dangerouslySetInnerHTML`,
		"改 textContent；必须插入 HTML 时先做消毒（DOMPurify）"),
	mustRule("TS-SQLI", "high", "ts", "模板字符串拼 SQL（SQL 注入）",
		"(?:query|execute|exec)\\s*\\(\\s*`(?:select|insert|update|delete)[^`]*\\$\\{",
		"使用参数化查询，禁止模板字符串拼 SQL"),
	mustRule("TS-CMD", "high", "ts", "child_process 拼接命令（命令注入）",
		`(?:execSync|exec)\s*\(\s*(?:`+"`"+`|[^)]*\+)`,
		"用 execFile/spawn 参数列表 + 白名单，禁止字符串拼接命令"),
	mustRule("TS-WEAKRAND", "medium", "ts", "弱随机（Math.random）",
		`Math\.random\s*\(`,
		"安全用途改 crypto.getRandomValues / crypto.randomBytes"),
	mustRule("TS-SECRET", "high", "ts", "前端疑似硬编码密钥",
		`(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`,
		"前端密钥天然泄露，改服务端代理"),
	mustRule("TS-JWT", "medium", "ts", "JWT 使用弱/字面量密钥",
		`jwt\.(?:sign|verify)\s*\([^)]*['"][^'"]{1,12}['"]`,
		"密钥从环境/密钥服务读取，长度 ≥32 字节"),
	mustRule("TS-REDIRECT", "medium", "ts", "开放重定向（用户输入直接跳转）",
		`res\.redirect\s*\(\s*req\.(?:query|params|body)`,
		"跳转目标白名单校验，禁止直接使用请求参数"),

	// ---- 密钥前缀（云厂商 / 代码托管 / IM token）----
	mustRule("GEN-AWSKEY", "high", "*", "疑似 AWS Access Key",
		`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`,
		"立即吊销并轮换；改用 IAM 角色/密钥服务"),
	mustRule("GEN-GCPKEY", "high", "*", "疑似 GCP API Key",
		`\bAIza[0-9A-Za-z_\-]{35}\b`,
		"立即吊销并轮换；API Key 限定来源/接口"),
	mustRule("GEN-AZUREKEY", "high", "*", "疑似 Azure 存储密钥/连接串",
		`AccountKey\s*=\s*[A-Za-z0-9+/=]{40,}|DefaultEndpointsProtocol=https?;AccountName=`,
		"立即轮换存储密钥；改用托管身份/临时 SAS"),
	mustRule("GEN-GITHUBTOKEN", "high", "*", "疑似 GitHub Token",
		`\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b`,
		"立即吊销并轮换；改用细粒度 token/App 安装令牌"),
	mustRule("GEN-SLACKTOKEN", "high", "*", "疑似 Slack Token",
		`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`,
		"立即吊销并轮换；改用 OAuth 安装令牌最小权限"),
}

// entropyRe 高熵密钥候选：常见密钥键名 + 字符串字面量（取字面量算熵）。
// 只取「键名=值」形态，避免把正文/哈希常量大面积误报。
var entropyRe = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]([^'"]{12,})['"]`)

// entropyMinLen 参与熵判定的字面量最小长度。
const entropyMinLen = 16

// entropyThreshold 高熵阈值（bit/byte）：随机 ASCII 密钥通常 ≥3.5；
// 自然语言/占位符（changeme/example/xxx）通常远低于此值。
const entropyThreshold = 3.5

// placeholderWords 常见占位符：即使长度够也不算真实密钥。
var placeholderWords = []string{
	"example", "changeme", "change-me", "your_", "your-", "placeholder",
	"dummy", "sample", "test123", "xxx", "<", "***", "replace",
}

// shannonEntropy 香农熵（bit/byte）。
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// scanHighEntropySecret 行级高熵密钥检测（GEN-ENTROPY）。
// 返回命中键名与字面量长度（不返回值本身：报告/Match 不二次泄露密钥）。
// 纯字母/数字混排且熵 ≥ entropyThreshold 才报；含明确占位符词的跳过。
func scanHighEntropySecret(line string) (key string, ok bool) {
	m := entropyRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	val := m[2]
	if len(val) < entropyMinLen {
		return "", false
	}
	low := strings.ToLower(val)
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return "", false
		}
	}
	if shannonEntropy(val) < entropyThreshold {
		return "", false
	}
	return m[1], true
}
