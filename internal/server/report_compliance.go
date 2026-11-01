package server

// 合规评估报告（CP-07）：把一次扫描结果映射到合规框架条款，输出
// Markdown / HTML 两种自包含报告（HTML 白底、可直接打印为 PDF）。
//
// 设计约束：
//   - 纯函数：输入 store.ScanRecord 或 engine.Result，输出字符串；不读写文件、
//     不发起网络、不改全局状态（便于测试与后续路由接线）；
//   - 两套模板：等保 2.0（GB/T 22239-2019 三级）/ OWASP ASVS 4.0.3；
//   - 只做「探测结果 → 条款」的提示性映射：未命中某条款不等于合规（探测范围
//     本身有限），报告内显式声明，避免把扫描报告当合规证书；
//   - 所有动态内容都转义：HTML 用 html.EscapeString，Markdown 表格单元格
//     转义竖线并折叠换行；严重度只允许白名单枚举进入 class 位。

import (
	"errors"
	"fmt"
	"html"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// ComplianceFramework 合规框架标识。
type ComplianceFramework string

const (
	// FrameworkMLPS 等保 2.0（GB/T 22239-2019，按三级要求映射）。
	FrameworkMLPS ComplianceFramework = "mlps"
	// FrameworkASVS OWASP ASVS 4.0.3（按 Level 2 要求映射）。
	FrameworkASVS ComplianceFramework = "asvs"
)

// ComplianceFormat 报告输出格式。
type ComplianceFormat string

const (
	FormatMarkdown ComplianceFormat = "md"
	FormatHTML     ComplianceFormat = "html"
)

var (
	// ErrUnsupportedFramework 未知合规框架。
	ErrUnsupportedFramework = errors.New("server: 不支持的合规框架（支持 mlps/asvs）")
	// ErrUnsupportedFormat 未知报告格式。
	ErrUnsupportedFormat = errors.New("server: 不支持的合规报告格式（支持 md/html）")
)

// 条款符合性判定（导出常量便于调用方/测试稳定引用）。
const (
	ComplianceFail       = "不符合"
	CompliancePartial    = "部分符合"
	ComplianceObserve    = "观察项"
	ComplianceNotObserve = "未发现"
	ComplianceManual     = "人工复核"
)

// ComplianceControl 一条合规条款的映射模板（纯数据）。
//
// Checks 是 SiteLens 检测项名称（check 字段）的前缀匹配串（小写），用于把
// 已验证发现自动归到条款下；为空表示该类要求无法由本次扫描自动探测，
// 报告里标记「人工复核」而不是假装「未发现」。
type ComplianceControl struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Requirement string   `json:"requirement"`
	Advice      string   `json:"advice"`
	Checks      []string `json:"checks,omitempty"`
}

// mlpsControls 等保 2.0 三级条款映射模板。
var mlpsControls = []ComplianceControl{
	{
		ID: "8.1.2.1", Title: "身份鉴别",
		Requirement: "对登录用户进行身份标识与鉴别，口令具备复杂度并要求定期更换，登录失败应处理。",
		Advice:      "启用强口令策略与多因素认证；增加登录失败锁定与验证码；避免默认/弱口令。",
		Checks:      []string{"weak-login", "weak-basic", "sqli-auth", "default-cred", "captcha"},
	},
	{
		ID: "8.1.2.2", Title: "访问控制",
		Requirement: "按最小权限原则配置访问控制策略，默认账户权限受控，防止越权访问。",
		Advice:      "在服务端对每次请求做对象级鉴权；移除默认账户与目录列表；修复 403 绕过路径。",
		Checks:      []string{"authz", "dir-bypass", "api-unauth", "api-idor", "exposed-endpoint", "dir-listing"},
	},
	{
		ID: "8.1.2.3", Title: "安全审计",
		Requirement: "对重要用户行为与安全事件进行审计，审计记录受到保护并保留规定时长。",
		Advice:      "开启应用与中间件审计日志，集中留存并设置防篡改/告警（需人工核查日志面）。",
		Checks:      nil, // 无源侧探测点，只能人工复核
	},
	{
		ID: "8.1.3.1", Title: "通信传输",
		Requirement: "采用密码技术保证通信过程中数据的完整性与保密性，启用 HTTPS 与 HSTS。",
		Advice:      "全站启用 HTTPS 并配置 HSTS（含子域）；禁用弱协议/弱套件；证书及时续期。",
		Checks:      []string{"hsts", "tls", "cert", "transport"},
	},
	{
		ID: "8.1.3.4", Title: "数据保密性",
		Requirement: "采用密码技术保证重要数据在传输和存储过程中的保密性，会话标识不可预测。",
		Advice:      "会话 ID/随机标识使用密码学安全随机源；敏感页禁止共享缓存；敏感数据加密存储。",
		Checks:      []string{"weak-session", "weak-random", "crypto", "cacheable-sensitive", "weak-cookie"},
	},
	{
		ID: "8.1.3.5", Title: "数据完整性",
		Requirement: "保证重要数据在传输和存储过程中的完整性，防止未授权篡改。",
		Advice:      "校验关键数据完整性；修复响应拆分/注入类缺陷；对反序列化入口做类型白名单。",
		Checks:      []string{"crlf", "deser"},
	},
	{
		ID: "8.1.4.1", Title: "入侵防范",
		Requirement: "能够发现并阻断常见注入、跨站脚本、命令执行等入侵行为，最小化暴露面。",
		Advice:      "参数化查询、输出编码、命令/模板/表达式输入白名单；关闭不必要的服务与端口。",
		Checks:      []string{"sqli", "xss", "cmd-inject", "ssti", "xxe", "ssrf", "nosql", "ldap", "xpath", "log4j", "expression", "lfi", "open-redirect", "oob"},
	},
	{
		ID: "8.1.4.2", Title: "恶意代码防范",
		Requirement: "对上传文件与可执行内容进行检测与限制，防止 WebShell 等恶意代码落地。",
		Advice:      "上传做扩展名/内容类型/魔数多重校验并重命名存储；上传目录禁止脚本执行。",
		Checks:      []string{"upload", "webshell"},
	},
	{
		ID: "8.1.4.3", Title: "漏洞修补",
		Requirement: "及时修补已知漏洞，组件版本不应存在已公开且可被利用的高危缺陷。",
		Advice:      "对识别到的技术组件核对 CVE/KEV，升级到修复版本并建立补丁流程。",
		Checks:      []string{"cve", "intel"},
	},
	{
		ID: "8.1.4.4", Title: "安全加固",
		Requirement: "关闭不必要的服务与功能，配置安全响应头/安全策略，减少可利用面。",
		Advice:      "补齐 CSP/X-Frame-Options/X-Content-Type-Options 等响应头；关闭目录列表与错误回显。",
		Checks:      []string{"csp", "x-frame", "x-content-type", "referrer", "header", "misconfig", "csrf", "dir-listing", "cookie"},
	},
	{
		ID: "8.1.4.5", Title: "数据备份恢复",
		Requirement: "提供重要数据的本地/异地备份与恢复能力，并定期演练。",
		Advice:      "建立备份策略并定期恢复演练（需人工核查，扫描器无法验证）。",
		Checks:      nil,
	},
}

// asvsControls OWASP ASVS 4.0.3（Level 2）条款映射模板。
var asvsControls = []ComplianceControl{
	{
		ID: "V2.2.1", Title: "认证强度",
		Requirement: "口令策略具备长度/复杂度/泄露校验，防暴力破解与默认凭据。",
		Advice:      "启用强口令策略、失败锁定、MFA；清理默认账户与示例口令。",
		Checks:      []string{"weak-login", "weak-basic", "sqli-auth", "default-cred", "captcha"},
	},
	{
		ID: "V2.2.2", Title: "认证抗枚举",
		Requirement: "认证接口的错误信息不应泄露账号是否存在。",
		Advice:      "统一登录失败提示；对登录接口限速并加验证码。",
		Checks:      nil,
	},
	{
		ID: "V3.1.1", Title: "会话管理",
		Requirement: "会话标识具备足够熵、不可预测，Cookie 具备 HttpOnly/Secure/SameSite 属性。",
		Advice:      "使用服务端安全随机会话 ID；为敏感 Cookie 设置 HttpOnly/Secure/SameSite。",
		Checks:      []string{"weak-session", "weak-random", "weak-cookie", "cookie", "csrf"},
	},
	{
		ID: "V4.1.1", Title: "访问控制",
		Requirement: "服务端按最小权限强制访问控制，防止横向/纵向越权与直接对象引用。",
		Advice:      "对每个对象操作做服务端鉴权；修复 403 绕过与未授权 API 访问。",
		Checks:      []string{"authz", "dir-bypass", "api-unauth", "api-idor", "exposed-endpoint"},
	},
	{
		ID: "V5.3.4", Title: "注入防御",
		Requirement: "所有输入在进入解释器前做上下文相关的输出编码/参数化处理。",
		Advice:      "使用参数化查询与上下文输出编码；对命令/模板/表达式输入做白名单。",
		Checks:      []string{"sqli", "xss", "cmd-inject", "ssti", "xxe", "nosql", "ldap", "xpath", "log4j", "expression", "lfi", "crlf"},
	},
	{
		ID: "V5.2.1", Title: "反序列化安全",
		Requirement: "不可信数据反序列化前应做类型/签名校验，禁止原生反序列化入口。",
		Advice:      "禁用不可信数据的原生反序列化；使用白名单类型与签名校验。",
		Checks:      []string{"deser"},
	},
	{
		ID: "V5.4.1", Title: "SSRF 防护",
		Requirement: "服务端发起的请求应受目的地址白名单约束，禁止访问内网与元数据地址。",
		Advice:      "对出站地址做白名单/解析后校验；禁止跟随重定向到内网。",
		Checks:      []string{"ssrf", "oob"},
	},
	{
		ID: "V5.1.5", Title: "重定向校验",
		Requirement: "开放重定向参数必须校验为站内相对地址。",
		Advice:      "对跳转参数做站内白名单或相对路径校验。",
		Checks:      []string{"open-redirect"},
	},
	{
		ID: "V7.4.1", Title: "异常处理与日志",
		Requirement: "异常信息不应泄露内部细节，安全事件应记录审计日志。",
		Advice:      "关闭详细报错回显；集中记录安全事件并设置告警（日志面需人工核查）。",
		Checks:      []string{"sqli-error", "error"},
	},
	{
		ID: "V9.1.1", Title: "通信安全",
		Requirement: "仅通过 TLS 提供访问，启用 HSTS，禁用弱协议/弱套件。",
		Advice:      "全站 HTTPS + HSTS；升级 TLS 配置并定期检查证书。",
		Checks:      []string{"hsts", "tls", "cert"},
	},
	{
		ID: "V12.1.1", Title: "文件上传",
		Requirement: "上传文件应校验类型与内容，存储位置不可执行脚本。",
		Advice:      "多重校验扩展名/内容类型/魔数；上传目录禁执行并随机化文件名。",
		Checks:      []string{"upload", "webshell"},
	},
	{
		ID: "V14.2.1", Title: "依赖组件",
		Requirement: "第三方组件应为受支持版本且无已知高危漏洞。",
		Advice:      "建立组件清单（SBOM）与补丁流程；对 CVE/KEV 命中项优先升级。",
		Checks:      []string{"cve", "intel"},
	},
	{
		ID: "V14.3.1", Title: "安全配置",
		Requirement: "生产环境关闭调试/示例功能，配置安全响应头与最小化暴露面。",
		Advice:      "补齐 CSP/X-Frame-Options 等响应头；关闭目录列表与默认页面。",
		Checks:      []string{"csp", "x-frame", "header", "misconfig", "dir-listing", "cacheable-sensitive"},
	},
}

// ComplianceControls 返回指定框架的条款映射模板（深拷贝，调用方可安全修改）。
func ComplianceControls(fw ComplianceFramework) ([]ComplianceControl, error) {
	var src []ComplianceControl
	switch fw {
	case FrameworkMLPS:
		src = mlpsControls
	case FrameworkASVS:
		src = asvsControls
	default:
		return nil, ErrUnsupportedFramework
	}
	out := make([]ComplianceControl, len(src))
	for i, c := range src {
		out[i] = c
		out[i].Checks = append([]string(nil), c.Checks...)
	}
	return out, nil
}

// complianceFrameworkLabel 框架展示名。
func complianceFrameworkLabel(fw ComplianceFramework) string {
	switch fw {
	case FrameworkMLPS:
		return "等保 2.0（GB/T 22239-2019 三级）"
	case FrameworkASVS:
		return "OWASP ASVS 4.0.3（Level 2）"
	}
	return string(fw)
}

// complianceSeverityOrder 严重度分组/排序顺序（高 → 低）。
var complianceSeverityOrder = []string{"critical", "high", "medium", "low", "info"}

// complianceSeverityZh 严重度中文名。
var complianceSeverityZh = map[string]string{
	"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息",
}

// complianceSeverity 归一化严重度：未知值降级为 info（展示与排序都安全）。
func complianceSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func complianceSeverityRank(sev string) int {
	sev = complianceSeverity(sev)
	for i, s := range complianceSeverityOrder {
		if s == sev {
			return i
		}
	}
	return len(complianceSeverityOrder)
}

// complianceFinding 报告中的一个发现（已归一化严重度）。
type complianceFinding struct {
	Severity string
	Title    string
	URL      string
	Check    string
	Advice   string
	Source   string
}

// complianceFindings 从扫描结果收集发现：已验证项（归并去重）+ 配置卫生 +
// 情报关联（CVE），全部归一化严重度后按（严重度, 标题, 检测项）稳定排序。
func complianceFindings(res *engine.Result) []complianceFinding {
	if res == nil {
		return nil
	}
	var out []complianceFinding
	for _, g := range mergeVerified(res.Verified) {
		srcs := make([]string, 0, len(g.Srcs))
		for s := range g.Srcs {
			srcs = append(srcs, srcLabel(s))
		}
		sort.Strings(srcs)
		u := ""
		if len(g.URLs) > 0 {
			u = g.URLs[0]
		}
		out = append(out, complianceFinding{
			Severity: complianceSeverity(g.Severity),
			Title:    g.Title,
			URL:      u,
			Check:    g.Check,
			Advice:   g.Advice,
			Source:   strings.Join(srcs, " / "),
		})
	}
	// 配置卫生（extras.hygiene）：配置事实，按同一套严重度归组并注明来源。
	// 历史记录经 JSON 反序列化后是 []any，内存结果直接是 []map[string]any，
	// 两种形态都要兼容（否则线上导出会丢整块卫生项）。
	for _, v := range hygieneFindings(res.Extras) {
		out = append(out, complianceFinding{
			Severity: complianceSeverity(strOf(v["severity"])),
			Title:    strOf(v["title"]),
			URL:      strOf(v["url"]),
			Check:    strOf(v["check"]),
			Advice:   strOf(v["advice"]),
			Source:   "配置卫生",
		})
	}
	// 情报关联（CVE）：归入「漏洞修补 / 依赖组件」类条款。
	for _, v := range res.Vulnerabilities {
		title := v.Name
		if title == "" {
			title = v.Title
		}
		if title == "" {
			title = v.CVE
		}
		out = append(out, complianceFinding{
			Severity: complianceSeverity(v.Severity),
			Title:    title,
			URL:      res.URL,
			Check:    "cve-intel",
			Advice:   "升级受影响组件至修复版本，并跟踪 KEV/威胁情报更新。",
			Source: "漏洞情报" + func() string {
				if v.CVE != "" {
					return "（" + v.CVE + "）"
				}
				return ""
			}(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := complianceSeverityRank(out[i].Severity), complianceSeverityRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// strOf 安全的 map 值转字符串（缺失/类型不符返回空串）。
func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// hygieneFindings 取 extras.hygiene 列表，兼容内存态 []map[string]any 与
// 历史记录 JSON 反序列化后的 []any 两种形态。
func hygieneFindings(extras map[string]any) []map[string]any {
	if extras == nil {
		return nil
	}
	switch v := extras["hygiene"].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// controlEval 一条条款的评估结果。
type controlEval struct {
	Control  ComplianceControl
	Findings []complianceFinding
	Status   string
}

// checkMatched finding 的检测项是否命中条款的任一前缀。
func checkMatched(check string, patterns []string) bool {
	check = strings.ToLower(strings.TrimSpace(check))
	if check == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && strings.HasPrefix(check, p) {
			return true
		}
	}
	return false
}

// evalControls 把发现按条款映射并计算符合性判定（确定性：条款顺序取自模板）。
func evalControls(controls []ComplianceControl, findings []complianceFinding) []controlEval {
	out := make([]controlEval, 0, len(controls))
	for _, c := range controls {
		ev := controlEval{Control: c}
		if len(c.Checks) == 0 {
			ev.Status = ComplianceManual
			out = append(out, ev)
			continue
		}
		for _, f := range findings {
			if checkMatched(f.Check, c.Checks) {
				ev.Findings = append(ev.Findings, f)
			}
		}
		switch {
		case len(ev.Findings) == 0:
			ev.Status = ComplianceNotObserve
		default:
			worst := "info"
			for _, f := range ev.Findings {
				if complianceSeverityRank(f.Severity) < complianceSeverityRank(worst) {
					worst = f.Severity
				}
			}
			switch worst {
			case "critical", "high":
				ev.Status = ComplianceFail
			case "medium", "low":
				ev.Status = CompliancePartial
			default:
				ev.Status = ComplianceObserve
			}
		}
		out = append(out, ev)
	}
	return out
}

// complianceReportData 渲染所需的完整中间模型（Markdown/HTML 共用）。
type complianceReportData struct {
	Framework     ComplianceFramework
	FrameworkName string
	URL           string
	Host          string
	Title         string
	ScannedAt     string
	Duration      float64
	Status        int
	Grade         string
	Score         int
	NoResult      bool
	Findings      []complianceFinding
	SeverityCount map[string]int
	Controls      []controlEval
}

// buildComplianceData 汇总报告模型（纯函数）。
func buildComplianceData(res *engine.Result, meta complianceMeta, fw ComplianceFramework) (*complianceReportData, error) {
	controls, err := ComplianceControls(fw)
	if err != nil {
		return nil, err
	}
	d := &complianceReportData{
		Framework:     fw,
		FrameworkName: complianceFrameworkLabel(fw),
		URL:           meta.URL,
		Host:          meta.Host,
		Title:         meta.Title,
		ScannedAt:     meta.ScannedAt,
		Duration:      meta.Duration,
		Status:        meta.Status,
		Grade:         meta.Grade,
		Score:         meta.Score,
		NoResult:      res == nil,
		SeverityCount: map[string]int{},
	}
	if res != nil {
		if d.URL == "" {
			d.URL = res.URL
		}
		if d.Host == "" {
			d.Host = res.Host
		}
		if d.Title == "" {
			d.Title = res.Title
		}
		if d.ScannedAt == "" {
			d.ScannedAt = res.ScannedAt
		}
		if d.Duration == 0 {
			d.Duration = res.Duration
		}
		if d.Status == 0 {
			d.Status = res.Status
		}
		if res.Security != nil {
			d.Grade = res.Security.Grade
			d.Score = res.Security.Score
		}
		d.Findings = complianceFindings(res)
	}
	for _, s := range complianceSeverityOrder {
		d.SeverityCount[s] = 0
	}
	for _, f := range d.Findings {
		d.SeverityCount[f.Severity]++
	}
	d.Controls = evalControls(controls, d.Findings)
	return d, nil
}

// complianceMeta 报告头部元数据（来自 ScanRecord 摘要；为空时从 Result 补齐）。
type complianceMeta struct {
	URL       string
	Host      string
	Title     string
	ScannedAt string
	Duration  float64
	Status    int
	Grade     string
	Score     int
}

// RenderCompliance 渲染一次扫描的合规评估报告（Markdown/HTML）。
//
// rec 可为空（表示历史记录缺少结果）；rec.Result 为 nil 时输出条款模板与
// 「无详细扫描结果」说明，仍是一份完整可读的报告。
func RenderCompliance(rec *store.ScanRecord, fw ComplianceFramework, format ComplianceFormat) (string, error) {
	if _, err := ComplianceControls(fw); err != nil {
		return "", err
	}
	var res *engine.Result
	meta := complianceMeta{}
	if rec != nil {
		meta = complianceMeta{
			URL: rec.URL, Host: rec.Host, Title: rec.Title,
			ScannedAt: rec.ScannedAt, Duration: rec.Duration,
			Status: rec.Status, Grade: rec.SecurityGrade, Score: rec.SecurityScore,
		}
		res = rec.Result
	}
	return renderComplianceReport(res, meta, fw, format)
}

// RenderComplianceResult 直接以 engine.Result 渲染合规报告（无历史记录时用；
// 元数据从 Result 自身取）。
func RenderComplianceResult(res *engine.Result, fw ComplianceFramework, format ComplianceFormat) (string, error) {
	if _, err := ComplianceControls(fw); err != nil {
		return "", err
	}
	return renderComplianceReport(res, complianceMeta{}, fw, format)
}

// renderComplianceReport 统一渲染入口。
func renderComplianceReport(res *engine.Result, meta complianceMeta, fw ComplianceFramework, format ComplianceFormat) (string, error) {
	d, err := buildComplianceData(res, meta, fw)
	if err != nil {
		return "", err
	}
	switch format {
	case FormatMarkdown:
		return renderComplianceMarkdown(d), nil
	case FormatHTML:
		return renderComplianceHTML(d), nil
	default:
		return "", ErrUnsupportedFormat
	}
}

// compMDCell Markdown 表格单元格转义：竖线断列、换行断行、尖括号可能被当
// HTML 渲染——全部收敛为安全文本。
func compMDCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// compMDText 非表格正文的 Markdown 文本转义（同样屏蔽 HTML 标签）。
func compMDText(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// renderComplianceMarkdown 生成 Markdown 报告。
func renderComplianceMarkdown(d *complianceReportData) string {
	var b strings.Builder
	b.WriteString("# 合规评估报告 · " + compMDText(d.FrameworkName) + "\n\n")
	b.WriteString("- 目标：" + compMDCell(d.URL) + "（" + compMDCell(d.Host) + "）\n")
	if d.Title != "" {
		b.WriteString("- 标题：" + compMDCell(d.Title) + "\n")
	}
	if d.ScannedAt != "" {
		b.WriteString("- 扫描时间：" + compMDCell(d.ScannedAt) + "\n")
	}
	if d.Duration > 0 {
		b.WriteString("- 扫描耗时：" + fmt.Sprintf("%.2fs", d.Duration) + "\n")
	}
	if d.Grade != "" || d.Score > 0 {
		b.WriteString("- 安全评分：" + compMDCell(d.Grade) + "（" + fmt.Sprintf("%d", d.Score) + " 分）\n")
	}
	b.WriteString("- 报告框架：" + compMDCell(d.FrameworkName) + "\n\n")
	b.WriteString("> 本报告由 SiteLens " + Version + " 生成。条款映射是辅助自查线索，不构成合规认证结论；" +
		"未命中条款不代表合规（探测范围有限），请结合人工核查。\n\n")

	if d.NoResult {
		b.WriteString("> 无详细扫描结果：本记录缺少引擎结果（可能未完成或为历史摘要），" +
			"以下仅列出条款模板与待核查项。\n\n")
	}

	// 风险概览（按严重度）
	b.WriteString("## 风险概览\n\n")
	b.WriteString("| 严重度 | 数量 |\n|---|---|\n")
	for _, s := range complianceSeverityOrder {
		b.WriteString("| " + complianceSeverityZh[s] + "（" + s + "） | " + fmt.Sprintf("%d", d.SeverityCount[s]) + " |\n")
	}
	b.WriteString("\n")

	// 发现（按严重度分组）
	b.WriteString("## 发现（按严重度分组）\n\n")
	if len(d.Findings) == 0 {
		b.WriteString("本次扫描未产生已验证发现。\n\n")
	} else {
		for _, sev := range complianceSeverityOrder {
			group := make([]complianceFinding, 0)
			for _, f := range d.Findings {
				if f.Severity == sev {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			b.WriteString("### " + complianceSeverityZh[sev] + "（" + sev + "，" + fmt.Sprintf("%d", len(group)) + " 项）\n\n")
			b.WriteString("| # | 检测项 | 标题 | 位置 | 来源 | 整改建议 |\n|---|---|---|---|---|---|\n")
			for i, f := range group {
				b.WriteString("| " + fmt.Sprintf("%d", i+1) +
					" | " + compMDCell(f.Check) +
					" | " + compMDCell(f.Title) +
					" | " + compMDCell(f.URL) +
					" | " + compMDCell(f.Source) +
					" | " + compMDCell(f.Advice) + " |\n")
			}
			b.WriteString("\n")
		}
	}

	// 合规条款映射表
	b.WriteString("## 合规条款映射（" + compMDText(d.FrameworkName) + "）\n\n")
	b.WriteString("| 条款 | 条款名称 | 要求摘要 | 关联发现数 | 符合性判定 | 整改建议 |\n|---|---|---|---|---|---|\n")
	for _, ev := range d.Controls {
		b.WriteString("| " + compMDCell(ev.Control.ID) +
			" | " + compMDCell(ev.Control.Title) +
			" | " + compMDCell(ev.Control.Requirement) +
			" | " + fmt.Sprintf("%d", len(ev.Findings)) +
			" | " + compMDCell(ev.Status) +
			" | " + compMDCell(ev.Control.Advice) + " |\n")
	}
	b.WriteString("\n")

	b.WriteString("## 覆盖与限制\n\n")
	b.WriteString("- 条款判定基于本次扫描产生的已验证发现与情报关联结果；未探测到的条款标记「未发现」，" +
		"不代表实际合规。\n")
	b.WriteString("- 标记「人工复核」的条款（如审计、备份）无法由扫描器验证，需人工检查配置与流程。\n")
	b.WriteString("- 发现为辅助人工复查线索，非最终判决；修复后建议复测并更新合规证据。\n")
	return b.String()
}

// renderComplianceHTML 生成自包含 HTML 报告（白底、可直接打印）。
func renderComplianceHTML(d *complianceReportData) string {
	var b strings.Builder
	esc := html.EscapeString
	b.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>合规评估报告 - " + esc(d.Host) + "</title><style>")
	b.WriteString(":root{color-scheme:light}")
	b.WriteString("body{background:#fff;color:#1f2937;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:1100px;margin:24px auto;padding:0 18px;line-height:1.55}")
	b.WriteString("h1{font-size:24px;margin:0 0 12px}h2{font-size:19px;margin:28px 0 10px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}")
	b.WriteString("h3{font-size:16px;margin:18px 0 8px}")
	b.WriteString("table{border-collapse:collapse;width:100%;margin:8px 0 20px}th,td{border:1px solid #d1d5db;padding:6px 9px;text-align:left;font-size:13px;vertical-align:top}")
	b.WriteString("th{background:#f3f4f6;font-weight:600}tbody tr:nth-child(even){background:#fafafa}")
	b.WriteString(".meta{color:#374151;font-size:13px}.muted{color:#6b7280;font-size:12px}")
	b.WriteString(".sev-critical{color:#b91c1c;font-weight:700}.sev-high{color:#dc2626;font-weight:600}")
	b.WriteString(".sev-medium{color:#b45309}.sev-low{color:#1d4ed8}.sev-info{color:#4b5563}")
	b.WriteString(".status-fail{color:#b91c1c;font-weight:700}.status-partial{color:#b45309;font-weight:600}")
	b.WriteString(".status-manual{color:#6b7280}.status-none{color:#047857}")
	b.WriteString(".notice{border-left:4px solid #f59e0b;background:#fffbeb;padding:8px 12px;margin:12px 0;font-size:13px}")
	b.WriteString("@media print{body{margin:0;max-width:none;padding:0 8mm}table{page-break-inside:auto}tr{page-break-inside:avoid}}")
	b.WriteString("</style></head><body>")

	b.WriteString("<h1>合规评估报告 · " + esc(d.FrameworkName) + "</h1>")
	b.WriteString("<p class=\"meta\">目标：<strong>" + esc(d.URL) + "</strong>（" + esc(d.Host) + "）")
	if d.Title != "" {
		b.WriteString(" ｜ 标题：" + esc(d.Title))
	}
	if d.ScannedAt != "" {
		b.WriteString(" ｜ 扫描时间：" + esc(d.ScannedAt))
	}
	if d.Duration > 0 {
		b.WriteString(" ｜ 耗时：" + fmt.Sprintf("%.2fs", d.Duration))
	}
	if d.Grade != "" || d.Score > 0 {
		b.WriteString(" ｜ 安全评分：" + esc(d.Grade) + "（" + fmt.Sprintf("%d", d.Score) + " 分）")
	}
	b.WriteString("</p>")
	b.WriteString("<p class=\"muted\">由 SiteLens " + esc(Version) + " 生成。条款映射是辅助自查线索，不构成合规认证结论；" +
		"未命中条款不代表合规（探测范围有限），请结合人工核查。</p>")
	if d.NoResult {
		b.WriteString("<p class=\"notice\">无详细扫描结果：本记录缺少引擎结果（可能未完成或为历史摘要），以下仅列出条款模板与待核查项。</p>")
	}

	// 风险概览
	b.WriteString("<h2>风险概览</h2><table><thead><tr><th>严重度</th><th>数量</th></tr></thead><tbody>")
	for _, s := range complianceSeverityOrder {
		b.WriteString("<tr><td class=\"sev-" + sevClass(s) + "\">" + esc(complianceSeverityZh[s]) + "（" + esc(s) + "）</td><td>" +
			fmt.Sprintf("%d", d.SeverityCount[s]) + "</td></tr>")
	}
	b.WriteString("</tbody></table>")

	// 发现（按严重度分组）
	b.WriteString("<h2>发现（按严重度分组）</h2>")
	if len(d.Findings) == 0 {
		b.WriteString("<p>本次扫描未产生已验证发现。</p>")
	} else {
		for _, sev := range complianceSeverityOrder {
			group := make([]complianceFinding, 0)
			for _, f := range d.Findings {
				if f.Severity == sev {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			b.WriteString("<h3 class=\"sev-" + sevClass(sev) + "\">" + esc(complianceSeverityZh[sev]) +
				"（" + esc(sev) + "，" + fmt.Sprintf("%d", len(group)) + " 项）</h3>")
			b.WriteString("<table><thead><tr><th>#</th><th>检测项</th><th>标题</th><th>位置</th><th>来源</th><th>整改建议</th></tr></thead><tbody>")
			for i, f := range group {
				b.WriteString("<tr><td>" + fmt.Sprintf("%d", i+1) + "</td><td>" + esc(f.Check) + "</td><td>" +
					esc(f.Title) + "</td><td>" + esc(f.URL) + "</td><td>" + esc(f.Source) + "</td><td>" +
					esc(f.Advice) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
	}

	// 合规条款映射表
	b.WriteString("<h2>合规条款映射（" + esc(d.FrameworkName) + "）</h2>")
	b.WriteString("<table><thead><tr><th>条款</th><th>条款名称</th><th>要求摘要</th><th>关联发现数</th><th>符合性判定</th><th>整改建议</th></tr></thead><tbody>")
	for _, ev := range d.Controls {
		b.WriteString("<tr><td>" + esc(ev.Control.ID) + "</td><td>" + esc(ev.Control.Title) + "</td><td>" +
			esc(ev.Control.Requirement) + "</td><td>" + fmt.Sprintf("%d", len(ev.Findings)) +
			"</td><td class=\"" + complianceStatusClass(ev.Status) + "\">" + esc(ev.Status) + "</td><td>" +
			esc(ev.Control.Advice) + "</td></tr>")
	}
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>覆盖与限制</h2><ul>")
	b.WriteString("<li>条款判定基于本次扫描产生的已验证发现与情报关联结果；未探测到的条款标记「未发现」，不代表实际合规。</li>")
	b.WriteString("<li>标记「人工复核」的条款（如审计、备份）无法由扫描器验证，需人工检查配置与流程。</li>")
	b.WriteString("<li>发现为辅助人工复查线索，非最终判决；修复后建议复测并更新合规证据。</li>")
	b.WriteString("</ul>")
	b.WriteString("</body></html>")
	return b.String()
}

// complianceStatusClass 判定状态的 CSS class（白名单，不拼接外部字符串）。
func complianceStatusClass(status string) string {
	switch status {
	case ComplianceFail:
		return "status-fail"
	case CompliancePartial:
		return "status-partial"
	case ComplianceManual:
		return "status-manual"
	default:
		return "status-none"
	}
}
