package checks

// metaExtraOverride 第二轮复核补充的显式覆盖（规则未覆盖或易误归类的 check）。
// 与 metaOverride 合并生效（MetaOf 先查 metaOverride，再查本表）。
var metaExtraOverride = map[string]Meta{
	// 目录列举（文件结构暴露）
	"dev-site":     {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "开发目录可列（文件结构暴露）"},
	"old-site":     {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "旧站目录可列"},
	"test-site":    {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "测试目录可列"},
	"staging-site": {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "预发目录可列"},
	"tmp-dir":      {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "临时目录可列"},
	"uploads-dir":  {ATTACK: []string{"T1592", "T1082"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "上传目录可列"},

	// 系统/应用信息与组件指纹
	"ds-store":        {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: ".DS_Store 泄露目录结构"},
	"tomcat-examples": {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Tomcat 示例页暴露（组件指纹）"},
	"tpl-invalidate":  {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "AEM 缓存失效端点暴露（组件指纹）"},

	// CellPower 敏感信息暴露（上游模板多路径展开）
	"tpl-cellpower-agent-backend-info-exposure-p0":           {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p0-x880cdc83": {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p1":           {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p1-x60a3524e": {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p2":           {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p2-x6da3026c": {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p3":           {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},
	"tpl-cellpower-agent-backend-info-exposure-p3-x8c02f87":  {ATTACK: []string{"T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "CellPower 敏感信息暴露（只读探测）"},

	// 文件读取类 CVE（只读验证，读取本地文件内容）
	"tpl-cve-2019-14322-p0": {ATTACK: []string{"T1005"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Odoo LFI 文件读取（只读验证）"},
	"tpl-cve-2019-14322-p1": {ATTACK: []string{"T1005"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Odoo LFI 文件读取（只读验证）"},
	"tpl-cve-2019-14322-p2": {ATTACK: []string{"T1005"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Odoo LFI 文件读取（只读验证）"},
	"tpl-cve-2019-5418":     {ATTACK: []string{"T1005"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Rails 文件读取信息泄露（只读验证）"},
	"tpl-cve-2026-9282-r0":  {ATTACK: []string{"T1005"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "W3TC 任意文件读取（只读验证）"},
	"tpl-cve-2018-11409-p0": {ATTACK: []string{"T1005", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Splunk 敏感信息泄露（只读验证）"},
	"tpl-cve-2018-11409-p1": {ATTACK: []string{"T1005", "T1592"}, Noise: NoiseLow, Safety: SafetyReadOnly, Reason: "Splunk 敏感信息泄露（只读验证）"},
}
