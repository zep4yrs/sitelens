// 技术名 → 模板 tag 归一：把指纹识别出的技术名展开成"网络上真的存在的
// 那几种 tag 写法"。
//
// 为什么需要：调度侧此前只做 `tags[strings.ToLower(t.Name)]` 的精确比对，
// 而指纹库里的技术名是显示名（`Microsoft IIS`、`Apache Tomcat`、
// `Oracle WebLogic Server`），模板 tag 是 slug（`iis`、`tomcat`、
// `weblogic`）——**两侧从来没有归一过**，于是 tag 这一路（Select 的第一
// 优先级）对绝大多数技术都空转，预算全落到 LRU 轮转上。
//
// 归一规则只做可证的机械变换，不做"产品联想"：
//  1. 全名小写；
//  2. 去常见厂商/形态前缀（microsoft/google/oracle/apache/…）；
//  3. 去形态后缀（server/service/platform/engine/…）；
//  4. 剩余词的连写（apachetomcat → 无意义）不生成——宁少不猜；
//  5. 全名连写（microsoftiis）也不生成，模板生态里不存在这种 tag。
//
// 每个技术的候选集里至少含「小写全名」（保持既有行为不变）。
package nuclei

import "strings"

// techVendorPrefixes 厂商 / 组织前缀（显示名首词常见，模板 tag 不带）。
var techVendorPrefixes = map[string]bool{
	"microsoft": true, "google": true, "oracle": true, "apache": true,
	"ibm": true, "cisco": true, "adobe": true, "atlassian": true,
	"red": true, "hat": true, "amazon": true, "aws": true,
	"alibaba": true, "tencent": true, "huawei": true, "sap": true,
	"vmware": true, "citrix": true, "fortinet": true, "palo": true,
	"sonicwall": true, "juniper": true, "f5": true, "zoho": true,
	"admin": true, "open": true, "the": true,
}

// techFormSuffixes 形态 / 角色后缀（显示名末词常见，模板 tag 不带）。
var techFormSuffixes = map[string]bool{
	"server": true, "service": true, "services": true, "platform": true,
	"engine": true, "manager": true, "management": true, "console": true,
	"framework": true, "system": true, "software": true, "suite": true,
	"appliance": true, "gateway": true, "proxy": true, "client": true,
}

// techtagAliases 少数经人工核实的显示名 → tag 映射（前缀/后缀规则覆盖不到）。
// 只收录"同一个东西的两种写法"，不做产品联想——错映射会把别家模板跑在
// 无关目标上，宁可少收录。
var techtagAliases = map[string][]string{
	"microsoft iis":                 {"iis", "microsoft-iis"},
	"internet information services": {"iis"},
	"apache tomcat":                 {"tomcat", "apache-tomcat"},
	"apache httpd":                  {"apache", "httpd"},
	"apache http server":            {"apache", "httpd"},
	"nginx":                         {"nginx"},
	"oracle weblogic server":        {"weblogic", "oracle-weblogic"},
	"oracle database":               {"oracle", "oracle-db"},
	"spring boot":                   {"springboot", "spring-boot"},
	"spring framework":              {"spring"},
	"microsoft exchange server":     {"exchange", "owa"},
	"microsoft sharepoint":          {"sharepoint"},
	"microsoft sql server":          {"mssql", "sqlserver"},
	"jenkins ci":                    {"jenkins"},
	"gitlab":                        {"gitlab"},
	"github enterprise":             {"github"},
	"wordpress":                     {"wordpress", "wp"},
	"phpmyadmin":                    {"phpmyadmin"},
	"jira":                          {"jira", "atlassian-jira"},
	"confluence":                    {"confluence", "atlassian-confluence"},
	"elasticsearch":                 {"elasticsearch", "elastic"},
	"redis":                         {"redis"},
	"mongodb":                       {"mongodb", "mongo"},
	"grafana":                       {"grafana"},
	"kibana":                        {"kibana"},
	"docker registry":               {"docker-registry", "registry"},
	"kubernetes":                    {"kubernetes", "k8s"},
	"citrix netscaler":              {"citrix", "netscaler"},
	"f5 big-ip":                     {"f5", "bigip", "big-ip"},
	"fortinet fortigate":            {"fortinet", "fortigate"},
	"palo alto networks pan-os":     {"paloalto", "panos"},
}

// TechTags 技术名 → 模板 tag 候选集（含全名小写形态，永不为空）。
func TechTags(techName string) []string {
	name := strings.ToLower(strings.TrimSpace(techName))
	if name == "" {
		return nil
	}
	out := []string{name}
	seen := map[string]bool{name: true}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] || len(s) < 2 {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, a := range techtagAliases[name] {
		add(a)
	}

	// 前缀 / 后缀剥离（可剥多轮：Microsoft SQL Server → sql）
	words := strings.FieldsFunc(name, func(r rune) bool {
		return r == ' ' || r == '/' || r == '-' || r == '_'
	})
	for len(words) > 1 && techVendorPrefixes[words[0]] {
		words = words[1:]
		add(strings.Join(words, "-"))
		add(strings.Join(words, ""))
	}
	for len(words) > 1 && techFormSuffixes[words[len(words)-1]] {
		words = words[:len(words)-1]
		add(strings.Join(words, "-"))
		add(strings.Join(words, ""))
	}
	// 去前缀后的主体词本身也是常见 tag 写法（apache tomcat → tomcat）
	if len(words) > 0 {
		add(words[len(words)-1])
	}
	return out
}

// techTagSet 多技术 → tag 集合（供 Select 的 tag 硬匹配）。
func techTagSet(techNames []string) map[string]bool {
	set := map[string]bool{}
	for _, n := range techNames {
		for _, t := range TechTags(n) {
			set[t] = true
		}
	}
	return set
}

// TechTagSet 导出包装（引擎侧调用）。
func TechTagSet(techNames []string) map[string]bool { return techTagSet(techNames) }

// CountTagHits tag 硬匹配的模板条数（调度可见性：预算被匹配吃掉多少）。
func CountTagHits(entries []Entry, techTags map[string]bool) int {
	if len(techTags) == 0 {
		return 0
	}
	n := 0
	for _, e := range entries {
		for _, tg := range e.Tags {
			if techTags[tg] {
				n++
				break
			}
		}
	}
	return n
}

// SourceCounts 按来源目录统计模板条数（来源 = 路径首段；
// 官方 http 目录下取第二段类别名）。报告里用它看"预算花在哪来的模板上"。
func SourceCounts(entries []Entry) map[string]int {
	out := map[string]int{}
	for _, e := range entries {
		parts := strings.Split(strings.Trim(e.Path, "/"), "/")
		if len(parts) == 0 {
			continue
		}
		key := parts[0]
		if key == "http" && len(parts) > 1 {
			key = parts[1] // 官方/镜像目录：取类别名（exposures/cves/…）
		}
		// legacy/ 是历史语料根，其下类别混杂，统一记 "legacy" 不再细分
		out[key]++
	}
	return out
}
