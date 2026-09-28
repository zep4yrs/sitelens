// prior.go 5.0 深度融合的 check 调度先验（开发文档-5.0-ML预训练.md §10.6）：
// 前置通道 = cve-tech 产品先验把相关 check 提到队列前段；中段通道 =
// check 命中后同家族姊妹 check 联动提前。铁律：只调序、只增量纳入
// （低档位纳入由引擎把扩展集 id 拼进 includeIDs 实现），绝不从执行集
// 剔除任何 check——ML 只增不删，4.0 的判定语义原样保留。
package checks

import "strings"
import "sync"

// Prior check 调度先验：check id → 提权权重（0-1]，值越大越先执行。
// 仅影响执行顺序；nil 等价于空先验（严格清单序，与 4.0 行为一致）。
type Prior struct {
	Boost map[string]float64
}

// checkFamily check 家族表（中段联动提权的依据）：同一家族 = 同一技术
// 栈的姊妹 check——一条命中即抬高其余成员的命中先验。刻意收窄：只收录
// 有明确技术栈归属的家族，宁少联动不误联动。
var checkFamily = map[string]string{
	"git-leak": "git", "git-index": "git",
	"svn-leak": "vcs", "ds-store": "vcs",
	"bak-dump": "bak", "bak-site": "bak", "bak-config": "bak",
	"wp-users": "wp", "wp-xmlrpc": "wp", "wp-readme": "wp",
	"wp-json": "wp", "wp-login": "wp",
	"actuator": "spring", "actuator-env": "spring",
	"swagger": "spring", "api-docs": "spring",
	"joomla-admin": "cms-login", "drupal-login": "cms-login",
	"typecho-login": "cms-login", "tp-admin": "cms-login",
	"adminer": "dbadmin", "druid": "dbadmin",
}

// familyOf check 所属家族（无家族返回空串）。
func familyOf(id string) string { return checkFamily[id] }

// mlProductChecks cve-tech 产品类别（vendor/product）→ 相关 check。
// 键为对类别串小写后的包含匹配 needle；只收录 cve-tech 196 类里真实
// 存在、且引擎有对应 check 的产品（映射表随类别表穷举维护）。
var mlProductChecks = []struct {
	key string
	ids []string
}{
	{"wordpress", []string{"wp-users", "wp-xmlrpc", "wp-readme", "wp-json", "wp-login"}},
	{"joomla", []string{"joomla-admin"}},
	{"drupal", []string{"drupal-login"}},
	{"tomcat", []string{"tomcat-manager"}},
	{"http_server", []string{"server-status"}},
	{"subversion", []string{"svn-leak"}},
	{"phpmyadmin", []string{"adminer"}},
	{"php", []string{"adminer"}},
}

// MLProductChecks cve-tech 产品类别映射到的相关 check id（无匹配 nil）。
// 引擎深度融合前置通道使用：预测产品 → check 提权 + 低档位增量纳入。
func MLProductChecks(class string) []string {
	low := strings.ToLower(class)
	var out []string
	for _, m := range mlProductChecks {
		if strings.Contains(low, m.key) {
			out = append(out, m.ids...)
		}
	}
	return out
}

// checkIndex check id → Check（惰性建一次；AllChecks 含插件注入件）。
var (
	checkIndexOnce sync.Once
	checkIndex     map[string]Check
)

// IsExtended check 是否扩展集（Lv1）——引擎低档位增量纳入的判断依据。
// 未收录的 id（nuclei 转换件等外部 check）返回 false。
func IsExtended(id string) bool {
	checkIndexOnce.Do(func() {
		checkIndex = map[string]Check{}
		for _, c := range AllChecks() {
			checkIndex[c.ID] = c
		}
	})
	c, ok := checkIndex[id]
	return ok && c.Lv == 1
}
