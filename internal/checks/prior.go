// prior.go 5.0 深度融合的 check 调度先验（开发文档-5.0-ML预训练.md §10.6）：
// 前置通道 = cve-tech 产品先验把相关 check 提到队列前段；中段通道 =
// check 命中后同家族姊妹 check 联动提前。铁律：只调序、只增量纳入
// （低档位纳入由引擎把扩展集 id 拼进 includeIDs 实现），绝不从执行集
// 剔除任何 check——ML 只增不删，4.0 的判定语义原样保留。
package checks

import (
	"strings"
	"sync/atomic"
)

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

// normTechKey 归一指纹技术名/映射 key：小写、仅保留字母数字。
// 与引擎 mlNorm 同口径（"Apache Tomcat" → "apachetomcat"、
// "http_server" → "httpserver"），保证两条先验通道语义一致。
func normTechKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MLProductTechMatch 指纹技术名命中的产品映射项。
type MLProductTechMatch struct {
	Key string   // 映射表 key（wordpress / tomcat / php …）
	IDs []string // 相关 check id（与 MLProductChecks 同一张表）
}

// MLProductChecksForTech 检出技术名 → 相关 check（5.2 阶段 2 确定性指纹先验）。
//
// 与 MLProductChecks 共用同一张 mlProductChecks 映射表：指纹通道把
// "检出技术名" 当作产品类别串直接匹配，不经过 cve-tech 模型，因此
// 不需要加载 94MB 资产、也不会被站点正文的泛化词带偏。
// 归一后做包含匹配（"Apache Tomcat" ⊃ "tomcat"），无匹配返回 nil。
func MLProductChecksForTech(techName string) []MLProductTechMatch {
	n := normTechKey(techName)
	if n == "" {
		return nil
	}
	var out []MLProductTechMatch
	for _, m := range mlProductChecks {
		k := normTechKey(m.key)
		if k != "" && strings.Contains(n, k) {
			out = append(out, MLProductTechMatch{Key: m.key, IDs: m.ids})
		}
	}
	return out
}

// checkIndex 是 check id → Check 的只读快照，随插件集版本换代。
//
// BUG-013：原实现用 sync.Once 只建一次索引，ConfigurePlugins 热重载
// userPlugins 后从不失效 → 新投放的插件在 IsExtended 里永久 false，
// 引擎低档位增量纳入静默漏掉该 check（静默漏检）。现改为「插件集版本 +
// 原子快照」：ConfigurePlugins/RegisterPlugins 变更集合时推进 pluginGen，
// 读侧发现版本不符才重建（稳态读无锁）。
type checkIndexSnapshot struct {
	gen   int64
	index map[string]Check
}

var (
	pluginGen      atomic.Int64
	checkIndexSnap atomic.Pointer[checkIndexSnapshot]
)

// IsExtended check 是否扩展集（Lv1）——引擎低档位增量纳入的判断依据。
// 未收录的 id（nuclei 转换件等外部 check）返回 false。
func IsExtended(id string) bool {
	gen := pluginGen.Load()
	snap := checkIndexSnap.Load()
	if snap == nil || snap.gen != gen {
		built := map[string]Check{}
		for _, c := range AllChecks() {
			built[c.ID] = c
		}
		// gen 先于 AllChecks 读取：若构建期间插件集又变更，快照版本会
		// 落后于当前 pluginGen，下次调用自动重建，绝不会永久驻留旧集合。
		snap = &checkIndexSnapshot{gen: gen, index: built}
		checkIndexSnap.Store(snap)
	}
	c, ok := snap.index[id]
	return ok && c.Lv == 1
}
