// CP-10 接线：check id → 模板来源 的解析器 + 每来源通过率聚合入口。
//
// 背景：nuclei 模板转换出的 check id 形如 `nuclei-<templateID>`，多路径/多
// matcher 组会追加 `~pN`/`~gN` 后缀；原生 check（internal/checks 内置）没有
// 前缀。模板索引 Entry 记录了来源（NormalizeSource 口径），但索引不保存
// templateID，因此这里用「模板文件名（去扩展名）≈ templateID」对齐（官方库
// 绝大多数一致），对不上的模板记 unknown——宁可标 unknown 也不猜。
//
// 纯函数：不读文件、不发网络；SourceResolver 只在构造时扫描一遍 entries。
package nuclei

import (
	"path/filepath"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// check id 与来源标签常量（报告/JSON 用稳定字符串）。
const (
	// TemplateCheckIDPrefix 模板转换 check 的 id 前缀（见 convertPathForm/buildChecks）。
	TemplateCheckIDPrefix = "nuclei-"
	// NativeCheckSource 原生 check（非模板）的来源标签。
	NativeCheckSource = "native"
	// UnknownCheckSource 无法对齐模板来源时的标签（报告会单独成列）。
	UnknownCheckSource = "unknown"
)

// TemplateIDFromCheckID 从 check id 提取模板 id：
// `nuclei-CVE-2024-1234~g2` → ("CVE-2024-1234", true)；
// 原生 check（无 nuclei- 前缀）或空 id → ("", false)。
func TemplateIDFromCheckID(checkID string) (string, bool) {
	checkID = strings.TrimSpace(checkID)
	if !strings.HasPrefix(checkID, TemplateCheckIDPrefix) {
		return "", false
	}
	rest := checkID[len(TemplateCheckIDPrefix):]
	if i := strings.IndexByte(rest, '~'); i >= 0 { // ~pN / ~gN 分组后缀
		rest = rest[:i]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return rest, true
}

// SourceResolver 由模板索引构造 check id → 来源 的解析函数：
//   - `nuclei-<templateID>`：按文件名（去扩展名）对齐 Entry.Path，返回其来源；
//   - 原生 check：返回 NativeCheckSource；
//   - 对齐不上：返回 UnknownCheckSource。
//
// 同一文件名出现多次时取索引中首个（Index 顺序稳定，报告可复现）。
// entries 为空/ nil 时所有模板 check 都归 unknown（仍区分 native）。
func SourceResolver(entries []Entry) func(checkID string) string {
	byStem := make(map[string]string, len(entries))
	for _, e := range entries {
		stem := strings.ToLower(strings.TrimSuffix(filepath.Base(filepath.ToSlash(e.Path)), filepath.Ext(e.Path)))
		if stem == "" {
			continue
		}
		src := e.Source
		if src == "" {
			src = NormalizeSource(e.Path)
		}
		if _, ok := byStem[stem]; !ok {
			byStem[stem] = src
		}
	}
	return func(checkID string) string {
		tplID, ok := TemplateIDFromCheckID(checkID)
		if !ok {
			return NativeCheckSource
		}
		if src, hit := byStem[strings.ToLower(tplID)]; hit {
			return src
		}
		return UnknownCheckSource
	}
}

// SourcePassRates 一轮 check/模板执行证据 → 每来源通过率（runs/pass/fail/
// pass_rate/hits/hit_rate），供季度报告直接消费。不修改入参。
func SourcePassRates(entries []Entry, runs []checks.CheckRun) []checks.SourcePassRate {
	return checks.AggregateBySource(checks.RunStatsFromCheckRuns(runs, SourceResolver(entries)))
}
