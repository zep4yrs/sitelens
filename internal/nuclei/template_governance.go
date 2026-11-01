// CP-10 模板元数据治理：质量分 / 重复检测 / 失效清单（纯函数，不发起网络、
// 不读写文件，便于单测与离线上报）。
//
// 质量分（100 分制，扣分项逐条可见，报告可直接解释）：
//
//	来源信任 25 + 更新时间 20 + 作者 10 + 严重度一致性 20 + 可执行性 15 + 元数据完整 10
//
// 用途：季度复评时输出「低质量模板清单」「重复模板组」「失效模板清单」，
// 作为模板库治理（清理/合并/重签）与 G02 覆盖率口径的输入。
//
// 元数据来源有两种：
//   - ParseTemplateMeta：从模板原文解析（含 id/author/severity/classification），
//     并复用转换漏斗判断是否可执行——信息最全，代价≈一次索引转换；
//   - TemplateMetaFromEntry：从已有索引 Entry 构造（无 author，作者项按缺失计，
//     适合快速全量巡检）。
package nuclei

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 质量扣分项代码（报告/CSV 用稳定枚举，禁止改语义只允许新增）。
const (
	QualityIssueSource          = "source-low-trust"      // 来源目录信任度低（legacy/unknown）
	QualityIssueUnknownAge      = "unknown-updated"       // 无更新时间（无法判断新鲜度）
	QualityIssueStale           = "stale-template"        // 超过 90 天未更新
	QualityIssueMissingAuthor   = "missing-author"        // 缺少作者/维护者
	QualityIssueMissingSeverity = "missing-severity"      // 缺少 severity
	QualityIssueBadSeverity     = "bad-severity"          // severity 不在 critical/high/medium/low/info
	QualityIssueCVESeverity     = "cve-severity-mismatch" // 声明 CVE 但 severity 为 low/info
	QualityIssueNotConvertible  = "not-convertible"       // 转换漏斗拒收（不可执行）
	QualityIssueNotRerunnable   = "not-rerunnable"        // 依赖交互式外带等外部条件，不可复跑
	QualityIssueMissingName     = "missing-name"          // 缺少 info.name
	QualityIssueMissingTags     = "missing-tags"          // 缺少 info.tags
	QualityIssueMissingID       = "missing-id"            // 缺少模板 id（回退文件名）
)

// 失效模板原因代码（FindInvalidTemplates 使用）。
const (
	InvalidNotConvertible = "not-convertible"
	InvalidEmptyName      = "empty-name"
	InvalidEmptyPath      = "empty-path"
	InvalidBadSeverity    = "bad-severity"
	InvalidBadProto       = "bad-proto"
)

// 严重度合法集合（nuclei 语义）。
var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// 官方镜像目录（高信任来源）；其余见 SourceTrustPoints。
var officialSources = map[string]bool{
	"cves": true, "exposed-panels": true, "technologies": true,
	"vulnerabilities": true, "misconfiguration": true, "exposures": true,
	"default-logins": true, "takeovers": true, "miscellaneous": true,
	"fuzzing": true, "cnvd": true, "network": true, "dns": true, "ssl": true,
}

// TemplateMeta 治理所需的模板元数据快照。
type TemplateMeta struct {
	ID          string    `json:"id"`
	Path        string    `json:"path"`   // 相对模板库根目录
	Name        string    `json:"name"`   // info.name
	Source      string    `json:"source"` // NormalizeSource 口径
	Author      string    `json:"author,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"` // 模板文件 mtime
	Severity    string    `json:"severity"`             // 原始值（未归一，非法值保留供治理）
	Tags        []string  `json:"tags,omitempty"`
	CVEs        []string  `json:"cves,omitempty"`
	Proto       string    `json:"proto,omitempty"` // tcp|dns|ssl（空 = HTTP）
	Convertible bool      `json:"convertible"`     // 能转换为可执行 check
	Rerunnable  bool      `json:"rerunnable"`      // 可重复执行（无交互式外带等外部依赖）
}

// QualityIssue 单条扣分项（Deducted 为扣掉的分数，便于报告解释）。
type QualityIssue struct {
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Deducted int    `json:"deducted"`
}

// QualityAssessment 单模板质量评估结果。
type QualityAssessment struct {
	ID     string         `json:"id"`
	Path   string         `json:"path"`
	Source string         `json:"source"`
	Score  int            `json:"score"` // 0-100
	Grade  string         `json:"grade"` // A(>=85) B(>=70) C(>=50) D
	Issues []QualityIssue `json:"issues,omitempty"`
}

// DuplicateGroup 一组疑似重复模板（同 id / 同文件名 / 路径高度相似）。
type DuplicateGroup struct {
	Key        string         `json:"key"`        // 归一组键（模板 id 或文件名）
	Reason     string         `json:"reason"`     // same-id | same-filename | similar-path
	Similarity float64        `json:"similarity"` // 组内最大路径相似度
	Templates  []TemplateMeta `json:"templates"`
}

// InvalidTemplate 失效模板（无法执行或元数据不可用），供清理清单。
type InvalidTemplate struct {
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Reasons []string `json:"reasons"` // Invalid* 常量
}

// ---- 元数据构造 ----

// ParseTemplateMeta 从模板原文解析治理元数据（纯函数；不判重、不落盘）。
// 复用转换漏斗（convertAny）判断可执行性——代价≈一次索引转换，适合离线
// 全量治理报告；单模板巡检亦可。
func ParseTemplateMeta(path string, data []byte, updated time.Time) TemplateMeta {
	meta := TemplateMeta{
		Path:      filepath.ToSlash(strings.TrimSpace(path)),
		Source:    NormalizeSource(path),
		UpdatedAt: updated,
	}
	var doc struct {
		ID   string `yaml:"id"`
		Info struct {
			Name           string  `yaml:"name"`
			Author         strList `yaml:"author"`
			Severity       string  `yaml:"severity"`
			Tags           strList `yaml:"tags"`
			Description    string  `yaml:"description"`
			Classification struct {
				CVEID strList `yaml:"cve-id"`
			} `yaml:"classification"`
		} `yaml:"info"`
	}
	// YAML 解析失败也继续：治理需要把坏模板列出来（后续 Convertible=false）。
	_ = yaml.Unmarshal(data, &doc)

	meta.ID = strings.TrimSpace(doc.ID)
	if meta.ID == "" {
		meta.ID = templateIDFromPath(meta.Path)
	}
	meta.Name = strings.TrimSpace(doc.Info.Name)
	meta.Author = strings.TrimSpace(strings.Join([]string(doc.Info.Author), ","))
	meta.Severity = strings.ToLower(strings.TrimSpace(doc.Info.Severity))
	meta.Tags = splitTagList(doc.Info.Tags)
	meta.CVEs = mergeCVEs(doc.Info.Classification.CVEID, string(data))

	checks := convertAny(data)
	meta.Convertible = len(checks) > 0
	meta.Rerunnable = meta.Convertible && !strings.Contains(strings.ToLower(string(data)), "interactsh")
	return meta
}

// TemplateMetaFromEntry 从索引 Entry 构造治理元数据。
// 注意：索引不保存 author（作者项按缺失计），适合快速全量巡检；要完整的
// 质量分请用 ParseTemplateMeta。
func TemplateMetaFromEntry(e Entry) TemplateMeta {
	meta := TemplateMeta{
		ID:          templateIDFromPath(e.Path),
		Path:        filepath.ToSlash(e.Path),
		Name:        e.Name,
		Source:      e.Source,
		Severity:    strings.ToLower(strings.TrimSpace(e.Sev)),
		Tags:        append([]string(nil), e.Tags...),
		CVEs:        append([]string(nil), e.CVEs...),
		Proto:       e.Proto,
		Convertible: e.Convertible,
		Rerunnable:  e.Convertible,
	}
	if meta.Source == "" {
		meta.Source = NormalizeSource(e.Path)
	}
	if e.MTime > 0 {
		meta.UpdatedAt = time.Unix(e.MTime, 0)
	}
	return meta
}

// templateIDFromPath 从模板路径取模板 id 回退值（文件名去扩展名）。
func templateIDFromPath(path string) string {
	base := filepath.Base(filepath.ToSlash(path))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// splitTagList tags 两种形态（逗号字符串/列表）→ 归一列表。
func splitTagList(raw strList) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			tag := strings.ToLower(strings.TrimSpace(part))
			if tag == "" || seen[tag] {
				continue
			}
			seen[tag] = true
			out = append(out, tag)
		}
	}
	return out
}

// mergeCVEs classification.cve-id 优先，缺失时从原文正则兜底（兼容旧模板）。
func mergeCVEs(declared strList, raw string) []string {
	out := make([]string, 0, len(declared)+2)
	seen := map[string]bool{}
	add := func(c string) {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, c := range declared {
		add(c)
	}
	if len(out) == 0 {
		for _, c := range metaCveRe.FindAllString(raw, 8) {
			add(c)
		}
	}
	return out
}

// ---- 质量分 ----

// SourceTrustPoints 来源信任分（25 分制）：官方镜像目录 25、afrog 18、
// legacy 8、空/unknown 3。
func SourceTrustPoints(source string) int {
	src := strings.ToLower(strings.TrimSpace(source))
	switch {
	case officialSources[src]:
		return 25
	case src == "afrog":
		return 18
	case src == "legacy":
		return 8
	default:
		return 3
	}
}

// freshnessPoints 更新时间分（20 分制）：≤90 天 20、≤180 天 15、≤365 天 10、
// ≤730 天 5、更旧 0；无更新时间 0。
func freshnessPoints(updated, now time.Time) int {
	if updated.IsZero() {
		return 0
	}
	d := now.Sub(updated)
	if d < 0 { // 未来时间（时钟偏差）按最新处理
		d = 0
	}
	days := int(d.Hours() / 24)
	switch {
	case days <= 90:
		return 20
	case days <= 180:
		return 15
	case days <= 365:
		return 10
	case days <= 730:
		return 5
	default:
		return 0
	}
}

// NormalizeSeverity 归一并校验 severity（非法/空返回 false）。
func NormalizeSeverity(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !validSeverities[s] {
		return s, false
	}
	return s, true
}

// AssessTemplate 单模板质量评估（now 显式传入，保证测试与季度报告可复现）。
func AssessTemplate(meta TemplateMeta, now time.Time) QualityAssessment {
	a := QualityAssessment{
		ID:     meta.ID,
		Path:   meta.Path,
		Source: meta.Source,
	}
	if a.Source == "" {
		a.Source = NormalizeSource(meta.Path)
	}
	deduct := func(code, detail string, points int) {
		if points <= 0 {
			return
		}
		a.Issues = append(a.Issues, QualityIssue{Code: code, Detail: detail, Deducted: points})
	}

	// 1) 来源信任（25）
	if trust := SourceTrustPoints(a.Source); trust < 25 {
		deduct(QualityIssueSource, fmt.Sprintf("来源 %q 信任分 %d/25", a.Source, trust), 25-trust)
	}

	// 2) 新鲜度（20）
	switch fresh := freshnessPoints(meta.UpdatedAt, now); {
	case meta.UpdatedAt.IsZero():
		deduct(QualityIssueUnknownAge, "缺少模板更新时间", 20)
	case fresh < 20:
		days := int(now.Sub(meta.UpdatedAt).Hours() / 24)
		deduct(QualityIssueStale, fmt.Sprintf("模板已 %d 天未更新", days), 20-fresh)
	}

	// 3) 作者（10）
	if strings.TrimSpace(meta.Author) == "" {
		deduct(QualityIssueMissingAuthor, "未标注作者/维护者", 10)
	}

	// 4) 严重度一致性（20）
	sev, sevOK := NormalizeSeverity(meta.Severity)
	switch {
	case strings.TrimSpace(meta.Severity) == "":
		deduct(QualityIssueMissingSeverity, "缺少 severity", 15)
	case !sevOK:
		deduct(QualityIssueBadSeverity, fmt.Sprintf("severity=%q 非法", meta.Severity), 20)
	}
	if sevOK && len(meta.CVEs) > 0 && (sev == "low" || sev == "info") {
		deduct(QualityIssueCVESeverity,
			fmt.Sprintf("声明 CVE 但 severity=%s（应 ≥medium 或降级为 info 的组件提示）", sev), 10)
	}

	// 5) 可执行性（15）
	if !meta.Convertible {
		deduct(QualityIssueNotConvertible, "转换漏斗拒收，无法执行", 10)
	}
	if !meta.Rerunnable {
		deduct(QualityIssueNotRerunnable, "不可复跑（依赖交互式外带/外部条件）", 5)
	}

	// 6) 元数据完整（10）
	if strings.TrimSpace(meta.Name) == "" {
		deduct(QualityIssueMissingName, "缺少 info.name", 4)
	}
	if len(meta.Tags) == 0 {
		deduct(QualityIssueMissingTags, "缺少 info.tags", 3)
	}
	if strings.TrimSpace(meta.ID) == "" {
		deduct(QualityIssueMissingID, "缺少模板 id 且无法从文件名回退", 3)
	}

	a.Score = 100
	for _, is := range a.Issues {
		a.Score -= is.Deducted
	}
	if a.Score < 0 {
		a.Score = 0
	}
	a.Grade = qualityGrade(a.Score)
	return a
}

func qualityGrade(score int) string {
	switch {
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 50:
		return "C"
	default:
		return "D"
	}
}

// AssessTemplates 批量评估，按分数升序（最差在前）、同分按路径排序（稳定，
// 报告可逐字节复盘）。now 显式传入。
func AssessTemplates(metas []TemplateMeta, now time.Time) []QualityAssessment {
	out := make([]QualityAssessment, 0, len(metas))
	for _, m := range metas {
		out = append(out, AssessTemplate(m, now))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score < out[j].Score
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// LowQualityTemplates 分数 ≤ maxScore 的模板（AssessTemplates 有序输出的子集）。
func LowQualityTemplates(metas []TemplateMeta, now time.Time, maxScore int) []QualityAssessment {
	all := AssessTemplates(metas, now)
	out := make([]QualityAssessment, 0, len(all))
	for _, a := range all {
		if a.Score <= maxScore {
			out = append(out, a)
		}
	}
	return out
}

// ---- 重复检测（按 id + path 相似）----

// FindDuplicateTemplates 找出疑似重复模板：
//   - same-id：模板 id 相同但路径不同（同名模板被多个目录/来源重复收录）；
//   - same-filename：文件名（去扩展名）相同、目录不同（fork/镜像副本）；
//   - similar-path：同目录下路径 token 相似度 ≥ threshold 的近同名文件。
//
// 为可跑 14 万级索引，先按 id/文件名/父目录建桶再桶内比对，不做全量 O(n²)
// （父目录桶 >256 条时跳过两两比对）。threshold ≤0 时取默认 0.8；
// 输出按组 Key 排序、组内按路径排序（确定性，报告可逐字节复盘）。
func FindDuplicateTemplates(metas []TemplateMeta, threshold float64) []DuplicateGroup {
	if threshold <= 0 {
		threshold = 0.8
	}
	n := len(metas)
	if n < 2 {
		return nil
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	// 桶 1：归一化模板 id
	idBucket := map[string][]int{}
	// 桶 2：归一化文件名（去扩展名）
	nameBucket := map[string][]int{}
	// 桶 3：父目录（同目录近同名文件 → similar-path；仅对中小目录做两两比对）
	dirBucket := map[string][]int{}
	for i, m := range metas {
		if id := strings.ToLower(strings.TrimSpace(m.ID)); id != "" {
			idBucket[id] = append(idBucket[id], i)
		}
		if stem := fileStem(m.Path); stem != "" {
			nameBucket[stem] = append(nameBucket[stem], i)
		}
		if dir := parentDir(m.Path); dir != "" {
			dirBucket[dir] = append(dirBucket[dir], i)
		}
	}
	for _, idxs := range idBucket {
		for k := 1; k < len(idxs); k++ {
			union(idxs[0], idxs[k])
		}
	}
	for _, idxs := range nameBucket {
		for a := 0; a < len(idxs); a++ {
			for b := a + 1; b < len(idxs); b++ {
				// 同文件名桶内再按路径相似度过滤，避免误并（如两个都叫 index.yaml）
				if PathSimilarity(metas[idxs[a]].Path, metas[idxs[b]].Path) >= threshold {
					union(idxs[a], idxs[b])
				}
			}
		}
	}
	const maxPairwiseBucket = 256 // 超大目录（如根目录/镜像大包）跳过两两比对，防 O(n²)
	for _, idxs := range dirBucket {
		if len(idxs) > maxPairwiseBucket {
			continue
		}
		for a := 0; a < len(idxs); a++ {
			for b := a + 1; b < len(idxs); b++ {
				if PathSimilarity(metas[idxs[a]].Path, metas[idxs[b]].Path) >= threshold {
					union(idxs[a], idxs[b])
				}
			}
		}
	}

	clusters := map[int][]int{}
	var order []int
	for i := 0; i < n; i++ {
		root := find(i)
		if _, ok := clusters[root]; !ok {
			order = append(order, root)
		}
		clusters[root] = append(clusters[root], i)
	}
	var groups []DuplicateGroup
	for _, root := range order {
		idxs := clusters[root]
		if len(idxs) < 2 {
			continue
		}
		sort.Slice(idxs, func(a, b int) bool { return metas[idxs[a]].Path < metas[idxs[b]].Path })
		items := make([]TemplateMeta, 0, len(idxs))
		for _, i := range idxs {
			items = append(items, metas[i])
		}
		groups = append(groups, DuplicateGroup{
			Key:        dupGroupKey(items),
			Reason:     dupGroupReason(items),
			Similarity: maxSimilarity(items),
			Templates:  items,
		})
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
	return groups
}

func dupGroupKey(items []TemplateMeta) string {
	if k := normalizeID(items[0].ID); k != "" && allSameID(items) {
		return k
	}
	if stem := fileStem(items[0].Path); stem != "" && allSameStem(items, stem) {
		return stem
	}
	return items[0].Path
}

func dupGroupReason(items []TemplateMeta) string {
	if allSameID(items) && normalizeID(items[0].ID) != "" {
		return "same-id"
	}
	if stem := fileStem(items[0].Path); stem != "" && allSameStem(items, stem) {
		return "same-filename"
	}
	return "similar-path"
}

func normalizeID(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

func allSameID(items []TemplateMeta) bool {
	first := normalizeID(items[0].ID)
	if first == "" {
		return false
	}
	for _, it := range items[1:] {
		if normalizeID(it.ID) != first {
			return false
		}
	}
	return true
}

func allSameStem(items []TemplateMeta, stem string) bool {
	for _, it := range items[1:] {
		if fileStem(it.Path) != stem {
			return false
		}
	}
	return true
}

func maxSimilarity(items []TemplateMeta) float64 {
	if len(items) < 2 {
		return 0
	}
	best := 0.0
	for i := 1; i < len(items); i++ {
		if sim := PathSimilarity(items[0].Path, items[i].Path); sim > best {
			best = sim
		}
	}
	return best
}

// fileStem 文件名（去扩展名、小写）。
func fileStem(path string) string {
	base := filepath.Base(filepath.ToSlash(strings.TrimSpace(path)))
	return strings.ToLower(strings.TrimSuffix(base, filepath.Ext(base)))
}

// parentDir 路径父目录（统一斜杠、小写；空/根返回空串）。
func parentDir(path string) string {
	p := strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
	dir := filepath.Dir(p)
	if dir == "." || dir == "/" || dir == "" {
		return ""
	}
	return dir
}

// PathSimilarity 模板路径相似度（0-1）：
//   - 同文件名（去扩展名）且路径不同 → 0.95（fork/镜像副本的强信号）；
//   - 其余按路径 token 的 Jaccard 系数；
//   - 任一路径为空 → 0。
func PathSimilarity(a, b string) float64 {
	if strings.EqualFold(a, b) {
		if strings.TrimSpace(a) == "" {
			return 0
		}
		return 1
	}
	sa, sb := fileStem(a), fileStem(b)
	if sa == "" || sb == "" {
		return 0
	}
	if sa == sb {
		return 0.95
	}
	ta, tb := pathTokens(a), pathTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for t := range ta {
		if tb[t] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func pathTokens(p string) map[string]bool {
	out := map[string]bool{}
	normalized := strings.ToLower(filepath.ToSlash(p))
	for _, seg := range strings.FieldsFunc(normalized, func(r rune) bool {
		switch r {
		case '/', '\\', '-', '_', '.', ' ', '\t':
			return true
		}
		return false
	}) {
		if seg != "" {
			out[seg] = true
		}
	}
	return out
}

// ---- 失效模板清单 ----

// FindInvalidTemplates 失效模板清单：不可执行或元数据不可用者。
// 输出按路径排序；reasons 使用 Invalid* 常量。
func FindInvalidTemplates(metas []TemplateMeta) []InvalidTemplate {
	var out []InvalidTemplate
	for _, m := range metas {
		var reasons []string
		if !m.Convertible {
			reasons = append(reasons, InvalidNotConvertible)
		}
		if strings.TrimSpace(m.Path) == "" {
			reasons = append(reasons, InvalidEmptyPath)
		}
		if strings.TrimSpace(m.Name) == "" {
			reasons = append(reasons, InvalidEmptyName)
		}
		if sev := strings.TrimSpace(m.Severity); sev != "" {
			if _, ok := NormalizeSeverity(sev); !ok {
				reasons = append(reasons, InvalidBadSeverity)
			}
		}
		if !validProto(m.Proto) {
			reasons = append(reasons, InvalidBadProto)
		}
		if len(reasons) == 0 {
			continue
		}
		out = append(out, InvalidTemplate{ID: m.ID, Path: m.Path, Reasons: reasons})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// validProto Proto 合法集合（空 = HTTP；协议模板 tcp/dns/ssl）。
func validProto(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "", "http", "tcp", "dns", "ssl":
		return true
	}
	return false
}
