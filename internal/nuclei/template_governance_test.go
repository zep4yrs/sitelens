package nuclei

// CP-10 模板治理单测：元数据解析 / 质量分 / 重复检测 / 失效清单。

import (
	"reflect"
	"testing"
	"time"
)

const governanceTpl = `id: CVE-2024-9999
info:
  name: Governance Test SQL Injection
  author: alice
  severity: high
  tags: cve,sqli
  classification:
    cve-id: CVE-2024-9999
http:
  - method: GET
    path:
      - "{{BaseURL}}/item?id=1"
    matchers:
      - type: word
        words:
          - "syntax error"
`

var fixedNow = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func hasIssue(a QualityAssessment, code string) bool {
	for _, is := range a.Issues {
		if is.Code == code {
			return true
		}
	}
	return false
}

// TestParseTemplateMeta 从模板原文提取治理元数据（含可执行性判定）。
func TestParseTemplateMeta(t *testing.T) {
	updated := fixedNow.Add(-10 * 24 * time.Hour)
	meta := ParseTemplateMeta("http/cves/2024/CVE-2024-9999.yaml", []byte(governanceTpl), updated)
	if meta.ID != "CVE-2024-9999" || meta.Name != "Governance Test SQL Injection" ||
		meta.Author != "alice" || meta.Source != "cves" || meta.Severity != "high" {
		t.Fatalf("基础元数据不符: %+v", meta)
	}
	if !meta.Convertible || !meta.Rerunnable {
		t.Fatalf("可执行模板应 Convertible/Rerunnable: %+v", meta)
	}
	if !meta.UpdatedAt.Equal(updated) {
		t.Fatalf("UpdatedAt=%v, want %v", meta.UpdatedAt, updated)
	}
	if want := []string{"cve", "sqli"}; !reflect.DeepEqual(meta.Tags, want) {
		t.Fatalf("Tags=%v, want %v", meta.Tags, want)
	}
	if want := []string{"CVE-2024-9999"}; !reflect.DeepEqual(meta.CVEs, want) {
		t.Fatalf("CVEs=%v, want %v", meta.CVEs, want)
	}

	// 交互式外带模板：漏斗拒收 → 不可执行/不可复跑
	interactsh := ParseTemplateMeta("http/cves/oob.yaml",
		[]byte(governanceTpl+"# requires interactsh server\n"), updated)
	if interactsh.Convertible || interactsh.Rerunnable {
		t.Fatalf("interactsh 模板应不可执行/不可复跑: %+v", interactsh)
	}

	// 缺 id → 文件名回退；缺 http 段 → 不可执行
	fallback := ParseTemplateMeta("legacy/no-id.yaml", []byte("info:\n  name: no id\n"), updated)
	if fallback.ID != "no-id" {
		t.Fatalf("ID 回退=%q, want no-id", fallback.ID)
	}
	if fallback.Convertible {
		t.Fatalf("无 http 段不应可执行: %+v", fallback)
	}
}

// TestAssessTemplateHighQuality 官方来源 + 新鲜 + 作者/严重度/可执行齐全 → 100/A。
func TestAssessTemplateHighQuality(t *testing.T) {
	meta := ParseTemplateMeta("http/cves/2024/CVE-2024-9999.yaml", []byte(governanceTpl),
		fixedNow.Add(-10*24*time.Hour))
	a := AssessTemplate(meta, fixedNow)
	if a.Score != 100 || a.Grade != "A" || len(a.Issues) != 0 {
		t.Fatalf("高质量模板应满分无扣分: %+v", a)
	}
	if a.ID != "CVE-2024-9999" || a.Source != "cves" {
		t.Fatalf("评估结果标识不符: %+v", a)
	}
}

// TestAssessTemplatePoorQuality legacy + 无更新时间 + 无作者 + CVE/low + 不可执行
// + 元数据缺失 → 低分 D，且扣分项齐全。
func TestAssessTemplatePoorQuality(t *testing.T) {
	meta := TemplateMeta{
		Path:     "legacy/broken.yaml",
		Source:   "legacy",
		Severity: "info",
		CVEs:     []string{"CVE-2020-0001"},
	}
	a := AssessTemplate(meta, fixedNow)
	// 17(来源) + 20(无更新时间) + 10(无作者) + 10(CVE/info) + 10(不可执行)
	// + 5(不可复跑) + 4(无名称) + 3(无 tags) + 3(无 id) = 82 → 18
	if a.Score != 18 || a.Grade != "D" {
		t.Fatalf("低质量模板 score=%d grade=%s, want 18/D（%+v）", a.Score, a.Grade, a.Issues)
	}
	for _, code := range []string{
		QualityIssueSource, QualityIssueUnknownAge, QualityIssueMissingAuthor,
		QualityIssueCVESeverity, QualityIssueNotConvertible, QualityIssueNotRerunnable,
		QualityIssueMissingName, QualityIssueMissingTags, QualityIssueMissingID,
	} {
		if !hasIssue(a, code) {
			t.Fatalf("缺少扣分项 %s: %+v", code, a.Issues)
		}
	}
}

// TestAssessTemplateSeverityIssues 严重度缺失/非法/CVE 不一致三种扣分。
func TestAssessTemplateSeverityIssues(t *testing.T) {
	base := TemplateMeta{
		ID: "x-1", Path: "http/cves/2024/x-1.yaml", Source: "cves",
		Name: "x", Author: "bob", Tags: []string{"cve"},
		UpdatedAt: fixedNow.Add(-5 * 24 * time.Hour), Convertible: true, Rerunnable: true,
	}

	missing := base
	missing.Severity = ""
	a := AssessTemplate(missing, fixedNow)
	if a.Score != 85 || !hasIssue(a, QualityIssueMissingSeverity) {
		t.Fatalf("缺 severity 应扣 15 → 85: %+v", a)
	}

	bad := base
	bad.Severity = "urgent"
	a = AssessTemplate(bad, fixedNow)
	if a.Score != 80 || !hasIssue(a, QualityIssueBadSeverity) {
		t.Fatalf("非法 severity 应扣 20 → 80: %+v", a)
	}

	mismatch := base
	mismatch.Severity = "low"
	mismatch.CVEs = []string{"CVE-2024-1234"}
	a = AssessTemplate(mismatch, fixedNow)
	if a.Score != 90 || !hasIssue(a, QualityIssueCVESeverity) {
		t.Fatalf("CVE+low 应扣 10 → 90: %+v", a)
	}
}

// TestSourceTrustPoints 来源信任分档（G02 报告按来源分列的依据）。
func TestSourceTrustPoints(t *testing.T) {
	cases := map[string]int{
		"cves": 25, "network": 25, "dns": 25, "cnvd": 25,
		"afrog": 18, "legacy": 8, "unknown": 3, "": 3,
	}
	for src, want := range cases {
		if got := SourceTrustPoints(src); got != want {
			t.Fatalf("SourceTrustPoints(%q)=%d, want %d", src, got, want)
		}
	}
}

// TestQualityGrade 分级边界。
func TestQualityGrade(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  string
	}{
		{100, "A"}, {85, "A"}, {84, "B"}, {70, "B"}, {69, "C"}, {50, "C"}, {49, "D"}, {0, "D"},
	} {
		if got := qualityGrade(tc.score); got != tc.want {
			t.Fatalf("qualityGrade(%d)=%s, want %s", tc.score, got, tc.want)
		}
	}
}

// TestFindDuplicateTemplates 同 id / 同文件名两种重复信号。
func TestFindDuplicateTemplates(t *testing.T) {
	metas := []TemplateMeta{
		{ID: "CVE-2024-0001", Path: "afrog/CVE-2024-0001.yaml"},
		{ID: "CVE-2024-0001", Path: "http/cves/2024/CVE-2024-0001.yaml"},
		{ID: "fork-a", Path: "http/misc/xss-fork.yaml"},
		{ID: "fork-b", Path: "legacy/xss-fork.yaml"},
		{ID: "unique-1", Path: "http/misc/unique.yaml"},
	}
	groups := FindDuplicateTemplates(metas, 0)
	if len(groups) != 2 {
		t.Fatalf("重复组数=%d, want 2: %+v", len(groups), groups)
	}
	// 按 Key 排序：cve-2024-0001 < xss-fork
	if groups[0].Reason != "same-id" || groups[0].Key != "cve-2024-0001" {
		t.Fatalf("第一组应为同 id: %+v", groups[0])
	}
	if groups[1].Reason != "same-filename" || groups[1].Key != "xss-fork" {
		t.Fatalf("第二组应为同文件名: %+v", groups[1])
	}
	for _, g := range groups {
		if len(g.Templates) != 2 {
			t.Fatalf("组 %s 应有 2 个模板: %+v", g.Key, g.Templates)
		}
		if g.Similarity < 0.9 {
			t.Fatalf("组 %s 相似度应 ≥0.9: %v", g.Key, g.Similarity)
		}
	}
	// 组内按路径排序（确定性）
	if groups[0].Templates[0].Path != "afrog/CVE-2024-0001.yaml" {
		t.Fatalf("组内未按路径排序: %+v", groups[0].Templates)
	}
	// 唯一模板不进组
	for _, g := range groups {
		for _, m := range g.Templates {
			if m.ID == "unique-1" {
				t.Fatalf("唯一模板被并入重复组: %+v", g)
			}
		}
	}
}

// TestFindDuplicateTemplatesSimilarPath 同目录近同名文件（id/文件名不同）：
// 默认阈值（0.8）即可识别（路径 token Jaccard≈0.857）；阈值 0.9 时不误报。
func TestFindDuplicateTemplatesSimilarPath(t *testing.T) {
	metas := []TemplateMeta{
		{ID: "aaa", Path: "http/cves/2024/CVE-2024-1111.yaml"},
		{ID: "bbb", Path: "http/cves/2024/CVE-2024-1111-copy.yaml"},
	}
	groups := FindDuplicateTemplates(metas, 0)
	if len(groups) != 1 || groups[0].Reason != "similar-path" || len(groups[0].Templates) != 2 {
		t.Fatalf("默认阈值应识别 similar-path: %+v", groups)
	}
	if groups := FindDuplicateTemplates(metas, 0.9); groups != nil {
		t.Fatalf("阈值 0.9 不应误报: %+v", groups)
	}
}

// TestPathSimilarity 相似度口径。
func TestPathSimilarity(t *testing.T) {
	same := "http/cves/2024/CVE-2024-1.yaml"
	if got := PathSimilarity(same, same); got != 1 {
		t.Fatalf("同路径相似度=%v, want 1", got)
	}
	if got := PathSimilarity("http/cves/2024/CVE-2024-1.yaml", "legacy/CVE-2024-1.yaml"); got != 0.95 {
		t.Fatalf("同文件名跨目录相似度=%v, want 0.95", got)
	}
	if got := PathSimilarity("http/cves/a.yaml", "network/b.yaml"); got >= 0.5 {
		t.Fatalf("不相关路径相似度过高: %v", got)
	}
	if got := PathSimilarity("", "http/x.yaml"); got != 0 {
		t.Fatalf("空路径相似度=%v, want 0", got)
	}
}

// TestFindInvalidTemplates 失效清单：不可执行/缺名称/坏严重度/坏协议。
func TestFindInvalidTemplates(t *testing.T) {
	metas := []TemplateMeta{
		{ID: "a", Path: "http/cves/a.yaml", Name: "a", Severity: "high", Convertible: false},
		{ID: "b", Path: "http/cves/b.yaml", Name: "", Severity: "high", Convertible: true},
		{ID: "c", Path: "http/cves/c.yaml", Name: "c", Severity: "urgent", Convertible: true},
		{ID: "d", Path: "network/d.yaml", Name: "d", Severity: "high", Proto: "udp", Convertible: true},
		{ID: "ok", Path: "http/cves/ok.yaml", Name: "ok", Severity: "medium", Convertible: true},
	}
	got := FindInvalidTemplates(metas)
	if len(got) != 4 {
		t.Fatalf("失效模板数=%d, want 4: %+v", len(got), got)
	}
	wantReasons := map[string]string{
		"http/cves/a.yaml": InvalidNotConvertible,
		"http/cves/b.yaml": InvalidEmptyName,
		"http/cves/c.yaml": InvalidBadSeverity,
		"network/d.yaml":   InvalidBadProto,
	}
	for _, it := range got {
		if want := wantReasons[it.Path]; want == "" || len(it.Reasons) != 1 || it.Reasons[0] != want {
			t.Fatalf("失效原因不符 path=%s: %+v", it.Path, it)
		}
	}
	// 排序确定性
	for i := 1; i < len(got); i++ {
		if got[i-1].Path > got[i].Path {
			t.Fatalf("失效清单未按路径排序: %+v", got)
		}
	}
}

// TestTemplateMetaFromEntry 索引 Entry 适配（无 author，来源回退）。
func TestTemplateMetaFromEntry(t *testing.T) {
	updated := time.Unix(1_700_000_000, 0)
	e := Entry{
		Path: "http/cves/2024/CVE-2024-1234.yaml", Name: "n", Sev: "HIGH",
		Tags: []string{"cve"}, CVEs: []string{"CVE-2024-1234"},
		MTime: updated.Unix(), Convertible: true, Proto: "tcp",
	}
	meta := TemplateMetaFromEntry(e)
	if meta.ID != "CVE-2024-1234" || meta.Source != "cves" || meta.Severity != "high" {
		t.Fatalf("Entry 适配字段不符: %+v", meta)
	}
	if !meta.UpdatedAt.Equal(updated) {
		t.Fatalf("UpdatedAt=%v, want %v", meta.UpdatedAt, updated)
	}
	if !meta.Convertible || !meta.Rerunnable || meta.Proto != "tcp" {
		t.Fatalf("可执行字段不符: %+v", meta)
	}
	if meta.Author != "" {
		t.Fatalf("索引不含作者，应为空: %q", meta.Author)
	}
}

// TestAssessTemplatesOrdering 批量评估最差在前；LowQualityTemplates 过滤。
func TestAssessTemplatesOrdering(t *testing.T) {
	good := TemplateMeta{
		ID: "good", Path: "http/cves/good.yaml", Source: "cves", Name: "good",
		Author: "x", Tags: []string{"cve"}, Severity: "high",
		UpdatedAt: fixedNow.Add(-time.Hour), Convertible: true, Rerunnable: true,
	}
	mid := TemplateMeta{
		ID: "mid", Path: "http/cves/mid.yaml", Source: "cves", Name: "mid",
		Author: "x", Tags: []string{"cve"}, Severity: "high",
		UpdatedAt: fixedNow.Add(-200 * 24 * time.Hour), Convertible: true, Rerunnable: true,
	}
	bad := TemplateMeta{ID: "bad", Path: "legacy/bad.yaml", Source: "legacy"}
	all := AssessTemplates([]TemplateMeta{good, mid, bad}, fixedNow)
	if len(all) != 3 || all[0].ID != "bad" || all[2].ID != "good" {
		t.Fatalf("批量评估排序不符: %+v", all)
	}
	low := LowQualityTemplates([]TemplateMeta{good, mid, bad}, fixedNow, 60)
	if len(low) != 1 || low[0].ID != "bad" {
		t.Fatalf("低质量过滤不符: %+v", low)
	}
}
