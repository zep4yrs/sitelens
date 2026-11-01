package server

// CP-07 合规报告模板测试：两套框架生成、严重度分组排序、转义、空结果、
// 非法参数与模板防御性拷贝。

import (
	"errors"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/security"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// complianceFixture 构造一份含多严重度、多条款映射的扫描记录。
func complianceFixture() *store.ScanRecord {
	res := &engine.Result{
		URL:       "https://target.example.com",
		Host:      "target.example.com",
		Title:     "测试目标",
		Status:    200,
		ScannedAt: "2026-11-01 08:00:00",
		Duration:  1.25,
		Security:  &security.Report{Score: 72, Grade: "C"},
		Verified: []map[string]any{
			{"check": "sqli-error", "title": "报错型 SQL 注入", "severity": "critical",
				"url": "https://target.example.com/item?id=1", "advice": "参数化查询", "src": "dast"},
			{"check": "xss-reflect", "title": "反射型 XSS", "severity": "high",
				"url": "https://target.example.com/search?q=1", "advice": "输出编码", "src": "dast"},
			{"check": "weak-cookie", "title": "Cookie 缺少安全属性", "severity": "medium",
				"url": "https://target.example.com/", "advice": "补 HttpOnly/Secure", "src": "passive"},
			{"check": "csp-weak-directive", "title": "CSP 策略可绕过", "severity": "low",
				"url": "https://target.example.com/", "advice": "收紧 CSP", "src": "security"},
			{"check": "dir-listing", "title": "目录列表开启", "severity": "info",
				"url": "https://target.example.com/static/", "advice": "关闭目录列表", "src": "check"},
		},
		Vulnerabilities: []intel.Finding{
			{Name: "Apache 组件已知漏洞", CVE: "CVE-2024-0001", Severity: "high", SeverityZh: "高"},
		},
		Extras: map[string]any{
			"hygiene": []map[string]any{
				{"check": "csp-missing", "title": "缺少 CSP 响应头", "severity": "medium",
					"url": "https://target.example.com/", "advice": "添加 CSP"},
			},
		},
	}
	return &store.ScanRecord{
		ScanSummary: store.ScanSummary{
			URL: "https://target.example.com", Host: "target.example.com",
			Title: "测试目标", Status: 200, SecurityGrade: "C", SecurityScore: 72,
			Duration: 1.25, ScannedAt: "2026-11-01 08:00:00",
		},
		Result: res,
	}
}

// TestComplianceControlsTemplates 两套模板存在、编号唯一、可防篡改拷贝。
func TestComplianceControlsTemplates(t *testing.T) {
	for _, fw := range []ComplianceFramework{FrameworkMLPS, FrameworkASVS} {
		ctrl, err := ComplianceControls(fw)
		if err != nil {
			t.Fatalf("%s 模板应可用: %v", fw, err)
		}
		if len(ctrl) < 8 {
			t.Fatalf("%s 模板条款过少: %d", fw, len(ctrl))
		}
		seen := map[string]bool{}
		probeable := 0
		for _, c := range ctrl {
			if c.ID == "" || c.Title == "" || c.Advice == "" {
				t.Fatalf("%s 条款字段不完整: %+v", fw, c)
			}
			if seen[c.ID] {
				t.Fatalf("%s 条款编号重复: %s", fw, c.ID)
			}
			seen[c.ID] = true
			if len(c.Checks) > 0 {
				probeable++
			}
		}
		if probeable == 0 {
			t.Fatalf("%s 应有可自动映射的条款", fw)
		}
		// 防篡改：修改返回值不得影响下一次调用。
		ctrl[0].Checks = append(ctrl[0].Checks, "hacked")
		again, err := ComplianceControls(fw)
		if err != nil {
			t.Fatalf("二次取模板: %v", err)
		}
		for _, c := range again[0].Checks {
			if c == "hacked" {
				t.Fatalf("%s 模板被外部篡改", fw)
			}
		}
	}
	if _, err := ComplianceControls("nope"); !errors.Is(err, ErrUnsupportedFramework) {
		t.Fatalf("未知框架应报错: %v", err)
	}
}

// TestRenderComplianceMarkdown Markdown 报告：框架标题、严重度分组顺序、
// 条款映射表、整改建议列、目标与判定。
func TestRenderComplianceMarkdown(t *testing.T) {
	md, err := RenderCompliance(complianceFixture(), FrameworkMLPS, FormatMarkdown)
	if err != nil {
		t.Fatalf("生成 Markdown: %v", err)
	}
	for _, want := range []string{
		"# 合规评估报告 · 等保 2.0",
		"## 风险概览",
		"## 发现（按严重度分组）",
		"## 合规条款映射（等保 2.0",
		"整改建议",
		"不符合",
		"人工复核",
		"https://target.example.com",
		"CVE-2024-0001",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("Markdown 缺少 %q\n%s", want, md)
		}
	}
	// 严重度分组顺序：严重 → 高 → 中 → 低 → 信息。
	order := []string{"### 严重（critical", "### 高（high", "### 中（medium", "### 低（low", "### 信息（info"}
	last := -1
	for _, marker := range order {
		i := strings.Index(md, marker)
		if i < 0 {
			t.Fatalf("缺少分组 %q", marker)
		}
		if i < last {
			t.Fatalf("严重度分组顺序错误: %q", marker)
		}
		last = i
	}
	// 条款映射：注入类条款应因 critical/high 判「不符合」；审计类无法探测应「人工复核」。
	if !strings.Contains(md, "| 8.1.4.1 | 入侵防范 |") || !strings.Contains(md, "| 8.1.2.3 | 安全审计 |") {
		t.Fatalf("条款映射表缺少预期条款\n%s", md)
	}
	if !strings.Contains(md, "| 不符合 |") || !strings.Contains(md, "| 人工复核 |") {
		t.Fatalf("条款判定列异常\n%s", md)
	}
}

// TestRenderComplianceHTMLSelfContained HTML 报告：自包含、白底、无外部资源/脚本。
func TestRenderComplianceHTMLSelfContained(t *testing.T) {
	h, err := RenderCompliance(complianceFixture(), FrameworkASVS, FormatHTML)
	if err != nil {
		t.Fatalf("生成 HTML: %v", err)
	}
	for _, want := range []string{
		"<!doctype html>", `lang="zh-CN"`, "background:#fff",
		"@media print", "OWASP ASVS", "风险概览", "合规条款映射", "整改建议",
	} {
		if !strings.Contains(h, want) {
			t.Fatalf("HTML 缺少 %q", want)
		}
	}
	for _, banned := range []string{"<script", "<link", "src=\"http", "<iframe", "<object"} {
		if strings.Contains(h, banned) {
			t.Fatalf("自包含报告不应包含 %q", banned)
		}
	}
}

// TestRenderComplianceHTMLEscaping HTML 转义：所有动态字段不得原样输出标签/
// 事件属性，严重度只允许白名单 class。
func TestRenderComplianceHTMLEscaping(t *testing.T) {
	res := &engine.Result{
		URL:  `https://evil.example.com/"><img src=x onerror=alert(1)>`,
		Host: `"><script>alert(1)</script>`,
		Verified: []map[string]any{
			{"check": "xss-reflect", "title": `<script>alert("x")</script> & "quoted"`,
				"severity": "high", "url": `https://evil.example.com/?q="><svg/onload=alert(1)>`,
				"advice": `"><img src=x onerror=alert(2)>`, "src": "dast"},
			{"check": "xss-stored", "title": `severity 注入`, "severity": `"><script>alert(3)</script>`,
				"url": `https://evil.example.com/2`, "advice": "修复", "src": "dast"},
		},
	}
	h, err := RenderComplianceResult(res, FrameworkMLPS, FormatHTML)
	if err != nil {
		t.Fatalf("生成 HTML: %v", err)
	}
	lower := strings.ToLower(h)
	for _, banned := range []string{"<script", "<img", "<svg", "<iframe", "<object"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("动态内容未转义，出现 %q", banned)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;") {
		t.Fatalf("应出现转义后的 &lt;script&gt;")
	}
	if strings.Contains(h, `class="sev-"><`) || strings.Contains(h, `class="sev-"><script`) {
		t.Fatalf("严重度 class 被注入")
	}
	// 非法严重度降级为 info。
	if !strings.Contains(h, `class="sev-info"`) {
		t.Fatalf("未知严重度应降级为 info class")
	}
}

// TestRenderComplianceMarkdownEscaping Markdown 转义：竖线不断列、换行不断行、
// 尖括号不被当 HTML。
func TestRenderComplianceMarkdownEscaping(t *testing.T) {
	res := &engine.Result{
		URL:  "https://a.example.com",
		Host: "a.example.com",
		Verified: []map[string]any{
			{"check": "xss-reflect", "title": "标题含|竖线\n与换行<script>x</script>",
				"severity": "high", "url": "https://a.example.com/?q=1|2", "advice": "建议|分段\n换行", "src": "dast"},
		},
	}
	md, err := RenderComplianceResult(res, FrameworkMLPS, FormatMarkdown)
	if err != nil {
		t.Fatalf("生成 Markdown: %v", err)
	}
	if strings.Contains(md, "<script>x</script>") {
		t.Fatalf("Markdown 不应原样输出 HTML 标签")
	}
	if !strings.Contains(md, "标题含\\|竖线 与换行&lt;script&gt;") {
		t.Fatalf("竖线/换行/尖括号转义不符:\n%s", md)
	}
	// 发现表格每行必须是同一列数的完整行（竖线已转义）。
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| 1 | xss-reflect |") {
			unescaped := strings.ReplaceAll(line, `\|`, "")
			if strings.Count(unescaped, "|") != 7 {
				t.Fatalf("表格行被内容中的竖线断列: %q", line)
			}
		}
	}
}

// TestRenderComplianceEmptyResult 空结果/空记录：不 panic、仍输出完整条款模板。
func TestRenderComplianceEmptyResult(t *testing.T) {
	cases := []*store.ScanRecord{
		nil,
		{},
		{Result: &engine.Result{}},
		{Result: &engine.Result{URL: "https://empty.example.com", Verified: []map[string]any{}}},
	}
	for i, rec := range cases {
		for _, fw := range []ComplianceFramework{FrameworkMLPS, FrameworkASVS} {
			md, err := RenderCompliance(rec, fw, FormatMarkdown)
			if err != nil {
				t.Fatalf("case %d %s md: %v", i, fw, err)
			}
			if !strings.Contains(md, "合规条款映射") || !strings.Contains(md, "未产生已验证发现") {
				t.Fatalf("case %d %s 空结果报告不完整:\n%s", i, fw, md)
			}
			h, err := RenderCompliance(rec, fw, FormatHTML)
			if err != nil {
				t.Fatalf("case %d %s html: %v", i, fw, err)
			}
			if !strings.Contains(h, "合规条款映射") || !strings.Contains(h, "未产生已验证发现") {
				t.Fatalf("case %d %s 空结果 HTML 不完整", i, fw)
			}
		}
	}
	if md, err := RenderCompliance(nil, FrameworkMLPS, FormatMarkdown); err != nil || !strings.Contains(md, "无详细扫描结果") {
		t.Fatalf("nil 记录应输出无结果说明: err=%v", err)
	}
}

// TestComplianceSeverityOrdering 输入乱序时输出仍按严重度降序分组，
// 且条款判定取最严重级别。
func TestComplianceSeverityOrdering(t *testing.T) {
	res := &engine.Result{
		URL: "https://order.example.com",
		Verified: []map[string]any{
			{"check": "dir-listing", "title": "info-项", "severity": "info", "url": "https://order.example.com/1", "advice": "a"},
			{"check": "xss-reflect", "title": "low-项", "severity": "low", "url": "https://order.example.com/2", "advice": "b"},
			{"check": "weak-cookie", "title": "medium-项", "severity": "medium", "url": "https://order.example.com/3", "advice": "c"},
			{"check": "xss-reflect", "title": "high-项", "severity": "high", "url": "https://order.example.com/4", "advice": "d"},
			{"check": "sqli-error", "title": "critical-项", "severity": "critical", "url": "https://order.example.com/5", "advice": "e"},
			{"check": "unknown-check", "title": "未知严重度", "severity": "weird", "url": "https://order.example.com/6", "advice": "f"},
		},
	}
	md, err := RenderComplianceResult(res, FrameworkASVS, FormatMarkdown)
	if err != nil {
		t.Fatalf("生成: %v", err)
	}
	order := []string{"### 严重（critical", "### 高（high", "### 中（medium", "### 低（low", "### 信息（info"}
	last := -1
	for _, m := range order {
		i := strings.Index(md, m)
		if i < 0 || i < last {
			t.Fatalf("严重度顺序异常（%q）", m)
		}
		last = i
	}
	// 未知严重度归入 info 组。
	if !strings.Contains(md, "未知严重度") {
		t.Fatalf("未知严重度发现应保留在 info 组")
	}
	// 注入类条款因 critical 判不符合。
	if !strings.Contains(md, "| V5.3.4 |") {
		t.Fatalf("ASVS 条款映射缺失")
	}
}

// TestRenderComplianceBadParams 非法框架/格式返回明确错误。
func TestRenderComplianceBadParams(t *testing.T) {
	if _, err := RenderCompliance(complianceFixture(), "iso27001", FormatMarkdown); !errors.Is(err, ErrUnsupportedFramework) {
		t.Fatalf("未知框架应报 ErrUnsupportedFramework: %v", err)
	}
	if _, err := RenderCompliance(complianceFixture(), FrameworkMLPS, "pdf"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("未知格式应报 ErrUnsupportedFormat: %v", err)
	}
	if _, err := RenderComplianceResult(&engine.Result{}, FrameworkMLPS, "docx"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("RenderComplianceResult 未知格式应报错: %v", err)
	}
}
