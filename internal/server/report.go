package server

import (
	"fmt"
	"html"
	"strconv"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// sevClass 严重度白名单映射：仅允许固定枚举进入 class 属性位与展示位，
// 其余一律降级为 info（防御插件/模板/历史回灌注入自由串——SEC-4 加固）。
func sevClass(sev string) string {
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

// htmlReport 渲染单次扫描的 HTML 报告（fmt=html 导出）。
func htmlReport(rec *store.ScanRecord) string {
	var b strings.Builder
	esc := html.EscapeString
	b.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	b.WriteString("<title>SiteLens 报告 - " + esc(rec.URL) + "</title><style>")
	b.WriteString("body{font-family:system-ui,max-width:900px;margin:24px auto;padding:0 16px;color:#1a1a1a}")
	b.WriteString("table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;font-size:14px}")
	b.WriteString("th{background:#f1f5f9}.sev-high{color:#dc2626;font-weight:600}.sev-medium{color:#d97706}.sev-low{color:#2563eb}")
	b.WriteString(".grade{display:inline-block;padding:2px 10px;border:1px solid #e2e8f0;border-radius:6px;font-weight:700}</style></head><body>")
	b.WriteString("<h1>SiteLens 扫描报告</h1>")
	b.WriteString("<p>目标 <strong>" + esc(rec.URL) + "</strong>（" + esc(rec.Host) + "）｜扫描时间 " + esc(rec.ScannedAt) + "｜耗时 " + strconv.FormatFloat(rec.Duration, 'f', 2, 64) + "s</p>")
	title := rec.Title
	b.WriteString("<p>标题：" + esc(title) + " ｜ HTTP " + strconv.Itoa(rec.Status) + "</p>")

	sec := rec.SecurityGrade
	if rec.Result != nil && rec.Result.Security != nil {
		sec = fmt.Sprintf("%s（%d 分）", rec.Result.Security.Grade, rec.Result.Security.Score)
	}
	b.WriteString("<p>安全评分：<span class=\"grade\">" + esc(sec) + "</span></p>")

	if rec.Result == nil {
		b.WriteString("<p>无详细结果数据。</p></body></html>")
		return b.String()
	}

	// 技术清单
	techs := rec.Result.Technologies
	b.WriteString("<h2>识别技术（" + strconv.Itoa(len(techs)) + "）</h2><table><tr><th>技术</th><th>版本</th><th>置信度</th><th>类别</th></tr>")
	for _, t := range techs {
		cats := make([]string, 0, len(t.Categories))
		for _, c := range t.Categories {
			cats = append(cats, categoryName(c))
		}
		b.WriteString("<tr><td>" + esc(t.Name) + "</td><td>" + esc(t.Version) + "</td><td>" + strconv.Itoa(t.Confidence) + "%</td><td>" + esc(strings.Join(cats, " / ")) + "</td></tr>")
	}
	b.WriteString("</table>")

	// 已验证发现
	if rec.Result != nil {
		b.WriteString("<h2>已验证发现（" + strconv.Itoa(len(rec.Result.Verified)) + "）</h2>")
		if len(rec.Result.Verified) == 0 {
			b.WriteString("<p>无</p>")
		} else {
			b.WriteString("<table><tr><th>严重度</th><th>标题</th><th>URL</th><th>证据</th><th>建议</th></tr>")
			for _, v := range rec.Result.Verified {
				sev, _ := v["severity"].(string)
				tit, _ := v["title"].(string)
				u, _ := v["url"].(string)
				ev, _ := v["evidence"].(string)
				ad, _ := v["advice"].(string)
				b.WriteString("<tr><td class=\"sev-" + sevClass(sev) + "\">" + sevClass(sev) + "</td><td>" + esc(tit) + "</td><td>" + esc(u) + "</td><td>" + esc(ev) + "</td><td>" + esc(ad) + "</td></tr>")
			}
			b.WriteString("</table>")
		}

		// 漏洞情报
		b.WriteString("<h2>漏洞情报关联（" + strconv.Itoa(len(rec.Result.Vulnerabilities)) + "）</h2>")
		if len(rec.Result.Vulnerabilities) == 0 {
			b.WriteString("<p>无</p>")
		} else {
			b.WriteString("<table><tr><th>严重度</th><th>技术</th><th>CVE</th><th>名称</th><th>判定</th><th>KEV</th></tr>")
			for _, v := range rec.Result.Vulnerabilities {
				kev := ""
				if v.KEV {
					kev = "KEV!"
				}
				b.WriteString("<tr><td class=\"sev-" + sevClass(v.Severity) + "\">" + sevClass(v.SeverityZh) + "</td><td>" + esc(v.Tech) + "</td><td>" + esc(v.CVE) + "</td><td>" + esc(v.Name) + "</td><td>" + esc(v.Verdict) + "</td><td>" + kev + "</td></tr>")
			}
			b.WriteString("</table>")
		}
	}
	b.WriteString("<p style=\"color:#64748b;font-size:12px\">由 SiteLens " + Version + " 生成；发现为辅助人工复查线索，非最终判决。</p>")
	b.WriteString("</body></html>")
	return b.String()
}
