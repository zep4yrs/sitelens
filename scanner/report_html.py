# -*- coding: utf-8 -*-
"""单文件 HTML 扫描报告：内联全部样式，离线双击即可打开。"""
import html


def render_html(r):
    """结果 dict → 独立 HTML 报告"""
    esc = lambda s: html.escape(str(s if s is not None else ""))
    sec = r.get("security") or {}
    grade = sec.get("grade", "-")
    grade_cls = "danger" if grade in ("F", "D") else ("warn" if grade == "C" else "ok")

    tech_rows = []
    for t in sorted(r.get("technologies", []), key=lambda x: -x.get("confidence", 0)):
        cats = " / ".join(t.get("categories") or []) or "misc"
        ev = esc(" | ".join(t.get("evidence") or []))
        tech_rows.append(
            "<tr><td><b>%s</b> %s</td><td>%s</td><td>%d%%</td><td class='mono small'>%s</td></tr>"
            % (esc(t["name"]), esc("v" + t["version"]) if t.get("version") else "",
               esc(cats), t.get("confidence", 0), ev))

    vuln_rows = []
    for v in (r.get("vulnerabilities") or [])[:60]:
        vuln_rows.append(
            "<tr><td><span class='sev sev-%s'>%s</span></td><td class='mono'>%s</td>"
            "<td>%s %s</td><td>%s</td><td class='mono small'>%s</td></tr>"
            % (esc(v.get("severity", "")), esc(v.get("severity_zh") or v.get("severity") or "-"),
               esc(v.get("tech")), esc(v.get("cve") or ""), esc(v.get("name") or v.get("title") or ""),
               esc(v.get("type") or "-"), esc(v.get("src"))))

    extras_html = ""
    titles = {"active_fp": "主动路径指纹", "dir_scan": "目录探测",
              "subdomain": "子域名", "service": "端口服务"}
    for key, items in (r.get("extras") or {}).items():
        lines = []
        for it in items:
            if key == "dir_scan":
                # 命中条目存的是完整 url（v1.0.2 起不含 path 字段）
                u = it.get("url") or it.get("path") or ""
                p = u.replace("://", " ", 1).split("/", 1)
                loc = "/" + p[1] if len(p) > 1 else u
                lines.append("%s → %s (%dB) %s" % (loc, it.get("status"), it.get("size"), it.get("title") or ""))
            elif key == "subdomain":
                lines.append("%s → %s" % (it.get("subdomain"), it.get("ip")))
            elif key == "service":
                lines.append(":%s %s %s" % (it.get("port"), it.get("service") or "", it.get("product") or ""))
            else:
                lines.append("%s (%s, %s)" % (it.get("product"), it.get("path"), it.get("status")))
        extras_html += "<h2>%s <small>%d</small></h2><pre>%s</pre>" % (
            esc(titles.get(key, key)), len(items), esc("\n".join(map(str, lines))))

    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SiteLens 报告 — __HOST__</title><style>
@media print { body { background: #fff; } .wrap { padding: 0; } }
body{margin:0;background:#fafafa;color:#1a1a1a;font:15px/1.6 "Noto Sans SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:40px 24px 80px}
h1{font-family:ui-monospace,Consolas,monospace;font-size:26px;margin:0 0 4px}
h2{font-family:ui-monospace,Consolas,monospace;font-size:18px;margin:34px 0 10px}
h2 small{color:#94a3b8;font-weight:400;font-size:13px}
.sub{color:#64748b;font-size:13px;margin-bottom:26px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:10px}
.cell{background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px}
.cell span{display:block;font-size:11px;color:#94a3b8}
.cell b{font-size:14px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:#fff;border:1px solid #e2e8f0;border-radius:6px}
th{text-align:left;padding:8px 10px;color:#64748b;font-weight:500;border-bottom:1px solid #e2e8f0;font-size:12px}
td{padding:8px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
.mono{font-family:ui-monospace,Consolas,monospace}.small{font-size:11px;color:#94a3b8}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
 border:1px solid #e2e8f0;background:#f8fafc}
.ok{color:#16a34a;border-color:#16a34a55;background:#16a34a11}
.warn{color:#d97706;border-color:#d9770655;background:#d9770611}
.danger{color:#dc2626;border-color:#dc262655;background:#dc262611}
.sev{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11.5px;color:#fff}
.sev-critical{background:#dc2626}.sev-high{background:#ea580c}.sev-medium{background:#d97706}.sev-low{background:#65a30d}
pre{background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:12px 14px;
 font:12.5px/1.9 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
a{color:#2563eb}
.foot{color:#94a3b8;font-size:12px;margin-top:40px;text-align:center}
</style></head><body><div class="wrap">
<h1>sitelens<span style="color:#16a34a">·</span>扫描报告</h1>
<div class="sub">生成于 __NOW__ · SiteLens/1.0 · 结果存于 PostgreSQL</div>
<div class="summary">
<div class="cell"><span>目标</span><b>__URL__</b></div>
<div class="cell"><span>标题</span><b>__TITLE__</b></div>
<div class="cell"><span>IP</span><b>__IP__</b></div>
<div class="cell"><span>响应</span><b>__RT__ ms</b></div>
<div class="cell"><span>安全响应头</span><b><span class="badge __GC__">__GRADE__ __SCORE__分</span></b></div>
<div class="cell"><span>耗时</span><b>__DUR__s</b></div>
</div>
<h2>指纹识别 <small>__NTECH__ 项</small></h2>
<table><tr><th>技术</th><th>类别</th><th>置信度</th><th>命中证据</th></tr>__TECH__</table>
<h2>漏洞情报关联 <small>__NVULN__ 条（按组件关联的历史漏洞，非漏洞验证）</small></h2>
__VULN__
__EXTRAS__
<div class="foot">SiteLens 站点透视 · 仅用于授权的安全研究与学习 · JSON 原始数据可经 /api/export/__SID__?fmt=json 获取</div>
</div></body></html>""" \
        .replace("__HOST__", esc(r.get("host"))) \
        .replace("__NOW__", esc(r.get("scanned_at"))) \
        .replace("__URL__", esc(r.get("url"))) \
        .replace("__TITLE__", esc((r.get("title") or "-")[:60])) \
        .replace("__IP__", esc(r.get("ip") or "-")) \
        .replace("__RT__", str(r.get("response_time_ms", 0))) \
        .replace("__GRADE__", esc(grade)) \
        .replace("__GC__", grade_cls) \
        .replace("__SCORE__", str(sec.get("score", 0))) \
        .replace("__DUR__", str(r.get("duration", 0))) \
        .replace("__NTECH__", str(len(r.get("technologies", [])))) \
        .replace("__TECH__", "".join(tech_rows) or "<tr><td colspan=4>无</td></tr>") \
        .replace("__NVULN__", str(len(r.get("vulnerabilities", [])))) \
        .replace("__VULN__", (
            "<table><tr><th>严重度</th><th>技术</th><th>漏洞</th><th>类型</th><th>来源</th></tr>"
            + "".join(vuln_rows) + "</table>")
            if vuln_rows else "<p style='color:#94a3b8;font-size:13px'>未命中已知漏洞情报。</p>") \
        .replace("__EXTRAS__", extras_html) \
        .replace("__SID__", esc(r.get("_scan_id", "")))
