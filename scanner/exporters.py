# -*- coding: utf-8 -*-
"""结果导出：JSON / 明细 CSV / 批量宽表 CSV（均基于结果 dict，便于从历史导出）。

宽表 CSV 与 Wappalyzer 类工具的导出格式一致：
第一列 URL，之后每列一个类别，一格内多个技术用 " ; " 分隔。
"""
import csv
import io
import json


class Exporter:
    """导出器（依赖 Registry 提供类别全集与顺序）"""

    def __init__(self, registry):
        self._registry = registry
        self._cat_order = list(registry.categories.keys())

    def to_json(self, result_dict):
        return json.dumps(result_dict, ensure_ascii=False, indent=2)

    def detail_csv(self, result_dict):
        """明细 CSV：每行一项技术（含类别/置信度/版本/证据）"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["技术", "类别", "置信度", "版本", "官网", "证据"])
        for t in result_dict.get("technologies", []):
            cats = " / ".join(self._registry.category_name(c) for c in t.get("categories", []))
            writer.writerow([t["name"], cats, "%d%%" % t.get("confidence", 0),
                             t.get("version") or "", t.get("website", ""),
                             " | ".join(t.get("evidence", []))])
        return buf.getvalue()

    def wide_csv(self, result_dicts):
        """宽表 CSV：多站点一张表（URL + 每类别一列）"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        header = ["URL"] + [self._registry.category_name(c) for c in self._cat_order]
        writer.writerow(header)
        for rd in result_dicts:
            cells = {c: [] for c in self._cat_order}
            for tech in rd.get("technologies", []):
                for cat in tech.get("categories", []):
                    if cat in cells:
                        cells[cat].append(tech["name"])
            line = [rd.get("url", "")]
            for c in self._cat_order:
                line.append(" ; ".join(cells[c]))
            writer.writerow(line)
        return buf.getvalue()

    def vuln_csv(self, result_dict):
        """漏洞情报 CSV：每行一条关联"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["涉及技术", "严重度", "CVE", "漏洞名称", "类型", "来源", "参考链接"])
        for v in result_dict.get("vulnerabilities", []):
            writer.writerow([v.get("tech"), v.get("severity_zh", v.get("severity")),
                             v.get("cve") or "-", v.get("name"), v.get("type"),
                             v.get("src"), v.get("ref")])
        return buf.getvalue()
