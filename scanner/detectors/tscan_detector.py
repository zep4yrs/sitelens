# -*- coding: utf-8 -*-
"""TscanPlus 指纹检测器：数据驱动的表达式引擎（2481 产品 / 4533 条件）。

规则结构（导入器生成）：
    [{"name": "Nacos", "cat": "middleware",
      "groups": [[{"f": "body", "n": false, "v": "console-ui"},
                  {"f": "header", "n": true, "v": "Server: nginx"}], ...]}, ...]
一组内条件 AND，组间 OR；"n": true 表示取反（!=）。
字段：body（HTML 原文包含）、title（标题包含）、header（响应头块包含）、
     icon_hash（favicon 的 fofa hash，见 scanner/favicon.py）。
"""
from .base import BaseDetector
import re


class TscanDetector(BaseDetector):
    """评估 TscanPlus 表达式指纹（FIELD=None：自带 scan 循环）"""

    FIELD = None
    SOURCE = "指纹库"

    def __init__(self, tscan_fingerprints):
        # 直接持有 tscan 结构（不走 BaseDetector 的指纹遍历）
        self._products = tscan_fingerprints
        self._needs_icon = any(
            cond.get("f") == "icon_hash"
            for t in tscan_fingerprints for group in t["groups"] for cond in group
        )

    @property
    def needs_icon(self):
        """是否需要 favicon hash（引擎据此决定是否抓取图标）"""
        return self._needs_icon

    def scan(self, evidence, signals=None):
        body = evidence.body or ""
        title = evidence.title or ""
        header_block = "\n".join("%s: %s" % (k, v) for k, v in evidence.headers.items())
        icon_hash = getattr(signals, "favicon_hash", None) if signals else None

        field_values = {
            "body": body.lower(),
            "title": title.lower(),
            "header": header_block.lower(),
        }

        hits = []
        for product in self._products:
            matched_detail = None
            for group in product["groups"]:
                if self._group_match(group, field_values, icon_hash):
                    matched_detail = group
                    break
            if matched_detail:
                conds = " && ".join(
                    ("非" if c.get("n") else "") + c["f"] + "含" + c["v"][:40]
                    for c in matched_detail)
                hits.append((product["name"], conds, None))
        return hits

    @staticmethod
    def _contains(haystack, needle):
        """包含判断；短词（<=6 字符）要求非字母边界，防止 plex 误中 complex"""
        if len(needle) <= 6 and needle.isalnum():
            pattern = r"(?:^|[^a-z0-9])" + re.escape(needle) + r"(?:$|[^a-z0-9])"
            return re.search(pattern, haystack) is not None
        return needle in haystack

    def _group_match(self, group, field_values, icon_hash):
        for cond in group:
            f, negated, value = cond["f"], cond.get("n", False), cond["v"]
            if f == "icon_hash":
                try:
                    hit = (icon_hash is not None and int(value) == icon_hash)
                except (TypeError, ValueError):
                    hit = False
            else:
                hit = self._contains(field_values.get(f, ""), value.lower())
            if negated:
                hit = not hit
            if not hit:
                return False       # AND 短路
        return True

    def detect(self, evidence, signals=None):
        return self.scan(evidence, signals)

    def _match_fingerprint(self, rule, evidence, signals):
        return None, None
