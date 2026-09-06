# -*- coding: utf-8 -*-
"""漏洞情报匹配：把识别出的技术映射到已知漏洞（vuln_kb + cve_ms）。

定位是「情报提示」而非「漏洞验证」——只按产品名/类别做情报关联，
不发起任何攻击性请求。输出按严重度排序，单技术最多保留 N 条。
配合 M2 版本区间判定（version_cmp）输出三级结论。
"""
import json
from pathlib import Path

from .version_cmp import version_in

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

MAX_PER_TECH = 20


class VulnMatcher:
    """技术 → 漏洞情报关联器（组合 KnowledgeBase）"""

    def __init__(self, kb):
        self._kb = kb
        self._kev = set()
        try:
            with kb.db.transaction(dict_rows=True) as cur:
                cur.execute("SELECT cve FROM kev")
                self._kev = {r["cve"] for r in cur.fetchall()}
        except Exception:
            self._kev = set()
        self._ranges = {}
        rng_path = Path(__file__).resolve().parents[1] / "data" / "affected_ranges.json"
        if rng_path.exists():
            self._ranges = json.loads(rng_path.read_text(encoding="utf8"))

    def match(self, technologies):
        """输入 Technology 列表，返回按严重度排序的漏洞情报列表。

        三级结论：confirmed（版本落在受影响区间）/ possible（同名提示）/
        excluded（有版本但不在区间，直接跳过不输出）。
        """
        out, seen = [], set()
        for tech in technologies:
            ranges = self._ranges.get(tech.name.lower(), [])
            if tech.version and ranges:
                # 有精确版本且该技术有区间数据：只输出区间判定结论
                for r in ranges:
                    if version_in(tech.version, r["affected"]):
                        out.append({"tech": tech.name, "version": tech.version,
                                    "cve": r.get("cve", ""), "title": r.get("title", ""),
                                    "severity": "high", "severity_zh": "确认受影响",
                                    "verdict": "confirmed", "src": "intel-range",
                                    "type": "", "ref": "", "name": r.get("title", ""),
                                    "product": tech.name, "descr": ""})
                continue
            hits = self._kb.vulns_for(tech.name)
            hits.sort(key=lambda v: SEV_ORDER.get(v["severity"], 4))
            for v in hits[:MAX_PER_TECH]:
                if v["id"] in seen:
                    continue
                # 版本区间三级判定（vuln_kb.affected 为 "|" 分隔的多组区间）
                verdict = "possible"
                if tech.version and v.get("affected"):
                    alts = [a.strip() for a in v["affected"].split("|") if a.strip()]
                    if alts:
                        verdict = "confirmed" if any(
                            version_in(tech.version, a) for a in alts) else "excluded"
                if verdict == "excluded":
                    seen.add(v["id"])
                    continue
                seen.add(v["id"])
                out.append({
                    "id": v["id"],
                    "tech": tech.name,
                    "version": tech.version or "",
                    "src": v["src"],
                    "name": v["name"],
                    "product": v["product"],
                    "cve": v["cve"],
                    "type": v["type"],
                    "severity": v["severity"],
                    "severity_zh": SEV_ZH.get(v["severity"], v["severity"]),
                    "ref": v["ref"],
                    "desc": v["descr"],
                    "verdict": verdict,
                    "affected": v.get("affected", ""),
                    "kev": (v.get("cve") or "") in self._kev,
                })
        out.sort(key=lambda v: SEV_ORDER.get(v["severity"], 4))
        return out

    # 技术名 → 微软公告组件名的常见别名
    MS_ALIASES = {
        "Microsoft IIS": "Internet Information Services",
        "ASP.NET": "ASP.NET Core",
        "Microsoft Edge": "Edge",
    }

    def match_cve_ms(self, technologies, limit=40):
        """微软安全公告索引关联（按组件名双向包含匹配）。

        cve_ms 表由资产包导入；空库部署时表不存在，静默跳过不阻塞扫描。
        """
        out, seen = [], set()
        for tech in technologies:
            for name in {tech.name, self.MS_ALIASES.get(tech.name, "")} - {""}:
                try:
                    with self._kb.db.transaction(dict_rows=True) as cur:
                        cur.execute(
                            "SELECT cve, component, title, severity, impact FROM cve_ms"
                            " WHERE position(lower(%s) in lower(component)) > 0"
                            " ORDER BY cve DESC LIMIT %s",
                            (name, 10))
                        rows = cur.fetchall()
                except Exception:
                    return sorted(out, key=lambda v: SEV_ORDER.get(v["severity"], 4))[:limit]
                for r in rows:
                        if r["cve"] in seen:
                            continue
                        seen.add(r["cve"])
                        sev = (r["severity"] or "").lower()
                        out.append({
                            "tech": tech.name,
                            "cve": r["cve"], "title": r["title"], "component": r["component"],
                            "severity": sev,
                            "severity_zh": SEV_ZH.get(sev, sev),
                            "src": "ms-bulletin", "ref": "", "type": r["impact"] or "",
                        })
        out.sort(key=lambda v: SEV_ORDER.get(v["severity"], 4))
        return out[:limit]
