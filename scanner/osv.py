# -*- coding: utf-8 -*-
"""OSV.dev 单 CVE 查询：返回受影响版本区间与 CVSS 向量。

HTTP 请求复用 scanner.fetcher.Fetcher（限速/UA 统一管理），
本模块只负责 URL 构造（字面量前缀 + 严格校验的 CVE id）与 JSON 解析。
"""
import json
import re
from urllib.parse import urljoin

from .fetcher import Fetcher

OSV_BASE = "https://api.osv.dev/v1/vulns/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_fetcher = None


def _get_fetcher():
    global _fetcher
    if _fetcher is None:
        _fetcher = Fetcher(rate_interval=0.05)
    return _fetcher


def osv_by_cve(cve, fetcher=None):
    """查询单个 CVE：返回 (区间列表, CVSS 向量) 或 None。

    cve 必须匹配严格格式；URL 由字面量前缀经 urljoin 构造。
    """
    if not cve or not CVE_RE.fullmatch(cve.upper()):
        return None
    url = urljoin(OSV_BASE, cve.upper())
    f = fetcher or _get_fetcher()
    try:
        resp = f.get_small(url)
        if resp.get("status") != 200:
            return None
        d = json.loads(resp.get("body") or "{}")
    except Exception:
        return None
    ranges, vector = [], ""
    for aff in d.get("affected", []):
        for rg in aff.get("ranges", []):
            if rg.get("type") not in ("ECOSYSTEM", "GIT"):
                continue
            introduced, fixed, last = "0", None, None
            for ev in rg.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                if "last_affected" in ev:
                    last = ev["last_affected"]
            segs = []
            if introduced and introduced != "0":
                segs.append(">=" + introduced)
            if fixed:
                segs.append("<" + fixed)
            elif last:
                segs.append("<=" + last)
            seg = ",".join(segs)
            if seg:
                ranges.append(seg)
    for sev in d.get("severity", []):
        if str(sev.get("type", "")).upper().startswith("CVSS"):
            vector = str(sev.get("score", ""))
            break
    return ranges, vector


# ---------------------------------------------------------------- CVSS v3 本地计分
_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss_v3_score(vector):
    """从 CVSS v3.x 向量按官方公式计算基础分（0-10）；向量非法返回 0。

    纯本地计算，无需访问 NVD。
    """
    if not vector or not vector.startswith("CVSS:"):
        return 0.0
    vals = {}
    for part in vector.split("/")[1:]:
        kv = part.split(":")
        if len(kv) == 2:
            vals[kv[0]] = kv[1]
    try:
        av = _CVSS_W["AV"][vals.get("AV", "N")]
        ac = _CVSS_W["AC"][vals.get("AC", "L")]
        scope_changed = vals.get("S") == "C"
        pr = _CVSS_W["PR"]["C" if scope_changed else "U"][vals.get("PR", "N")]
        ui = _CVSS_W["UI"][vals.get("UI", "N")]
        c = _CVSS_W["CIA"][vals.get("C", "N")]
        i = _CVSS_W["CIA"][vals.get("I", "N")]
        a = _CVSS_W["CIA"][vals.get("A", "N")]
    except KeyError:
        return 0.0
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    import math
    exploitability = 8.22 * av * ac * pr * ui
    return min(math.ceil((impact + exploitability) * 10) / 10, 10.0)


def cvss_label(score):
    """分数 → 严重度标签（与 GHSA/NVD 口径一致）"""
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return ""
