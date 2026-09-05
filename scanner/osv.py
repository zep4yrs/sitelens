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
