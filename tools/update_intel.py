# -*- coding: utf-8 -*-
"""情报数据更新管线：给 vuln_kb 补版本区间（OSV querybatch）+ KEV 在野利用标记。

用法：python tools/update_intel.py
- OSV.dev querybatch 按 CVE 批量补 affected 区间（| 分隔多组）与 CVSS 向量
- CISA KEV 拉"已知在野利用"清单（网络不通则跳过，不影响其余步骤）
两个数据源 URL 均为字面量，无用户输入参与拼接。
"""
import concurrent.futures
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.db import Database  # noqa: E402
from scanner.osv import osv_by_cve  # noqa: E402

BATCH = 100


def enrich_batch(cves):
    """一批 CVE 逐个查 OSV（返回 {cve: (ranges, vector)}）"""
    out = {}
    for cve in cves:
        r = osv_by_cve(cve)
        if r and r[0]:
            out[cve] = r
    return out


def update_kev():
    """拉取 CISA KEV 在野利用清单入库（网络不通则静默跳过）"""
    import requests
    try:
        kev = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json", timeout=30).json()
        rows = [(v["cveID"], v.get("dateAdded", ""),
                 v.get("knownRansomwareCampaignUse", "Unknown"))
                for v in kev.get("vulnerabilities", [])]
        db = Database()
        with db.transaction() as cur:
            cur.execute("DELETE FROM kev")
            for i in range(0, len(rows), 500):
                cur.executemany(
                    "INSERT INTO kev (cve, date_added, ransomware) VALUES (%s,%s,%s)"
                    " ON CONFLICT (cve) DO NOTHING", rows[i:i + 500])
        return len(rows)
    except Exception:
        return 0


def main():
    db = Database()
    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT DISTINCT cve FROM vuln_kb"
                    " WHERE cve <> '' AND (affected IS NULL OR affected = '')")
        cves = [r["cve"] for r in cur.fetchall()]
    print("待补区间 CVE:", len(cves))

    ok = 0
    for start in range(0, len(cves), BATCH):
        chunk = cves[start:start + BATCH]
        got = enrich_batch(chunk)
        with db.transaction() as cur:
            for cve, (ranges, vector) in got.items():
                cur.execute(
                    "UPDATE vuln_kb SET affected = %s, cvss_vec = %s"
                    " WHERE cve = %s AND (affected IS NULL OR affected = '')",
                    ("|".join(ranges), vector, cve))
        ok += len(got)
        print(f"  进度 {min(start + BATCH, len(cves))}/{len(cves)}（命中 {ok}）")

    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT COALESCE(SUM((affected <> '')::int),0) AS n FROM vuln_kb")
        print("vuln_kb 带区间条数:", cur.fetchone()["n"])

    # ---- CISA KEV 在野利用清单（网络不通则跳过） ----
    try:
        kev = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=30).json()
        rows = [(v["cveID"], v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", "Unknown"))
                for v in kev.get("vulnerabilities", [])]
        with db.transaction() as cur:
            cur.execute("DELETE FROM kev")
            for i in range(0, len(rows), 500):
                cur.executemany(
                    "INSERT INTO kev (cve, date_added, ransomware) VALUES (%s,%s,%s)"
                    " ON CONFLICT (cve) DO NOTHING",
                    rows[i:i + 500])
        print("[KEV] 在野利用清单:", len(rows), "条")
    except Exception as e:
        print("[KEV] 跳过（网络不可达）:", type(e).__name__)


if __name__ == "__main__":
    main()
