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
from scanner.osv import osv_by_cve, cvss_v3_score, cvss_label  # noqa: E402

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


# ---------------------------------------------------------------- 全量多源同步（OSV + GHSA）
import concurrent.futures as _cf

_gh_token_cache = None


def _gh_headers():
    """复用 gh CLI 登录令牌访问 GitHub Advisory API（REST 5000 次/小时）"""
    global _gh_token_cache
    if _gh_token_cache is None:
        try:
            import subprocess
            r = subprocess.run(["gh", "auth", "token"],
                               capture_output=True, text=True, timeout=10)
            _gh_token_cache = r.stdout.strip() if (
                r.returncode == 0 and r.stdout.strip()) else ""
        except Exception:
            _gh_token_cache = ""
    return ({"Authorization": "Bearer " + _gh_token_cache,
             "Accept": "application/vnd.github+json"} if _gh_token_cache else {})


def ghsa_lookup(cve):
    """GitHub Advisory 按 CVE 查询；返回公告 dict 或 None"""
    import requests
    try:
        r = requests.get("https://api.github.com/advisories",
                         params={"cve_id": cve},
                         headers=_gh_headers(), timeout=15)
        if r.status_code == 200:
            items = r.json()
            return items[0] if items else None
    except Exception:
        return None
    return None


def _norm_range(r):
    """版本区间归一化：去掉空格（>= 2.0, < 2.14.2 → >=2.0,<2.14.2）"""
    return (r or "").replace(" ", "")


def _merge_ranges(old, parts):
    """合并区间组，'|' 分隔多组，去重保序"""
    out = []
    for p in list((old or "").split("|")) + list(parts or []):
        p = (p or "").strip()
        if p and p not in out:
            out.append(p)
    return "|".join(out)


def ensure_ext_columns(db):
    """多源同步所需的扩展列（幂等，全部内联字面量 DDL）"""
    with db.transaction(dict_rows=True) as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_name = 'vuln_kb'")
        have = {r["column_name"] for r in cur.fetchall()}
        if "sources" not in have:
            cur.execute("ALTER TABLE vuln_kb ADD COLUMN sources TEXT DEFAULT ''")
        if "cvss_score" not in have:
            cur.execute("ALTER TABLE vuln_kb ADD COLUMN cvss_score REAL DEFAULT 0")
        if "cvss_sev" not in have:
            cur.execute("ALTER TABLE vuln_kb ADD COLUMN cvss_sev TEXT DEFAULT ''")
        if "cvss_vector_txt" not in have:
            cur.execute(
                "ALTER TABLE vuln_kb ADD COLUMN cvss_vector_txt TEXT DEFAULT ''")


def full_sync(db, workers=16, progress=None, do_osv=True, do_ghsa=True):
    """全量多源同步：vuln_kb 全部 CVE × (OSV 刷新 + GHSA 官方公告)。

    刷新语义：已有区间的 CVE 也重查（区间可能更新），合并去重；
    来源写入 sources 列；GHSA 的 CVSS 写入 cvss_score/cvss_sev/cvss_vector_txt。
    """
    ensure_ext_columns(db)
    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT DISTINCT cve FROM vuln_kb"
                    " WHERE cve <> '' ORDER BY cve")
        cves = [r["cve"] for r in cur.fetchall()]
    total = len(cves)
    if not total:
        return {"cves": 0}

    def worker(cve):
        out = {"cve": cve}
        if do_osv:
            try:
                out["osv"] = osv_by_cve(cve)
            except Exception:
                out["osv"] = None
        if do_ghsa:
            out["ghsa"] = ghsa_lookup(cve)
        return out

    done_n = 0
    results = []
    with _cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for out in pool.map(worker, cves):
            results.append(out)
            done_n += 1
            if progress and done_n % 25 == 0:
                progress(done_n, total, "查询中 %d/%d" % (done_n, total))

    n_osv = n_ghsa = n_ranges = 0
    with db.transaction(dict_rows=True) as cur:
        for out in results:
            cve = out["cve"]
            osv_r = out.get("osv")
            g = out.get("ghsa")
            parts, sources, score, sev, vec_txt = [], set(), 0, "", ""
            if osv_r and osv_r[0]:
                n_osv += 1
                sources.add("osv")
                parts += [_norm_range(x) for x in osv_r[0]]
            if g:
                n_ghsa += 1
                sources.add("ghsa")
                sev = (g.get("severity") or "").lower()
                cv = g.get("cvss") or {}
                score = cv.get("score") or 0
                vec_txt = cv.get("vector_string") or ""
                for v in (g.get("vulnerabilities") or []):
                    vr = _norm_range(v.get("vulnerable_version_range"))
                    if vr:
                        parts.append(vr)
            if not score and osv_r and len(osv_r) > 1 and osv_r[1]:
                # GHSA 未给分时：用 OSV 的 CVSS 向量本地计分（无需 NVD）
                vec_txt = osv_r[1]
                score = cvss_v3_score(vec_txt)
                sev = cvss_label(score)
            cur.execute("SELECT affected, sources FROM vuln_kb"
                        " WHERE cve = %s LIMIT 1", (cve,))
            row = cur.fetchone()
            if not row:
                continue
            merged = _merge_ranges(row["affected"], parts)
            if merged:
                n_ranges += 1
            src_set = [s for s in (row["sources"] or "").replace("|", ",").split(",")
                       if s.strip()]
            for s in sources:
                if s not in src_set:
                    src_set.append(s)
            src_new = ",".join(src_set)
            cur.execute(
                "UPDATE vuln_kb SET affected = %s, sources = %s,"
                " cvss_score = %s, cvss_sev = %s, cvss_vector_txt = %s"
                " WHERE cve = %s",
                (merged, src_new, score, sev, vec_txt, cve))

    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT COALESCE(SUM((affected <> '')::int),0) AS n FROM vuln_kb")
        with_ranges = cur.fetchone()["n"]
    return {"cves": total, "osv_hits": n_osv, "ghsa_hits": n_ghsa,
            "rows_with_ranges": with_ranges}


def nvd_sync(db, api_key, progress=None, interval=0.65):
    """NVD API 2.0 评分补全（可选，需 api_key；nvd.nist.gov 免费申请）"""
    import requests
    import time
    ensure_ext_columns(db)
    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT DISTINCT cve FROM vuln_kb"
                    " WHERE cve <> '' AND (cvss_score IS NULL OR cvss_score = 0)"
                    " ORDER BY cve")
        cves = [r["cve"] for r in cur.fetchall()]
    n = 0
    for i, cve in enumerate(cves):
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve},
                headers={"apiKey": api_key}, timeout=20)
            vulns = (r.json() or {}).get("vulnerabilities") or []
            if vulns:
                metrics = (vulns[0].get("cve", {}).get("metrics") or {})
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(k):
                        m = metrics[k][0].get("cvssData", {})
                        with db.transaction() as cur:
                            cur.execute(
                                "UPDATE vuln_kb SET cvss_score = %s, cvss_sev = %s,"
                                " cvss_vector_txt = %s, sources = %s"
                                " WHERE cve = %s",
                                (m.get("baseScore", 0),
                                 str(m.get("baseSeverity",
                                           m.get("baseScore", ""))).lower(),
                                 m.get("vectorString", ""),
                                 "nvd", cve))
                        n += 1
                        break
        except Exception:
            pass
        if progress:
            progress(i + 1, len(cves), cve)
        time.sleep(interval)
    return {"enriched": n, "total": len(cves)}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "full":
        db = Database()

        def _p(d, t, m):
            print("\r  %d/%d %s" % (d, t, m), end="", flush=True)

        res = full_sync(db, progress=_p)
        print("\n[全量同步] CVE %d | OSV 命中 %d | GHSA 命中 %d | 带区间行 %d"
              % (res["cves"], res["osv_hits"], res["ghsa_hits"],
                 res["rows_with_ranges"]))
    elif len(sys.argv) > 1 and sys.argv[1] == "nvd":
        key = sys.argv[2] if len(sys.argv) > 2 else ""
        if not key:
            print("用法：python tools/update_intel.py nvd <NVD_API_KEY>")
        else:
            res = nvd_sync(Database(), key,
                           progress=lambda d, t, m: (
                               print("\r  %d/%d %s" % (d, t, m),
                                     end="", flush=True)))
            print("\n[NVD] 补全 %d/%d" % (res["enriched"], res["total"]))
    else:
        main()
