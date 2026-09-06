# -*- coding: utf-8 -*-
"""知识库数据包导出：把 PG 里的情报/指纹/字典数据导出为可分发文件。

用途：交作业或离线部署时，无需携带 159MB 原始资产包——
导出文件 data/intel_dump.json.gz 随源码分发，import_assets 在
没有资产包时自动加载它恢复知识库。

只导出元数据（无任何 POC 载荷），来源均为公开渠道，可署名。
embedding 列不导出：它是确定性哈希 TF-IDF，导入时按同一公式本地重算。
用法：python tools/export_intel.py
"""
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.db import Database, load_env  # noqa: E402

DUMP_PATH = ROOT / "data" / "intel_dump.json.gz"


def export(db):
    tables = {}
    with db.transaction(dict_rows=True) as cur:
        cur.execute(
            "SELECT src, name, product, cve, type, severity, ref, descr,"
            " affected, sources, cvss_score, cvss_sev, cvss_vector_txt"
            " FROM vuln_kb ORDER BY id")
        tables["vuln_kb"] = [dict(r) for r in cur.fetchall()]
        cur.execute(
            "SELECT name, cat, groups FROM tscan_fingerprints ORDER BY name")
        tables["tscan_fingerprints"] = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT product, spec FROM fingerdir ORDER BY product")
        tables["fingerdir"] = [dict(r) for r in cur.fetchall()]
        cur.execute(
            "SELECT service, pattern, product, version, soft"
            " FROM service_fp ORDER BY id")
        tables["service_fp"] = [dict(r) for r in cur.fetchall()]
        cur.execute(
            "SELECT cve, component, title, severity, impact, date"
            " FROM cve_ms ORDER BY id")
        tables["cve_ms"] = [dict(r) for r in cur.fetchall()]
        cur.execute(
            "SELECT cve, date_added, ransomware FROM kev ORDER BY cve")
        tables["kev"] = [dict(r) for r in cur.fetchall()]

    dump = {
        "kind": "sitelens-intel-dump",
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": tables,
    }
    DUMP_PATH.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(DUMP_PATH, "wt", encoding="utf8", compresslevel=9) as f:
        json.dump(dump, f, ensure_ascii=False, separators=(",", ":"))
    return {name: len(rows) for name, rows in tables.items()}


if __name__ == "__main__":
    res = export(Database(load_env()))
    size = DUMP_PATH.stat().st_size / 1048576
    print("[知识库数据包] %s（%.1f MB）" % (DUMP_PATH.name, size))
    for name, n in res.items():
        print("  %-20s %6d 行" % (name, n))
