"""Dataset 构建（P2）：真实历史扫描 → D1-D5 五张表 + 内置 check 候选集。

所有表每行都带 scan_uid/host/scanned_at_dt/era/data_origin（隔离与追溯要求，
开发文档 §2）。输出落 data/ml/dataset/ + DATASET_MANIFEST.json + 统计。

诚实性约束（开发文档 §2 D4）：
  - D4 行本身 = executed ∧ 命中（命中才落库），execution_status=executed；
  - 候选集中"未见命中"的组合 execution_status=unknown（无执行日志，
    内置 check 仅能由 options.checks 档位推断"被选择"，推断不出单请求
    成败，更推断不出可靠 not_executed）；
  - unknown 绝不记为 negative（negative 只能来自 executed ∧ 未命中，
    当前历史为 0，由 Label 阶段断言）。
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pandas as pd

from . import config, manifest, normalize, readers

CATALOG_PATH = Path(__file__).parent / "data" / "check_catalog.json"

# T2 candidate 的排除原因（每一条都要在统计里可解释）
EXCL_LEVEL_NONE = "options.checks=none（check 引擎未启用）"
EXCL_LEVEL_UNKNOWN = "options 缺 checks 档位（无法复原当时选择）"
EXCL_UNREACHABLE = "扫描失败（result.error 非空，引擎早期退出未跑 check）"

TABLE_FILES = {
    "scans": "d1_scans.jsonl.gz", "techs": "d2_techs.jsonl.gz",
    "intel": "d3_intel.jsonl.gz", "verified": "d4_verified.jsonl.gz",
    "candidates": "d4b_candidates.jsonl.gz", "cve_features": "d5_cve_features.jsonl.gz",
    "tech_catalog": "d5_tech_catalog.jsonl.gz",
}


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def build_tables(paths: config.Paths) -> tuple[dict[str, pd.DataFrame], dict, list[dict]]:
    """主入口：读取全部来源 → 构表 → 统计。返回 (tables, stats, inputs)。"""
    catalog = load_catalog()
    records, src_stats = readers.load_all_scans(paths)
    tables, stats = build_from_records(records, catalog)
    tables["cve_features"] = build_cve_features(paths, tables["intel"])
    tables["tech_catalog"] = build_tech_catalog(paths)
    stats["source"] = src_stats
    stats["counts"] = {k: int(len(v)) for k, v in tables.items()}

    inputs = [manifest.file_input(paths.history_json, role="source:history")]
    if paths.premigrate_json.is_file():
        inputs.append(manifest.file_input(paths.premigrate_json, role="source:premigrate"))
    if paths.matrix_dir and Path(paths.matrix_dir).is_dir():
        for p in sorted(Path(paths.matrix_dir).glob("*.json")):
            inputs.append(manifest.file_input(p, role="source:matrix"))
    inputs.append(manifest.file_input(CATALOG_PATH, role="config:check_catalog"))
    return tables, stats, inputs


def build_from_records(
    records: list[dict], catalog: dict,
    cve_features: pd.DataFrame | None = None,
    tech_catalog: pd.DataFrame | None = None,
) -> tuple[dict[str, pd.DataFrame], dict]:
    """从扫描记录构建各表（与来源解耦，真实数据与测试夹具共用）。"""
    checks = {c["id"]: c for c in catalog["checks"]}
    cms_checks = catalog["cms_checks"]

    scans, techs, intel, verified, candidates = [], [], [], [], []
    excl = {EXCL_LEVEL_NONE: 0, EXCL_LEVEL_UNKNOWN: 0, EXCL_UNREACHABLE: 0}

    for rec in records:
        uid, origin = rec["scan_uid"], rec["origin"]
        host = rec.get("host", "")
        sat = normalize.parse_scanned_at(rec.get("scanned_at"))
        era = normalize.era_of(origin, rec.get("id"))
        r = rec.get("result") or {}
        if not isinstance(r, dict):
            r = {}
        sec = r.get("security") or {}
        if not isinstance(sec, dict):
            sec = {}
        opts = rec.get("options") or {}
        if not isinstance(opts, dict):
            opts = {}

        scans.append({
            "scan_uid": uid, "origin": origin, "scan_id": rec.get("id"),
            "host": host, "url": rec.get("url", ""), "ip": (r.get("ip") or ""),
            "title": rec.get("title", ""), "status": r.get("status"),
            "security_grade": sec.get("grade"), "security_score": sec.get("score"),
            "tech_count": rec.get("tech_count"), "vuln_count": rec.get("vuln_count"),
            "duration_s": rec.get("duration"),
            "scanned_at": rec.get("scanned_at", ""), "scanned_at_dt": sat,
            "era": era, "page_count": len(r.get("pages") or []),
            "response_time_ms": r.get("response_time_ms"),
            "result_error": (r.get("error") or ""),
            "options_json": json.dumps(opts, ensure_ascii=False, sort_keys=True),
            "options_checks": normalize.norm_check_level(opts.get("checks")),
        })

        for t in r.get("technologies") or []:
            techs.append({
                "scan_uid": uid, "host": host, "scanned_at_dt": sat, "era": era,
                "name": t.get("name", ""), "categories": "|".join(t.get("categories") or []),
                "confidence": t.get("confidence"), "version": (t.get("version") or ""),
                "has_version": bool(t.get("version")),
                "evidence_channels": "|".join(normalize.evidence_channels(t.get("evidence"))),
                "n_evidence": len(t.get("evidence") or []),
            })

        for v in r.get("vulnerabilities") or []:
            intel.append({
                "scan_uid": uid, "host": host, "scanned_at_dt": sat, "era": era,
                "tech": v.get("tech", ""), "version": (v.get("version") or ""),
                "src": v.get("src", ""), "cve": (v.get("cve") or "").upper(),
                "severity_raw": v.get("severity"),
                "severity_norm": normalize.norm_severity(v.get("severity")),
                "verdict": normalize.norm_verdict(v.get("verdict")),
                "cvss_score": v.get("cvss_score") or None,
                "cvss_sev": v.get("cvss_sev") or None,
                "kev": bool(v.get("kev")),
                "n_templates": len(v.get("templates") or []),
                "title": v.get("title", ""),
            })

        for i, x in enumerate(r.get("verified") or []):
            resp = x.get("response") or {}
            verified.append({
                "scan_uid": uid, "host": host, "scanned_at_dt": sat, "era": era,
                "row_idx": i, "src": x.get("src", ""), "check": x.get("check", ""),
                "severity_raw": x.get("severity"),
                "severity_norm": normalize.norm_severity(x.get("severity")),
                "url": x.get("url", ""), "param": x.get("param", ""),
                "has_payload": bool(x.get("payload")),
                "confirmed": bool(x.get("confirmed")),
                "has_evidence_chain": bool(x.get("request")) and bool(x.get("response"))
                and bool(x.get("replay")) and bool(x.get("signals")),
                "resp_status": resp.get("status"), "resp_size": resp.get("size"),
                "signals_count": len(x.get("signals") or []),
                "impact": x.get("impact"),  # 可空；显式 missing，绝不填 0/空串冒充
                "execution_status": config.EXEC_EXECUTED,
                "execution_basis": "verified 命中落库即执行证明",
            })

        # ---- 内置 check 候选集（T2 evaluation target，开发文档 §5）----
        if r.get("error"):
            excl[EXCL_UNREACHABLE] += 1
            continue
        level = normalize.norm_check_level(opts.get("checks"))
        if level is None:
            excl[EXCL_LEVEL_UNKNOWN] += 1
            continue
        if level == "none":
            excl[EXCL_LEVEL_NONE] += 1
            continue
        scan_techs = {t.get("name", "") for t in r.get("technologies") or []}
        linked: set[str] = set()
        for tech_name in scan_techs:
            linked.update(cms_checks.get(tech_name, []))
        for cid, c in checks.items():
            # 与 checks.RunChecks 的选择语义一致：level==all 全跑；Lv0 核心集
            # 在 core/all 跑；CMS 联动集无论档位强制加入（checks.go:79-85）
            selected = c["lv"] == 0 or level == "all" or cid in linked
            if not selected:
                continue
            candidates.append({
                "scan_uid": uid, "host": host, "scanned_at_dt": sat, "era": era,
                "check_id": cid, "check_lv": c["lv"], "check_severity": c["severity"],
                "level": level, "cms_linked": cid in linked,
                "execution_status": config.EXEC_UNKNOWN,
                "execution_basis": "options.checks 档位仅证明被选择；单请求成败无日志",
            })

    tables = {
        "scans": pd.DataFrame(scans),
        "techs": pd.DataFrame(techs),
        "intel": pd.DataFrame(intel),
        "verified": pd.DataFrame(verified),
        "candidates": pd.DataFrame(candidates),
        "cve_features": cve_features if cve_features is not None else pd.DataFrame(),
        "tech_catalog": tech_catalog if tech_catalog is not None else pd.DataFrame(),
    }
    df_scans, df_intel = tables["scans"], tables["intel"]
    stats = {
        "counts": {k: int(len(v)) for k, v in tables.items()},
        "era": {k: int(v) for k, v in df_scans["era"].value_counts().items()} if len(df_scans) else {},
        "hosts": int(df_scans["host"].nunique()) if len(df_scans) else 0,
        "candidate_exclusions": excl,
        "severity_raw": {k: int(v) for k, v in df_intel["severity_raw"].value_counts(dropna=False).items()} if len(df_intel) else {},
        "verdict": {k: int(v) for k, v in df_intel["verdict"].value_counts(dropna=False).items()} if len(df_intel) else {},
    }
    return tables, stats


def build_cve_features(paths: config.Paths, df_intel: pd.DataFrame) -> pd.DataFrame:
    """D5：仅对 D3 中观测到的 CVE 构建字典特征投影（NVD/KEV/模板情报/精选区间）。

    字段全部来自真实字典文件；字典中查不到的 CVE 显式 missing（不填 0 冒充）。
    """
    cves = sorted({c for c in (df_intel["cve"].fillna("") if len(df_intel) else []) if c})
    want = set(cves)
    rows: dict[str, dict] = {c: {"cve": c} for c in cves}

    kev_set: set[str] = set()
    if paths.kev_extra.is_file():
        try:
            kev = json.loads(paths.kev_extra.read_text(encoding="utf-8"))
            entries = kev if isinstance(kev, list) else kev.get("entries", [])
            for e in entries:
                cve = str(e.get("cve", "")).upper()
                if cve:
                    kev_set.add(cve)
        except (json.JSONDecodeError, OSError):
            pass  # 缓存损坏按缺失处理，不阻塞

    if paths.nvd_cves.is_file() and want:
        with gzip.open(paths.nvd_cves, "rt", encoding="utf-8") as f:
            nvd = json.load(f)
        for e in nvd.get("cves", []):
            cve = str(e.get("cve", "")).upper()
            if cve not in want:
                continue
            row = rows[cve]
            row["nvd_score"] = e.get("score")
            row["nvd_sev"] = e.get("sev")
            row["nvd_pub"] = e.get("pub")
            row["nvd_vector"] = e.get("vector")
            for comp in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
                row[f"cvss_{comp.lower()}"] = _vector_component(e.get("vector"), comp)

    for c in cves:
        rows[c]["kev"] = c in kev_set
        rows[c].setdefault("nvd_score", None)

    if paths.tpl_intel.is_file() and want:
        with gzip.open(paths.tpl_intel, "rt", encoding="utf-8") as f:
            tpl = json.load(f)
        counts: dict[str, int] = {}
        for r_ in tpl.get("rows", []):
            cve = str(r_.get("cve", "")).upper()
            if cve:
                counts[cve] = counts.get(cve, 0) + 1
        for c in cves:
            rows[c]["n_tpl_intel"] = counts.get(c, 0)

    if paths.affected_ranges.is_file():
        try:
            ranges = json.loads(paths.affected_ranges.read_text(encoding="utf-8"))
            curated: set[str] = set()
            for _tech, rs in ranges.items():
                for r_ in rs:
                    curated.add(str(r_.get("cve", "")).upper())
            for c in cves:
                rows[c]["in_curated_range"] = c in curated
        except (json.JSONDecodeError, OSError):
            pass

    return pd.DataFrame([rows[c] for c in cves])


def _vector_component(vector: str | None, comp: str) -> str | None:
    if not vector:
        return None
    for part in str(vector).split("/"):
        if part.strip().upper().startswith(comp + ":"):
            return part.split(":", 1)[1].strip()
    return None


def build_tech_catalog(paths: config.Paths) -> pd.DataFrame:
    """D5：指纹库技术目录（name/cats/conf；rules 体积大且非特征，不入表）。"""
    if not paths.technologies_json.is_file():
        return pd.DataFrame(columns=["name", "categories", "conf"])
    data = json.loads(paths.technologies_json.read_text(encoding="utf-8"))
    rows = [
        {"name": t.get("name", ""), "categories": "|".join(t.get("cats") or []),
         "conf": t.get("conf")}
        for t in data.get("technologies", []) if t.get("name")
    ]
    return pd.DataFrame(rows)


def write_dataset(paths: config.Paths, tables: dict[str, pd.DataFrame], stats: dict,
                  inputs: list[dict], version: str = "ds-5.0.0") -> Path:
    out = paths.out_root / "dataset"
    files: list[Path] = []
    for key, name in TABLE_FILES.items():
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        tables[key].to_json(p, orient="records", lines=True, force_ascii=False,
                            compression="gzip")
        files.append(p)
    (out / "dataset_stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    man = manifest.make_manifest(
        kind="dataset", version=version,
        inputs=inputs + [manifest.file_input(p, role="output") for p in files],
        params={"sources": list(stats.get("source", {}).get("per_source_raw", {}).keys())},
        producer="ml/dataset.py:build_tables",
        scope={"scans": stats["counts"]["scans"], "hosts": stats["hosts"],
               "era": stats["era"]},
    )
    return manifest.write_manifest(man, out / "DATASET_MANIFEST.json")
