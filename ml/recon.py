"""数据侦察（学习阶段第一步）：主仓库大规模安全数据全量盘点。

原则：不假设数据结构——每个来源先看真实字段再统计；所有数字来自实读。
产出：recon_report.json（全量统计）+ 各来源血缘（来源→字段→键→可关联性）。
"""

from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from pathlib import Path

import pandas as pd

from . import config, manifest


def _load_json_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def inventory_files(data_root: Path) -> list[dict]:
    rows = []
    for p in sorted(Path(data_root).rglob("*")):
        if p.is_file():
            rows.append({"rel": str(p.relative_to(data_root)), "bytes": p.stat().st_size})
    return rows


def recon_nvd(paths: config.Paths) -> dict:
    if not paths.nvd_cves.is_file():
        return {"present": False}
    nvd = _load_json_gz(paths.nvd_cves)
    cves = nvd.get("cves", [])
    keys = Counter()
    for e in cves[:200000]:
        keys.update(e.keys())
    dups = len(cves) - len({e.get("cve") for e in cves})
    years = [int(e["pub"][:4]) for e in cves if e.get("pub") and len(e["pub"]) >= 4]
    n_products = sum(len(e.get("prods") or []) for e in cves)
    has_cwe = sum(1 for e in cves if "cwe" in e)
    sev = Counter((e.get("sev") or "").lower() for e in cves)
    return {
        "present": True, "records": len(cves), "declared_count": nvd.get("count"),
        "exported_at": nvd.get("exported_at"),
        "fields_sample": dict(keys), "dup_cve": dups,
        "pub_year_min": min(years) if years else None,
        "pub_year_max": max(years) if years else None,
        "total_prod_constraints": n_products,
        "has_cwe_field": int(has_cwe),
        "sev_dist": dict(sev),
    }


def recon_nuclei_index(paths: config.Paths) -> dict:
    if not paths.nuclei_index.is_file():
        return {"present": False}
    d = json.loads(paths.nuclei_index.read_text(encoding="utf-8"))
    ents = d.get("entries", [])
    sev = Counter(e.get("sev", "") for e in ents)
    proto = Counter(e.get("proto", "") for e in ents if e.get("proto"))
    conv = sum(1 for e in ents if e.get("convertible"))
    withcve = sum(1 for e in ents if e.get("cves"))
    n_cve_rel = sum(len(e.get("cves") or []) for e in ents)
    lastrun = sum(1 for e in ents if e.get("lastrun"))
    tagc = Counter()
    for e in ents:
        for t in (e.get("tags") or [])[:8]:
            tagc[t] += 1
    return {
        "present": True, "schema": d.get("schema"), "files_declared": d.get("files"),
        "records": len(ents), "convertible": conv,
        "sev_dist": dict(sev), "proto_dist": dict(proto),
        "with_cves": withcve, "cve_relations": n_cve_rel,
        "with_lastrun": lastrun, "top_tags": dict(tagc.most_common(20)),
        "dup_paths": len(ents) - len({e.get("path") for e in ents}),
    }


def scan_template_yaml_ids(nuclei_dir: Path, cache: Path, limit: int | None = None) -> dict:
    """扫描模板文件头部 `id:` 字段 → 路径映射（Template↔Check 关系的钥匙：
    verified 行 check id = 'nuclei-' + yaml id）。结果缓存，只扫一次。"""
    if cache.is_file():
        return json.loads(cache.read_text(encoding="utf-8"))
    pat = re.compile(r"^id:\s*([^\s#]+)", re.M)
    mapping = {}
    files = sorted(Path(nuclei_dir).rglob("*.yaml")) + sorted(Path(nuclei_dir).rglob("*.yml"))
    for i, p in enumerate(files):
        if limit and i >= limit:
            break
        try:
            head = p.read_text(encoding="utf-8", errors="ignore")[:4096]
        except OSError:
            continue
        m = pat.search(head)
        if m:
            mapping[str(p.relative_to(nuclei_dir)).replace("\\", "/")] = m.group(1)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(mapping, ensure_ascii=False), encoding="utf-8")
    return mapping


def recon_intel_dump(paths: config.Paths) -> dict:
    if not paths.intel_dump.is_file():
        return {"present": False}
    box = _load_json_gz(paths.intel_dump)
    t = box.get("tables", {})
    out: dict = {"present": True, "tables": {}}
    vkb = t.get("vuln_kb", [])
    out["tables"]["vuln_kb"] = {
        "records": len(vkb),
        "src_dist": dict(Counter(r.get("src", "") for r in vkb)),
        "unique_cve": len({r.get("cve") for r in vkb if r.get("cve")}),
        "unique_product": len({r.get("product") for r in vkb if r.get("product")}),
        "with_affected": sum(1 for r in vkb if r.get("affected")),
        "with_cvss": sum(1 for r in vkb if r.get("cvss_score")),
    }
    cms = t.get("cve_ms", [])
    out["tables"]["cve_ms"] = {
        "records": len(cms),
        "unique_cve": len({r.get("cve") for r in cms if r.get("cve")}),
        "date_min": min((r.get("date") or "") for r in cms) or None,
        "date_max": max((r.get("date") or "") for r in cms) or None,
    }
    out["tables"]["kev"] = {"records": len(t.get("kev", []))}
    out["tables"]["fingerdir"] = {"records": len(t.get("fingerdir", []))}
    sfp = t.get("service_fp", [])
    out["tables"]["service_fp"] = {
        "records": len(sfp),
        "unique_service": len({r.get("service") for r in sfp if r.get("service")}),
    }
    out["tables"]["tscan_fingerprints"] = {"records": len(t.get("tscan_fingerprints", []))}
    return out


def recon_tpl_intel(paths: config.Paths) -> dict:
    if not paths.tpl_intel.is_file():
        return {"present": False}
    b = _load_json_gz(paths.tpl_intel)
    rows = b.get("rows", [])
    src = Counter(r.get("src", "") for r in rows)
    return {
        "present": True, "records": len(rows),
        "unique_cve": len({r.get("cve") for r in rows if r.get("cve")}),
        "unique_product": len({r.get("product") for r in rows if r.get("product")}),
        "unique_name": len({r.get("name") for r in rows if r.get("name")}),
        "src_dist": dict(src),
        "with_cvss": sum(1 for r in rows if r.get("cvss_score")),
        "fields_sample": sorted(rows[0].keys()) if rows else [],
    }


def recon_technologies(paths: config.Paths) -> dict:
    if not paths.technologies_json.is_file():
        return {"present": False}
    d = json.loads(paths.technologies_json.read_text(encoding="utf-8"))
    techs = d.get("technologies", [])
    cats = Counter()
    channels = Counter()
    for t in techs:
        for c in t.get("cats") or []:
            cats[c] += 1
        rules = t.get("rules") or {}
        if isinstance(rules, dict):
            for ch in ("headers", "cookies", "meta", "html", "scripts", "dom", "icon_hash"):
                if rules.get(ch):
                    channels[ch] += 1
    return {"present": True, "records": len(techs),
            "unique_name": len({t.get("name") for t in techs if t.get("name")}),
            "cats_top": dict(cats.most_common(15)), "rule_channels": dict(channels)}


def recon_tech_cpe(paths: config.Paths) -> dict:
    p = paths.data_root / "go" / "tech_cpe.json"
    if not p.is_file():
        return {"present": False}
    d = json.loads(p.read_text(encoding="utf-8"))
    return {"present": True, "records": len(d),
            "sample": dict(list(d.items())[:3]) if isinstance(d, dict) else []}


def cve_overlaps(paths: config.Paths, tables: dict) -> dict:
    """CVE 集合的跨来源可关联率（交集计数）。"""
    sets: dict[str, set] = {}
    nvd = tables.get("nvd_cves") or set()
    sets["nvd"] = nvd
    if paths.intel_dump.is_file():
        t = _load_json_gz(paths.intel_dump)["tables"]
        sets["vuln_kb"] = {r.get("cve", "").upper() for r in t.get("vuln_kb", []) if r.get("cve")}
        sets["cve_ms"] = {r.get("cve", "").upper() for r in t.get("cve_ms", []) if r.get("cve")}
        sets["kev"] = {r.get("cve", "").upper() for r in t.get("kev", []) if r.get("cve")}
    if paths.tpl_intel.is_file():
        sets["tpl_intel"] = {r.get("cve", "").upper() for r in
                             _load_json_gz(paths.tpl_intel)["rows"] if r.get("cve")}
    idx = tables.get("index_cves") or set()
    if idx:
        sets["nuclei_index"] = idx
    names = list(sets)
    out = {"set_sizes": {k: len(v) for k, v in sets.items()}, "pairs": {}}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            out["pairs"][f"{a}&{b}"] = len(sets[a] & sets[b])
    return out


def run_recon(paths: config.Paths, scan_template_ids: bool = True) -> dict:
    nvd = recon_nvd(paths)
    idx = recon_nuclei_index(paths)
    report = {
        "file_inventory": {
            "total_files": 0, "total_bytes": 0, "per_top_dir": {}},
        "nvd": nvd,
        "nuclei_index": idx,
        "intel_dump": recon_intel_dump(paths),
        "tpl_intel": recon_tpl_intel(paths),
        "technologies": recon_technologies(paths),
        "tech_cpe": recon_tech_cpe(paths),
        "scan_history_note": "119 ScanRecord 见 DATASET ds-5.0.0（审计报告 §7）",
    }
    inv = inventory_files(paths.data_root)
    report["file_inventory"]["total_files"] = len(inv)
    report["file_inventory"]["total_bytes"] = sum(x["bytes"] for x in inv)
    per = Counter()
    perb = Counter()
    for x in inv:
        top = x["rel"].split("\\", 1)[0].split("/", 1)[0]
        per[top] += 1
        perb[top] += x["bytes"]
    report["file_inventory"]["per_top_dir"] = {
        k: {"files": per[k], "bytes": perb[k]} for k in sorted(per)}

    # 跨来源 CVE 交集
    nvd_cves = set()
    if nvd.get("present"):
        nvd_cves = {e.get("cve", "").upper() for e in _load_json_gz(paths.nvd_cves)["cves"]}
    idx_cves = set()
    if idx.get("present") and paths.nuclei_index.is_file():
        d = json.loads(paths.nuclei_index.read_text(encoding="utf-8"))
        idx_cves = {c.upper() for e in d["entries"] for c in (e.get("cves") or [])}
    report["cve_overlaps"] = cve_overlaps(paths, {"nvd_cves": nvd_cves,
                                                  "index_cves": idx_cves})

    # Template↔Check 钥匙：yaml id 扫描（带缓存）
    nuclei_dir = paths.data_root / "nuclei"
    if scan_template_ids and nuclei_dir.is_dir():
        mapping = scan_template_yaml_ids(nuclei_dir, paths.out_root / "cache" / "template_yaml_ids.json")
        report["template_yaml_ids"] = {
            "files_scanned": len(mapping),
            "unique_yaml_ids": len(set(mapping.values())),
            "dup_yaml_ids": len(mapping) - len(set(mapping.values())),
            "sample": dict(list(mapping.items())[:3]),
        }
    return report


def write_recon(paths: config.Paths, report: dict, version: str = "recon-5.0.0") -> Path:
    inputs = [manifest.file_input(paths.nuclei_index, role="source:nuclei_index")]
    out = paths.out_root / "metrics" / "recon_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    man = manifest.make_manifest(
        kind="report", version=version,
        inputs=inputs + [manifest.file_input(out, role="output")],
        params={"scope": "main-repo-data-recon"},
        producer="ml/recon.py:run_recon",
        scope={"data_root": str(paths.data_root)},
    )
    manifest.write_manifest(man, paths.out_root / "metrics" / "RECON_MANIFEST.json")
    return out
