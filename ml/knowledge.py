"""知识层构建（学习阶段）：主仓库大规模安全数据 → 规范化 KB 表。

数据血缘（recon_report 实证）：
  NVD 371,755 CVE（0 重复，pub 1988-2026，3,038,966 产品约束，无 CWE 字段）
  nuclei_index 117,889 模板（56,066 带 CVE；sev 有社区拼写脏数据 → 归一）
  tpl_intel 29,554（每行唯一 CVE，10,288 产品，全部可回联 NVD）
  intel_dump：vuln_kb 1,985 / cve_ms 34,931 / kev 1,695 / service_fp 11,966
  yaml id 扫描 142,167 文件 → 115,635 唯一 id（= verified check id 联接钥匙）

数据分层（目标要求）：raw(原文件) / normalized(本模块) / knowledge(关联表) /
weak_label(关系标签) / training(向量化样本) / evaluation(跨源+时间切分)。
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pandas as pd

from . import config, manifest

# 社区模板 sev 字段脏值归一（recon 实证的拼写错误，逐条映射，绝不猜测未listed值）
TEMPLATE_SEV_MAP = {
    "critical": "critical", "criticall": "critical", "cretical": "critical",
    "high": "high", "hight": "high", "highx": "high", "severe": "high",
    "medium": "medium", "meduim": "medium",
    "low": "low",
    "info": "info", "informative": "info",
    "unknown": None, "unknnown": None, "potential": None,
}

PRODUCT_MIN_CVES = 30  # K2 关系任务的产品类别下限（类别过多且稀疏的不学）


def norm_template_sev(raw: str | None) -> str | None:
    if raw is None:
        return None
    return TEMPLATE_SEV_MAP.get(str(raw).strip().lower(), None)


def _load_json_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def build_kb_tables(paths: config.Paths) -> dict[str, pd.DataFrame]:
    """构建 KB 表：kb_cve / kb_template / kb_template_cve / kb_tpl_intel /
    kb_cve_product / kb_product_stats。"""
    # ---- NVD（raw → normalized）----
    nvd = _load_json_gz(paths.nvd_cves)["cves"]
    cve_rows = []
    edges = []
    for e in nvd:
        cve = (e.get("cve") or "").upper()
        if not cve:
            continue
        cve_rows.append({
            "cve": cve, "pub": e.get("pub"), "mod": e.get("mod"),
            "sev": (e.get("sev") or "").lower() or None,
            "score": e.get("score"), "vector": e.get("vector"),
            "descr_len": len(e.get("descr") or ""),
            "descr": e.get("descr") or "",
            "n_prods": len(e.get("prods") or []),
        })
        for p in e.get("prods") or []:
            vp = p.get("vp", "")
            vendor, _, product = vp.partition("/")
            edges.append({
                "cve": cve, "vendor": vendor.strip().lower(),
                "product": product.strip().lower() if product else vendor.strip().lower(),
                "has_bound": bool(p.get("ee") or p.get("ei") or p.get("si") or p.get("se") or p.get("v")),
            })
    kb_cve = pd.DataFrame(cve_rows)
    kb_cve_product = pd.DataFrame(edges)
    prod_stats = (kb_cve_product.groupby(["vendor", "product"]).size()
                  .rename("n_cves").reset_index()
                  .sort_values("n_cves", ascending=False))
    prod_stats["vendor_product"] = prod_stats["vendor"] + "/" + prod_stats["product"]

    # ---- 模板（index + yaml id + sev 归一）----
    idx = json.loads(paths.nuclei_index.read_text(encoding="utf-8"))["entries"]
    id_cache = paths.out_root / "cache" / "template_yaml_ids.json"
    yaml_ids = json.loads(id_cache.read_text(encoding="utf-8")) if id_cache.is_file() else {}
    tpl_rows, tpl_cve_rows = [], []
    for e in idx:
        path = e.get("path", "")
        yid = yaml_ids.get(path)
        tpl_rows.append({
            "path": path, "name": e.get("name", ""), "yaml_id": yid,
            "check_id": f"nuclei-{yid}" if yid else None,
            "sev_raw": e.get("sev", ""),
            "sev_norm": norm_template_sev(e.get("sev")),
            "proto": e.get("proto") or "http",
            "n_tags": len(e.get("tags") or []),
            "tags": "|".join((e.get("tags") or [])[:12]),
            "n_cves": len(e.get("cves") or []),
            "source": path.split("/", 1)[0] if "/" in path else path,
        })
        for c in e.get("cves") or []:
            tpl_cve_rows.append({"path": path, "cve": str(c).upper()})
    kb_template = pd.DataFrame(tpl_rows)
    kb_template_cve = pd.DataFrame(tpl_cve_rows)

    # ---- tpl_intel（模板情报行：product 维度）----
    ti_rows = []
    if paths.tpl_intel.is_file():
        for r in _load_json_gz(paths.tpl_intel)["rows"]:
            ti_rows.append({
                "cve": (r.get("cve") or "").upper(), "name": r.get("name", ""),
                "product": (r.get("product") or "").lower(), "src": r.get("src", ""),
                "severity": r.get("severity"), "cvss_score": r.get("cvss_score"),
            })
    kb_tpl_intel = pd.DataFrame(ti_rows)

    kb_product_stats = prod_stats
    return {
        "kb_cve": kb_cve,
        "kb_cve_product": kb_cve_product,
        "kb_product_stats": kb_product_stats,
        "kb_template": kb_template,
        "kb_template_cve": kb_template_cve,
        "kb_tpl_intel": kb_tpl_intel,
    }


def kb_stats(tables: dict[str, pd.DataFrame], paths: config.Paths) -> dict:
    cve = tables["kb_cve"]
    tpl = tables["kb_template"]
    st: dict = {
        "kb_cve": {
            "records": int(len(cve)),
            "unique_cve": int(cve["cve"].nunique()),
            "labeled_sev": int(cve["sev"].notna().sum()),
            "sev_dist": {k: int(v) for k, v in cve["sev"].value_counts(dropna=False).items()},
            "pub_min": str(cve["pub"].dropna().min()) if cve["pub"].notna().any() else None,
            "pub_max": str(cve["pub"].dropna().max()) if cve["pub"].notna().any() else None,
            "with_descr": int((cve["descr_len"] > 0).sum()),
        },
        "kb_cve_product": {
            "edges": int(len(tables["kb_cve_product"])),
            "unique_vendor": int(tables["kb_cve_product"]["vendor"].nunique()),
            "unique_product": int(tables["kb_cve_product"]["product"].nunique()),
            "products_ge30": int((tables["kb_product_stats"]["n_cves"] >= PRODUCT_MIN_CVES).sum()),
            "products_ge100": int((tables["kb_product_stats"]["n_cves"] >= 100).sum()),
            "top10": tables["kb_product_stats"].head(10).to_dict("records"),
        },
        "kb_template": {
            "records": int(len(tpl)),
            "unique_yaml_id": int(tpl["yaml_id"].nunique()),
            "with_yaml_id": int(tpl["yaml_id"].notna().sum()),
            "sev_norm_dist": {k: int(v) for k, v in tpl["sev_norm"].value_counts(dropna=False).items()},
            "sev_raw_unmapped": int(tpl["sev_norm"].isna().sum()),
            "with_cves": int((tpl["n_cves"] > 0).sum()),
            "by_source": {k: int(v) for k, v in tpl["source"].value_counts().items()},
        },
        "kb_template_cve": {"edges": int(len(tables["kb_template_cve"]))},
        "kb_tpl_intel": {"records": int(len(tables["kb_tpl_intel"]))},
    }
    return st


def write_kb(paths: config.Paths, tables: dict[str, pd.DataFrame], stats: dict,
             version: str = "kb-5.0.0") -> Path:
    out = paths.out_root / "dataset" / "kb"
    out.mkdir(parents=True, exist_ok=True)
    files = []
    for name, df in tables.items():
        p = out / f"{name}.jsonl.gz"
        df.to_json(p, orient="records", lines=True, force_ascii=False, compression="gzip")
        files.append(p)
    (out / "KB_STATS.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    inputs = [manifest.file_input(paths.nvd_cves, role="source:nvd"),
              manifest.file_input(paths.nuclei_index, role="source:nuclei_index"),
              manifest.file_input(paths.tpl_intel, role="source:tpl_intel"),
              manifest.file_input(paths.intel_dump, role="source:intel_dump")]
    if (paths.out_root / "cache" / "template_yaml_ids.json").is_file():
        inputs.append(manifest.file_input(
            paths.out_root / "cache" / "template_yaml_ids.json", role="source:yaml_ids"))
    man = manifest.make_manifest(
        kind="dataset", version=version,
        inputs=inputs + [manifest.file_input(p, role="output") for p in files],
        params={"template_sev_map": config.__name__ + ".knowledge.TEMPLATE_SEV_MAP",
                "product_min_cves": PRODUCT_MIN_CVES},
        producer="ml/knowledge.py:build_kb_tables",
        scope={"kb_cve": stats["kb_cve"]["records"],
               "kb_template": stats["kb_template"]["records"]},
    )
    return manifest.write_manifest(man, out / "KB_MANIFEST.json")
